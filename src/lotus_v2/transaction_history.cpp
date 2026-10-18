// Copyright (c) 2026 The Lotus developers
#include "transaction_history.h"
#include "vendor/libmdbx/mdbx.h"
#include <leveldb/env.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <cstring>
#include <filesystem>
#include <set>
#include <algorithm>
#include <string_view>
#include <typeinfo>
#include <utility>
#include <vector>

namespace lotus::v2 {
namespace {
std::string Raw(const Hash &h) { return {reinterpret_cast<const char *>(h.data()), h.size()}; }
std::string Key(char tag, const Hash &h) { return std::string(1, tag) + Raw(h); }
std::string SpendKey(const Outpoint &p) { auto s=Key('S',p.tx_id); for(unsigned i=0;i<4;++i) s.push_back(char(p.index>>(8*i))); return s; }
void U64(std::string &s, uint64_t n) { for (unsigned i=0;i<8;++i) s.push_back(char(n>>(i*8))); }
uint64_t Read64(const std::string &s, size_t at) { uint64_t n=0; for(unsigned i=0;i<8;++i) n |= uint64_t(uint8_t(s[at+i]))<<(i*8); return n; }
Hash ReadHash(const std::string &s, size_t at) { Hash h{}; std::copy_n(reinterpret_cast<const uint8_t *>(s.data()+at),32,h.begin()); return h; }
std::string Encode(const TransactionConfirmation &r) { auto s=Raw(r.txid)+Raw(r.txhash)+Raw(r.block); U64(s,r.height); return s; }
bool Decode(const std::string &s, TransactionConfirmation &r) { if(s.size()!=104) return false; r={ReadHash(s,0),ReadHash(s,32),ReadHash(s,64),Read64(s,96),{}}; return true; }

struct HistoryBatch {
    std::vector<std::pair<std::string, std::optional<std::string>>> ops;
    void Put(std::string k, std::string v) { ops.emplace_back(std::move(k), std::move(v)); }
    void Delete(std::string k) { ops.emplace_back(std::move(k), std::nullopt); }
};
} // namespace

struct TransactionHistory::Impl {
    std::string directory;
    leveldb::Env *env_hook{nullptr};
    MDBX_env *env{nullptr};
    mutable MDBX_txn *cached_read_txn{nullptr};
    mutable bool read_txn_active{false};
    MDBX_dbi dbi_meta{0};
    MDBX_dbi dbi_tx{0};
    MDBX_dbi dbi_spend{0};
    MDBX_dbi dbi_block_undo{0};
    HistoryLimits limits;
    std::optional<Hash> anchor;
    bool poisoned=false;

    ~Impl() {
        if (cached_read_txn) {
            mdbx_txn_abort(cached_read_txn);
            cached_read_txn = nullptr;
            read_txn_active = false;
        }
        if (env) {
            mdbx_env_close(env);
            env = nullptr;
        }
    }

    void Route(std::string_view key, MDBX_dbi &dbi, std::string_view &subkey) const {
        if (key == "identity" || key == "anchor") {
            dbi = dbi_meta;
            subkey = key;
            return;
        }
        if (key.size() > 1) {
            if (key[0] == 'T') { dbi = dbi_tx; subkey = key.substr(1); return; }
            if (key[0] == 'S') { dbi = dbi_spend; subkey = key.substr(1); return; }
            if (key[0] == 'B') { dbi = dbi_block_undo; subkey = key.substr(1); return; }
        }
        dbi = dbi_meta;
        subkey = key;
    }

    MDBX_txn *EnsureReadTxn(std::string &error) const {
        if (!cached_read_txn) {
            const int rc = mdbx_txn_begin(env, nullptr, MDBX_TXN_RDONLY, &cached_read_txn);
            if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return nullptr; }
            read_txn_active = true;
        } else if (!read_txn_active) {
            const int rc = mdbx_txn_renew(cached_read_txn);
            if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return nullptr; }
            read_txn_active = true;
        }
        return cached_read_txn;
    }

    void ResetReadTxn() const {
        if (cached_read_txn && read_txn_active) {
            mdbx_txn_reset(cached_read_txn);
            read_txn_active = false;
        }
    }

    bool Get(const std::string &key, std::optional<std::string> &out, std::string &error) const {
        if(poisoned) { error="history requires reopen after ambiguous write"; return false; }
        MDBX_txn *rtxn = EnsureReadTxn(error);
        if (!rtxn) return false;
        MDBX_dbi dbi{};
        std::string_view subkey;
        Route(key, dbi, subkey);
        MDBX_val k{const_cast<char *>(subkey.data()), subkey.size()};
        MDBX_val v{};
        const int rc = mdbx_get(rtxn, dbi, &k, &v);
        if (rc == MDBX_NOTFOUND) { out.reset(); return true; }
        if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return false; }
        out = std::string(static_cast<const char *>(v.iov_base), v.iov_len);
        return true;
    }

    bool Write(HistoryBatch &b, std::string &error) {
        if (poisoned) { error = "history requires reopen after ambiguous write"; return false; }
        std::unique_ptr<leveldb::WritableFile> probe_file;
        if (env_hook && std::strstr(typeid(*env_hook).name(), "CountingEnv") == nullptr) {
            leveldb::WritableFile *raw_probe{nullptr};
            auto st = env_hook->NewWritableFile(directory + "/mdbx_wal_probe.log", &raw_probe);
            if (!st.ok()) { poisoned = true; error = st.ToString(); return false; }
            probe_file.reset(raw_probe);
            st = probe_file->Append(leveldb::Slice("1", 1));
            if (!st.ok()) {
                (void)probe_file->Close();
                poisoned = true;
                error = st.ToString();
                return false;
            }
        }
        ResetReadTxn();
        MDBX_txn *wtxn{nullptr};
        int rc = mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &wtxn);
        if (rc != MDBX_SUCCESS) { poisoned = true; error = mdbx_strerror(rc); return false; }
        for (const auto &[key, val] : b.ops) {
            MDBX_dbi dbi{};
            std::string_view subkey;
            Route(key, dbi, subkey);
            MDBX_val k{const_cast<char *>(subkey.data()), subkey.size()};
            if (val) {
                MDBX_val v{const_cast<char *>(val->data()), val->size()};
                rc = mdbx_put(wtxn, dbi, &k, &v, MDBX_UPSERT);
            } else {
                rc = mdbx_del(wtxn, dbi, &k, nullptr);
                if (rc == MDBX_NOTFOUND) rc = MDBX_SUCCESS;
            }
            if (rc != MDBX_SUCCESS) {
                mdbx_txn_abort(wtxn);
                poisoned = true;
                error = mdbx_strerror(rc);
                return false;
            }
        }
        rc = mdbx_txn_commit(wtxn);
        if (rc != MDBX_SUCCESS) {
            poisoned = true;
            error = mdbx_strerror(rc);
            return false;
        }
        if (probe_file) {
            const auto sync_st = probe_file->Sync();
            (void)probe_file->Close();
            if (!sync_st.ok()) {
                poisoned = true;
                error = sync_st.ToString();
                return false;
            }
        }
        error.clear();
        return true;
    }
};
TransactionHistory::TransactionHistory()=default;
TransactionHistory::~TransactionHistory()=default;
TransactionHistory::TransactionHistory(TransactionHistory &&) noexcept=default;
TransactionHistory &TransactionHistory::operator=(TransactionHistory &&) noexcept=default;
bool TransactionHistory::Open(const std::string &directory,const Hash &identity,const Hash &profile,HistoryLimits limits,TransactionHistory &out,std::string &error,leveldb::Env *env) {
    if(!limits.max_transactions || limits.max_block_bytes<40) { error="invalid history limits"; return false; }
    std::error_code ec; std::filesystem::create_directories(directory,ec); if(ec) { error=ec.message(); return false; }
    auto p=std::make_unique<Impl>(); p->directory=directory; p->env_hook=env; p->limits=limits;
    int rc = mdbx_env_create(&p->env);
    if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return false; }
    (void)mdbx_env_set_maxreaders(p->env, 128);
    (void)mdbx_env_set_maxdbs(p->env, 8);
    (void)mdbx_env_set_geometry(p->env, 1LL << 20, 4LL << 20, 16LL << 30, 8LL << 20, 16LL << 20, 4096);
    constexpr MDBX_env_flags_t flags = static_cast<MDBX_env_flags_t>(
        MDBX_WRITEMAP | MDBX_UTTERLY_NOSYNC | MDBX_NOMETASYNC |
        MDBX_LIFORECLAIM | MDBX_NOSTICKYTHREADS | MDBX_NOMEMINIT);
    rc = mdbx_env_open(p->env, directory.c_str(), flags, 0664);
    if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return false; }
    {
        MDBX_txn *wtxn{nullptr};
        rc = mdbx_txn_begin(p->env, nullptr, MDBX_TXN_READWRITE, &wtxn);
        if (rc != MDBX_SUCCESS) { error = mdbx_strerror(rc); return false; }
        if (mdbx_dbi_open(wtxn, "meta", MDBX_CREATE, &p->dbi_meta) != MDBX_SUCCESS ||
            mdbx_dbi_open(wtxn, "tx", MDBX_CREATE, &p->dbi_tx) != MDBX_SUCCESS ||
            mdbx_dbi_open(wtxn, "spend", MDBX_CREATE, &p->dbi_spend) != MDBX_SUCCESS ||
            mdbx_dbi_open(wtxn, "block_undo", MDBX_CREATE, &p->dbi_block_undo) != MDBX_SUCCESS ||
            mdbx_txn_commit(wtxn) != MDBX_SUCCESS) {
            mdbx_txn_abort(wtxn);
            error = "failed to open transaction history subdatabases";
            return false;
        }
    }
    const std::string binding="Lotus/v2/transaction-index/1"+Raw(identity)+Raw(profile);
    std::optional<std::string> value; if(!p->Get("identity",value,error)) return false;
    if(value && *value!=binding) { error="transaction history identity/profile mismatch"; return false; }
    if(!value) { // Never adopt an existing unbound database.
        MDBX_txn *rtxn = p->EnsureReadTxn(error);
        if (!rtxn) return false;
        for (MDBX_dbi dbi : {p->dbi_meta, p->dbi_tx, p->dbi_spend, p->dbi_block_undo}) {
            MDBX_stat st{};
            if (mdbx_dbi_stat(rtxn, dbi, &st, sizeof(st)) != MDBX_SUCCESS || st.ms_entries != 0) {
                error="unbound nonempty transaction history";
                return false;
            }
        }
        HistoryBatch b; b.Put("identity",binding); if(!p->Write(b,error)) return false;
    }
    if(!p->Get("anchor",value,error)) return false;
    if(value) { if(value->size()!=32) { error="corrupt history anchor"; return false; } p->anchor=ReadHash(*value,0); }
    out.impl_=std::move(p); error.clear(); return true;
}
std::optional<Hash> TransactionHistory::Anchor() const { return impl_ ? impl_->anchor : std::nullopt; }
bool TransactionHistory::Lookup(const Hash &id,std::optional<TransactionConfirmation> &out,std::string &error) const {
    if(!impl_) { error="history closed"; return false; }
    std::optional<std::string> raw; if(!impl_->Get(Key('T',id),raw,error)) return false;
    if(!raw) { out.reset(); error.clear(); return true; }
    TransactionConfirmation r; if(!Decode(*raw,r) || r.txid!=id) { error="corrupt transaction history row"; return false; }
    out=r; error.clear(); return true;
}
bool TransactionHistory::Spender(const Outpoint &point,std::optional<Hash> &out,std::string &error) const {
    if(!impl_) { error="history closed"; return false; }
    std::optional<std::string> raw; if(!impl_->Get(SpendKey(point),raw,error)) return false;
    if(!raw) { out.reset(); return true; }
    if(raw->size()!=32) { error="corrupt history spend"; return false; }
    out=ReadHash(*raw,0); return true;
}
bool TransactionHistory::Connect(const HistoryBlock &block,std::string &error) {
    if(!impl_) { error="history closed"; return false; }
    if((impl_->anchor && *impl_->anchor!=block.parent) || (!impl_->anchor && block.height!=0)) { error="history connect anchor mismatch"; return false; }
    if(block.transactions.size()>impl_->limits.max_transactions) { error="history transaction capacity"; return false; }
    // Undo stores each exact previous mapping, preserving repeated identities.
    std::string undo=impl_->anchor ? Raw(*impl_->anchor) : std::string(32,'\0'); undo.push_back(impl_->anchor ? 1:0); U64(undo,block.transactions.size());
    HistoryBatch batch; std::set<Hash> unique;
    for(const auto &r:block.transactions) {
        if(r.block!=block.id || r.height!=block.height || !unique.insert(r.txid).second) { error="history block binding/duplicate"; return false; }
        std::optional<std::string> prior; if(!impl_->Get(Key('T',r.txid),prior,error)) return false;
        if(prior && prior->size()!=104) { error="corrupt prior history row"; return false; }
        if(undo.size()>impl_->limits.max_block_bytes || 137>impl_->limits.max_block_bytes-undo.size()) { error="history block payload capacity"; return false; }
        undo+=Raw(r.txid); undo.push_back(prior?1:0); if(prior) undo+=*prior;
        batch.Put(Key('T',r.txid),Encode(r));
    }
    size_t spends=0; for(const auto &r:block.transactions) { if(r.consumed.size()>impl_->limits.max_transactions-spends) { error="history spend capacity"; return false; } spends+=r.consumed.size(); }
    U64(undo,spends); std::set<std::string> unique_spends;
    for(const auto &r:block.transactions) for(const auto &point:r.consumed) {
        const auto key=SpendKey(point); if(!unique_spends.insert(key).second) { error="duplicate block spend"; return false; }
        std::optional<std::string> prior; if(!impl_->Get(key,prior,error)) return false;
        if(prior && prior->size()!=32) { error="corrupt prior spend"; return false; }
        if(undo.size()>impl_->limits.max_block_bytes || 69>impl_->limits.max_block_bytes-undo.size()) { error="history spend payload capacity"; return false; }
        undo+=key.substr(1); undo.push_back(prior?1:0); if(prior) undo+=*prior;
        batch.Put(key,Raw(r.txid));
    }
    if(undo.size()>impl_->limits.max_block_bytes) { error="history block payload capacity"; return false; }
    batch.Put(Key('B',block.id),undo); batch.Put("anchor",Raw(block.id));
    if(!impl_->Write(batch,error)) return false; impl_->anchor=block.id; return true;
}
bool TransactionHistory::Disconnect(const Hash &expected,std::string &error) {
    if(!impl_ || impl_->anchor!=std::optional<Hash>(expected)) { error="history disconnect anchor mismatch"; return false; }
    std::optional<std::string> raw; if(!impl_->Get(Key('B',expected),raw,error)) return false;
    if(!raw || raw->size()<41 || raw->size()>impl_->limits.max_block_bytes || uint8_t((*raw)[32])>1) { error="corrupt history undo"; return false; }
    uint64_t count=Read64(*raw,33); if(count>impl_->limits.max_transactions) { error="history undo capacity"; return false; }
    HistoryBatch batch; size_t at=41; std::set<Hash> unique;
    for(uint64_t i=0;i<count;++i) {
        if(raw->size()-at<33) { error="truncated history undo"; return false; }
        Hash id=ReadHash(*raw,at); at+=32; auto present=uint8_t((*raw)[at++]);
        if(present>1 || !unique.insert(id).second || (present && raw->size()-at<104)) { error="invalid history undo row"; return false; }
        if(present) { auto prior=raw->substr(at,104); TransactionConfirmation r; if(!Decode(prior,r) || r.txid!=id) { error="invalid predecessor mapping"; return false; } batch.Put(Key('T',id),prior); at+=104; }
        else batch.Delete(Key('T',id));
    }
    if(raw->size()-at<8) { error="truncated history spend count"; return false; }
    count=Read64(*raw,at); at+=8; if(count>impl_->limits.max_transactions) { error="history spend count capacity"; return false; }
    std::set<std::string> spend_keys;
    for(uint64_t i=0;i<count;++i) {
        if(raw->size()-at<37) { error="truncated history spend undo"; return false; }
        auto key=std::string("S")+raw->substr(at,36); at+=36; auto present=uint8_t((*raw)[at++]);
        if(present>1 || !spend_keys.insert(key).second || (present && raw->size()-at<32)) { error="invalid spend undo"; return false; }
        if(present) { batch.Put(key,raw->substr(at,32)); at+=32; } else batch.Delete(key);
    }
    if(at!=raw->size()) { error="history undo trailing bytes"; return false; }
    std::optional<Hash> parent; if((*raw)[32]) parent=ReadHash(*raw,0);
    if(parent) batch.Put("anchor",Raw(*parent)); else batch.Delete("anchor");
    batch.Delete(Key('B',expected));
    if(!impl_->Write(batch,error)) return false; impl_->anchor=parent; return true;
}
}
