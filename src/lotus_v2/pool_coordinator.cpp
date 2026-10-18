// Copyright (c) 2026 The Lotus developers
#include "pool_coordinator.h"
#include "block_wire.h"
#include "signing.h"
#include <algorithm>
#include <limits>
namespace lotus::v2 {
namespace {
bool Quiescent(const DevelopmentRuntimeSnapshot &s) {
    return s.chain && !s.reopen_required && !s.execution_paused &&
        !s.chain->pending_journal && !s.chain->pending_receipt && !s.chain->pending_propagation;
}
PoolAnchor Anchor(const DevelopmentRuntimeSnapshot &s) { return {s.chain->stable_tip,s.context_generation}; }
}
struct PoolCoordinator::Impl {
    DevelopmentRuntime &runtime;
    PoolCoordinatorConfig config;
    TransactionPool pool;
    TransactionHistory history;
    std::set<Hash> pool_ids; // Retained even while a failed reconciliation disables reads.
    std::optional<PoolAnchor> published;
    std::vector<std::vector<uint8_t>> detached;
    size_t detached_bytes=0;
    explicit Impl(DevelopmentRuntime &r,PoolCoordinatorConfig c):runtime(r),config(std::move(c)),pool(config.pool) {}
    bool Bound(const DevelopmentRuntimeSnapshot &s) const {
        return Quiescent(s) && s.chain->identity==config.identity && s.chain->profile_digest==config.profile_digest;
    }
    bool Current(PoolAnchor a) const { const auto s=runtime.Snapshot(); return Bound(s) && Anchor(s)==a; }
    bool Ready() const { return published && Current(*published) && history.Anchor()==std::optional<Hash>(published->tip); }
    bool Read(const Hash &id,std::optional<IndexedHeader> &h,std::string &error) {
        if(runtime.ReadHeader(id,h,error)!=DevelopmentRuntimeResult::Progress || !h) { if(error.empty()) error="missing indexed history header"; return false; } return true;
    }
    bool Context(PoolAnchor a,PoolContext &out,std::string &error) {
        if(!Current(a)) { error="runtime anchor changed"; return false; }
        std::vector<Header> window; Hash cursor=a.tip;
        for(size_t i=0;i<11;++i) {
            std::optional<IndexedHeader> h; if(!Read(cursor,h,error)) return false;
            window.push_back(h->header); if(h->header.height==0) break; cursor=h->header.prev_id;
        }
        const auto mtp=ParentMedianTime(config.headers,window.front(),window);
        if(!mtp || window.front().height==std::numeric_limits<uint64_t>::max()) { error="invalid pool parent context"; return false; }
        out.anchor=a; out.profile=config.ordinary; out.profile.candidate_height=window.front().height+1; out.profile.parent_mtp=*mtp;
        out.chain_id=config.headers.chain_id; out.cost=config.cost;
        out.current=[this,a] { return Current(a) && history.Anchor()==std::optional<Hash>(a.tip); };
        out.active_coins=[this,a](const Outpoint &point,Coin &coin,std::string &why) {
            if(!Current(a)) { why="runtime context changed"; return CoinReadResult::Error; }
            std::optional<Coin> found;
            if(runtime.ReadCoin(point,found,why)!=DevelopmentRuntimeResult::Progress || !Current(a)) return CoinReadResult::Error;
            if(!found) return CoinReadResult::Missing; coin=*found; return CoinReadResult::Found;
        };
        out.classify_missing=[this,a](const Outpoint &point,std::string &why) {
            if(!Current(a) || history.Anchor()!=std::optional<Hash>(a.tip)) { why="history context changed"; return PoolMissingState::Error; }
            std::optional<Hash> spender; if(!history.Spender(point,spender,why)) return PoolMissingState::Error;
            return spender ? PoolMissingState::Spent : PoolMissingState::Unknown;
        };
        return Current(a);
    }
    bool Body(const Hash &id,FramedBlock &out,std::string &error) {
        std::vector<uint8_t> wire;
        if(runtime.ReadConnectedBody(id,config.max_block_bytes,wire,error)!=DevelopmentRuntimeResult::Progress) return false;
        if(!DecodeBlockWire(wire,config.ordinary.transaction,config.headers.chain_id,out,error)) return false;
        Hash actual{}; if(!BlockId(config.headers.chain_id,out.header,actual) || actual!=id) { error="connected body index binding mismatch"; return false; }
        return true;
    }
};
PoolCoordinator::PoolCoordinator(std::unique_ptr<Impl> p):impl_(std::move(p)) {}
PoolCoordinator::~PoolCoordinator()=default;
bool PoolCoordinator::Open(DevelopmentRuntime &r,PoolCoordinatorConfig c,std::unique_ptr<PoolCoordinator> &out,std::string &error) {
    // The manifest supplies rules, not a candidate context. Context() derives
    // the actual height and MTP from the authenticated runtime before admission.
    auto structural = c.ordinary;
    structural.candidate_height = 1;
    if(!c.max_path || !c.max_detached_transactions || !c.max_detached_bytes || !c.max_block_bytes || !ValidateOrdinaryProfile(structural,error)) { if(error.empty()) error="invalid pool coordinator limits"; return false; }
    auto p=std::make_unique<Impl>(r,std::move(c));
    auto s=r.Snapshot(); if(!s.chain || s.chain->identity!=p->config.identity || s.chain->profile_digest!=p->config.profile_digest) { error="pool coordinator runtime identity/profile mismatch"; return false; }
    if(!TransactionHistory::Open(p->config.directory,p->config.identity,p->config.profile_digest,p->config.history,p->history,error,p->config.history_env)) return false;
    out.reset(new PoolCoordinator(std::move(p))); return true;
}
CoordinatorResult PoolCoordinator::Tick(PoolCoordinatorBudget &budget,std::string &error) {
    auto &p=*impl_; auto s=p.runtime.Snapshot(); error.clear();
    if(!p.Bound(s)) { p.published.reset(); return CoordinatorResult::Deferred; }
    auto a=Anchor(s);
    if(p.Ready()) return CoordinatorResult::Ready;
    p.published.reset();
    size_t transitions=0;
    while(p.history.Anchor()!=std::optional<Hash>(a.tip)) {
        if(!budget.blocks || budget.header_reads<2 || transitions>=p.config.max_path)
            return CoordinatorResult::Progress;
        --budget.blocks; budget.header_reads-=2; ++transitions;
        const auto anchor=p.history.Anchor();
        bool disconnect=false; Hash id=p.config.headers.genesis_id;
        if(anchor) {
            // Unknown/nonactive locators fall back to the genesis child. A
            // matching predecessor proves this indexed tip is still active.
            const std::array<Hash,1> locator{*anchor}; std::vector<Header> headers;
            DiskStateError failure;
            const auto read=p.runtime.ReadHeaders(a.tip,locator,Hash{},1,1,headers,failure);
            if(read==ChainIndexResult::StaleTip || read==ChainIndexResult::Deferred)
                return CoordinatorResult::Deferred;
            if(read!=ChainIndexResult::Complete) { error=failure.message; return CoordinatorResult::StorageError; }
            if(headers.empty() || headers.front().prev_id!=*anchor) {disconnect=true;id=*anchor;}
            else if(!BlockId(p.config.headers.chain_id,headers.front(),id)) {
                error="active history header identity";return CoordinatorResult::StorageError;
            }
        }
        FramedBlock body;if(!p.Body(id,body,error)) return CoordinatorResult::StorageError;
        if(disconnect) {
            std::vector<std::vector<uint8_t>> wires;size_t bytes=0;
            for(size_t i=1;i<body.transactions.size();++i) {
                std::vector<uint8_t> wire;
                if(!EncodeTransaction(body.transactions[i],p.config.ordinary.transaction,wire,error)) return CoordinatorResult::StorageError;
                if(wires.size()>=p.config.max_detached_transactions-p.detached.size() || wire.size()>p.config.max_detached_bytes-p.detached_bytes-bytes) {
                    error="detached pool replay capacity";return CoordinatorResult::Capacity;
                }
                bytes+=wire.size();wires.push_back(std::move(wire));
            }
            if(!p.Current(a)) return CoordinatorResult::Deferred;
            if(!p.history.Disconnect(id,error)) return CoordinatorResult::StorageError;
            p.detached.insert(p.detached.begin(),std::make_move_iterator(wires.begin()),std::make_move_iterator(wires.end()));p.detached_bytes+=bytes;
        } else {
            HistoryBlock block;block.id=id;block.parent=body.header.prev_id;block.height=body.header.height;
            if(body.transactions.size()>p.config.history.max_transactions) { error="history transaction capacity";return CoordinatorResult::Capacity; }
            for(const auto &tx:body.transactions) {
                IdentityDigests d;if(!ComputeIdentities(tx,p.config.ordinary.transaction,p.config.headers.chain_id,d,error)) return CoordinatorResult::StorageError;
                TransactionConfirmation row{d.txid,d.txhash,id,block.height,{}};
                for(const auto &in:tx.inputs) if(in.flags==1) row.consumed.push_back({in.prev_txid,in.prev_index});
                block.transactions.push_back(std::move(row));
            }
            if(!p.Current(a)) return CoordinatorResult::Deferred;
            if(!p.history.Connect(block,error)) return CoordinatorResult::StorageError;
        }
    }
    {
        // Fixed eleven-header MTP lookup is charged before entering Context.
        if(budget.header_reads<11) return CoordinatorResult::Progress; budget.header_reads-=11;
        PoolContext context{}; if(!p.Context(a,context,error)) return CoordinatorResult::Deferred;
        std::set<Hash> connected;
        // Consult the derived index for existing pool IDs, including confirmations
        // applied during an interrupted earlier synchronization attempt.
        for(const auto &id:p.pool_ids) {
            std::optional<TransactionConfirmation> row;
            if(!p.history.Lookup(id,row,error)) return CoordinatorResult::StorageError;
            if(row) connected.insert(id);
        }
        std::vector<std::vector<uint8_t>> detached;
        for(const auto &wire:p.detached) {
            Transaction tx; IdentityDigests ids;
            if(!DecodeTransaction(wire,p.config.ordinary.transaction,tx,error) ||
               !ComputeIdentities(tx,p.config.ordinary.transaction,p.config.headers.chain_id,ids,error))
                return CoordinatorResult::StorageError;
            std::optional<TransactionConfirmation> row;
            if(!p.history.Lookup(ids.txid,row,error)) return CoordinatorResult::StorageError;
            if(!row) detached.push_back(wire);
        }
        // Reconcile itself removes confirmed/conflicting survivors via active
        // coins and the exact spent index, including unknown earlier anchors.
        auto result=p.pool.Reconcile(context,connected,{},detached,budget.validation);
        if(result.status==PoolStatus::Capacity) { error=result.error; return p.pool.ReconcilePending() ? CoordinatorResult::Progress:CoordinatorResult::Capacity; }
        if(result.status==PoolStatus::Operational) { error=result.error; return CoordinatorResult::StorageError; }
        if(result.status==PoolStatus::Stale || !p.Current(a)) return CoordinatorResult::Deferred;
        if(result.status!=PoolStatus::Accepted) {error="unexpected pool reconciliation result";return CoordinatorResult::StorageError;}
        p.pool_ids.clear();
        for(const auto &entry:p.pool.Snapshot(a,p.config.pool.max_entries,p.config.pool.max_bytes).entries)
            p.pool_ids.insert(entry.effects.txid);
        p.detached.clear(); p.detached_bytes=0; p.published=a;
        return CoordinatorResult::Ready;
    }
    return CoordinatorResult::Progress;
}
PoolResult PoolCoordinator::Submit(const std::vector<uint8_t> &wire,const Hash &tip,PoolBudget &budget) {
    auto &p=*impl_; PoolResult result;
    if(!p.Ready() || p.published->tip!=tip) { result.status=PoolStatus::Stale; result.error="pool/history runtime synchronization required"; return result; }
    if(wire.size()>p.config.pool.max_transaction_bytes) {result.status=PoolStatus::Capacity;result.error="transaction wire policy capacity";return result;}
    Transaction tx; if(!DecodeTransaction(wire,p.config.ordinary.transaction,tx,result.error)) { result.status=PoolStatus::Invalid; return result; }
    IdentityDigests ids; if(!ComputeIdentities(tx,p.config.ordinary.transaction,p.config.headers.chain_id,ids,result.error)) { result.status=PoolStatus::Invalid; return result; }
    result.txid=ids.txid; result.txhash=ids.txhash;
    std::optional<TransactionConfirmation> confirmed;
    if(!p.history.Lookup(ids.txid,confirmed,result.error)) { result.status=PoolStatus::Operational; return result; }
    if(confirmed) { result.status=confirmed->txhash==ids.txhash ? PoolStatus::Duplicate:PoolStatus::Conflict; return result; }
    PoolContext context{}; if(!p.Context(*p.published,context,result.error)) { result.status=PoolStatus::Stale; return result; }
    result=p.pool.Admit(wire,context,budget);
    if(result.status==PoolStatus::Accepted) p.pool_ids.insert(result.txid);
    return result;
}
PoolSnapshot PoolCoordinator::Snapshot(size_t entries,size_t bytes) const {
    const auto &p=*impl_; if(!p.Ready()) return {}; return p.pool.Snapshot(*p.published,entries,bytes);
}
bool PoolCoordinator::ReadWire(const Hash &hash,std::vector<uint8_t> &out,size_t max_bytes) const {
    const auto &p=*impl_; if(!p.Ready()) return false;
    std::vector<uint8_t> wire;
    if(!p.pool.ReadWire(hash,wire) || wire.size()>max_bytes) return false;
    out=std::move(wire); return true;
}
std::vector<Hash> PoolCoordinator::Inventory(size_t offset,size_t count) const {
    const auto &p=*impl_; if(!p.Ready()) return {};
    return p.pool.Inventory(offset,std::min(count,p.config.pool.max_entries));
}
bool PoolCoordinator::SelectedHash(const Hash &id,Hash &out) const {
    const auto &p=*impl_; return p.Ready() && p.pool.SelectedHash(id,out);
}
TransactionStatus PoolCoordinator::Status(const Hash &id,const std::optional<Hash> &hash,const std::vector<uint8_t> *wire) {
    auto &p=*impl_; TransactionStatus out; out.txid=id;
    if(!p.Ready()) { out.diagnostic="transaction index is synchronizing"; return out; }
    IdentityDigests ids{}; Transaction tx;
    if(wire && (wire->size()>p.config.pool.max_transaction_bytes || !DecodeTransaction(*wire,p.config.ordinary.transaction,tx,out.diagnostic) || !ComputeIdentities(tx,p.config.ordinary.transaction,p.config.headers.chain_id,ids,out.diagnostic) || ids.txid!=id || (hash && *hash!=ids.txhash))) { out.diagnostic="transaction query identity mismatch"; return out; }
    const auto wanted=hash ? hash : wire ? std::optional<Hash>(ids.txhash):std::nullopt;
    if(wanted) out.txhash=*wanted;
    if(!p.history.Lookup(id,out.confirmation,out.diagnostic)) return out;
    if(out.confirmation) { out.txhash=out.confirmation->txhash; out.state=wanted && *wanted!=out.txhash ? TransactionState::Conflicted:TransactionState::Confirmed; return out; }
    Hash selected{};
    if(p.pool.SelectedHash(id,selected)) { out.txhash=selected; out.state=wanted && *wanted!=selected ? TransactionState::Conflicted:TransactionState::Pending; return out; }
    const auto pending=wire ? p.pool.Snapshot(*p.published,p.config.pool.max_entries,p.config.pool.max_bytes):PoolSnapshot{};
    if(wire) for(const auto &in:tx.inputs) if(in.flags==1) {
        std::optional<Hash> spender; if(!p.history.Spender({in.prev_txid,in.prev_index},spender,out.diagnostic)) return out;
        if(spender && *spender!=id) { out.state=TransactionState::Conflicted; out.txhash=ids.txhash; return out; }
        const Outpoint point{in.prev_txid,in.prev_index};
        for(const auto &entry:pending.entries)
            if(entry.effects.txid!=id && std::find(entry.effects.consumed.begin(),entry.effects.consumed.end(),point)!=entry.effects.consumed.end()) {
                out.state=TransactionState::Conflicted; out.txhash=ids.txhash; return out;
            }
    }
    out.state=TransactionState::Unknown; return out;
}
}
