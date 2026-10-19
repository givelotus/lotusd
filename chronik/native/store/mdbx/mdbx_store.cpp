// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// MDBX backend of the native Chronik KvStore. Reproduces the Rust Chronik
// MDBX environment (chronik-db/src/db.rs) so both implementations open the
// same index directory: same geometry, flags, sync options, file mode, DBI
// names and flags, and the same physical key for keys longer than 7500 bytes.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/error.h>
#include <chronik/native/mdbx_store.h>

#include <mdbx.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace chronik::native {

static_assert(mdbx_flags::kSafeNoSync == MDBX_SAFE_NOSYNC);
static_assert(mdbx_flags::kNoMetaSync == MDBX_NOMETASYNC);
static_assert(mdbx_flags::kNoStickyThreads == MDBX_NOSTICKYTHREADS);
static_assert(mdbx_flags::kNoMemInit == MDBX_NOMEMINIT);
static_assert(mdbx_flags::kLifoReclaim == MDBX_LIFORECLAIM);
static_assert(mdbx_flags::kDupSort == MDBX_DUPSORT);
static_assert(mdbx_flags::kDupFixed == MDBX_DUPFIXED);

namespace {

constexpr std::string_view kHashedKeyPrefix = "MDBX_SHA256_KEY:";
constexpr size_t kHashedKeyLen = 16 + 32;
constexpr size_t kMaxPooledReadTxns = 32;

[[noreturn]] void ThrowMdbx(int rc, std::string_view context) {
    const char *msg = mdbx_strerror(rc);
    throw ChronikError("libmdbx error: " + std::string(context) + ": [" +
                       std::to_string(rc) + "] " +
                       (msg ? std::string(msg) : "unknown mdbx error"));
}

inline MDBX_val ToVal(ByteView v) {
    MDBX_val val;
    val.iov_base = const_cast<uint8_t *>(v.data());
    val.iov_len = v.size();
    return val;
}

inline ByteView FromVal(const MDBX_val &v) {
    if (v.iov_len == 0) {
        return ByteView();
    }
    return ByteView(static_cast<const uint8_t *>(v.iov_base), v.iov_len);
}

inline bool Found(int rc) {
    return rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE;
}

inline bool Missing(int rc) {
    return rc == MDBX_NOTFOUND || rc == MDBX_ENODATA;
}

class MdbxStore;

/** Normalized physical key (long keys are hashed), owning its buffer. */
class NormKey {
public:
    NormKey(const MdbxStore &store, ByteView key);
    ByteView View() const { return m_view; }
    MDBX_val Val() const { return ToVal(m_view); }

private:
    std::array<uint8_t, kHashedKeyLen> m_buf{};
    ByteView m_view;
};

class MdbxStore final : public KvStore {
public:
    MdbxStore(const std::filesystem::path &dir,
              std::span<const TableSpec> tables, const StoreOptions &opts,
              const MdbxEnvProfile &profile);
    ~MdbxStore() override;

    TableId Table(std::string_view name) const override {
        auto it = m_by_name.find(std::string(name));
        if (it == m_by_name.end()) {
            throw ChronikError("Column family " + std::string(name) +
                               " doesn't exist");
        }
        return it->second;
    }
    std::vector<std::string> TableNames() const override { return m_names; }
    std::unique_ptr<ReadTxn> BeginRead() const override;
    std::unique_ptr<WriteTxn> BeginWrite() override;
    void Sync(bool force) override {
        const int rc = mdbx_env_sync_ex(m_env, force, false);
        if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
            ThrowMdbx(rc, "mdbx_env_sync_ex");
        }
    }

    MDBX_dbi Dbi(TableId id) const {
        if (id >= m_dbis.size()) {
            throw ChronikError("Unknown Chronik table id " +
                               std::to_string(id));
        }
        return m_dbis[id];
    }
    const TableSpec &Spec(TableId id) const { return m_specs.at(id); }
    MDBX_env *Env() const { return m_env; }
    size_t MaxInlineKeyLen() const { return m_profile.max_inline_key_len; }
    void HashKey(ByteView key, uint8_t out[32]) const {
        if (!m_opts.sha256) {
            throw ChronikError(
                "MDBX store needs a SHA-256 hook for keys longer than " +
                std::to_string(m_profile.max_inline_key_len) + " bytes");
        }
        m_opts.sha256(key, out);
    }

    MDBX_txn *AcquireReadTxn() const;
    void ReleaseReadTxn(MDBX_txn *txn) const;

private:
    MDBX_env *m_env = nullptr;
    StoreOptions m_opts;
    MdbxEnvProfile m_profile;
    std::vector<std::string> m_names;
    std::vector<TableSpec> m_specs; // names point into m_names
    std::vector<MDBX_dbi> m_dbis;
    std::map<std::string, TableId> m_by_name;
    mutable std::mutex m_pool_mutex;
    mutable std::vector<MDBX_txn *> m_read_pool;
};

NormKey::NormKey(const MdbxStore &store, ByteView key) {
    if (key.size() <= store.MaxInlineKeyLen()) {
        m_view = key;
        return;
    }
    std::memcpy(m_buf.data(), kHashedKeyPrefix.data(), kHashedKeyPrefix.size());
    store.HashKey(key, m_buf.data() + kHashedKeyPrefix.size());
    m_view = ByteView(m_buf.data(), m_buf.size());
}

// ---- Cursors ----

class MdbxCursor final : public Cursor {
public:
    MdbxCursor(const MdbxStore &store, MDBX_txn *txn, MDBX_dbi dbi)
        : m_store(store) {
        const int rc = mdbx_cursor_open(txn, dbi, &m_cursor);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_cursor_open");
        }
    }
    ~MdbxCursor() override { mdbx_cursor_close(m_cursor); }

    bool SeekFirst() override { return Op(nullptr, MDBX_FIRST); }
    bool SeekLast() override { return Op(nullptr, MDBX_LAST); }
    bool SeekGe(ByteView key) override {
        NormKey norm(m_store, key);
        return Op(&norm, MDBX_SET_RANGE);
    }
    bool SeekLe(ByteView key) override {
        NormKey norm(m_store, key);
        return Op(&norm, MDBX_TO_KEY_LESSER_OR_EQUAL);
    }
    bool Next() override { return m_valid && Op(nullptr, MDBX_NEXT); }
    bool Prev() override { return m_valid && Op(nullptr, MDBX_PREV); }
    bool Valid() const override { return m_valid; }
    ByteView Key() const override { return FromVal(m_key); }
    ByteView Value() const override { return FromVal(m_val); }

private:
    bool Op(const NormKey *key, MDBX_cursor_op op) {
        if (key) {
            m_key = key->Val();
        }
        m_val = MDBX_val{nullptr, 0};
        const int rc = mdbx_cursor_get(m_cursor, &m_key, &m_val, op);
        if (Found(rc)) {
            m_valid = true;
            return true;
        }
        m_valid = false;
        if (Missing(rc)) {
            return false;
        }
        ThrowMdbx(rc, "mdbx_cursor_get");
    }

    const MdbxStore &m_store;
    MDBX_cursor *m_cursor = nullptr;
    MDBX_val m_key{nullptr, 0};
    MDBX_val m_val{nullptr, 0};
    bool m_valid = false;
};

class MdbxDupCursor final : public DupCursor {
public:
    MdbxDupCursor(const MdbxStore &store, MDBX_txn *txn, TableId table)
        : m_store(store), m_txn(txn), m_dbi(store.Dbi(table)),
          m_fixed(store.Spec(table).dup_fixed_size) {
        const int rc = mdbx_cursor_open(txn, m_dbi, &m_cursor);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_cursor_open");
        }
    }
    ~MdbxDupCursor() override { mdbx_cursor_close(m_cursor); }

    bool Seek(ByteView key) override {
        NormKey norm(m_store, key);
        MDBX_val k = norm.Val();
        m_val = MDBX_val{nullptr, 0};
        return Result(mdbx_cursor_get(m_cursor, &k, &m_val, MDBX_SET_KEY));
    }
    bool SeekValueGe(ByteView key, ByteView value_prefix) override {
        NormKey norm(m_store, key);
        MDBX_val k = norm.Val();
        Bytes search = SearchValue(value_prefix);
        m_val = ToVal(search);
        return Result(
            mdbx_cursor_get(m_cursor, &k, &m_val, MDBX_GET_BOTH_RANGE));
    }
    bool Next() override {
        if (!m_valid) {
            return false;
        }
        MDBX_val k{nullptr, 0};
        m_val = MDBX_val{nullptr, 0};
        return Result(mdbx_cursor_get(m_cursor, &k, &m_val, MDBX_NEXT_DUP));
    }
    bool Valid() const override { return m_valid; }
    ByteView Value() const override { return FromVal(m_val); }
    size_t CountRemaining() override {
        if (!m_valid) {
            return 0;
        }
        MDBX_cursor *copy = mdbx_cursor_create(nullptr);
        if (!copy) {
            throw ChronikError("libmdbx error: mdbx_cursor_create failed");
        }
        int rc = mdbx_cursor_copy(m_cursor, copy);
        if (rc != MDBX_SUCCESS) {
            mdbx_cursor_close(copy);
            ThrowMdbx(rc, "mdbx_cursor_copy");
        }
        size_t count = 1;
        while (true) {
            MDBX_val k{nullptr, 0}, v{nullptr, 0};
            rc = mdbx_cursor_get(copy, &k, &v, MDBX_NEXT_DUP);
            if (Found(rc)) {
                ++count;
                continue;
            }
            mdbx_cursor_close(copy);
            if (Missing(rc)) {
                return count;
            }
            ThrowMdbx(rc, "mdbx_cursor_get(count)");
        }
    }

    /** Search value for GET_BOTH_RANGE: DUPFIXED needs the exact size. */
    Bytes SearchValue(ByteView prefix) const {
        Bytes search(prefix.begin(), prefix.end());
        if (m_fixed) {
            if (search.size() > *m_fixed) {
                search.resize(*m_fixed);
            }
            search.resize(*m_fixed, 0);
        }
        return search;
    }

private:
    bool Result(int rc) {
        if (Found(rc)) {
            m_valid = true;
            return true;
        }
        m_valid = false;
        if (Missing(rc)) {
            return false;
        }
        ThrowMdbx(rc, "mdbx_cursor_get(dup)");
    }

    const MdbxStore &m_store;
    MDBX_txn *m_txn;
    MDBX_dbi m_dbi;
    std::optional<uint32_t> m_fixed;
    MDBX_cursor *m_cursor = nullptr;
    MDBX_val m_val{nullptr, 0};
    bool m_valid = false;
};

// ---- Transactions ----

/** Read operations shared by read and write txns. */
class TxnOps {
public:
    TxnOps(const MdbxStore &store, MDBX_txn *txn) : m_store(store), m_txn(txn) {}

    std::optional<ByteView> DoGet(TableId table, ByteView key) const {
        NormKey norm(m_store, key);
        MDBX_val k = norm.Val();
        MDBX_val v{nullptr, 0};
        const int rc = mdbx_get(m_txn, m_store.Dbi(table), &k, &v);
        if (rc == MDBX_SUCCESS) {
            return FromVal(v);
        }
        if (rc == MDBX_NOTFOUND) {
            return std::nullopt;
        }
        ThrowMdbx(rc, "mdbx_get");
    }
    uint64_t DoEstimate(TableId table) const {
        MDBX_stat stat{};
        const int rc =
            mdbx_dbi_stat(m_txn, m_store.Dbi(table), &stat, sizeof(stat));
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_dbi_stat");
        }
        return stat.ms_entries;
    }

    const MdbxStore &m_store;
    MDBX_txn *m_txn;
};

class MdbxReadTxn final : public ReadTxn {
public:
    MdbxReadTxn(const MdbxStore &store, MDBX_txn *txn) : m_ops(store, txn) {}
    ~MdbxReadTxn() override { m_ops.m_store.ReleaseReadTxn(m_ops.m_txn); }

    std::optional<ByteView> Get(TableId table, ByteView key) const override {
        return m_ops.DoGet(table, key);
    }
    std::unique_ptr<Cursor> OpenCursor(TableId table) const override {
        return std::make_unique<MdbxCursor>(m_ops.m_store, m_ops.m_txn,
                                            m_ops.m_store.Dbi(table));
    }
    std::unique_ptr<DupCursor> OpenDupCursor(TableId table) const override {
        return std::make_unique<MdbxDupCursor>(m_ops.m_store, m_ops.m_txn,
                                               table);
    }
    uint64_t EstimateEntries(TableId table) const override {
        return m_ops.DoEstimate(table);
    }

private:
    TxnOps m_ops;
};

class MdbxWriteTxn final : public WriteTxn {
public:
    MdbxWriteTxn(const MdbxStore &store, MDBX_txn *txn) : m_ops(store, txn) {}
    ~MdbxWriteTxn() override {
        if (m_ops.m_txn) {
            mdbx_txn_abort(m_ops.m_txn);
        }
    }

    std::optional<ByteView> Get(TableId table, ByteView key) const override {
        return m_ops.DoGet(table, Live(key));
    }
    std::unique_ptr<Cursor> OpenCursor(TableId table) const override {
        return std::make_unique<MdbxCursor>(m_ops.m_store, Txn(),
                                            m_ops.m_store.Dbi(table));
    }
    std::unique_ptr<DupCursor> OpenDupCursor(TableId table) const override {
        return std::make_unique<MdbxDupCursor>(m_ops.m_store, Txn(), table);
    }
    uint64_t EstimateEntries(TableId table) const override {
        Txn();
        return m_ops.DoEstimate(table);
    }

    void Put(TableId table, ByteView key, ByteView value) override {
        NormKey norm(m_ops.m_store, key);
        MDBX_val k = norm.Val();
        MDBX_val v = ToVal(value);
        const int rc =
            mdbx_put(Txn(), m_ops.m_store.Dbi(table), &k, &v, MDBX_UPSERT);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_put");
        }
    }
    void Del(TableId table, ByteView key) override {
        NormKey norm(m_ops.m_store, key);
        MDBX_val k = norm.Val();
        const int rc = mdbx_del(Txn(), m_ops.m_store.Dbi(table), &k, nullptr);
        if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) {
            ThrowMdbx(rc, "mdbx_del");
        }
    }
    void PutDup(TableId table, ByteView key, ByteView value) override {
        NormKey norm(m_ops.m_store, key);
        MDBX_val k = norm.Val();
        MDBX_val v = ToVal(value);
        const int rc =
            mdbx_put(Txn(), m_ops.m_store.Dbi(table), &k, &v, MDBX_UPSERT);
        // An identical duplicate is a no-op (MDBX_KEYEXIST only arises with
        // MDBX_NODUPDATA, but tolerate it for idempotence).
        if (rc != MDBX_SUCCESS && rc != MDBX_KEYEXIST) {
            ThrowMdbx(rc, "mdbx_put(dup)");
        }
    }
    void DelDup(TableId table, ByteView key, ByteView value) override {
        NormKey norm(m_ops.m_store, key);
        MDBX_val k = norm.Val();
        MDBX_val v = ToVal(value);
        const int rc = mdbx_del(Txn(), m_ops.m_store.Dbi(table), &k, &v);
        if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) {
            ThrowMdbx(rc, "mdbx_del(dup)");
        }
    }
    void DelDupByPrefix(TableId table, ByteView key,
                        ByteView value_prefix) override {
        // Same as the Rust batch op: GET_BOTH_RANGE to the first dup >= the
        // (zero-padded) prefix, delete it if it starts with the prefix.
        MdbxDupCursor cursor(m_ops.m_store, Txn(), table);
        if (!cursor.SeekValueGe(key, value_prefix)) {
            return;
        }
        if (!StartsWith(cursor.Value(), value_prefix)) {
            return;
        }
        MDBX_cursor *c = nullptr;
        // Re-position a raw cursor for deletion.
        int rc = mdbx_cursor_open(Txn(), m_ops.m_store.Dbi(table), &c);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_cursor_open");
        }
        NormKey norm(m_ops.m_store, key);
        MDBX_val k = norm.Val();
        Bytes found(cursor.Value().begin(), cursor.Value().end());
        MDBX_val v = ToVal(found);
        rc = mdbx_cursor_get(c, &k, &v, MDBX_GET_BOTH);
        if (Found(rc)) {
            rc = mdbx_cursor_del(c, MDBX_CURRENT);
            mdbx_cursor_close(c);
            if (rc != MDBX_SUCCESS) {
                ThrowMdbx(rc, "mdbx_cursor_del");
            }
            return;
        }
        mdbx_cursor_close(c);
        if (!Missing(rc)) {
            ThrowMdbx(rc, "mdbx_cursor_get(del_prefix)");
        }
    }
    void Clear(TableId table) override {
        const int rc = mdbx_drop(Txn(), m_ops.m_store.Dbi(table), false);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_drop(delete_range)");
        }
    }
    void Commit() override {
        MDBX_txn *txn = Txn();
        m_ops.m_txn = nullptr;
        const int rc = mdbx_txn_commit_ex(txn, nullptr);
        if (rc != MDBX_SUCCESS) {
            ThrowMdbx(rc, "mdbx_txn_commit_ex(write_batch)");
        }
    }

private:
    MDBX_txn *Txn() const {
        if (!m_ops.m_txn) {
            throw ChronikError("Chronik write txn used after commit");
        }
        return m_ops.m_txn;
    }
    ByteView Live(ByteView key) const {
        Txn();
        return key;
    }

    TxnOps m_ops;
};

// ---- Store ----

MdbxStore::MdbxStore(const std::filesystem::path &dir,
                     std::span<const TableSpec> tables,
                     const StoreOptions &opts, const MdbxEnvProfile &profile)
    : m_opts(opts), m_profile(profile) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        throw ChronikError("libmdbx error: Failed to create DB directory " +
                           dir.string() + ": " + ec.message());
    }
    m_names.reserve(tables.size());
    for (const TableSpec &spec : tables) {
        m_names.emplace_back(spec.name);
    }
    for (size_t i = 0; i < tables.size(); ++i) {
        TableSpec spec = tables[i];
        spec.name = m_names[i];
        m_specs.push_back(spec);
        if (!m_by_name.emplace(m_names[i], TableId(i)).second) {
            throw ChronikError("Duplicate Chronik table " + m_names[i]);
        }
    }

    int rc = mdbx_env_create(&m_env);
    if (rc != MDBX_SUCCESS) {
        m_env = nullptr;
        ThrowMdbx(rc, "mdbx_env_create");
    }
    auto fail = [&](int code, std::string_view ctx) {
        mdbx_env_close_ex(m_env, true);
        m_env = nullptr;
        ThrowMdbx(code, ctx);
    };
    rc = mdbx_env_set_maxreaders(m_env, profile.max_readers);
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_env_set_maxreaders");
    }
    const uint32_t max_dbs =
        profile.max_dbs ? profile.max_dbs
                        : std::max<uint32_t>(uint32_t(tables.size()) + 16, 64);
    rc = mdbx_env_set_maxdbs(m_env, max_dbs);
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_env_set_maxdbs");
    }
    rc = mdbx_env_set_geometry(m_env, intptr_t(profile.size_lower),
                               intptr_t(profile.size_now),
                               intptr_t(profile.size_upper),
                               intptr_t(profile.growth_step),
                               intptr_t(profile.shrink_threshold),
                               intptr_t(profile.pagesize));
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_env_set_geometry");
    }
    unsigned flags = 0;
    if (profile.safe_nosync) flags |= MDBX_SAFE_NOSYNC;
    if (profile.nometasync) flags |= MDBX_NOMETASYNC;
    if (profile.liforeclaim) flags |= MDBX_LIFORECLAIM;
    if (profile.nostickythreads) flags |= MDBX_NOSTICKYTHREADS;
    if (profile.nomeminit) flags |= MDBX_NOMEMINIT;
    rc = mdbx_env_open(m_env, dir.string().c_str(), MDBX_env_flags_t(flags),
                       mdbx_mode_t(profile.mode));
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_env_open");
    }
    if (profile.sync_bytes) {
        rc = mdbx_env_set_option(m_env, MDBX_opt_sync_bytes,
                                 *profile.sync_bytes);
        if (rc != MDBX_SUCCESS) {
            fail(rc, "mdbx_env_set_option(sync)");
        }
    }
    if (profile.sync_period) {
        rc = mdbx_env_set_option(m_env, MDBX_opt_sync_period,
                                 *profile.sync_period);
        if (rc != MDBX_SUCCESS) {
            fail(rc, "mdbx_env_set_option(sync)");
        }
    }

    MDBX_txn *txn = nullptr;
    rc = mdbx_txn_begin_ex(m_env, nullptr, MDBX_TXN_READWRITE, &txn, nullptr);
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_txn_begin_ex(open_cfs)");
    }
    for (const TableSpec &spec : m_specs) {
        unsigned dbi_flags = MDBX_CREATE;
        if (spec.kind == TableSpec::Kind::Dup) {
            dbi_flags |= MDBX_DUPSORT;
            if (spec.dup_fixed_size) {
                dbi_flags |= MDBX_DUPFIXED;
            }
        }
        MDBX_dbi dbi = 0;
        const std::string name(spec.name);
        rc = mdbx_dbi_open(txn, name.c_str(), MDBX_db_flags_t(dbi_flags), &dbi);
        if (rc != MDBX_SUCCESS) {
            mdbx_txn_abort(txn);
            fail(rc, "mdbx_dbi_open");
        }
        m_dbis.push_back(dbi);
    }
    rc = mdbx_txn_commit_ex(txn, nullptr);
    if (rc != MDBX_SUCCESS) {
        fail(rc, "mdbx_txn_commit_ex(open_cfs)");
    }
    if (profile.sync_after_open) {
        // Publish the DBI metadata durably before returning, like Rust.
        Sync(true);
    }
}

MdbxStore::~MdbxStore() {
    {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        for (MDBX_txn *txn : m_read_pool) {
            mdbx_txn_abort(txn);
        }
        m_read_pool.clear();
    }
    if (m_env) {
        const int rc = mdbx_env_sync_ex(m_env, true, false);
        if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
            std::fprintf(stderr, "Chronik MDBX shutdown sync failed: %s\n",
                         mdbx_strerror(rc));
        }
        mdbx_env_close_ex(m_env, false);
    }
}

MDBX_txn *MdbxStore::AcquireReadTxn() const {
    MDBX_txn *txn = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        if (!m_read_pool.empty()) {
            txn = m_read_pool.back();
            m_read_pool.pop_back();
        }
    }
    if (txn) {
        const int rc = mdbx_txn_renew(txn);
        if (rc == MDBX_SUCCESS) {
            return txn;
        }
        mdbx_txn_abort(txn);
        ThrowMdbx(rc, "mdbx_txn_renew");
    }
    const int rc =
        mdbx_txn_begin_ex(m_env, nullptr, MDBX_TXN_RDONLY, &txn, nullptr);
    if (rc != MDBX_SUCCESS) {
        ThrowMdbx(rc, "mdbx_txn_begin_ex(read)");
    }
    return txn;
}

void MdbxStore::ReleaseReadTxn(MDBX_txn *txn) const {
    if (!txn) {
        return;
    }
    if (mdbx_txn_reset(txn) == MDBX_SUCCESS) {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        if (m_read_pool.size() < kMaxPooledReadTxns) {
            m_read_pool.push_back(txn);
            return;
        }
    }
    mdbx_txn_abort(txn);
}

std::unique_ptr<ReadTxn> MdbxStore::BeginRead() const {
    return std::make_unique<MdbxReadTxn>(*this, AcquireReadTxn());
}

std::unique_ptr<WriteTxn> MdbxStore::BeginWrite() {
    MDBX_txn *txn = nullptr;
    const int rc =
        mdbx_txn_begin_ex(m_env, nullptr, MDBX_TXN_READWRITE, &txn, nullptr);
    if (rc != MDBX_SUCCESS) {
        ThrowMdbx(rc, "mdbx_txn_begin_ex(write_batch)");
    }
    return std::make_unique<MdbxWriteTxn>(*this, txn);
}

} // namespace

MdbxEnvProfile ChronikIndexProfile() {
    return MdbxEnvProfile{};
}

std::unique_ptr<KvStore> OpenMdbxStore(const std::filesystem::path &dir,
                                       std::span<const TableSpec> tables,
                                       const StoreOptions &opts,
                                       const MdbxEnvProfile &profile) {
    return std::make_unique<MdbxStore>(dir, tables, opts, profile);
}

void DestroyMdbxStore(const std::filesystem::path &dir) {
    // Same file set as Rust Db::destroy, which also clears RocksDB leftovers.
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        return;
    }
    std::filesystem::remove_all(dir / "rocksdb.bak", ec);
    for (const char *name : {"mdbx.dat", "mdbx.lck", "LOCK", "CURRENT",
                             "IDENTITY", "LOG", "LOG.old"}) {
        std::filesystem::remove(dir / name, ec);
    }
    for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
        const std::string fname = entry.path().filename().string();
        auto starts = [&](std::string_view p) {
            return fname.rfind(p, 0) == 0;
        };
        auto ends = [&](std::string_view s) {
            return fname.size() >= s.size() &&
                   fname.compare(fname.size() - s.size(), s.size(), s) == 0;
        };
        if (starts("MANIFEST-") || starts("OPTIONS-") || starts("LOG.old.") ||
            ends(".sst") || ends(".log")) {
            std::error_code ec2;
            std::filesystem::remove(entry.path(), ec2);
        }
    }
    // Only removes the directory if it is now empty (like fs::remove_dir).
    std::filesystem::remove(dir, ec);
}

void RegisterMdbxStore() {
    RegisterStoreBackend(
        StoreBackend::Mdbx,
        [](const std::filesystem::path &dir, std::span<const TableSpec> tables,
           const StoreOptions &opts) {
            return OpenMdbxStore(dir, tables, opts, ChronikIndexProfile());
        },
        [](const std::filesystem::path &dir) { DestroyMdbxStore(dir); });
}

MdbxStoreInfo GetMdbxStoreInfo(const KvStore &kv) {
    const auto *store = dynamic_cast<const MdbxStore *>(&kv);
    if (!store) {
        throw ChronikError("Not an MDBX store");
    }
    MdbxStoreInfo out;
    MDBX_envinfo info{};
    int rc = mdbx_env_info_ex(store->Env(), nullptr, &info, sizeof(info));
    if (rc != MDBX_SUCCESS) {
        ThrowMdbx(rc, "mdbx_env_info_ex");
    }
    out.geo_lower = info.mi_geo.lower;
    out.geo_upper = info.mi_geo.upper;
    out.geo_current = info.mi_geo.current;
    out.geo_grow = info.mi_geo.grow;
    out.geo_shrink = info.mi_geo.shrink;
    out.pagesize = info.mi_dxb_pagesize;
    out.max_readers = info.mi_maxreaders;
    unsigned flags = 0;
    rc = mdbx_env_get_flags(store->Env(), &flags);
    if (rc != MDBX_SUCCESS) {
        ThrowMdbx(rc, "mdbx_env_get_flags");
    }
    out.env_flags = flags;
    mdbx_env_get_option(store->Env(), MDBX_opt_sync_bytes, &out.sync_bytes);
    mdbx_env_get_option(store->Env(), MDBX_opt_sync_period, &out.sync_period);
    MDBX_txn *txn = store->AcquireReadTxn();
    for (size_t i = 0; i < store->TableNames().size(); ++i) {
        unsigned dbi_flags = 0, state = 0;
        rc = mdbx_dbi_flags_ex(txn, store->Dbi(TableId(i)), &dbi_flags,
                               &state);
        if (rc != MDBX_SUCCESS) {
            store->ReleaseReadTxn(txn);
            ThrowMdbx(rc, "mdbx_dbi_flags_ex");
        }
        out.dbi_flags.push_back(dbi_flags);
    }
    store->ReleaseReadTxn(txn);
    return out;
}

} // namespace chronik::native
