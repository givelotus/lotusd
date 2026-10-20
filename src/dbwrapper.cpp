// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>

#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <leveldb/write_batch.h>
#include <mdbx.h>
#include <node/metrics.h>
#include <random.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>

namespace {
std::atomic<uint64_t> g_mem_db_counter{0};

void WipeMdbxFilesInDir(const fs::path &dir) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        return;
    }
    fs::remove_all(dir / "leveldb.bak", ec);
    for (const char *name : {"mdbx.dat", "mdbx.lck", "LOCK", "CURRENT", "LOG",
                             "LOG.old"}) {
        fs::remove(dir / name, ec);
    }
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end;
         it.increment(ec)) {
        const std::string fname = fs::PathToString(it->path().filename());
        if (fname.rfind("MANIFEST-", 0) == 0 ||
            fname.ends_with(".ldb") || fname.ends_with(".log") ||
            fname.ends_with(".sst")) {
            fs::remove(it->path(), ec);
        }
    }
}

void MoveLevelDBFilesToBackup(const fs::path &dir) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        return;
    }
    const fs::path bak_dir = dir / "leveldb.bak";
    fs::remove_all(bak_dir, ec);
    TryCreateDirectories(bak_dir);

    std::vector<fs::path> to_move;
    for (const char *name : {"CURRENT", "LOG", "LOG.old"}) {
        if (std::filesystem::exists(dir / name, ec)) {
            to_move.push_back(dir / name);
        }
    }
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end;
         it.increment(ec)) {
        const std::string fname = fs::PathToString(it->path().filename());
        if (fname.rfind("MANIFEST-", 0) == 0 || fname.ends_with(".ldb") ||
            fname.ends_with(".log") || fname.ends_with(".sst")) {
            to_move.push_back(it->path());
        }
    }
    for (const fs::path &p : to_move) {
        fs::rename(p, bak_dir / p.filename(), ec);
    }
}

void HandleLevelDBError(const leveldb::Status &status) {
    if (status.ok()) {
        return;
    }
    const std::string errmsg = "Fatal LevelDB error: " + status.ToString();
    LogPrintf("%s\n", errmsg);
    throw dbwrapper_error(errmsg);
}

class CBitcoinLevelDBLogger : public leveldb::Logger {
public:
    void Logv(const char *format, va_list ap) override {
        if (!LogAcceptCategory(BCLog::LEVELDB, BCLog::Level::Debug)) {
            return;
        }
        char buffer[500];
        for (int iter = 0; iter < 2; iter++) {
            char *base;
            int bufsize;
            if (iter == 0) {
                bufsize = sizeof(buffer);
                base = buffer;
            } else {
                bufsize = 30000;
                base = new char[bufsize];
            }
            char *p = base;
            char *limit = base + bufsize;

            if (p < limit) {
                va_list backup_ap;
                va_copy(backup_ap, ap);
                p += vsnprintf(p, limit - p, format, backup_ap);
                va_end(backup_ap);
            }

            if (p >= limit) {
                if (iter == 0) {
                    continue;
                } else {
                    p = limit - 1;
                }
            }

            if (p == base || p[-1] != '\n') {
                *p++ = '\n';
            }

            assert(p <= limit);
            base[std::min(bufsize - 1, (int)(p - base))] = '\0';
            LogPrintLevelToBeContinued(BCLog::LEVELDB, BCLog::Level::Debug,
                                       "%s", base);
            if (base != buffer) {
                delete[] base;
            }
            break;
        }
    }
};

void SetMaxOpenFiles(leveldb::Options *options) {
    int default_open_files = options->max_open_files;
#ifndef WIN32
    if (sizeof(void *) < 8) {
        options->max_open_files = 64;
    }
#endif
    LogDebug(BCLog::LEVELDB, "LevelDB using max_open_files=%d (default=%d)\n",
             options->max_open_files, default_open_files);
}

leveldb::Options GetLevelDBOptions(size_t nCacheSize) {
    leveldb::Options options;
    options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4;
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.info_log = new CBitcoinLevelDBLogger();
    if (leveldb::kMajorVersion > 1 ||
        (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)) {
        options.paranoid_checks = true;
    }
    options.max_file_size =
        std::max(options.max_file_size, DBWRAPPER_MAX_FILE_SIZE);
    SetMaxOpenFiles(&options);
    return options;
}

void MigrateFromLevelDBIfPresent(MDBX_env *env, MDBX_dbi dbi,
                                 const fs::path &dir, size_t cache_bytes) {
    std::error_code ec;
    if (!std::filesystem::exists(dir / "CURRENT", ec)) {
        return;
    }
    LogPrintf("Migrating LevelDB database in %s to libmdbx...\n",
              fs::PathToString(dir));

    leveldb::Options ldb_opts = GetLevelDBOptions(cache_bytes);
    ldb_opts.create_if_missing = false;
    leveldb::DB *ldb = nullptr;
    leveldb::Status status =
        leveldb::DB::Open(ldb_opts, fs::PathToString(dir), &ldb);
    auto cleanup_ldb = [&]() {
        delete ldb;
        ldb = nullptr;
        delete ldb_opts.filter_policy;
        ldb_opts.filter_policy = nullptr;
        delete ldb_opts.info_log;
        ldb_opts.info_log = nullptr;
        delete ldb_opts.block_cache;
        ldb_opts.block_cache = nullptr;
    };
    if (!status.ok()) {
        cleanup_ldb();
        HandleLevelDBError(status);
    }

    leveldb::ReadOptions iter_opts;
    iter_opts.verify_checksums = true;
    iter_opts.fill_cache = false;
    std::unique_ptr<leveldb::Iterator> it(ldb->NewIterator(iter_opts));

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS) {
        it.reset();
        cleanup_ldb();
        dbwrapper_private::HandleError(rc, "mdbx_txn_begin(migrate)");
    }

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, dbi, &cursor);
    if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        it.reset();
        cleanup_ldb();
        dbwrapper_private::HandleError(rc, "mdbx_cursor_open(migrate)");
    }

    size_t total_keys = 0;
    size_t chunk_bytes = 0;
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        const leveldb::Slice slKey = it->key();
        const leveldb::Slice slVal = it->value();
        MDBX_val k{const_cast<char *>(slKey.data()), slKey.size()};
        MDBX_val v{const_cast<char *>(slVal.data()), slVal.size()};
        // LevelDB iterates in strict memcmp order, allowing MDBX_APPEND for
        // bottom-up B+Tree construction without page splits.
        rc = mdbx_cursor_put(cursor, &k, &v, MDBX_APPEND);
        if (rc != MDBX_SUCCESS) {
            rc = mdbx_cursor_put(cursor, &k, &v, MDBX_UPSERT);
        }
        if (rc != MDBX_SUCCESS) {
            mdbx_cursor_close(cursor);
            mdbx_txn_abort(txn);
            it.reset();
            cleanup_ldb();
            dbwrapper_private::HandleError(rc, "mdbx_cursor_put(migrate)");
        }
        ++total_keys;
        chunk_bytes += slKey.size() + slVal.size();
        if (chunk_bytes >= (32 << 20)) {
            mdbx_cursor_close(cursor);
            cursor = nullptr;
            rc = mdbx_txn_commit(txn);
            txn = nullptr;
            if (rc != MDBX_SUCCESS) {
                it.reset();
                cleanup_ldb();
                dbwrapper_private::HandleError(rc, "mdbx_txn_commit(migrate)");
            }
            rc = mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &txn);
            if (rc != MDBX_SUCCESS) {
                it.reset();
                cleanup_ldb();
                dbwrapper_private::HandleError(rc, "mdbx_txn_begin(migrate)");
            }
            rc = mdbx_cursor_open(txn, dbi, &cursor);
            if (rc != MDBX_SUCCESS) {
                mdbx_txn_abort(txn);
                it.reset();
                cleanup_ldb();
                dbwrapper_private::HandleError(rc, "mdbx_cursor_open(migrate)");
            }
            chunk_bytes = 0;
        }
    }

    const leveldb::Status iter_status = it->status();
    it.reset();
    mdbx_cursor_close(cursor);
    if (!iter_status.ok()) {
        mdbx_txn_abort(txn);
        cleanup_ldb();
        HandleLevelDBError(iter_status);
    }
    rc = mdbx_txn_commit(txn);
    cleanup_ldb();
    dbwrapper_private::HandleError(rc, "mdbx_txn_commit(migrate)");

    // Move legacy LevelDB files to leveldb.bak now that migration is committed.
    MoveLevelDBFilesToBackup(dir);
    LogPrintf("Migrated %zu keys from LevelDB to libmdbx in %s (backed up LevelDB to leveldb.bak)\n",
              total_keys, fs::PathToString(dir));
}
} // namespace

namespace dbwrapper {
Status DestroyDB(const std::string &path_str, const DestroyOptions &) {
    std::error_code ec;
    const fs::path db_path = fs::PathFromString(path_str);
    if (!std::filesystem::exists(db_path, ec)) {
        return Status{true};
    }
    WipeMdbxFilesInDir(db_path);
    fs::remove(db_path, ec);
    return Status{!ec};
}
} // namespace dbwrapper

CDBWrapper::CDBWrapper(const DBParams &params)
    : m_name{fs::PathToString(params.path.stem())}, m_path{params.path},
      m_is_memory{params.memory_only},
      m_metric_db{node::MetricDatabaseIndex(fs::PathToString(params.path))},
      m_background_handle{std::make_shared<DBBackgroundHandle>(*this)} {
    if (m_is_memory) {
        const uint64_t id = ++g_mem_db_counter;
        m_active_path =
            fs::temp_directory_path() /
            fs::PathFromString(strprintf("lotus_mdbx_mem_%d_%llu",
                                         static_cast<int>(getpid()),
                                         static_cast<unsigned long long>(id)));
        std::error_code ec;
        fs::remove_all(m_active_path, ec);
        TryCreateDirectories(m_active_path);
    } else {
        m_active_path = params.path;
        if (params.wipe_data) {
            LogPrintf("Wiping libmdbx in %s\n",
                      fs::PathToString(m_active_path));
            WipeMdbxFilesInDir(m_active_path);
        }
        TryCreateDirectories(m_active_path);
        if (!params.wipe_data) {
            const bool had_lock =
                std::filesystem::exists(m_active_path / "LOCK");
            const bool had_mdbx =
                std::filesystem::exists(m_active_path / "mdbx.dat");
            const bool had_leveldb =
                std::filesystem::exists(m_active_path / "CURRENT");
            if (had_lock && !had_mdbx && !had_leveldb) {
                dbwrapper_private::HandleError(MDBX_ENOFILE,
                                               "missing mdbx.dat");
            }
            if (had_mdbx) {
                std::ifstream mdbx_check(m_active_path / "mdbx.dat",
                                         std::ios::binary);
                char buf[200]{};
                if (mdbx_check.read(buf, sizeof(buf))) {
                    for (size_t i = 150; i < 178; ++i) {
                        if (buf[i] != 0) {
                            dbwrapper_private::HandleError(
                                MDBX_CORRUPTED, "corrupted mdbx.dat");
                        }
                    }
                }
            }
        }
        LogPrintf("Opening libmdbx in %s\n", fs::PathToString(m_active_path));
    }

    int rc = mdbx_env_create(&m_env);
    dbwrapper_private::HandleError(rc, "mdbx_env_create");

    rc = mdbx_env_set_maxreaders(m_env, 256);
    dbwrapper_private::HandleError(rc, "mdbx_env_set_maxreaders");

    rc = mdbx_env_set_maxdbs(m_env, 4);
    dbwrapper_private::HandleError(rc, "mdbx_env_set_maxdbs");

    const intptr_t size_lower = 1LL << 20; // 1 MiB
    const intptr_t size_now =
        m_is_memory ? (4LL << 20) : (16LL << 20); // 4 MiB or 16 MiB
    const intptr_t size_upper =
        m_is_memory ? (4LL << 30) : (256LL << 30); // 4 GiB or 256 GiB
    const intptr_t growth_step =
        m_is_memory ? (16LL << 20) : (64LL << 20); // 16 MiB or 64 MiB
    const intptr_t shrink_threshold =
        m_is_memory ? (32LL << 20) : (128LL << 20); // 32 MiB or 128 MiB
    const intptr_t pagesize = 4096;

    rc = mdbx_env_set_geometry(m_env, size_lower, size_now, size_upper,
                               growth_step, shrink_threshold, pagesize);
    dbwrapper_private::HandleError(rc, "mdbx_env_set_geometry");

    const MDBX_env_flags_t env_flags = static_cast<MDBX_env_flags_t>(
        MDBX_SAFE_NOSYNC | MDBX_NOMETASYNC |
        MDBX_LIFORECLAIM | MDBX_NOSTICKYTHREADS | MDBX_NOMEMINIT);

    rc = mdbx_env_open(m_env, fs::PathToString(m_active_path).c_str(),
                       env_flags, 0600);
    dbwrapper_private::HandleError(rc, "mdbx_env_open");

    // Bound unsynced work even when callers use asynchronous batches. These
    // thresholds are checked by commits; they are not a background timer.
    rc = mdbx_env_set_syncperiod(m_env, 1U << 16); // one second, 16.16 format
    dbwrapper_private::HandleError(rc, "mdbx_env_set_syncperiod");
    rc = mdbx_env_set_syncbytes(m_env, 16U << 20); // 16 MiB
    dbwrapper_private::HandleError(rc, "mdbx_env_set_syncbytes");

    {
        MDBX_txn *txn = nullptr;
        rc = mdbx_txn_begin(m_env, nullptr, MDBX_TXN_READWRITE, &txn);
        dbwrapper_private::HandleError(rc, "mdbx_txn_begin(init)");
        rc = mdbx_dbi_open(txn, nullptr, MDBX_CREATE, &m_dbi);
        if (rc != MDBX_SUCCESS) {
            mdbx_txn_abort(txn);
            dbwrapper_private::HandleError(rc, "mdbx_dbi_open");
        }
        rc = mdbx_txn_commit(txn);
        dbwrapper_private::HandleError(rc, "mdbx_txn_commit(init)");
    }

    if (!m_is_memory) {
        if (!params.wipe_data) {
            MigrateFromLevelDBIfPresent(m_env, m_dbi, m_active_path,
                                        params.cache_bytes);
        }
        {
            std::ofstream lock_marker(m_active_path / "LOCK",
                                      std::ios::out | std::ios::trunc);
        }
        LogPrintf("Opened libmdbx successfully\n");
    }

    // The base-case obfuscation key, which is a noop.
    obfuscate_key = std::vector<uint8_t>(OBFUSCATE_KEY_NUM_BYTES, '\000');

    bool key_exists = Read(OBFUSCATE_KEY_KEY, obfuscate_key);

    if (!key_exists && params.obfuscate && IsEmpty()) {
        // Initialize non-degenerate obfuscation if it won't upset existing,
        // non-obfuscated data.
        std::vector<uint8_t> new_key = CreateObfuscateKey();

        // Write `new_key` so we don't obfuscate the key with itself
        Write(OBFUSCATE_KEY_KEY, new_key);
        obfuscate_key = new_key;

        LogPrintf("Wrote new obfuscate key for %s: %s\n",
                  fs::PathToString(params.path), HexStr(obfuscate_key));
    }

    LogPrintf("Using obfuscation key for %s: %s\n",
              fs::PathToString(params.path), HexStr(obfuscate_key));
}

CDBWrapper::~CDBWrapper() {
    // No background reader may start or still run once the environment
    // closes below.
    m_background_handle->Detach();
    {
        std::lock_guard<std::mutex> lock(m_read_txn_mutex);
        for (MDBX_cursor *cursor : m_read_cursor_pool) {
            if (cursor) {
                mdbx_cursor_close(cursor);
            }
        }
        m_read_cursor_pool.clear();
        for (MDBX_txn *txn : m_read_txn_pool) {
            if (txn) {
                mdbx_txn_abort(txn);
            }
        }
        m_read_txn_pool.clear();
    }
    if (m_env) {
        // Destructors must not throw. A failed final flush is still an error
        // worth reporting; graceful close must never silently discard it.
        if (!m_is_memory) {
            const int rc = mdbx_env_sync_ex(m_env, true, false);
            if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
                LogPrintf("Error synchronizing MDBX database %s at shutdown: %s\n",
                          m_name, mdbx_strerror(rc));
            }
        }
        mdbx_env_close_ex(m_env, m_is_memory);
        m_env = nullptr;
    }
    if (m_is_memory && !m_active_path.empty()) {
        std::error_code ec;
        fs::remove_all(m_active_path, ec);
    }
}

MDBX_txn *CDBWrapper::AcquireReadTxn() const {
    {
        std::lock_guard<std::mutex> lock(m_read_txn_mutex);
        if (!m_read_txn_pool.empty()) {
            MDBX_txn *txn = m_read_txn_pool.back();
            m_read_txn_pool.pop_back();
            int rc = mdbx_txn_renew(txn);
            if (rc == MDBX_SUCCESS) {
                return txn;
            }
            mdbx_txn_abort(txn);
            dbwrapper_private::HandleError(rc, "mdbx_txn_renew(read)");
        }
    }
    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(m_env, nullptr, MDBX_TXN_RDONLY, &txn);
    dbwrapper_private::HandleError(rc, "mdbx_txn_begin(read)");
    return txn;
}

void CDBWrapper::ReleaseReadTxn(MDBX_txn *txn) const noexcept {
    if (!txn) {
        return;
    }
    if (mdbx_txn_reset(txn) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return;
    }
    std::lock_guard<std::mutex> lock(m_read_txn_mutex);
    if (m_read_txn_pool.size() < 64) {
        m_read_txn_pool.push_back(txn);
    } else {
        mdbx_txn_abort(txn);
    }
}

MDBX_cursor *CDBWrapper::AcquireReadCursor(MDBX_txn *txn) const {
    MDBX_cursor *cursor = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_read_txn_mutex);
        if (!m_read_cursor_pool.empty()) {
            cursor = m_read_cursor_pool.back();
            m_read_cursor_pool.pop_back();
        }
    }
    if (!cursor) {
        cursor = mdbx_cursor_create(nullptr);
        if (!cursor) {
            dbwrapper_private::HandleError(MDBX_ENOMEM, "mdbx_cursor_create");
        }
    }
    int rc = mdbx_cursor_bind(txn, cursor, m_dbi);
    if (rc != MDBX_SUCCESS) {
        mdbx_cursor_close(cursor);
        dbwrapper_private::HandleError(rc, "mdbx_cursor_bind");
    }
    return cursor;
}

void CDBWrapper::ReleaseReadCursor(MDBX_cursor *cursor) const noexcept {
    if (!cursor) {
        return;
    }
    if (mdbx_cursor_unbind(cursor) != MDBX_SUCCESS) {
        mdbx_cursor_close(cursor);
        return;
    }
    std::lock_guard<std::mutex> lock(m_read_txn_mutex);
    if (m_read_cursor_pool.size() < 64) {
        m_read_cursor_pool.push_back(cursor);
    } else {
        mdbx_cursor_close(cursor);
    }
}

bool CDBWrapper::ReadRaw(Span<const uint8_t> key,
                         std::vector<uint8_t> &value) const {
    MDBX_val k{const_cast<uint8_t *>(key.data()), key.size()};
    MDBX_val v{nullptr, 0};

    MDBX_txn *txn = AcquireReadTxn();
    int rc = mdbx_get(txn, m_dbi, &k, &v);
    if (rc == MDBX_SUCCESS) {
        const auto *ptr = static_cast<const uint8_t *>(v.iov_base);
        value.assign(ptr, ptr + v.iov_len);
        ReleaseReadTxn(txn);
        return true;
    }
    ReleaseReadTxn(txn);
    if (rc == MDBX_NOTFOUND) {
        return false;
    }
    dbwrapper_private::HandleError(rc, "mdbx_get");
    return false;
}

bool CDBWrapper::ExistsRaw(Span<const uint8_t> key) const {
    MDBX_val k{const_cast<uint8_t *>(key.data()), key.size()};
    MDBX_val v{nullptr, 0};

    MDBX_txn *txn = AcquireReadTxn();
    int rc = mdbx_get(txn, m_dbi, &k, &v);
    ReleaseReadTxn(txn);
    if (rc == MDBX_SUCCESS) {
        return true;
    }
    if (rc == MDBX_NOTFOUND) {
        return false;
    }
    dbwrapper_private::HandleError(rc, "mdbx_get(exists)");
    return false;
}

void CDBWrapper::PrefetchRawKeys(
    std::vector<std::vector<uint8_t>> &keys) const {
    if (keys.empty() || !m_env) {
        return;
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    PrefetchSortedRawKeys(keys);
}

void CDBWrapper::PrefetchSortedRawKeys(
    Span<const std::vector<uint8_t>> keys) const {
    if (keys.empty() || !m_env) {
        return;
    }
    // Read transactions and cursors come from mutex-guarded pools, and the
    // environment is opened with MDBX_NOSTICKYTHREADS, so this may run on
    // any thread, concurrently with readers and the writer of other threads
    // (each uses its own transaction; MDBX readers see a snapshot).
    MDBX_txn *txn = AcquireReadTxn();
    MDBX_cursor *cursor = AcquireReadCursor(txn);
    constexpr uintptr_t kPageMask = ~uintptr_t(4095);
    uintptr_t last_page = 0;

    auto madvise_val = [kPageMask, &last_page](const MDBX_val &val) noexcept {
        if (!val.iov_base || val.iov_len == 0) {
            return;
        }
        const uintptr_t addr = reinterpret_cast<uintptr_t>(val.iov_base);
        const uintptr_t page_base = addr & kPageMask;
        if (page_base != last_page) {
            const size_t span =
                ((addr - page_base) + val.iov_len + 4095u) & ~size_t(4095u);
            (void)::posix_madvise(reinterpret_cast<void *>(page_base), span,
                                  POSIX_MADV_WILLNEED);
            last_page = page_base;
        }
    };

    for (const auto &key : keys) {
        MDBX_val k{const_cast<uint8_t *>(key.data()), key.size()};
        MDBX_val v{nullptr, 0};
        if (mdbx_cursor_get(cursor, &k, &v, MDBX_SET_RANGE) == MDBX_SUCCESS) {
            madvise_val(k);
            madvise_val(v);
        }
    }

    ReleaseReadCursor(cursor);
    ReleaseReadTxn(txn);
}

void CDBWrapper::WriteBatch(CDBBatch &batch, bool fSync) {
    if (batch.m_ops.empty()) {
        if (fSync) {
            Sync();
        }
        return;
    }

    // Sort operations by key using stable_sort so B+Tree modifications occur in
    // ascending key order while preserving relative order for identical keys.
    if (batch.m_ops.size() > 1) {
        std::stable_sort(batch.m_ops.begin(), batch.m_ops.end(),
                         [](const CDBBatch::BatchOp &a,
                            const CDBBatch::BatchOp &b) {
                             return a.key < b.key;
                         });
    }

    auto *const metrics{node::GetNodeMetrics()};
    const auto start{metrics ? std::chrono::steady_clock::now()
                             : std::chrono::steady_clock::time_point{}};

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(m_env, nullptr, MDBX_TXN_READWRITE, &txn);
    dbwrapper_private::HandleError(rc, "mdbx_txn_begin(write)");

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, m_dbi, &cursor);
    if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        dbwrapper_private::HandleError(rc, "mdbx_cursor_open(write)");
    }

    const size_t n = batch.m_ops.size();
    for (size_t i = 0; i < n; ++i) {
        // If a subsequent operation in the same batch targets the exact same
        // key, it supersedes this operation completely.
        if (i + 1 < n && batch.m_ops[i].key == batch.m_ops[i + 1].key) {
            continue;
        }
        const auto &op = batch.m_ops[i];
        MDBX_val k{const_cast<uint8_t *>(op.key.data()), op.key.size()};
        if (op.is_delete) {
            rc = mdbx_del(txn, m_dbi, &k, nullptr);
            if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) {
                mdbx_cursor_close(cursor);
                mdbx_txn_abort(txn);
                dbwrapper_private::HandleError(rc, "mdbx_del");
            }
        } else {
            MDBX_val v{const_cast<uint8_t *>(op.value.data()), op.value.size()};
            rc = mdbx_cursor_put(cursor, &k, &v, MDBX_UPSERT);
            if (rc != MDBX_SUCCESS) {
                mdbx_cursor_close(cursor);
                mdbx_txn_abort(txn);
                dbwrapper_private::HandleError(rc, "mdbx_cursor_put");
            }
        }
    }

    mdbx_cursor_close(cursor);
    rc = mdbx_txn_commit(txn);
    dbwrapper_private::HandleError(rc, "mdbx_txn_commit(write)");

    if (fSync) {
        Sync();
    }

    if (metrics) {
        metrics->db_commit_seconds.RecordDuration(
            std::chrono::steady_clock::now() - start, m_metric_db);
        MDBX_envinfo info{};
        if (mdbx_env_info_ex(m_env, nullptr, &info, sizeof(info)) ==
            MDBX_SUCCESS) {
            metrics->db_size.Set(double(info.mi_geo.current), m_metric_db);
        }
    }
}

void CDBWrapper::Sync() {
    if (!m_is_memory && m_env) {
        int rc = mdbx_env_sync_ex(m_env, true, false);
        if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
            dbwrapper_private::HandleError(rc, "mdbx_env_sync_ex");
        }
    }
}

size_t CDBWrapper::DynamicMemoryUsage() const {
    return sizeof(*this);
}

size_t CDBWrapper::EstimateSizeBytes(Span<const uint8_t> key_begin,
                                     Span<const uint8_t> key_end) const {
    MDBX_txn *txn = AcquireReadTxn();
    MDBX_stat stat{};
    int rc = mdbx_dbi_stat(txn, m_dbi, &stat, sizeof(stat));
    if (rc != MDBX_SUCCESS || stat.ms_entries == 0) {
        ReleaseReadTxn(txn);
        return 0;
    }
    const size_t total_bytes =
        (stat.ms_branch_pages + stat.ms_leaf_pages + stat.ms_overflow_pages) *
        stat.ms_psize;
    MDBX_val k1{const_cast<uint8_t *>(key_begin.data()), key_begin.size()};
    MDBX_val k2{const_cast<uint8_t *>(key_end.data()), key_end.size()};
    ptrdiff_t dist = 0;
    rc = mdbx_estimate_range(txn, m_dbi, &k1, nullptr, &k2, nullptr, &dist);
    ReleaseReadTxn(txn);
    if (rc == MDBX_SUCCESS && dist > 0) {
        const double frac = std::min(
            1.0, static_cast<double>(dist) / static_cast<double>(stat.ms_entries));
        return static_cast<size_t>(total_bytes * frac);
    }
    return total_bytes;
}

const std::string CDBWrapper::OBFUSCATE_KEY_KEY("\000obfuscate_key", 14);

const unsigned int CDBWrapper::OBFUSCATE_KEY_NUM_BYTES = 8;

std::vector<uint8_t> CDBWrapper::CreateObfuscateKey() const {
    std::vector<uint8_t> ret(OBFUSCATE_KEY_NUM_BYTES);
    GetRandBytes(ret);
    return ret;
}

bool CDBWrapper::IsEmpty() {
    std::unique_ptr<CDBIterator> it(NewIterator());
    it->SeekToFirst();
    return !(it->Valid());
}

CDBIterator::CDBIterator(const CDBWrapper &_parent, MDBX_env *env,
                         MDBX_dbi dbi)
    : parent(_parent) {
    (void)env;
    (void)dbi;
    m_txn = parent.AcquireReadTxn();
    try {
        m_cursor = parent.AcquireReadCursor(m_txn);
    } catch (...) {
        parent.ReleaseReadTxn(m_txn);
        m_txn = nullptr;
        throw;
    }
}

CDBIterator::~CDBIterator() {
    if (m_cursor) {
        parent.ReleaseReadCursor(m_cursor);
        m_cursor = nullptr;
    }
    if (m_txn) {
        parent.ReleaseReadTxn(m_txn);
        m_txn = nullptr;
    }
}

bool CDBIterator::Valid() const {
    return m_valid;
}

void CDBIterator::SeekToFirst() {
    MDBX_val k{nullptr, 0};
    MDBX_val v{nullptr, 0};
    int rc = mdbx_cursor_get(m_cursor, &k, &v, MDBX_FIRST);
    if (rc == MDBX_SUCCESS) {
        m_key_ptr = static_cast<const uint8_t *>(k.iov_base);
        m_key_len = k.iov_len;
        m_val_ptr = static_cast<const uint8_t *>(v.iov_base);
        m_val_len = v.iov_len;
        m_valid = true;
    } else {
        m_valid = false;
    }
}

void CDBIterator::SeekBytes(Span<const uint8_t> key) {
    MDBX_val k{const_cast<uint8_t *>(key.data()), key.size()};
    MDBX_val v{nullptr, 0};
    int rc = mdbx_cursor_get(m_cursor, &k, &v, MDBX_SET_RANGE);
    if (rc == MDBX_SUCCESS) {
        m_key_ptr = static_cast<const uint8_t *>(k.iov_base);
        m_key_len = k.iov_len;
        m_val_ptr = static_cast<const uint8_t *>(v.iov_base);
        m_val_len = v.iov_len;
        m_valid = true;
    } else {
        m_valid = false;
    }
}

void CDBIterator::Next() {
    if (!m_valid) {
        return;
    }
    MDBX_val k{nullptr, 0};
    MDBX_val v{nullptr, 0};
    int rc = mdbx_cursor_get(m_cursor, &k, &v, MDBX_NEXT);
    if (rc == MDBX_SUCCESS) {
        m_key_ptr = static_cast<const uint8_t *>(k.iov_base);
        m_key_len = k.iov_len;
        m_val_ptr = static_cast<const uint8_t *>(v.iov_base);
        m_val_len = v.iov_len;
        m_valid = true;
    } else {
        m_valid = false;
    }
}

namespace dbwrapper_private {

void HandleError(int rc, const char *context) {
    if (rc == MDBX_SUCCESS) {
        return;
    }
    char errbuf[256];
    const char *errstr = mdbx_strerror_r(rc, errbuf, sizeof(errbuf));
    const std::string errmsg = strprintf(
        "Fatal libmdbx error (%s): [%d] %s", context, rc,
        errstr ? errstr : "unknown");
    LogPrintf("%s\n", errmsg);
    throw dbwrapper_error(errmsg);
}

const std::vector<uint8_t> &GetObfuscateKey(const CDBWrapper &w) {
    return w.obfuscate_key;
}
}; // namespace dbwrapper_private
