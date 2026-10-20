// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DBWRAPPER_H
#define BITCOIN_DBWRAPPER_H

#include <common/system.h>
#include <logging.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

struct MDBX_env;
struct MDBX_txn;
struct MDBX_cursor;
using MDBX_dbi = uint32_t;

static const size_t DBWRAPPER_PREALLOC_KEY_SIZE = 64;
static const size_t DBWRAPPER_PREALLOC_VALUE_SIZE = 1024;
static const size_t DBWRAPPER_MAX_FILE_SIZE = 32 << 20; // 32 MiB

//! User-controlled performance and debug options.
struct DBOptions {
    //! Compact database on startup.
    bool force_compact = false;
};

//! Application-specific storage settings.
struct DBParams {
    //! Location in the filesystem where database data will be stored.
    fs::path path;
    //! Configures database cache/sizing settings.
    size_t cache_bytes;
    //! If true, use an ephemeral in-memory/temp environment.
    bool memory_only = false;
    //! If true, remove all existing data.
    bool wipe_data = false;
    //! If true, store data obfuscated via simple XOR. If false, XOR with a
    //! zero'd byte array.
    bool obfuscate = false;
    //! Passed-through options.
    DBOptions options{};
};

class dbwrapper_error : public std::runtime_error {
public:
    explicit dbwrapper_error(const std::string &msg)
        : std::runtime_error(msg) {}
};

class CDBWrapper;

/**
 * Lets threads that do not own a CDBWrapper read from it while it may be
 * destroyed meanwhile (e.g. a background prefetch racing a cache resize or
 * shutdown). Use() runs its function only while the database is open; the
 * database's destructor first stops new uses, then waits for running ones.
 * Holding the handle never keeps the database alive.
 */
class DBBackgroundHandle {
public:
    explicit DBBackgroundHandle(const CDBWrapper &db) : m_db{&db} {}

    /** Run f(db) if the database is still open. Returns whether it ran.
     * f must not take locks held by whoever destroys the database. */
    template <typename F> bool Use(F &&f) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_db) {
                return false;
            }
            ++m_active;
        }
        struct Done {
            DBBackgroundHandle &h;
            ~Done() {
                std::lock_guard<std::mutex> lock(h.m_mutex);
                if (--h.m_active == 0) {
                    h.m_idle.notify_all();
                }
            }
        } done{*this};
        f(*m_db);
        return true;
    }

    /** Whether the database is still open. */
    bool IsOpen() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_db != nullptr;
    }

private:
    friend class CDBWrapper;
    //! Called by the database's destructor.
    void Detach() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_db = nullptr;
        m_idle.wait(lock, [this] { return m_active == 0; });
    }

    mutable std::mutex m_mutex;
    std::condition_variable m_idle;
    const CDBWrapper *m_db;
    size_t m_active{0};
};

namespace dbwrapper {
struct DestroyOptions {};
struct Status {
    bool m_ok{true};
    bool ok() const { return m_ok; }
};
Status DestroyDB(const std::string &path_str,
                 const DestroyOptions &options = {});
} // namespace dbwrapper

/**
 * These should be considered an implementation detail of the specific database.
 */
namespace dbwrapper_private {

/**
 * Handle database error by throwing dbwrapper_error exception.
 */
void HandleError(int rc, const char *context = "libmdbx");

/**
 * Work around circular dependency, as well as for testing in dbwrapper_tests.
 * Database obfuscation should be considered an implementation detail of the
 * specific database.
 */
const std::vector<uint8_t> &GetObfuscateKey(const CDBWrapper &w);
}; // namespace dbwrapper_private

/** Batch of changes queued to be written to a CDBWrapper */
class CDBBatch {
    friend class CDBWrapper;

public:
    struct BatchOp {
        std::vector<uint8_t> key;
        std::vector<uint8_t> value;
        bool is_delete{false};
    };

private:
    const CDBWrapper &parent;
    std::vector<BatchOp> m_ops;

    DataStream ssKey{};
    DataStream ssValue{};

    size_t size_estimate{0};

public:
    /**
     * @param[in] _parent   CDBWrapper that this batch is to be submitted to
     */
    explicit CDBBatch(const CDBWrapper &_parent) : parent(_parent) {}

    void Clear() {
        m_ops.clear();
        size_estimate = 0;
    }

    template <typename K, typename V> void Write(const K &key, const V &value) {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;

        ssValue.reserve(DBWRAPPER_PREALLOC_VALUE_SIZE);
        ssValue << value;
        ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));

        const auto key_span = MakeUCharSpan(ssKey);
        const auto val_span = MakeUCharSpan(ssValue);

        BatchOp op;
        op.key.assign(key_span.begin(), key_span.end());
        op.value.assign(val_span.begin(), val_span.end());
        op.is_delete = false;

        size_estimate += 3 + (op.key.size() > 127) + op.key.size() +
                         (op.value.size() > 127) + op.value.size();
        m_ops.push_back(std::move(op));

        ssKey.clear();
        ssValue.clear();
    }

    template <typename K> void Erase(const K &key) {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;

        const auto key_span = MakeUCharSpan(ssKey);

        BatchOp op;
        op.key.assign(key_span.begin(), key_span.end());
        op.is_delete = true;

        size_estimate += 2 + (op.key.size() > 127) + op.key.size();
        m_ops.push_back(std::move(op));

        ssKey.clear();
    }

    size_t SizeEstimate() const { return size_estimate; }
};

class CDBIterator {
private:
    const CDBWrapper &parent;
    MDBX_txn *m_txn{nullptr};
    MDBX_cursor *m_cursor{nullptr};
    const uint8_t *m_key_ptr{nullptr};
    size_t m_key_len{0};
    const uint8_t *m_val_ptr{nullptr};
    size_t m_val_len{0};
    bool m_valid{false};

    void SeekBytes(Span<const uint8_t> key);

public:
    CDBIterator(const CDBWrapper &_parent, MDBX_env *env, MDBX_dbi dbi);
    ~CDBIterator();

    CDBIterator(const CDBIterator &) = delete;
    CDBIterator &operator=(const CDBIterator &) = delete;

    bool Valid() const;

    void SeekToFirst();

    template <typename K> void Seek(const K &key) {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        SeekBytes(MakeUCharSpan(ssKey));
    }

    void Next();

    template <typename K> bool GetKey(K &key) {
        if (!m_valid) {
            return false;
        }
        try {
            DataStream ssKey{Span<const std::byte>(
                reinterpret_cast<const std::byte *>(m_key_ptr), m_key_len)};
            ssKey >> key;
        } catch (const std::exception &) {
            return false;
        }
        return true;
    }

    template <typename V> bool GetValue(V &value) {
        if (!m_valid) {
            return false;
        }
        try {
            DataStream ssValue{Span<const std::byte>(
                reinterpret_cast<const std::byte *>(m_val_ptr), m_val_len)};
            ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
            ssValue >> value;
        } catch (const std::exception &) {
            return false;
        }
        return true;
    }

    unsigned int GetValueSize() {
        return m_valid ? static_cast<unsigned int>(m_val_len) : 0;
    }
};

class CDBWrapper {
    friend struct CDBWrapperTestAccess;
    friend const std::vector<uint8_t> &
    dbwrapper_private::GetObfuscateKey(const CDBWrapper &w);
    friend class CDBIterator;

private:
    //! libmdbx environment and default database handle
    MDBX_env *m_env{nullptr};
    MDBX_dbi m_dbi{0};

    //! pool of reusable read-only transactions and cursors
    mutable std::mutex m_read_txn_mutex;
    mutable std::vector<MDBX_txn *> m_read_txn_pool;
    mutable std::vector<MDBX_cursor *> m_read_cursor_pool;

    MDBX_txn *AcquireReadTxn() const;
    void ReleaseReadTxn(MDBX_txn *txn) const noexcept;
    MDBX_cursor *AcquireReadCursor(MDBX_txn *txn) const;
    void ReleaseReadCursor(MDBX_cursor *cursor) const noexcept;

    //! the name of this database
    std::string m_name;

    //! a key used for optional XOR-obfuscation of the database
    std::vector<uint8_t> obfuscate_key;

    //! the key under which the obfuscation key is stored
    static const std::string OBFUSCATE_KEY_KEY;

    //! the length of the obfuscate key in number of bytes
    static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

    std::vector<uint8_t> CreateObfuscateKey() const;

    //! path to filesystem storage
    const fs::path m_path;

    //! actual directory path opened by libmdbx (temp dir when memory_only)
    fs::path m_active_path;

    //! whether or not the database resides in memory
    bool m_is_memory;

    //! Label index of this database in the metrics (MetricDatabaseIndex)
    size_t m_metric_db;
    //! Shared with background users; detached first in the destructor.
    std::shared_ptr<DBBackgroundHandle> m_background_handle;

    bool ReadRaw(Span<const uint8_t> key, std::vector<uint8_t> &value) const;
    bool ExistsRaw(Span<const uint8_t> key) const;
    size_t EstimateSizeBytes(Span<const uint8_t> key_begin,
                             Span<const uint8_t> key_end) const;

public:
    CDBWrapper(const DBParams &params);
    ~CDBWrapper();

    CDBWrapper(const CDBWrapper &) = delete;
    CDBWrapper &operator=(const CDBWrapper &) = delete;

    template <typename K, typename V> bool Read(const K &key, V &value) const {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;

        std::vector<uint8_t> raw_value;
        if (!ReadRaw(MakeUCharSpan(ssKey), raw_value)) {
            return false;
        }
        try {
            DataStream ssValue{MakeByteSpan(raw_value)};
            ssValue.Xor(obfuscate_key);
            ssValue >> value;
        } catch (const std::exception &) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    void Write(const K &key, const V &value, bool fSync = false) {
        CDBBatch batch(*this);
        batch.Write(key, value);
        WriteBatch(batch, fSync);
    }

    //! @returns filesystem path to the on-disk data.
    std::optional<fs::path> StoragePath() {
        if (m_is_memory) {
            return {};
        }
        return m_path;
    }

    template <typename K> bool Exists(const K &key) const {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        return ExistsRaw(MakeUCharSpan(ssKey));
    }

    template <typename K> void Erase(const K &key, bool fSync = false) {
        CDBBatch batch(*this);
        batch.Erase(key);
        WriteBatch(batch, fSync);
    }

    void WriteBatch(CDBBatch &batch, bool fSync = false);

    /** Sort and deduplicate keys, then walk them (PrefetchSortedRawKeys). */
    void PrefetchRawKeys(std::vector<std::vector<uint8_t>> &keys) const;
    /**
     * Seek a read cursor to each of keys (ascending) and hint the kernel to
     * read the pages holding them (posix_madvise WILLNEED). The seeks fault
     * in the B-tree pages synchronously on the calling thread. Thread-safe:
     * uses its own pooled read transaction and cursor.
     */
    void PrefetchSortedRawKeys(Span<const std::vector<uint8_t>> keys) const;

    /** Handle for using this database from threads that do not own it. */
    std::shared_ptr<DBBackgroundHandle> GetBackgroundHandle() const {
        return m_background_handle;
    }

    void Sync();

    // Get an estimate of database memory usage (in bytes).
    size_t DynamicMemoryUsage() const;

    CDBIterator *NewIterator() {
        return new CDBIterator(*this, m_env, m_dbi);
    }

    /**
     * Return true if the database managed by this class contains no entries.
     */
    bool IsEmpty();

    template <typename K>
    size_t EstimateSize(const K &key_begin, const K &key_end) const {
        DataStream ssKey1{}, ssKey2{};
        ssKey1.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey2.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey1 << key_begin;
        ssKey2 << key_end;
        return EstimateSizeBytes(MakeUCharSpan(ssKey1), MakeUCharSpan(ssKey2));
    }

    /**
     * Compact a certain range of keys in the database (no-op for B+Tree libmdbx).
     */
    template <typename K>
    void CompactRange(const K &key_begin, const K &key_end) const {
        (void)key_begin;
        (void)key_end;
    }
};

#endif // BITCOIN_DBWRAPPER_H
