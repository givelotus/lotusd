// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_STORE_H
#define CHRONIK_NATIVE_STORE_H

#include <chronik/native/types.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/**
 * Ordered key-value storage interface. This is the ONLY path from the native
 * Chronik core to storage: the core never includes a database header. Each
 * backend (MDBX, LevelDB) is a separate library implementing this interface,
 * so a host can link exactly the backends it wants.
 */
namespace chronik::native {

enum class StoreBackend { Mdbx, LevelDb };

struct TableSpec {
    /** Exact Rust CF name, e.g. "script_utxo" */
    std::string_view name;
    enum class Kind { Plain, Dup } kind = Kind::Plain;
    /** Dup only; MDBX_DUPFIXED when set */
    std::optional<uint32_t> dup_fixed_size;
};
using TableId = uint16_t;

/** Ordered iteration over one table (plain tables). */
class Cursor {
public:
    virtual ~Cursor() = default;
    virtual bool SeekFirst() = 0;
    virtual bool SeekLast() = 0;
    /** First key >= key (MDBX_SET_RANGE) */
    virtual bool SeekGe(ByteView key) = 0;
    /** Last key <= key (MDBX_TO_KEY_LESSER_OR_EQUAL) */
    virtual bool SeekLe(ByteView key) = 0;
    virtual bool Next() = 0;
    virtual bool Prev() = 0;
    virtual bool Valid() const = 0;
    /** Views valid until the cursor moves or the txn ends. */
    virtual ByteView Key() const = 0;
    virtual ByteView Value() const = 0;
};

/** The duplicate values of one key, ascending (dup tables). */
class DupCursor {
public:
    virtual ~DupCursor() = default;
    /** Position at the first dup of key; false if the key has no dups. */
    virtual bool Seek(ByteView key) = 0;
    /** First dup of key with value >= value_prefix (GET_BOTH_RANGE). */
    virtual bool SeekValueGe(ByteView key, ByteView value_prefix) = 0;
    /** Next dup of the same key; false at the end. */
    virtual bool Next() = 0;
    virtual bool Valid() const = 0;
    virtual ByteView Value() const = 0;
    /** Number of dups from the current position to the end of the key. */
    virtual size_t CountRemaining() = 0;
};

class ReadTxn {
public:
    virtual ~ReadTxn() = default;
    /** View valid until the txn ends or (write txn) the next write. */
    virtual std::optional<ByteView> Get(TableId, ByteView key) const = 0;
    virtual std::unique_ptr<Cursor> OpenCursor(TableId) const = 0;
    virtual std::unique_ptr<DupCursor> OpenDupCursor(TableId) const = 0;
    virtual uint64_t EstimateEntries(TableId) const = 0;
};

/** Reads observe this txn's own writes. */
class WriteTxn : public ReadTxn {
public:
    virtual void Put(TableId, ByteView key, ByteView value) = 0;
    virtual void Del(TableId, ByteView key) = 0;
    /** Idempotent */
    virtual void PutDup(TableId, ByteView key, ByteView value) = 0;
    /** Exact match */
    virtual void DelDup(TableId, ByteView key, ByteView value) = 0;
    /** Delete the first dup of key starting with value_prefix (if any). */
    virtual void DelDupByPrefix(TableId, ByteView key,
                                ByteView value_prefix) = 0;
    /** Remove every entry of the table (mdbx_drop(..., false)) */
    virtual void Clear(TableId) = 0;
    /** Throws on failure; txn unusable after. */
    virtual void Commit() = 0;
};

class KvStore {
public:
    virtual ~KvStore() = default;
    /** Throws ChronikError "Column family <name> doesn't exist" if unknown. */
    virtual TableId Table(std::string_view name) const = 0;
    /** Names of all tables, in the order they were opened. */
    virtual std::vector<std::string> TableNames() const = 0;
    /** Any thread, concurrent */
    virtual std::unique_ptr<ReadTxn> BeginRead() const = 0;
    /** Writer thread only */
    virtual std::unique_ptr<WriteTxn> BeginWrite() = 0;
    /** Durability checkpoint (force = full fsync). */
    virtual void Sync(bool force) = 0;
};

/**
 * Lifetime rule: every ReadTxn/WriteTxn (and their cursors) must be destroyed
 * before the KvStore that created them. A ReadTxn may be used from any thread,
 * but by one thread at a time.
 */

/** Hook used by backends needing SHA-256 (MDBX long-key hashing). */
using Sha256Fn = std::function<void(ByteView data, uint8_t out[32])>;

struct StoreOptions {
    Sha256Fn sha256;
};

/**
 * Backend registry. Each backend library exposes an explicit registration
 * function (e.g. RegisterMdbxStore() in chronik/native/mdbx_store.h), which the
 * host adapter calls for the backends it links. Opening an unregistered
 * backend throws.
 */
using StoreOpenFn = std::function<std::unique_ptr<KvStore>(
    const std::filesystem::path &dir, std::span<const TableSpec> tables,
    const StoreOptions &opts)>;
using StoreDestroyFn = std::function<void(const std::filesystem::path &dir)>;

void RegisterStoreBackend(StoreBackend, StoreOpenFn, StoreDestroyFn);
bool HasStoreBackend(StoreBackend);
std::unique_ptr<KvStore> OpenStore(StoreBackend,
                                   const std::filesystem::path &dir,
                                   std::span<const TableSpec> tables,
                                   const StoreOptions &opts);
void DestroyStore(StoreBackend, const std::filesystem::path &dir);
std::string_view StoreBackendName(StoreBackend);
/** Inverse of StoreBackendName ("mdbx", "leveldb"); nullopt if unknown. */
std::optional<StoreBackend> ParseStoreBackend(std::string_view name);
/**
 * Index directory under <datadir_net>/indexes: "chronik" for MDBX (shared
 * with Rust Chronik), "chronik-leveldb" for LevelDB, so the two layouts are
 * never confused.
 */
std::string_view StoreIndexDirName(StoreBackend);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_STORE_H
