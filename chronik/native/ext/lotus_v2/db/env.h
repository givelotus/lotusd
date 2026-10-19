// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ENV_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ENV_H

#include <chronik/native/store.h>
#include <ext/lotus_v2/db/model.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

/**
 * The dedicated `v2_index` env (port of chronik-db/src/mdbx.rs), on the native
 * MDBX backend with the Rust env's exact profile and named subdatabases, plus
 * the append-only flat segment files `v2_tx_NNNNN.dat` in the same directory.
 *
 * Callers use the Rust logical keys; RouteKey() maps each to its subdatabase
 * and subkey ("v2-binding"/"tip"/"disconnected"/"flat_pos" -> meta, 'b'+32,
 * 'u'+32, 't'+32, 'o'+36, 'p'+69 (postings, DUPFIXED 36-byte outpoint dup),
 * "eH"+8, "eB"+32, "eO"+36, "eT"+32, "eX"+32, "eI"+36, "eW"+40, "eA"+32,
 * "eE"+44, "eP"+48). All errors are V2Error::Db with the Rust MdbxError text,
 * except that MDBX return codes are reported in the native backend's format.
 */
namespace chronik::native::lotus_v2 {

/** Maximum byte size per flat transaction wire segment file. */
inline constexpr uint64_t MAX_FLAT_SEGMENT_BYTES = uint64_t(2) << 30;

/** Append-only flat segment files of exact transaction wire bytes. */
class FlatFileStore {
public:
    explicit FlatFileStore(std::filesystem::path dir) : m_dir(std::move(dir)) {}

    std::filesystem::path SegmentPath(uint32_t file_num) const;
    /** pwrite at (file_num, offset); empty bytes only open/create. */
    void WriteAt(uint32_t file_num, uint64_t offset, ByteView bytes) const;
    /** fdatasync (F_FULLFSYNC on Apple, like Rust's sync_data). */
    void SyncFile(uint32_t file_num) const;
    /** Exact pread; a short read is an error. */
    Bytes ReadAt(uint32_t file_num, uint64_t offset, size_t len) const;
    /**
     * Truncate segment file_num to write_pos (if it exists), then drop and
     * delete every cached higher segment.
     */
    void TruncateTo(uint32_t file_num, uint64_t write_pos) const;

private:
    struct File {
        int fd = -1;
        ~File();
    };
    std::shared_ptr<File> GetOrOpen(uint32_t file_num, bool create) const;

    std::filesystem::path m_dir;
    mutable std::mutex m_mutex;
    mutable std::map<uint32_t, std::shared_ptr<File>> m_files;
};

/** Staged write batch for atomic commit across subdatabases. */
class V2WriteBatch {
public:
    void Put(Bytes key, Bytes value) {
        m_bytes += key.size() + value.size();
        m_ops.push_back({std::move(key), std::move(value)});
    }
    void Delete(Bytes key) {
        m_bytes += key.size();
        m_ops.push_back({std::move(key), std::nullopt});
    }
    /** Approximate serialized size: key + value bytes of every op. */
    size_t SizeInBytes() const { return m_bytes; }

private:
    friend class V2Env;
    std::vector<std::pair<Bytes, std::optional<Bytes>>> m_ops;
    size_t m_bytes = 0;
};

class V2Env;

/** Consistent MVCC read-only snapshot (one MDBX read txn). */
class V2EnvSnapshot {
public:
    V2EnvSnapshot(const V2Env &env, std::unique_ptr<ReadTxn> txn);
    V2EnvSnapshot(V2EnvSnapshot &&) noexcept;
    V2EnvSnapshot &operator=(V2EnvSnapshot &&) noexcept;
    ~V2EnvSnapshot();

    std::optional<Bytes> Get(ByteView key) const;
    /** (file_num, offset, len) of the flat segment store. */
    Bytes ReadFlat(uint32_t file_num, uint64_t offset, size_t len) const;
    /** Next 36-byte posting strictly after `after` (or the first). */
    std::optional<std::array<uint8_t, 36>>
    NextPostingDupfixed(const Bytes32 &root, uint8_t pos,
                        const std::optional<std::array<uint8_t, 36>> &after)
        const;
    /** Every posting strictly after `after` (or all). */
    std::vector<std::array<uint8_t, 36>> PostingsDupfixedAfter(
        const Bytes32 &root, uint8_t pos,
        const std::optional<std::array<uint8_t, 36>> &after) const;
    /**
     * Exclusive bounded seek in one regular family (eH/eO/eI/eW/eA/eE/eP)
     * under `prefix`. charge() runs once before the initial seek and once more
     * before stepping past an exact `after` match. Returns the logical key.
     */
    std::optional<std::pair<Bytes, Bytes>>
    SeekNextRegular(ByteView prefix, std::optional<ByteView> after,
                    const std::function<void()> &charge) const;
    /** Every logical (key, value), postings as 'p'||key33||dup36 -> "". */
    std::vector<std::pair<Bytes, Bytes>> DumpAll() const;

private:
    const V2Env *m_env;
    std::unique_ptr<ReadTxn> m_txn;
};

class V2Env {
public:
    /** Opens (creating the directory and tables) the env at dir. */
    explicit V2Env(const std::filesystem::path &dir);
    ~V2Env();
    V2Env(const V2Env &) = delete;
    V2Env &operator=(const V2Env &) = delete;

    /** Point read on a fresh snapshot. */
    std::optional<Bytes> Get(ByteView key) const;
    /** Single-key write transaction. */
    void Put(ByteView key, ByteView value);
    /** Applies the ops in order in one write transaction. */
    void Write(const V2WriteBatch &batch);
    V2EnvSnapshot Snapshot() const;
    std::vector<std::pair<Bytes, Bytes>> DumpAll() const;
    bool IsEmpty() const;
    const FlatFileStore &Flat() const { return m_flat; }

    /** The underlying native store (tests and the dump tool). */
    const KvStore &Store() const { return *m_store; }

    enum Table : TableId {
        META,
        BLOCK_RECEIPTS,
        UNDO,
        TX_LOCATIONS,
        OUTPUTS,
        POSTINGS,
        EXPLORER_HEIGHT,
        EXPLORER_BLOCK,
        EXPLORER_BLOCK_TX,
        EXPLORER_TX,
        EXPLORER_TXHASH,
        EXPLORER_INPUT,
        EXPLORER_WITNESS,
        ASSET_SUMMARY,
        ASSET_EVENT,
        ASSET_OUTPUT,
        N_TABLES,
    };
    /** Table specs, in the Rust DBI open order. */
    static std::span<const TableSpec> Tables();

    struct Route {
        TableId table;
        ByteView subkey;
        /** Postings only: the 36-byte dup value. */
        std::optional<ByteView> dup;
    };
    /** Throws Db("unrecognized logical key of length N"). */
    static Route RouteKey(ByteView key);

private:
    std::unique_ptr<KvStore> m_store;
    FlatFileStore m_flat;
};

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ENV_H
