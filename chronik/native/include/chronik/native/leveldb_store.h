// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_LEVELDB_STORE_H
#define CHRONIK_NATIVE_LEVELDB_STORE_H

#include <chronik/native/store.h>

#include <filesystem>
#include <memory>
#include <span>

/**
 * Optional LevelDB storage backend (library chronik_native_store_leveldb,
 * built with CHRONIK_NATIVE_LEVELDB=ON). Only this library includes LevelDB
 * headers; the core reaches it only through the KvStore interface.
 *
 * The logical schema is the same as with MDBX, but the physical layout is
 * not byte-compatible with Rust Chronik data (switching backends needs a
 * reindex). Physical layout, in one LevelDB with the bytewise comparator:
 *
 *   store metadata  0x00 || "format"           -> "chronik-native-leveldb-1"
 *                   0x00 || "table:" || name   -> varint(id) || kind
 *                                                 [|| varint(dup_fixed_size)]
 *   plain table     varint(id) || key          -> value
 *   dup table       varint(id) || escaped(key) || dup_value -> ""
 *
 * varint is unsigned LEB128. escaped(key) is the key with every 0x00 byte
 * written as 0x00 0xff, followed by 0x00 0x00: prefix-free and
 * order-preserving, so keys iterate in memcmp order (as in MDBX, also for a
 * plain cursor over a dup table) and the dups of one key are a prefix scan
 * in memcmp order, which is the MDBX DUPSORT order. Table ids start at 1 and
 * are assigned the first time a table name is opened, then persisted, so
 * adding tables later (e.g. by a tier extension) never renumbers existing
 * ones. Keys are never hashed (LevelDB has no key-length limit).
 *
 * A ReadTxn is a LevelDB snapshot. A WriteTxn is an in-memory ordered overlay
 * over a snapshot (read-your-writes), written as one WriteBatch on Commit
 * with sync=false; Sync() writes an empty batch with sync=true.
 */
namespace chronik::native {

/** Registers StoreBackend::LevelDb in the registry. */
void RegisterLevelDbStore();

std::unique_ptr<KvStore> OpenLevelDbStore(const std::filesystem::path &dir,
                                          std::span<const TableSpec> tables,
                                          const StoreOptions &opts);

/** Deletes the LevelDB files (and the directory if then empty). */
void DestroyLevelDbStore(const std::filesystem::path &dir);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_LEVELDB_STORE_H
