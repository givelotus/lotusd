// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MDBX_STORE_H
#define CHRONIK_NATIVE_MDBX_STORE_H

#include <chronik/native/store.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>

/**
 * MDBX storage backend (library chronik_native_store_mdbx). Only this library
 * includes mdbx.h; the core reaches it only through the KvStore interface.
 */
namespace chronik::native {

/**
 * Environment profile. The default (ChronikIndexProfile) reproduces the Rust
 * Chronik index env of chronik-db/src/db.rs `Db::open_with_cfs` exactly; tier
 * extensions (e.g. the Lotus V2 v2_index env) define their own.
 */
struct MdbxEnvProfile {
    int64_t size_lower = 1 << 20;             // 1 MiB
    int64_t size_now = 16 << 20;              // 16 MiB
    int64_t size_upper = int64_t(256) << 30;  // 256 GiB
    int64_t growth_step = 64 << 20;           // 64 MiB
    int64_t shrink_threshold = 128 << 20;     // 128 MiB
    int64_t pagesize = 16384;                 // 16 KiB
    // Env flags
    bool safe_nosync = true;
    bool nometasync = true;
    bool liforeclaim = true;
    bool nostickythreads = true;
    bool nomeminit = true;
    uint32_t mode = 0600;
    uint32_t max_readers = 256;
    /** 0 => max(n_tables + 16, 64), like Rust. */
    uint32_t max_dbs = 0;
    /** MDBX_OPT_SYNC_BYTES / MDBX_OPT_SYNC_PERIOD, if set */
    std::optional<uint64_t> sync_bytes = uint64_t(16) << 20;
    std::optional<uint64_t> sync_period = uint64_t(1) << 16;
    /** Keys longer than this are stored as "MDBX_SHA256_KEY:" || sha256. */
    size_t max_inline_key_len = 7500;
    /** Durable env sync right after creating the DBIs (Rust does this). */
    bool sync_after_open = true;
};

/** The Rust Chronik index env (indexes/chronik). */
MdbxEnvProfile ChronikIndexProfile();

/** Registers StoreBackend::Mdbx (with ChronikIndexProfile) in the registry. */
void RegisterMdbxStore();

std::unique_ptr<KvStore> OpenMdbxStore(const std::filesystem::path &dir,
                                       std::span<const TableSpec> tables,
                                       const StoreOptions &opts,
                                       const MdbxEnvProfile &profile);

/** Deletes the env files, like Rust Db::destroy (incl. RocksDB leftovers). */
void DestroyMdbxStore(const std::filesystem::path &dir);

/** Diagnostics of an open MDBX store (tests, dump tool). */
struct MdbxStoreInfo {
    uint64_t geo_lower{}, geo_upper{}, geo_current{}, geo_grow{}, geo_shrink{};
    uint32_t pagesize{};
    uint32_t env_flags{};
    uint32_t max_readers{};
    uint64_t sync_bytes{}, sync_period{};
    /** Per-table DBI flags (MDBX_DUPSORT etc.), in TableNames() order. */
    std::vector<uint32_t> dbi_flags;
};
/** Throws if store is not an MDBX store. */
MdbxStoreInfo GetMdbxStoreInfo(const KvStore &store);

/** Flag values (as in mdbx.h), for interpreting MdbxStoreInfo. */
namespace mdbx_flags {
inline constexpr uint32_t kSafeNoSync = 0x10000;
inline constexpr uint32_t kNoMetaSync = 0x40000;
inline constexpr uint32_t kNoStickyThreads = 0x200000;
inline constexpr uint32_t kNoMemInit = 0x1000000;
inline constexpr uint32_t kLifoReclaim = 0x4000000;
inline constexpr uint32_t kDupSort = 0x04;
inline constexpr uint32_t kDupFixed = 0x10;
} // namespace mdbx_flags

} // namespace chronik::native

#endif // CHRONIK_NATIVE_MDBX_STORE_H
