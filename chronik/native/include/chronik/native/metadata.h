// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_METADATA_H
#define CHRONIK_NATIVE_METADATA_H

#include <chronik/native/store.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

/**
 * The `meta` table and the open-time schema/flag checks: a port of
 * chronik-db io/metadata.rs and of the verify_* functions of
 * chronik-indexer/src/indexer.rs (eCash tier). Error and log texts are the
 * Rust ones.
 */
namespace chronik::native {

using SchemaVersion = uint64_t;

namespace meta_fields {
inline constexpr std::string_view kSchemaVersion = "SCHEMA_VERSION";
inline constexpr std::string_view kTokenIndexEnabled = "TOKEN_INDEX_ENABLED";
inline constexpr std::string_view kLokadIdIndexEnabled =
    "LOKAD_ID_INDEX_ENABLED";
inline constexpr std::string_view kScripthashIndexEnabled =
    "SCRIPTHASH_INDEX_ENABLED";
/**
 * Native-only diagnostic: postcard String "native/<version>", written on
 * every open. The Rust implementation never reads it.
 */
inline constexpr std::string_view kNativeLastWriter = "NATIVE_LAST_WRITER";
} // namespace meta_fields

class MetadataReader {
public:
    MetadataReader(const ReadTxn &txn, TableId meta) : m_txn(txn), m_meta(meta) {}
    std::optional<SchemaVersion> GetSchemaVersion() const;
    /** Defaults to true when unset, like Rust. */
    bool IsTokenIndexEnabled() const;
    std::optional<bool> IsLokadIdIndexEnabled() const;
    std::optional<bool> IsScripthashIndexEnabled() const;
    std::optional<std::string> NativeLastWriter() const;

private:
    const ReadTxn &m_txn;
    TableId m_meta;
};

class MetadataWriter {
public:
    MetadataWriter(WriteTxn &txn, TableId meta) : m_txn(txn), m_meta(meta) {}
    void UpdateSchemaVersion(SchemaVersion version);
    void UpdateIsTokenIndexEnabled(bool enabled);
    void UpdateIsLokadIdIndexEnabled(bool enabled);
    void UpdateIsScripthashIndexEnabled(bool enabled);
    void UpdateNativeLastWriter(std::string_view writer);

private:
    WriteTxn &m_txn;
    TableId m_meta;
};

/** Log sink (Rust `log!`, i.e. always logged). */
using MetaLogFn = std::function<void(const std::string &)>;

/**
 * Refuse to open a directory holding a legacy RocksDB index (Rust
 * Db::open_with_cfs): CURRENT, IDENTITY, rocksdb.bak, MANIFEST-*, OPTIONS-*,
 * *.sst. Throws the Rust LegacyRocksDb error text. Call before OpenStore.
 */
void RefuseLegacyRocksDb(const std::filesystem::path &db_path);

/** Rust Db::is_db_empty: no table has any entry. */
bool IsStoreEmpty(const KvStore &store);

/** Rust verify_schema_version. */
void VerifySchemaVersion(KvStore &store, const MetaLogFn &log);
/** Rust verify_enable_token_index. */
void VerifyEnableTokenIndex(KvStore &store, bool enable_token_index,
                            const MetaLogFn &log);
/** Rust verify_lokad_id_index; returns whether a reindex is needed. */
bool VerifyLokadIdIndex(KvStore &store, bool is_db_empty, bool enable,
                        const MetaLogFn &log);
/** Rust verify_scripthash_index; returns whether a reindex is needed. */
bool VerifyScripthashIndex(KvStore &store, bool is_db_empty, bool enable,
                           const MetaLogFn &log);

/**
 * The native implementation has no plugin support: a DB indexed by the Rust
 * Chronik with plugins (non-empty plugin_meta) is refused instead of letting
 * the plugin tables silently desynchronize.
 */
inline constexpr std::string_view kPluginDataError =
    "Chronik database was built with Chronik plugins, which the native Chronik "
    "implementation does not support; reindex with -chronikreindex or use the "
    "Rust build";
void RefuseIfPluginData(const KvStore &store);

void WriteNativeLastWriter(KvStore &store, std::string_view writer);

struct PrepareDbParams {
    bool enable_token_index = true;
    bool enable_lokad_id_index = true;
    bool enable_scripthash_index = false;
    /** e.g. "native/v0.34.1"; empty: not written */
    std::string native_last_writer;
};
struct PreparedDb {
    bool needs_lokad_id_reindex = false;
    bool needs_scripthash_reindex = false;
};

/**
 * Rust ChronikIndexer::prepare_db after Db::open: is_db_empty, verify the
 * schema version, refuse plugin data (before any flag is rewritten), verify
 * the token, LOKAD ID and scripthash indexes, and finally record
 * NATIVE_LAST_WRITER.
 */
PreparedDb PrepareDb(KvStore &store, const PrepareDbParams &params,
                     const MetaLogFn &log);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_METADATA_H
