// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/metadata.h>
#include <chronik/native/schema.h>

namespace chronik::native {

namespace {

ByteView Key(std::string_view field) {
    return AsView(field);
}

std::optional<bool> ReadBool(const ReadTxn &txn, TableId meta,
                             std::string_view field) {
    const auto value = txn.Get(meta, Key(field));
    if (!value) {
        return std::nullopt;
    }
    return postcard::DbDeserialize(*value, "bool",
                                   [](postcard::Reader &r) { return r.Bool(); });
}

void WriteBool(WriteTxn &txn, TableId meta, std::string_view field, bool v) {
    Bytes out;
    postcard::Writer(out).Bool(v);
    txn.Put(meta, Key(field), out);
}

} // namespace

std::optional<SchemaVersion> MetadataReader::GetSchemaVersion() const {
    const auto value = m_txn.Get(m_meta, Key(meta_fields::kSchemaVersion));
    if (!value) {
        return std::nullopt;
    }
    return postcard::DbDeserialize(*value, "u64",
                                   [](postcard::Reader &r) { return r.U64(); });
}

bool MetadataReader::IsTokenIndexEnabled() const {
    // By default, the token index is enabled
    return ReadBool(m_txn, m_meta, meta_fields::kTokenIndexEnabled)
        .value_or(true);
}

std::optional<bool> MetadataReader::IsLokadIdIndexEnabled() const {
    return ReadBool(m_txn, m_meta, meta_fields::kLokadIdIndexEnabled);
}

std::optional<bool> MetadataReader::IsScripthashIndexEnabled() const {
    return ReadBool(m_txn, m_meta, meta_fields::kScripthashIndexEnabled);
}

std::optional<std::string> MetadataReader::NativeLastWriter() const {
    const auto value = m_txn.Get(m_meta, Key(meta_fields::kNativeLastWriter));
    if (!value) {
        return std::nullopt;
    }
    return postcard::DbDeserialize(
        *value, "alloc::string::String",
        [](postcard::Reader &r) { return r.Str(); });
}

void MetadataWriter::UpdateSchemaVersion(SchemaVersion version) {
    Bytes out;
    postcard::Writer(out).U64(version);
    m_txn.Put(m_meta, Key(meta_fields::kSchemaVersion), out);
}

void MetadataWriter::UpdateIsTokenIndexEnabled(bool enabled) {
    WriteBool(m_txn, m_meta, meta_fields::kTokenIndexEnabled, enabled);
}

void MetadataWriter::UpdateIsLokadIdIndexEnabled(bool enabled) {
    WriteBool(m_txn, m_meta, meta_fields::kLokadIdIndexEnabled, enabled);
}

void MetadataWriter::UpdateIsScripthashIndexEnabled(bool enabled) {
    WriteBool(m_txn, m_meta, meta_fields::kScripthashIndexEnabled, enabled);
}

void MetadataWriter::UpdateNativeLastWriter(std::string_view writer) {
    Bytes out;
    postcard::Writer(out).Str(writer);
    m_txn.Put(m_meta, Key(meta_fields::kNativeLastWriter), out);
}

void RefuseLegacyRocksDb(const std::filesystem::path &db_path) {
    std::error_code ec;
    if (!std::filesystem::exists(db_path, ec)) {
        return;
    }
    for (const auto &entry : std::filesystem::directory_iterator(db_path)) {
        const std::string name = entry.path().filename().string();
        auto starts = [&](std::string_view p) { return name.rfind(p, 0) == 0; };
        const bool is_sst =
            name.size() >= 4 && name.compare(name.size() - 4, 4, ".sst") == 0;
        if (name == "CURRENT" || name == "IDENTITY" || name == "rocksdb.bak" ||
            starts("MANIFEST-") || starts("OPTIONS-") || is_sst) {
            throw ChronikError(
                "Existing RocksDB index at " + db_path.string() +
                "; automatic MDBX migration is unsupported. Existing files "
                "were left untouched. Stop the node, move the entire reported "
                "Chronik index directory to a backup outside the datadir, and "
                "restart with -chronik=1 -chronikreindex=1 to rebuild from "
                "block files. Do not remove chainstate or blocks; retain "
                "unpruned block files or resync the chain if historical blocks "
                "are unavailable.");
        }
    }
}

bool IsStoreEmpty(const KvStore &store) {
    const auto txn = store.BeginRead();
    for (const std::string &name : store.TableNames()) {
        if (txn->EstimateEntries(store.Table(name)) > 0) {
            return false;
        }
    }
    return true;
}

void VerifySchemaVersion(KvStore &store, const MetaLogFn &log) {
    const TableId meta = store.Table(schema::kMeta);
    const bool is_empty = IsStoreEmpty(store);
    std::optional<SchemaVersion> schema_version;
    {
        const auto txn = store.BeginRead();
        try {
            schema_version = MetadataReader(*txn, meta).GetSchemaVersion();
        } catch (const ChronikError &) {
            // Rust: .wrap_err(CorruptedSchemaVersion)
            throw ChronikError(
                "Corrupted schema version in the Chronik database, consider "
                "running -reindex/-chronikreindex");
        }
    }
    const uint64_t current = schema::kCurrentIndexerVersion;
    if (schema_version) {
        if (is_empty) {
            throw ChronikError("Empty DB can't have a schema version");
        }
        if (*schema_version > current) {
            throw ChronikError(
                "Chronik outdated: Chronik has version " +
                std::to_string(current) + ", but the database has version " +
                std::to_string(*schema_version) +
                ". Upgrade your node to the appropriate version.");
        }
        if (*schema_version < current) {
            throw ChronikError(
                "DB outdated: Chronik has version " + std::to_string(current) +
                ", but the database has version " +
                std::to_string(*schema_version) +
                ". -reindex/-chronikreindex to reindex the database to the "
                "new version.");
        }
        log("Chronik has version " + std::to_string(current) +
            ", DB has version " + std::to_string(*schema_version) + "\n");
    } else {
        if (!is_empty) {
            throw ChronikError(
                "Missing schema version in non-empty Chronik database, "
                "consider running -reindex/-chronikreindex");
        }
        auto txn = store.BeginWrite();
        MetadataWriter(*txn, meta).UpdateSchemaVersion(current);
        txn->Commit();
        log("Chronik has version " + std::to_string(current) +
            ", initialized DB with that version\n");
    }
}

void VerifyEnableTokenIndex(KvStore &store, bool enable_token_index,
                            const MetaLogFn &log) {
    const TableId meta = store.Table(schema::kMeta);
    const bool is_empty = IsStoreEmpty(store);
    bool is_token_index_enabled;
    {
        const auto txn = store.BeginRead();
        is_token_index_enabled = MetadataReader(*txn, meta).IsTokenIndexEnabled();
    }
    auto txn = store.BeginWrite();
    if (!is_empty) {
        // Cannot enable token index if not already previously enabled
        if (enable_token_index && !is_token_index_enabled) {
            throw ChronikError(
                "Cannot enable -chroniktokenindex on a DB that previously had "
                "it disabled. Provide -reindex/-chronikreindex to reindex the "
                "database with token data, or specify -chroniktokenindex=0 to "
                "disable the token index again.");
        }
        // Wipe token index if previously enabled and now disabled
        if (!enable_token_index && is_token_index_enabled) {
            log("Warning: Wiping existing token index, since "
                "-chroniktokenindex=0\n");
            log("You will need to -reindex/-chronikreindex to restore\n");
            // TokenWriter::wipe
            txn->Clear(store.Table(schema::kTokenGenesisInfo));
            txn->Clear(store.Table(schema::kTokenMeta));
            txn->Clear(store.Table(schema::kTokenTx));
        }
    }
    MetadataWriter(*txn, meta).UpdateIsTokenIndexEnabled(enable_token_index);
    txn->Commit();
}

bool VerifyLokadIdIndex(KvStore &store, bool is_db_empty, bool enable,
                        const MetaLogFn &log) {
    const TableId meta = store.Table(schema::kMeta);
    bool is_enabled_db;
    {
        const auto txn = store.BeginRead();
        is_enabled_db =
            MetadataReader(*txn, meta).IsLokadIdIndexEnabled().value_or(false);
    }
    auto txn = store.BeginWrite();
    if (!is_db_empty) {
        if (enable && !is_enabled_db) {
            // DB non-empty without LOKAD ID index, but index enabled ->
            // reindex
            return true;
        }
        if (!enable && is_enabled_db) {
            log("Warning: Wiping existing LOKAD ID index, since "
                "-chroniklokadidindex=0\n");
            log("You will need to specify -chroniklokadidindex=1 to "
                "restore\n");
            // LokadIdHistoryWriter::wipe
            txn->Clear(store.Table(schema::kLokadIdHistory));
            txn->Clear(store.Table(schema::kLokadIdHistoryNumTxs));
        }
    }
    MetadataWriter(*txn, meta).UpdateIsLokadIdIndexEnabled(enable);
    txn->Commit();
    return false;
}

bool VerifyScripthashIndex(KvStore &store, bool is_db_empty, bool enable,
                           const MetaLogFn &log) {
    const TableId meta = store.Table(schema::kMeta);
    bool is_enabled_db;
    {
        const auto txn = store.BeginRead();
        is_enabled_db = MetadataReader(*txn, meta)
                            .IsScripthashIndexEnabled()
                            .value_or(false);
    }
    auto txn = store.BeginWrite();
    if (!is_db_empty) {
        if (enable && !is_enabled_db) {
            // DB non-empty without scripthash index, but index enabled ->
            // reindex
            return true;
        }
        if (!enable && is_enabled_db) {
            log("Warning: Wiping existing scripthash index, since "
                "-chronikscripthashindex=0\n");
            log("You will need to specify -chronikscripthashindex=1 to "
                "restore\n");
            // ScriptHistoryWriter::wipe_member_hash
            txn->Clear(store.Table(schema::kScripthash));
        }
    }
    MetadataWriter(*txn, meta).UpdateIsScripthashIndexEnabled(enable);
    txn->Commit();
    return false;
}

void RefuseIfPluginData(const KvStore &store) {
    const auto txn = store.BeginRead();
    if (txn->EstimateEntries(store.Table(schema::kPluginMeta)) > 0) {
        throw ChronikError(std::string(kPluginDataError));
    }
}

void WriteNativeLastWriter(KvStore &store, std::string_view writer) {
    auto txn = store.BeginWrite();
    MetadataWriter(*txn, store.Table(schema::kMeta))
        .UpdateNativeLastWriter(writer);
    txn->Commit();
}

PreparedDb PrepareDb(KvStore &store, const PrepareDbParams &params,
                     const MetaLogFn &log) {
    const bool is_db_empty = IsStoreEmpty(store);
    VerifySchemaVersion(store, log);
    RefuseIfPluginData(store);
    VerifyEnableTokenIndex(store, params.enable_token_index, log);
    PreparedDb prepared;
    prepared.needs_lokad_id_reindex = VerifyLokadIdIndex(
        store, is_db_empty, params.enable_lokad_id_index, log);
    prepared.needs_scripthash_reindex = VerifyScripthashIndex(
        store, is_db_empty, params.enable_scripthash_index, log);
    if (!params.native_last_writer.empty()) {
        WriteNativeLastWriter(store, params.native_last_writer);
    }
    return prepared;
}

} // namespace chronik::native
