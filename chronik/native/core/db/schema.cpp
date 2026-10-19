// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/error.h>
#include <chronik/native/schema.h>

#include <array>

namespace chronik::native::schema {

namespace {
using Kind = TableSpec::Kind;

constexpr TableSpec Plain(std::string_view name) {
    return TableSpec{name, Kind::Plain, std::nullopt};
}

// Order of Db::open: BlockWriter, BlockStatsWriter, MetadataWriter, TxWriter,
// ScriptHistoryWriter, ScriptUtxoWriter, SpentByWriter, TokenWriter,
// TokenIdHistoryWriter, TokenIdUtxoWriter, LokadIdHistoryWriter,
// PluginsWriter (each add_cfs).
const std::array<TableSpec, 26> kEcashTables = {{
    // BlockWriter
    Plain(kBlk),
    Plain(kLookupBlkByHash),
    // BlockStatsWriter
    Plain(kBlkStats),
    // MetadataWriter
    Plain(kMeta),
    // TxWriter
    Plain(kTx),
    Plain(kBlkByFirstTx),
    Plain(kFirstTxByBlk),
    Plain(kLookupTxByHash),
    // ScriptHistoryWriter
    Plain(kScriptHistory),
    Plain(kScriptHistoryNumTxs),
    Plain(kScripthash),
    // ScriptUtxoWriter (UtxoDataValue: DUPSORT | DUPFIXED)
    TableSpec{kScriptUtxo, Kind::Dup, kUtxoValueDupSize},
    // SpentByWriter
    Plain(kSpentBy),
    // TokenWriter
    Plain(kTokenGenesisInfo),
    Plain(kTokenMeta),
    Plain(kTokenTx),
    // TokenIdHistoryWriter
    Plain(kTokenIdHistory),
    Plain(kTokenIdHistoryNumTxs),
    // TokenIdUtxoWriter (UtxoDataOutput: DUPSORT only)
    TableSpec{kTokenIdUtxo, Kind::Dup, std::nullopt},
    // LokadIdHistoryWriter
    Plain(kLokadIdHistory),
    Plain(kLokadIdHistoryNumTxs),
    // PluginsWriter: opened like Rust so the env is identical; never written
    // by the native implementation.
    Plain(kPluginMeta),
    Plain(kPluginOutputs),
    TableSpec{kPluginGroupUtxos, Kind::Dup, std::nullopt},
    Plain(kPluginHistory),
    Plain(kPluginHistoryNumTxs),
}};
} // namespace

std::span<const TableSpec> EcashTables() {
    return kEcashTables;
}

Schema::Schema() : m_tables(kEcashTables.begin(), kEcashTables.end()) {}

void Schema::Add(TableSpec spec) {
    for (const TableSpec &t : m_tables) {
        if (t.name == spec.name) {
            throw ChronikError("Duplicate Chronik table " +
                               std::string(spec.name));
        }
    }
    m_tables.push_back(spec);
}

} // namespace chronik::native::schema
