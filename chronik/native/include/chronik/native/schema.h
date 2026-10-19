// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SCHEMA_H
#define CHRONIK_NATIVE_SCHEMA_H

#include <chronik/native/store.h>

#include <span>
#include <string_view>
#include <vector>

/**
 * The Chronik index tables (Rust column families) of the eCash tier, exactly
 * as chronik-db `Db::open` registers them (build/ecash-src
 * chronik/chronik-db/src/db.rs). Tier extensions (e.g. Lotus V2) append their
 * own tables to a Schema; the eCash-tier core never opens them.
 */
namespace chronik::native::schema {

inline constexpr uint64_t kCurrentIndexerVersion = 13;

inline constexpr std::string_view kBlk = "blk";
inline constexpr std::string_view kBlkByFirstTx = "blk_by_first_tx";
inline constexpr std::string_view kBlkStats = "blk_stats";
inline constexpr std::string_view kFirstTxByBlk = "first_tx_by_blk";
inline constexpr std::string_view kLokadIdHistory = "lokad_id_history";
inline constexpr std::string_view kLokadIdHistoryNumTxs =
    "lokad_id_history_num_txs";
inline constexpr std::string_view kLookupBlkByHash = "lookup_blk_by_hash";
inline constexpr std::string_view kLookupTxByHash = "lookup_tx_by_hash";
inline constexpr std::string_view kMeta = "meta";
inline constexpr std::string_view kPluginGroupUtxos = "plugin_utxos";
inline constexpr std::string_view kPluginHistory = "plugin_history";
inline constexpr std::string_view kPluginHistoryNumTxs =
    "plugin_history_num_txs";
inline constexpr std::string_view kPluginMeta = "plugin_meta";
inline constexpr std::string_view kPluginOutputs = "plugin_outputs";
inline constexpr std::string_view kScripthash = "scripthash";
inline constexpr std::string_view kScriptHistory = "script_history";
inline constexpr std::string_view kScriptHistoryNumTxs =
    "script_history_num_txs";
inline constexpr std::string_view kScriptUtxo = "script_utxo";
inline constexpr std::string_view kTokenIdHistory = "token_id_history";
inline constexpr std::string_view kTokenIdHistoryNumTxs =
    "token_id_history_num_txs";
inline constexpr std::string_view kTokenIdUtxo = "token_id_utxo";
inline constexpr std::string_view kSpentBy = "spent_by";
inline constexpr std::string_view kTokenGenesisInfo = "token_genesis_info";
inline constexpr std::string_view kTokenMeta = "token_meta";
inline constexpr std::string_view kTokenTx = "token_tx";
inline constexpr std::string_view kTx = "tx";

/** 12-byte big-endian (tx_num, out_idx) prefix of every UTXO dup value. */
inline constexpr uint32_t kUtxoOutpointSize = 12;
/**
 * Dup size of "value" UTXO groups (UtxoDataValue = sats): outpoint || sats
 * as little-endian i64. Those tables are MDBX_DUPSORT | MDBX_DUPFIXED.
 * "Output" groups (UtxoDataOutput) store outpoint || sats LE8 || raw script,
 * variable length, MDBX_DUPSORT only.
 */
inline constexpr uint32_t kUtxoValueDupSize = 20;

/** The 26 eCash-tier tables, in Rust registration order. */
std::span<const TableSpec> EcashTables();

/** A table set: the eCash-tier tables plus any tier-extension tables. */
class Schema {
public:
    /** Starts with EcashTables(). */
    Schema();
    /** Append an extension table; throws if the name is already present. */
    void Add(TableSpec spec);
    std::span<const TableSpec> Tables() const { return m_tables; }

private:
    std::vector<TableSpec> m_tables;
};

} // namespace chronik::native::schema

#endif // CHRONIK_NATIVE_SCHEMA_H
