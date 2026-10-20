// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/group_utxos.rs (QueryGroupUtxos).

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/mem/mempool.h>

#include <algorithm>
#include <type_traits>

namespace chronik::native::query {

namespace {

template <typename P>
void SetCommon(P &utxo, const OutPoint &outpoint, BlockHeight block_height,
               bool is_coinbase, int64_t sats, bool is_final,
               const std::optional<token::SpentToken> &token) {
    *utxo.mutable_outpoint() = MakeOutpointProto(outpoint);
    utxo.set_block_height(block_height);
    utxo.set_is_coinbase(is_coinbase);
    utxo.set_sats(sats);
    utxo.set_is_final(is_final);
    if (token) {
        *utxo.mutable_token() = MakeUtxoTokenProto(token->token);
    }
}

template <typename P> void FinishUtxosImpl(const Host &host, UtxoPlan<P> &plan) {
    for (const auto &[idx, txid] : plan.preconsensus) {
        if (IsFinalPreconsensus(host, txid)) {
            plan.utxos[idx].set_is_final(true);
        }
    }
    plan.preconsensus.clear();
}

} // namespace

void FinishUtxos(const Host &host, UtxoPlan<proto::ScriptUtxo> &plan) {
    FinishUtxosImpl(host, plan);
}
void FinishUtxos(const Host &host, UtxoPlan<proto::Utxo> &plan) {
    FinishUtxosImpl(host, plan);
}

script::Script
GroupUtxosQuery::Script(const GroupMemberArg &member,
                        const DecompressPubKeyFn &decompress_pubkey) const {
    const index::GroupHistoryReader history_reader(snap.Store(), snap.Txn(),
                                                   group);
    if (member.member) {
        return script::Script(*member.member);
    }
    if (!is_scripthash_index_enabled) {
        throw ChronikError("400: Script hash index disabled");
    }
    std::optional<Bytes> script_ser;
    if (auto mempool_script_ser =
            snap.Mempool().ScriptHistory().MemberSerByMemberHash(
                member.member_hash)) {
        script_ser = Bytes(mempool_script_ser->begin(), mempool_script_ser->end());
    } else {
        script_ser = history_reader.MemberSerByMemberHash(member.member_hash);
        if (!script_ser) {
            throw ChronikError(
                "404: Script hash " +
                RustDebugStr(HexEncode(ByteView(member.member_hash.data(),
                                                member.member_hash.size()))) +
                " not found");
        }
    }
    std::optional<Bytes> script = DecompressScript(*script_ser, decompress_pubkey);
    if (!script) {
        throw ChronikError("Failed decompressing script " +
                           HexEncode(*script_ser));
    }
    return script::Script(std::move(*script));
}

template <typename P>
UtxoPlan<P> GroupUtxosQuery::Utxos(ByteView member) const {
    constexpr bool kOutput = std::is_same_v<P, proto::Utxo>;
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const index::GroupUtxoReader utxo_reader(snap.Store(), snap.Txn(), group);
    const Bytes member_ser = group.SerMember(member);
    const Avalanche avalanche = snap.GetAvalanche();
    const mem::MempoolSpentBy &mempool_spent_by = snap.Mempool().SpentBy();

    // Read UTXO entries from DB and mempool
    const std::vector<index::UtxoEntry> db_utxos =
        utxo_reader.Utxos(member_ser).value_or(std::vector<index::UtxoEntry>{});
    std::vector<OutPoint> mempool_outpoints;
    if (mempool_utxos) {
        if (const auto *utxos = mempool_utxos->GetUtxos(member_ser)) {
            mempool_outpoints.assign(utxos->begin(), utxos->end());
            std::sort(mempool_outpoints.begin(), mempool_outpoints.end(),
                      OutPointLessBe);
        }
    }

    UtxoPlan<P> plan;
    plan.utxos.reserve(db_utxos.size() + mempool_outpoints.size());

    // Read + add DB UTXOs
    for (const index::UtxoEntry &db_utxo : db_utxos) {
        const TxNum tx_num = db_utxo.outpoint.tx_num;
        const uint32_t out_idx = db_utxo.outpoint.out_idx;

        // Read some tx DB data (without reading the full tx off disk)
        const std::optional<index::BlockTx> db_tx = tx_reader.TxByTxNum(tx_num);
        if (!db_tx) {
            throw ChronikError("500: Inconsistent DB: Transaction num " +
                               std::to_string(tx_num) + " not in DB");
        }
        const TxId &txid = db_tx->entry.txid;

        // Skip UTXOs that are spent in the mempool
        if (const auto *spent_entries = mempool_spent_by.OutputsSpent(txid)) {
            if (spent_entries->count(out_idx)) {
                continue;
            }
        }

        const bool is_final_height = avalanche.IsFinalHeight(db_tx->block_height);
        P utxo;
        utxo.set_is_legacy(db_tx->entry.is_legacy);
        SetCommon(utxo, OutPoint{txid, out_idx}, db_tx->block_height,
                  db_tx->entry.is_coinbase, db_utxo.sats, is_final_height,
                  ReadDbTokenOutput(snap.Store(), snap.Txn(), tx_num, out_idx,
                                    is_token_index_enabled));
        if constexpr (kOutput) {
            utxo.set_script(BytesStr(db_utxo.script));
        }
        if (!is_final_height) {
            plan.preconsensus.emplace_back(plan.utxos.size(), txid);
        }
        plan.utxos.push_back(std::move(utxo));
    }

    // Add mempool UTXOs
    const mem::MempoolTokens *tokens = SnapshotMempoolTokens(snap);
    for (const OutPoint &mempool_outpoint : mempool_outpoints) {
        const mem::MempoolTx *mempool_tx =
            snap.Mempool().GetTx(mempool_outpoint.txid);
        if (!mempool_tx) {
            throw ChronikError("500: Inconsistent mempool: Transaction " +
                               HashToHex(mempool_outpoint.txid) +
                               " not in mempool");
        }
        const TxId &txid = mempool_tx->tx->txid;
        const std::vector<TxOutput> &outputs = mempool_tx->tx->outputs;
        if (mempool_outpoint.out_idx >= outputs.size()) {
            throw ChronikError(
                "500: Inconsistent mempool: Transaction for " +
                index::DebugOutPoint(mempool_outpoint) +
                " exists in mempool, but the output doesn't");
        }
        const TxOutput &output = outputs[mempool_outpoint.out_idx];
        std::optional<token::SpentToken> token;
        if (tokens) {
            auto result = tokens->SpentToken(mempool_outpoint);
            if (!result.ok()) {
                throw ChronikError(result.error().ToString());
            }
            token = std::move(result.value());
        }
        P utxo;
        utxo.set_is_legacy(mempool_tx->tx->version != 7);
        SetCommon(utxo, mempool_outpoint, -1, false, output.sats, false, token);
        if constexpr (kOutput) {
            utxo.set_script(BytesStr(output.script));
        }
        plan.preconsensus.emplace_back(plan.utxos.size(), txid);
        plan.utxos.push_back(std::move(utxo));
    }
    return plan;
}

UtxoPlan<proto::ScriptUtxo> GroupUtxosQuery::ValueUtxos(ByteView member) const {
    return Utxos<proto::ScriptUtxo>(member);
}

UtxoPlan<proto::Utxo> GroupUtxosQuery::OutputUtxos(ByteView member) const {
    return Utxos<proto::Utxo>(member);
}

} // namespace chronik::native::query
