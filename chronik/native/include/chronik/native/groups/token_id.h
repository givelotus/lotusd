// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_GROUPS_TOKEN_ID_H
#define CHRONIK_NATIVE_GROUPS_TOKEN_ID_H

#include <chronik/native/extension.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>
#include <chronik/native/subs.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/token_io/batch.h>

#include <optional>
#include <span>

namespace chronik::native::mem {
class MempoolTokens;
} // namespace chronik::native::mem

/**
 * Port of chronik-db groups/token_id.rs: group txs by token ID.
 *
 * Member: the token ID's 32 bytes in internal (LE) order; SerMember: the
 * big-endian bytes (TokenId::to_be_bytes). Tables: token_id_history (page
 * size 1000), token_id_history_num_txs and token_id_utxo with the eCash-tier
 * "Output" dup encoding (12-byte outpoint || sats LE8 || raw script).
 */
namespace chronik::native::groups {

/**
 * Auxillary data for indexing by token ID (Rust `TokenIdGroupAux`): for each
 * txid, the token ID (if any) of each input and each output. It is both the
 * GroupAux of TokenIdGroup and the subscription hub's TokenIdSubsAux (pass
 * `&aux` as SubsAux::token_id).
 */
struct TokenIdGroupAux final : public GroupAux, public TokenIdSubsAux {
    /** Build aux data from a processed token batch (block connect). */
    static TokenIdGroupAux
    FromBatch(std::span<const index::IndexTx> txs,
              const token_io::ProcessedTokenTxBatch &batch);

    /**
     * Retrieve the aux data from the DB (block disconnect: call BEFORE
     * TokenWriter::Delete in the same txn; also for txs read from the DB).
     */
    static TokenIdGroupAux FromDb(std::span<const index::IndexTx> txs,
                                  const KvStore &store, const ReadTxn &txn);

    /** Retrieve the aux data from the mempool */
    static TokenIdGroupAux FromMempool(const Tx &tx,
                                       const mem::MempoolTokens &mempool);

    /** Build aux data from probed tx token info */
    static TokenIdGroupAux
    FromProbedTx(const TxId &txid, const token::TokenTx &token_tx,
                 std::span<const std::optional<token::SpentToken>>
                     spent_tokens);
};

/** Group txs by token ID. */
class TokenIdGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "TokenIdGroup"; }
    /** Token IDs of the inputs (none for coinbase), from TokenIdGroupAux. */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** Token IDs of the outputs, from TokenIdGroupAux. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    /** member.to_be_bytes() */
    Bytes SerMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override;
    std::optional<GroupUtxoConf> UtxoConf() const override;
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Output; }
};

} // namespace chronik::native::groups

#endif // CHRONIK_NATIVE_GROUPS_TOKEN_ID_H
