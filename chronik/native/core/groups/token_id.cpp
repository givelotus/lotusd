// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/groups/token_id.h>

#include <chronik/native/mem/tokens.h>
#include <chronik/native/schema.h>
#include <chronik/native/token_io/io.h>

#include <map>
#include <set>

namespace chronik::native::groups {

using token::TokenId;
using MaybeTokenIds = TokenIdSubsAux::MaybeTokenIds;

namespace {

const TokenIdGroupAux *AsAux(const GroupAux *aux) {
    return dynamic_cast<const TokenIdGroupAux *>(aux);
}

void AppendMembers(const MaybeTokenIds &token_ids,
                   std::vector<MemberItem> &out) {
    for (size_t idx = 0; idx < token_ids.size(); ++idx) {
        if (const auto &token_id = token_ids[idx]) {
            const auto &b = token_id->txid.b;
            out.push_back(MemberItem{idx, Bytes(b.begin(), b.end())});
        }
    }
}

MaybeTokenIds SpentTokenIds(
    std::span<const std::optional<token::SpentToken>> spent_tokens) {
    MaybeTokenIds ids;
    ids.reserve(spent_tokens.size());
    for (const auto &token : spent_tokens) {
        ids.push_back(token ? std::optional<TokenId>(token->token.meta.token_id)
                            : std::nullopt);
    }
    return ids;
}

MaybeTokenIds OutputTokenIds(const token::TokenTx &token_tx) {
    MaybeTokenIds ids;
    ids.reserve(token_tx.outputs.size());
    for (const auto &output : token_tx.outputs) {
        ids.push_back(output ? std::optional<TokenId>(
                                   token_tx.GetToken(*output).meta.token_id)
                             : std::nullopt);
    }
    return ids;
}

} // namespace

// ---- TokenIdGroup ----

void TokenIdGroup::InputMembers(const GroupQuery &query, const GroupAux *aux,
                                std::vector<MemberItem> &out) const {
    if (query.is_coinbase) {
        return;
    }
    const TokenIdGroupAux *token_aux = AsAux(aux);
    if (!token_aux) {
        return;
    }
    const auto it = token_aux->txs.find(query.tx->txid);
    if (it == token_aux->txs.end()) {
        return;
    }
    AppendMembers(it->second.first, out);
}

void TokenIdGroup::OutputMembers(const GroupQuery &query, const GroupAux *aux,
                                 std::vector<MemberItem> &out) const {
    const TokenIdGroupAux *token_aux = AsAux(aux);
    if (!token_aux) {
        return;
    }
    const auto it = token_aux->txs.find(query.tx->txid);
    if (it == token_aux->txs.end()) {
        return;
    }
    AppendMembers(it->second.second, out);
}

Bytes TokenIdGroup::SerMember(ByteView member) const {
    const auto be = Hash32::FromBytes(member).Reversed();
    return Bytes(be.begin(), be.end());
}

std::optional<GroupHistoryConf> TokenIdGroup::TxHistoryConf() const {
    return GroupHistoryConf{schema::kTokenIdHistory,
                            schema::kTokenIdHistoryNumTxs, 1000,
                            std::nullopt};
}

std::optional<GroupUtxoConf> TokenIdGroup::UtxoConf() const {
    return GroupUtxoConf{schema::kTokenIdUtxo};
}

// ---- TokenIdGroupAux ----

TokenIdGroupAux
TokenIdGroupAux::FromBatch(std::span<const index::IndexTx> txs,
                           const token_io::ProcessedTokenTxBatch &batch) {
    TokenIdGroupAux aux;
    for (const index::IndexTx &tx : txs) {
        const auto spent_it = batch.spent_tokens.find(tx.tx_num);
        if (spent_it == batch.spent_tokens.end()) {
            continue;
        }
        const auto token_tx_it = batch.valid_txs.find(tx.tx_num);
        MaybeTokenIds outputs =
            token_tx_it != batch.valid_txs.end()
                ? OutputTokenIds(token_tx_it->second)
                : MaybeTokenIds(tx.tx->outputs.size());
        aux.txs.insert_or_assign(
            tx.tx->txid,
            std::make_pair(SpentTokenIds(spent_it->second), std::move(outputs)));
    }
    return aux;
}

TokenIdGroupAux TokenIdGroupAux::FromDb(std::span<const index::IndexTx> txs,
                                        const KvStore &store,
                                        const ReadTxn &txn) {
    const token_io::TokenReader token_reader(store, txn);
    std::set<token_io::TxNum> tx_nums;
    for (const index::IndexTx &tx : txs) {
        tx_nums.insert(tx.tx_num);
    }
    std::map<token_io::TxNum, token_io::DbTokenTx> db_token_txs;
    for (auto &[tx_num, db_tx] : token_reader.TokenTxs(tx_nums)) {
        db_token_txs.insert_or_assign(tx_num, std::move(db_tx));
    }
    std::set<token_io::TxNum> token_tx_nums;
    for (const auto &[tx_num, token_tx] : db_token_txs) {
        token_tx_nums.insert(token_tx.token_tx_nums.begin(),
                             token_tx.token_tx_nums.end());
    }
    std::map<token_io::TxNum, token::TokenMeta> token_metas;
    for (const auto &[tx_num, meta] : token_reader.TokenMetas(token_tx_nums)) {
        token_metas.insert_or_assign(tx_num, meta);
    }
    TokenIdGroupAux aux;
    for (const index::IndexTx &tx : txs) {
        const auto it = db_token_txs.find(tx.tx_num);
        if (it == db_token_txs.end()) {
            continue;
        }
        const token_io::DbTokenTx &db_token_tx = it->second;
        const auto db_token_id =
            [&](const token_io::DbToken &db_token) -> std::optional<TokenId> {
            const auto token_tx_num = db_token_tx.TokenTxNum(db_token);
            if (!token_tx_num) {
                return std::nullopt;
            }
            const auto meta_it = token_metas.find(*token_tx_num);
            if (meta_it == token_metas.end()) {
                return std::nullopt;
            }
            return meta_it->second.token_id;
        };
        MaybeTokenIds input_token_ids;
        for (const auto &input : db_token_tx.inputs) {
            input_token_ids.push_back(db_token_id(input));
        }
        MaybeTokenIds output_token_ids;
        for (const auto &output : db_token_tx.outputs) {
            output_token_ids.push_back(db_token_id(output));
        }
        aux.txs.insert_or_assign(tx.tx->txid,
                                 std::make_pair(std::move(input_token_ids),
                                                std::move(output_token_ids)));
    }
    return aux;
}

TokenIdGroupAux
TokenIdGroupAux::FromMempool(const Tx &tx, const mem::MempoolTokens &mempool) {
    const token::TokenTx *token_tx = mempool.TokenTx(tx.txid);
    if (!token_tx) {
        return TokenIdGroupAux{};
    }
    MaybeTokenIds output_token_ids = OutputTokenIds(*token_tx);
    const mem::SpentTokens *spent_tokens = mempool.TxTokenInputs(tx.txid);
    MaybeTokenIds input_token_ids = spent_tokens
                                        ? SpentTokenIds(*spent_tokens)
                                        : MaybeTokenIds(tx.inputs.size());
    TokenIdGroupAux aux;
    aux.txs.insert_or_assign(tx.txid,
                             std::make_pair(std::move(input_token_ids),
                                            std::move(output_token_ids)));
    return aux;
}

TokenIdGroupAux TokenIdGroupAux::FromProbedTx(
    const TxId &txid, const token::TokenTx &token_tx,
    std::span<const std::optional<token::SpentToken>> spent_tokens) {
    TokenIdGroupAux aux;
    aux.txs.insert_or_assign(txid, std::make_pair(SpentTokenIds(spent_tokens),
                                                  OutputTokenIds(token_tx)));
    return aux;
}

} // namespace chronik::native::groups
