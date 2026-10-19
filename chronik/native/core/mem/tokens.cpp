// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/mem/tokens.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/token/color.h>
#include <chronik/native/token_io/io.h>

#include <algorithm>
#include <map>
#include <set>

namespace chronik::native::mem {

using namespace token;
using token_io::TxNum;

std::string MempoolTokensError::ToString() const {
    switch (kind) {
    case Kind::InputTxNotFound:
        return "Failed indexing mempool token tx: Tx is spending " +
               HashToHex(txid) + " which is found neither in the mempool nor DB";
    case Kind::InputTxNoSuchOutput:
        return "Failed indexing mempool token tx: Tx spends non-existent token "
               "output " +
               index::DebugOutPoint(outpoint);
    }
    return "";
}

// ---- MempoolTokenHook ----

void MempoolTokens::Insert(const KvStore &store, const MempoolTx &tx,
                           const IsMempoolTxFn &is_mempool_tx) {
    const auto txn = store.BeginRead();
    InsertTx(store, *txn, tx, is_mempool_tx);
}

std::shared_ptr<const GroupAux> MempoolTokens::AuxFromMempool(const Tx &tx) {
    return std::make_shared<groups::TokenIdGroupAux>(
        groups::TokenIdGroupAux::FromMempool(tx, *this));
}

void MempoolTokens::Remove(const TxId &txid) {
    m_token_txs.erase(txid);
    m_tx_token_inputs.erase(txid);
}

std::shared_ptr<const GroupAux>
MempoolTokens::Probe(const KvStore &store, const MempoolTx &tx,
                     const IsMempoolTxFn &is_mempool_tx) const {
    const auto txn = store.BeginRead();
    auto probed = ProbeTx(store, *txn, *tx.tx, is_mempool_tx);
    if (!probed) {
        return nullptr;
    }
    return std::make_shared<groups::TokenIdGroupAux>(
        groups::TokenIdGroupAux::FromProbedTx(tx.tx->txid, probed->first,
                                              probed->second));
}

// ---- MempoolTokens ----

std::optional<std::pair<token::TokenTx, SpentTokens>>
MempoolTokens::ProbeTx(const KvStore &store, const ReadTxn &txn, const Tx &tx,
                       const IsMempoolTxFn &is_mempool_tx) const {
    SpentTokensResult spent_result =
        FetchTxSpentTokens(store, txn, tx, is_mempool_tx);
    if (!spent_result.ok()) {
        throw MempoolTokensException(spent_result.error());
    }
    SpentTokens spent_tokens = std::move(spent_result.value());
    const bool has_any_tokens =
        std::any_of(spent_tokens.begin(), spent_tokens.end(),
                    [](const auto &token) { return token.has_value(); });

    std::optional<ColoredTx> colored = ColoredTx::ColorTx(tx);
    if (!colored && !has_any_tokens) {
        return std::nullopt;
    }
    if (!colored) {
        colored.emplace();
        colored->outputs.resize(tx.outputs.size());
    }

    // MINT txs on SLP V2 tokens need the output script and genesis data.
    // See the Rust comment on the accepted SLP V2 inconsistencies.
    std::optional<std::vector<script::Script>> spent_scripts;
    std::optional<token::GenesisInfo> genesis_info;
    if (!colored->sections.empty()) {
        const ColoredTxSection &first_section = colored->sections.front();
        if (first_section.IsMintVaultMint()) {
            spent_scripts.emplace();
            spent_scripts->reserve(tx.inputs.size());
            for (const TxInput &input : tx.inputs) {
                spent_scripts->emplace_back(
                    input.coin ? input.coin->output.script : Bytes{});
            }
            const index::TxReader tx_reader(store, txn);
            const token_io::TokenReader token_reader(store, txn);
            const std::optional<TxNum> tx_num =
                tx_reader.TxNumByTxid(first_section.meta.token_id.txid);
            if (tx_num) {
                if (auto db_genesis_info = token_reader.GenesisInfo(*tx_num)) {
                    genesis_info = std::move(*db_genesis_info);
                }
            }
        }
    }

    VerifyContext context;
    context.genesis_info = genesis_info ? &*genesis_info : nullptr;
    context.spent_tokens = spent_tokens;
    context.spent_scripts = spent_scripts ? &*spent_scripts : nullptr;
    context.override_has_mint_vault = std::nullopt;
    token::TokenTx verified = context.Verify(std::move(*colored));

    return std::make_pair(std::move(verified), std::move(spent_tokens));
}

void MempoolTokens::InsertTx(const KvStore &store, const ReadTxn &txn,
                             const MempoolTx &tx,
                             const IsMempoolTxFn &is_mempool_tx) {
    auto probed = ProbeTx(store, txn, *tx.tx, is_mempool_tx);
    if (!probed) {
        return;
    }
    auto &[verified, spent_tokens] = *probed;
    m_token_txs.insert_or_assign(tx.tx->txid, std::move(verified));
    if (std::any_of(spent_tokens.begin(), spent_tokens.end(),
                    [](const auto &token) { return token.has_value(); })) {
        m_tx_token_inputs.insert_or_assign(tx.tx->txid,
                                           std::move(spent_tokens));
    }
}

SpentTokensResult
MempoolTokens::FetchTxSpentTokens(const KvStore &store, const ReadTxn &txn,
                                  const Tx &tx,
                                  const IsMempoolTxFn &is_mempool_tx) const {
    return FetchTxSpentTokensBatch(store, txn, tx, is_mempool_tx, {});
}

SpentTokensResult MempoolTokens::FetchTxSpentTokensBatch(
    const KvStore &store, const ReadTxn &txn, const Tx &tx,
    const IsMempoolTxFn &is_mempool_tx, const BatchTokenTxs &batch_txs) const {
    const index::TxReader tx_reader(store, txn);
    const token_io::TokenReader token_reader(store, txn);

    // The spent tokens we've found, all default to None
    SpentTokens spent_tokens(tx.inputs.size());
    // TxNums for which we'll look up token data in the DB
    std::vector<std::optional<TxNum>> input_tx_nums(tx.inputs.size());
    for (size_t input_idx = 0; input_idx < tx.inputs.size(); ++input_idx) {
        const TxInput &input = tx.inputs[input_idx];
        const TxId &input_txid = input.prev_out.txid;
        const size_t out_idx = input.prev_out.out_idx;

        // If we find the prevout in the mempool, set the SpentToken
        if (const auto it = m_token_txs.find(input_txid);
            it != m_token_txs.end()) {
            const token::TokenTx &token_tx = it->second;
            if (out_idx >= token_tx.outputs.size()) {
                return Err(
                    MempoolTokensError::InputTxNoSuchOutput(input.prev_out));
            }
            const auto &output = token_tx.outputs[out_idx];
            spent_tokens[input_idx] =
                output ? std::optional<token::SpentToken>(
                             token_tx.GetSpentToken(*output))
                       : std::nullopt;
            continue;
        }

        // prevout is in the mempool (or batch) but not in our token_txs -
        // check batch_txs for chained broadcast
        if (is_mempool_tx(input_txid)) {
            if (const auto it = batch_txs.find(input_txid);
                it != batch_txs.end()) {
                const token::TokenTx &token_tx = it->second;
                if (out_idx >= token_tx.outputs.size()) {
                    return Err(MempoolTokensError::InputTxNoSuchOutput(
                        input.prev_out));
                }
                if (const auto &output = token_tx.outputs[out_idx]) {
                    spent_tokens[input_idx] = token_tx.GetSpentToken(*output);
                }
                // else: Output exists but is not a token output
            }
            continue;
        }

        // Otherwise, tx should be in the DB, query just its TxNum and store
        // it in input_tx_nums, so we know which ones to fill in later.
        const std::optional<TxNum> tx_num = tx_reader.TxNumByTxid(input_txid);
        if (!tx_num) {
            return Err(MempoolTokensError::InputTxNotFound(input_txid));
        }
        input_tx_nums[input_idx] = *tx_num;
    }

    // Batch-query the token data for DB inputs; only once per TxNum
    std::set<TxNum> query_tx_nums;
    for (const auto &tx_num : input_tx_nums) {
        if (tx_num) {
            query_tx_nums.insert(*tx_num);
        }
    }
    std::map<TxNum, token_io::DbTokenTx> token_txs;
    for (auto &[tx_num, db_tx] : token_reader.TokenTxs(query_tx_nums)) {
        token_txs.insert_or_assign(tx_num, std::move(db_tx));
    }

    // Collect all the token_tx_nums actually used in the inputs...
    std::set<TxNum> token_tx_nums;
    for (size_t input_idx = 0; input_idx < tx.inputs.size(); ++input_idx) {
        const TxInput &input = tx.inputs[input_idx];
        const size_t out_idx = input.prev_out.out_idx;
        const auto &input_tx_num = input_tx_nums[input_idx];
        if (!input_tx_num) {
            // We already found the input in the mempool previously
            continue;
        }
        const auto it = token_txs.find(*input_tx_num);
        if (it == token_txs.end()) {
            // Input tx not a token tx
            continue;
        }
        const token_io::DbTokenTx &token_tx = it->second;
        if (token_tx.outputs.size() <= out_idx) {
            return Err(MempoolTokensError::InputTxNoSuchOutput(input.prev_out));
        }
        const auto token_num_idx = token_tx.outputs[out_idx].TokenNumIdx();
        if (!token_num_idx) {
            // Ignore non-token or unknown outputs
            continue;
        }
        token_tx_nums.insert(token_tx.token_tx_nums.at(*token_num_idx));
        if (const auto group_it =
                token_tx.group_token_indices.find(*token_num_idx);
            group_it != token_tx.group_token_indices.end()) {
            token_tx_nums.insert(token_tx.token_tx_nums.at(group_it->second));
        }
    }

    // ...and batch-lookup their TokenMetas
    std::map<TxNum, token::TokenMeta> token_metas;
    for (const auto &[tx_num, meta] : token_reader.TokenMetas(token_tx_nums)) {
        token_metas.insert_or_assign(tx_num, meta);
    }

    // Now, we can fill in the found SpentTokens from the DB
    for (size_t input_idx = 0; input_idx < tx.inputs.size(); ++input_idx) {
        const size_t out_idx = tx.inputs[input_idx].prev_out.out_idx;
        const auto &input_tx_num = input_tx_nums[input_idx];
        if (!input_tx_num) {
            continue;
        }
        const auto it = token_txs.find(*input_tx_num);
        if (it == token_txs.end()) {
            continue;
        }
        const token_io::DbTokenTx &token_tx = it->second;
        // This will always succeed as `TokenMetas()` throws on missing
        // TokenMetas already.
        spent_tokens[input_idx] = token_tx.SpentToken(
            token_tx.outputs[out_idx],
            [&](TxNum tx_num) { return token_metas.at(tx_num); });
    }

    return spent_tokens;
}

const token::TokenTx *MempoolTokens::TokenTx(const TxId &txid) const {
    const auto it = m_token_txs.find(txid);
    return it == m_token_txs.end() ? nullptr : &it->second;
}

const SpentTokens *MempoolTokens::TxTokenInputs(const TxId &txid) const {
    const auto it = m_tx_token_inputs.find(txid);
    return it == m_tx_token_inputs.end() ? nullptr : &it->second;
}

Result<std::optional<token::SpentToken>, MempoolTokensError>
MempoolTokens::SpentToken(const OutPoint &outpoint) const {
    const size_t out_idx = outpoint.out_idx;
    const auto it = m_token_txs.find(outpoint.txid);
    if (it == m_token_txs.end()) {
        return std::optional<token::SpentToken>{};
    }
    const token::TokenTx &tx_tokens = it->second;
    if (out_idx >= tx_tokens.outputs.size()) {
        return Err(MempoolTokensError::InputTxNoSuchOutput(outpoint));
    }
    const auto &token_output = tx_tokens.outputs[out_idx];
    if (!token_output) {
        return std::optional<token::SpentToken>{};
    }
    return std::optional<token::SpentToken>(
        tx_tokens.GetSpentToken(*token_output));
}

const token::GenesisInfo *MempoolTokens::GenesisInfo(const TxId &txid) const {
    const auto it = m_token_txs.find(txid);
    if (it == m_token_txs.end() || it->second.entries.empty() ||
        !it->second.entries.front().genesis_info) {
        return nullptr;
    }
    return &*it->second.entries.front().genesis_info;
}

void MempoolTokens::Clear() {
    m_token_txs.clear();
    m_tx_token_inputs.clear();
}

} // namespace chronik::native::mem
