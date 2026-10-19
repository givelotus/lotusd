// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token_io/batch.h>

#include <chronik/native/index/debug_fmt.h>

#include <algorithm>
#include <deque>

namespace chronik::native::token_io {

using namespace token;
using index::IndexTx;

BatchError BatchError::Cycle() {
    return BatchError("Cycle in SLP txs");
}

BatchError BatchError::MissingTokenTxNum(TxNum tx_num) {
    return BatchError(
        "Inconsistent BatchDbData: Missing TokenId for token tx num " +
        std::to_string(tx_num));
}

BatchError BatchError::MissingTxInputCoin(const OutPoint &outpoint) {
    return BatchError("Inconsistent Tx: Missing coin for TxInput " +
                      index::DebugOutPoint(outpoint));
}

// ---- TokenMetaBiMap ----

void TokenMetaBiMap::Insert(TxNum tx_num, const TokenMeta &meta) {
    if (const auto it = m_left.find(tx_num); it != m_left.end()) {
        m_right.erase(it->second);
        m_left.erase(it);
    }
    if (const auto it = m_right.find(meta); it != m_right.end()) {
        m_left.erase(it->second);
        m_right.erase(it);
    }
    m_left.emplace(tx_num, meta);
    m_right.emplace(meta, tx_num);
}

const TokenMeta *TokenMetaBiMap::GetByLeft(TxNum tx_num) const {
    const auto it = m_left.find(tx_num);
    return it == m_left.end() ? nullptr : &it->second;
}

const TxNum *TokenMetaBiMap::GetByRight(const TokenMeta &meta) const {
    const auto it = m_right.find(meta);
    return it == m_right.end() ? nullptr : &it->second;
}

// ---- helpers ----

namespace {

uint32_t MetaIdx(const TokenMeta &needle_meta,
                 const std::vector<TokenMeta> &metas) {
    const auto it = std::find(metas.begin(), metas.end(), needle_meta);
    if (it == metas.end()) {
        // Rust: .expect("TokenMeta should be in the list")
        throw ChronikError("TokenMeta should be in the list");
    }
    return uint32_t(it - metas.begin());
}

DbToken ToDbToken(const Token *token, const std::vector<TokenMeta> &metas) {
    if (!token) {
        return DbToken::NoToken();
    }
    switch (token->variant.kind) {
    case TokenVariant::Kind::Atoms:
        return DbToken::MakeAtoms(MetaIdx(token->meta, metas),
                                  token->variant.atoms_value);
    case TokenVariant::Kind::MintBaton:
        return DbToken::MintBaton(MetaIdx(token->meta, metas));
    case TokenVariant::Kind::Unknown:
        return token->meta.token_type.IsSlp()
                   ? DbToken::UnknownSlp(token->variant.unknown)
                   : DbToken::UnknownAlp(token->variant.unknown);
    }
    return DbToken::NoToken();
}

bool Contains(const std::vector<TokenMeta> &metas, const TokenMeta &meta) {
    return std::find(metas.begin(), metas.end(), meta) != metas.end();
}

} // namespace

// ---- BatchProcessor ----

BatchProcessor BatchProcessor::Prepare(std::span<const IndexTx> txs) {
    BatchProcessor processor;
    for (const IndexTx &tx : txs) {
        std::optional<ColoredTx> colored = ColoredTx::ColorTx(*tx.tx);
        if (colored && !colored->sections.empty()) {
            processor.prepared_txs.insert_or_assign(
                tx.tx_num, PreparedTx{&tx, std::move(*colored)});
        } else {
            processor.non_token_txs.push_back(&tx);
        }
    }
    // Coloring step ensures all GENESIS are at the first section
    processor.has_any_genesis = std::any_of(
        processor.prepared_txs.begin(), processor.prepared_txs.end(),
        [](const auto &entry) {
            return entry.second.colored.sections[0].tx_type == TxType::GENESIS;
        });
    return processor;
}

std::set<TokenMeta> BatchProcessor::CollectMintVaultMetas() const {
    std::set<TokenMeta> metas;
    for (const auto &[tx_num, tx] : prepared_txs) {
        if (tx.colored.sections[0].IsMintVaultMint()) {
            metas.insert(tx.colored.sections[0].meta);
        }
    }
    return metas;
}

ProcessedTokenTxBatch BatchProcessor::Verify(BatchDbData db_data) {
    // Build a DAG of tx nums so we can sort topologically (topo_sort crate:
    // dependencies outside the node set and self references are ignored,
    // duplicate dependencies count once).
    std::map<TxNum, std::set<TxNum>> deps;
    std::map<TxNum, std::vector<TxNum>> dependents;
    for (const auto &[tx_num, batch_tx] : prepared_txs) {
        auto &node_deps = deps[tx_num];
        for (const TxNum input_num : batch_tx.tx->input_nums) {
            if (input_num != tx_num && prepared_txs.count(input_num)) {
                node_deps.insert(input_num);
            }
        }
    }
    std::map<TxNum, size_t> num_edges;
    std::deque<TxNum> no_edges;
    for (const auto &[tx_num, node_deps] : deps) {
        num_edges[tx_num] = node_deps.size();
        for (const TxNum dep : node_deps) {
            dependents[dep].push_back(tx_num);
        }
        if (node_deps.empty()) {
            no_edges.push_back(tx_num);
        }
    }

    // Iterate txs in topological order
    ProcessedTokenTxBatch processed_batch;
    processed_batch.did_validation = true;
    size_t num_processed = 0;
    while (!no_edges.empty()) {
        const TxNum tx_num = no_edges.front();
        no_edges.pop_front();
        ++num_processed;
        for (const TxNum dependent : dependents[tx_num]) {
            if (--num_edges[dependent] == 0) {
                no_edges.push_back(dependent);
            }
        }
        auto node = prepared_txs.extract(tx_num);
        VerifyTokenTx(std::move(node.mapped()), db_data, processed_batch);
    }
    if (num_processed != deps.size()) {
        throw BatchError::Cycle();
    }

    // Non-token txs can still contain token inputs, add those to the index
    // too
    for (const IndexTx *non_token_tx : non_token_txs) {
        ProcessNonTokenTx(*non_token_tx, db_data, processed_batch);
    }

    return processed_batch;
}

void BatchProcessor::VerifyTokenTx(
    PreparedTx prepared_tx, BatchDbData &db_data,
    ProcessedTokenTxBatch &processed_batch) const {
    const TxNum tx_num = prepared_tx.tx->tx_num;
    std::vector<std::optional<SpentToken>> spent_tokens =
        TxTokenInputs(*prepared_tx.tx, db_data, processed_batch.valid_txs);

    const ColoredTxSection &first_section = prepared_tx.colored.sections[0];
    const bool is_genesis = first_section.genesis_info.has_value();
    const bool is_mint_vault_mint = first_section.IsMintVaultMint();

    // MINT txs on SLP V2 tokens need spent scripts and genesis data
    std::optional<std::vector<script::Script>> spent_scripts;
    const GenesisInfo *genesis_info = nullptr;
    if (is_mint_vault_mint) {
        spent_scripts = TxSpentScripts(*prepared_tx.tx);
        const auto it = db_data.genesis_infos.find(first_section.meta);
        if (it != db_data.genesis_infos.end()) {
            genesis_info = &it->second;
        }
    }

    VerifyContext context;
    context.spent_tokens = spent_tokens;
    context.spent_scripts = spent_scripts ? &*spent_scripts : nullptr;
    context.genesis_info = genesis_info;
    context.override_has_mint_vault = std::nullopt;
    TokenTx valid_tx = context.Verify(std::move(prepared_tx.colored));

    const bool has_any_inputs =
        std::any_of(spent_tokens.begin(), spent_tokens.end(),
                    [](const auto &input) { return input.has_value(); });
    const bool has_any_outputs =
        std::any_of(valid_tx.outputs.begin(), valid_tx.outputs.end(),
                    [](const auto &token) { return token.has_value(); });
    bool has_mint_vault = false;
    if (is_mint_vault_mint) {
        has_mint_vault =
            !valid_tx.entries.empty() && !valid_tx.entries.front().is_invalid;
    }

    // Don't store txs that have no actual token inputs or outputs or
    // GENESIS data or mint vault inputs.
    if (!has_any_outputs && !has_any_inputs && !is_genesis &&
        !has_mint_vault) {
        return;
    }

    // Add new tokens from GENESIS txs
    if (!valid_tx.entries.empty()) {
        const TokenTxEntry &entry = valid_tx.entries.front();
        // Skip invalid GENESIS txs
        if (!entry.is_invalid && entry.genesis_info) {
            db_data.token_metas.Insert(tx_num, entry.meta);
            processed_batch.new_tokens.emplace_back(tx_num, entry.meta,
                                                    *entry.genesis_info);
            // Note: Don't update db_data.genesis_info, because SLP V2
            // GENESIS txs require a confirmation before they take effect.
        }
    }

    std::vector<TxNum> token_tx_nums;
    std::vector<TokenMeta> token_metas;
    std::map<TokenMeta, TokenMeta> group_token_metas;
    for (const TokenTxEntry &entry : valid_tx.entries) {
        const TxNum *token_tx_num = db_data.token_metas.GetByRight(entry.meta);
        if (!token_tx_num) {
            continue;
        }
        if (!Contains(token_metas, entry.meta)) {
            token_tx_nums.push_back(*token_tx_num);
            token_metas.push_back(entry.meta);
        }
        if (entry.group_token_meta) {
            const TokenMeta &group_meta = *entry.group_token_meta;
            const TxNum *group_tx_num =
                db_data.token_metas.GetByRight(group_meta);
            if (group_tx_num && !Contains(token_metas, group_meta)) {
                token_tx_nums.push_back(*group_tx_num);
                token_metas.push_back(group_meta);
                group_token_metas.insert_or_assign(entry.meta, group_meta);
            }
        }
    }

    uint8_t flags = 0;
    if (has_mint_vault) {
        flags |= FLAGS_HAS_MINT_VAULT;
    }

    DbTokenTx db_token_tx;
    db_token_tx.token_tx_nums = std::move(token_tx_nums);
    for (const auto &[meta, group_meta] : group_token_metas) {
        db_token_tx.group_token_indices.insert_or_assign(
            MetaIdx(meta, token_metas), MetaIdx(group_meta, token_metas));
    }
    for (const auto &input : spent_tokens) {
        db_token_tx.inputs.push_back(
            ToDbToken(input ? &input->token : nullptr, token_metas));
    }
    for (const auto &output : valid_tx.outputs) {
        if (output) {
            const Token token = valid_tx.GetToken(*output);
            db_token_tx.outputs.push_back(ToDbToken(&token, token_metas));
        } else {
            db_token_tx.outputs.push_back(ToDbToken(nullptr, token_metas));
        }
    }
    db_token_tx.flags = flags;
    processed_batch.db_token_txs.insert_or_assign(tx_num,
                                                  std::move(db_token_tx));
    processed_batch.valid_txs.insert_or_assign(tx_num, std::move(valid_tx));
    processed_batch.spent_tokens.insert_or_assign(tx_num,
                                                  std::move(spent_tokens));
}

void BatchProcessor::ProcessNonTokenTx(
    const IndexTx &tx, BatchDbData &db_data,
    ProcessedTokenTxBatch &processed_batch) const {
    std::vector<TxNum> db_token_tx_nums;
    std::vector<DbToken> db_inputs;
    db_inputs.reserve(tx.input_nums.size());
    std::map<TokenIdx, TokenIdx> db_group_token_indices;
    const auto position_or_push = [&](TxNum needle) {
        const auto it = std::find(db_token_tx_nums.begin(),
                                  db_token_tx_nums.end(), needle);
        if (it != db_token_tx_nums.end()) {
            return size_t(it - db_token_tx_nums.begin());
        }
        db_token_tx_nums.push_back(needle);
        return db_token_tx_nums.size() - 1;
    };
    const size_t n = std::min(tx.input_nums.size(), tx.tx->inputs.size());
    for (size_t i = 0; i < n; ++i) {
        const TxNum input_tx_num = tx.input_nums[i];
        const size_t out_idx = tx.tx->inputs[i].prev_out.out_idx;
        const DbTokenTx *db_token_tx = nullptr;
        if (const auto it = processed_batch.db_token_txs.find(input_tx_num);
            it != processed_batch.db_token_txs.end()) {
            db_token_tx = &it->second;
        } else if (const auto it2 = db_data.token_txs.find(input_tx_num);
                   it2 != db_data.token_txs.end()) {
            db_token_tx = &it2->second;
        }
        if (!db_token_tx) {
            db_inputs.push_back(DbToken::NoToken());
            continue;
        }
        const DbToken &db_token = db_token_tx->outputs.at(out_idx);
        const std::optional<TxNum> token_tx_num =
            db_token_tx->TokenTxNum(db_token);
        if (!token_tx_num) {
            db_inputs.push_back(db_token);
            continue;
        }
        const size_t token_num_idx = position_or_push(*token_tx_num);
        if (const std::optional<TxNum> group_token_tx_num =
                db_token_tx->GroupTokenTxNum(db_token)) {
            const size_t group_token_num_idx =
                position_or_push(*group_token_tx_num);
            db_group_token_indices.insert_or_assign(
                uint32_t(token_num_idx), uint32_t(group_token_num_idx));
        }
        db_inputs.push_back(db_token.WithIdx(uint32_t(token_num_idx)));
    }

    // Skip non-token tx if we don't have any token inputs
    if (std::any_of(db_inputs.begin(), db_inputs.end(), [](const auto &in) {
            return !(in == DbToken::NoToken());
        })) {
        DbTokenTx db_token_tx;
        db_token_tx.token_tx_nums = std::move(db_token_tx_nums);
        db_token_tx.group_token_indices = std::move(db_group_token_indices);
        db_token_tx.inputs = std::move(db_inputs);
        db_token_tx.outputs.assign(tx.tx->outputs.size(), DbToken::NoToken());
        db_token_tx.flags = 0;
        processed_batch.db_token_txs.insert_or_assign(tx.tx_num,
                                                      std::move(db_token_tx));
        processed_batch.spent_tokens.insert_or_assign(
            tx.tx_num, TxTokenInputs(tx, db_data, processed_batch.valid_txs));
    }
}

std::vector<script::Script>
BatchProcessor::TxSpentScripts(const IndexTx &tx) {
    std::vector<script::Script> spent_scripts;
    spent_scripts.reserve(tx.tx->inputs.size());
    for (const TxInput &tx_input : tx.tx->inputs) {
        if (!tx_input.coin) {
            throw BatchError::MissingTxInputCoin(tx_input.prev_out);
        }
        spent_scripts.emplace_back(tx_input.coin->output.script);
    }
    return spent_scripts;
}

std::vector<std::optional<SpentToken>> BatchProcessor::TxTokenInputs(
    const IndexTx &tx, const BatchDbData &db_data,
    const std::map<TxNum, TokenTx> &valid_txs) const {
    if (tx.is_coinbase) {
        return std::vector<std::optional<SpentToken>>(tx.tx->inputs.size());
    }
    std::vector<std::optional<SpentToken>> inputs;
    const size_t n = std::min(tx.input_nums.size(), tx.tx->inputs.size());
    inputs.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        inputs.push_back(TokenOutput(tx.input_nums[i],
                                     tx.tx->inputs[i].prev_out.out_idx,
                                     db_data, valid_txs));
    }
    return inputs;
}

std::optional<SpentToken> BatchProcessor::TokenOutput(
    TxNum tx_num, size_t out_idx, const BatchDbData &db_data,
    const std::map<TxNum, TokenTx> &valid_txs) const {
    // Output is from this batch
    if (const auto it = valid_txs.find(tx_num); it != valid_txs.end()) {
        const TokenTx &token_tx = it->second;
        if (out_idx >= token_tx.outputs.size() || !token_tx.outputs[out_idx]) {
            return std::nullopt;
        }
        return token_tx.GetSpentToken(*token_tx.outputs[out_idx]);
    }

    // Output is from the DB
    const auto it = db_data.token_txs.find(tx_num);
    if (it == db_data.token_txs.end()) {
        return std::nullopt;
    }
    const DbTokenTx &db_token_tx = it->second;
    return db_token_tx.SpentToken(
        db_token_tx.outputs.at(out_idx), [&](TxNum meta_tx_num) {
            const TokenMeta *meta = db_data.token_metas.GetByLeft(meta_tx_num);
            if (!meta) {
                throw BatchError::MissingTokenTxNum(meta_tx_num);
            }
            return *meta;
        });
}

} // namespace chronik::native::token_io
