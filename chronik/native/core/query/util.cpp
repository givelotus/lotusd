// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/util.rs and query/tx_token_data.rs, plus the
// two-phase tx rendering shared by all queries returning txs.

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/token/color.h>
#include <chronik/native/token_io/io.h>

#include <algorithm>
#include <tuple>

namespace {
chronik::native::ByteView AsBytes(const std::string &s) {
    return chronik::native::ByteView(
        reinterpret_cast<const uint8_t *>(s.data()), s.size());
}
} // namespace

namespace chronik::native::query {

std::optional<Hash32> ParseHashBeHex(std::string_view hex) {
    std::optional<Bytes> bytes = HexDecode(hex);
    if (!bytes || bytes->size() != 32) {
        return std::nullopt;
    }
    return Hash32::FromReversed(*bytes);
}

namespace {

/** Rust `str::parse::<i32>` success check (any error => nullopt). */
std::optional<int32_t> ParseI32(std::string_view s) {
    if (s.empty()) {
        return std::nullopt;
    }
    size_t i = 0;
    bool neg = false;
    if (s[0] == '+' || s[0] == '-') {
        neg = s[0] == '-';
        i = 1;
        if (s.size() == 1) {
            return std::nullopt;
        }
    }
    int64_t value = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return std::nullopt;
        }
        value = value * 10 + (neg ? -(s[i] - '0') : (s[i] - '0'));
        if (value > INT32_MAX || value < INT32_MIN) {
            return std::nullopt;
        }
    }
    return int32_t(value);
}

} // namespace

HashOrHeight ParseHashOrHeight(std::string_view hash_or_height) {
    HashOrHeight result;
    if (std::optional<Hash32> hash = ParseHashBeHex(hash_or_height)) {
        result.is_hash = true;
        result.hash = *hash;
        return result;
    }
    const std::optional<int32_t> height = ParseI32(hash_or_height);
    // disallow leading zeros
    if (height && *height == 0 && hash_or_height.size() == 1) {
        result.height = 0;
    } else if (height && !hash_or_height.starts_with('0')) {
        result.height = *height;
    } else {
        throw ChronikError("400: Not a hash or height: " +
                           std::string(hash_or_height));
    }
    return result;
}

// ------------------------------------------------------------ OutputsSpent

OutputsSpent
OutputsSpent::NewMempool(std::optional<MempoolSpentEntries> mempool) {
    OutputsSpent result;
    result.m_mempool = std::move(mempool);
    return result;
}

OutputsSpent OutputsSpent::Query(const index::SpentByReader &spent_by_reader,
                                 const index::TxReader &tx_reader,
                                 std::optional<MempoolSpentEntries> mempool,
                                 TxNum tx_num) {
    OutputsSpent result;
    result.m_mempool = std::move(mempool);
    result.m_blocks = spent_by_reader.ByTxNum(tx_num).value_or(
        std::vector<index::SpentByEntry>{});
    for (const index::SpentByEntry &spent_by : result.m_blocks) {
        if (result.m_txid_by_num.count(spent_by.tx_num)) {
            continue;
        }
        const std::optional<TxId> txid =
            tx_reader.TxidByTxNum(spent_by.tx_num);
        if (!txid) {
            throw ChronikError(
                "500: Inconsistent DB: tx_num = " + std::to_string(tx_num) +
                " has spent entry " + index::DebugSpentByEntry(spent_by) +
                " in the DB, but the tx cannot be not found in the index");
        }
        result.m_txid_by_num.emplace(spent_by.tx_num, *txid);
    }
    return result;
}

std::optional<mem::SpentBy> OutputsSpent::SpentBy(uint32_t output_idx) const {
    if (m_mempool) {
        if (auto it = m_mempool->find(output_idx); it != m_mempool->end()) {
            return it->second;
        }
    }
    // binary_search_by_key on out_idx
    auto it = std::lower_bound(
        m_blocks.begin(), m_blocks.end(), output_idx,
        [](const index::SpentByEntry &entry, uint32_t idx) {
            return entry.out_idx < idx;
        });
    if (it == m_blocks.end() || it->out_idx != output_idx) {
        return std::nullopt;
    }
    return mem::SpentBy{m_txid_by_num.at(it->tx_num), it->input_idx};
}

std::optional<MempoolSpentEntries>
CopyMempoolSpent(const IndexerSnapshot &snap, const TxId &txid) {
    const MempoolSpentEntries *entries =
        snap.Mempool().SpentBy().OutputsSpent(txid);
    if (!entries) {
        return std::nullopt;
    }
    return *entries;
}

const mem::MempoolTokens *SnapshotMempoolTokens(const IndexerSnapshot &snap) {
    return mem::MempoolTokens::FromHook(snap.Mempool().Tokens());
}

// ------------------------------------------------------------ TxTokenData

namespace {

token::ColoredTx EmptyColoredTx(const Tx &tx) {
    token::ColoredTx colored;
    colored.outputs.assign(tx.outputs.size(), std::nullopt);
    return colored;
}

} // namespace

std::optional<TxTokenData>
TxTokenData::FromMempool(const mem::MempoolTokens *tokens, const Tx &tx) {
    if (!tokens) {
        return std::nullopt;
    }
    const token::TokenTx *token_tx = tokens->TokenTx(tx.txid);
    const mem::SpentTokens *token_inputs = tokens->TxTokenInputs(tx.txid);
    if (!token_tx && !token_inputs) {
        return std::nullopt;
    }
    TxTokenData data;
    if (token_inputs) {
        data.inputs = *token_inputs;
    } else {
        data.inputs.assign(tx.inputs.size(), std::nullopt);
    }
    if (token_tx) {
        data.tx = *token_tx;
    } else {
        token::VerifyContext context;
        context.genesis_info = nullptr;
        context.spent_tokens = *token_inputs;
        context.spent_scripts = nullptr;
        context.override_has_mint_vault = false;
        data.tx = context.Verify(EmptyColoredTx(tx));
    }
    return data;
}

std::optional<TxTokenData> TxTokenData::FromDb(const KvStore &store,
                                               const ReadTxn &txn,
                                               TxNum tx_num, const Tx &tx,
                                               bool is_token_index_enabled) {
    if (!is_token_index_enabled) {
        // User disabled token index, always return None
        return std::nullopt;
    }
    const token_io::TokenReader token_reader(store, txn);
    std::optional<token::ColoredTx> colored = token::ColoredTx::ColorTx(tx);
    std::vector<std::optional<token::SpentToken>> spent_tokens;
    token_io::DbTokenTx db_tx_data;
    if (auto db_data = token_reader.SpentTokensAndDbTx(tx_num)) {
        spent_tokens = std::move(db_data->first);
        db_tx_data = std::move(db_data->second);
    } else if (!colored) {
        return std::nullopt;
    }
    token::VerifyContext context;
    context.genesis_info = nullptr;
    context.spent_tokens = spent_tokens;
    context.spent_scripts = nullptr;
    context.override_has_mint_vault = db_tx_data.HasMintVault();
    TxTokenData data;
    data.tx = context.Verify(colored ? std::move(*colored) : EmptyColoredTx(tx));
    data.inputs = std::move(spent_tokens);
    return data;
}

std::optional<TxTokenData> TxTokenData::FromUnbroadcastTxBatch(
    const KvStore &store, const ReadTxn &txn, const mem::Mempool &mempool,
    const mem::MempoolTokens *tokens, const Tx &tx,
    const std::set<TxId> *batch_txids, const mem::BatchTokenTxs &batch_txs) {
    if (!tokens) {
        return std::nullopt;
    }
    std::optional<token::ColoredTx> colored = token::ColoredTx::ColorTx(tx);

    const index::TxReader tx_reader(store, txn);
    const token_io::TokenReader token_reader(store, txn);
    const auto is_mempool_tx = [&](const TxId &txid) {
        return mempool.GetTx(txid) != nullptr ||
               (batch_txids && batch_txids->count(txid) > 0);
    };
    mem::SpentTokensResult spent_tokens_result =
        tokens->FetchTxSpentTokensBatch(store, txn, tx, is_mempool_tx,
                                        batch_txs);
    if (!spent_tokens_result.ok()) {
        throw ChronikError("400: " + spent_tokens_result.error().ToString());
    }
    mem::SpentTokens spent_tokens = std::move(spent_tokens_result.value());

    token::ColoredTx colored_tx =
        colored ? std::move(*colored) : EmptyColoredTx(tx);
    std::optional<std::vector<script::Script>> spent_scripts;
    std::optional<token::GenesisInfo> genesis_info;
    if (!colored_tx.sections.empty()) {
        const token::ColoredTxSection &first_section =
            colored_tx.sections.front();
        if (first_section.IsMintVaultMint()) {
            spent_scripts.emplace();
            spent_scripts->reserve(tx.inputs.size());
            for (const TxInput &tx_input : tx.inputs) {
                if (!tx_input.coin) {
                    throw ChronikError("400: TxInput " +
                                       index::DebugOutPoint(tx_input.prev_out) +
                                       " has no coin");
                }
                spent_scripts->emplace_back(tx_input.coin->output.script);
            }
            const std::optional<TxNum> genesis_tx_num =
                tx_reader.TxNumByTxid(first_section.meta.token_id.txid);
            if (genesis_tx_num) {
                if (auto db_genesis_info =
                        token_reader.GenesisInfo(*genesis_tx_num)) {
                    genesis_info = std::move(*db_genesis_info);
                }
            }
        }
    }

    token::VerifyContext context;
    context.genesis_info = genesis_info ? &*genesis_info : nullptr;
    context.spent_tokens = spent_tokens;
    context.spent_scripts = spent_scripts ? &*spent_scripts : nullptr;
    context.override_has_mint_vault = std::nullopt;
    TxTokenData data;
    data.tx = context.Verify(std::move(colored_tx));
    data.inputs = std::move(spent_tokens);
    return data;
}

std::optional<proto::Token>
TxTokenData::InputTokenProto(size_t input_idx) const {
    if (input_idx >= inputs.size() || !inputs[input_idx]) {
        return std::nullopt;
    }
    const token::Token &token = inputs[input_idx]->token;
    int32_t entry_idx = -1;
    for (size_t i = 0; i < tx.entries.size(); ++i) {
        if (tx.entries[i].meta == token.meta) {
            entry_idx = int32_t(i);
            break;
        }
    }
    proto::Token result;
    result.set_token_id(token.meta.token_id.ToString());
    *result.mutable_token_type() = MakeTokenTypeProto(token.meta.token_type);
    result.set_entry_idx(entry_idx);
    result.set_atoms(token.variant.atoms());
    result.set_is_mint_baton(token.variant.IsMintBaton());
    return result;
}

std::optional<proto::Token>
TxTokenData::OutputTokenProto(size_t output_idx) const {
    if (output_idx >= tx.outputs.size() || !tx.outputs[output_idx]) {
        return std::nullopt;
    }
    const token::TokenOutput &token_output = *tx.outputs[output_idx];
    const token::Token token = tx.GetToken(token_output);
    proto::Token result;
    result.set_token_id(token.meta.token_id.ToString());
    *result.mutable_token_type() = MakeTokenTypeProto(token.meta.token_type);
    result.set_entry_idx(int32_t(token_output.token_idx));
    result.set_atoms(token.variant.atoms());
    result.set_is_mint_baton(token.variant.IsMintBaton());
    return result;
}

namespace {

proto::TokenTxType TokenTxTypeProto(const std::optional<token::TxType> &t) {
    if (!t) {
        return proto::NONE;
    }
    switch (*t) {
    case token::TxType::GENESIS:
        return proto::GENESIS;
    case token::TxType::MINT:
        return proto::MINT;
    case token::TxType::SEND:
        return proto::SEND;
    case token::TxType::UNKNOWN:
        return proto::UNKNOWN;
    case token::TxType::BURN:
        return proto::BURN;
    }
    return proto::NONE;
}

} // namespace

void TxTokenData::EntriesProto(
    google::protobuf::RepeatedPtrField<proto::TokenEntry> &out) const {
    for (const token::TokenTxEntry &entry : tx.entries) {
        proto::TokenEntry *p = out.Add();
        p->set_token_id(entry.meta.token_id.ToString());
        *p->mutable_token_type() = MakeTokenTypeProto(entry.meta.token_type);
        p->set_tx_type(TokenTxTypeProto(entry.tx_type));
        p->set_is_invalid(entry.is_invalid);
        p->set_group_token_id(entry.group_token_meta
                                  ? entry.group_token_meta->token_id.ToString()
                                  : std::string());
        p->set_burn_summary(entry.IsNormal() ? std::string()
                                             : entry.BurnSummary());
        for (const token::FailedColoring &failed : entry.failed_colorings) {
            proto::TokenFailedColoring *fc = p->add_failed_colorings();
            fc->set_pushdata_idx(int32_t(failed.pushdata_idx));
            fc->set_error(failed.error.ToString());
        }
        p->set_actual_burn_atoms(token::U128ToString(entry.actual_burn_atoms));
        p->set_intentional_burn_atoms(entry.intentional_burn_atoms.value_or(0));
        p->set_burns_mint_batons(entry.burns_mint_batons);
    }
}

std::optional<token::SpentToken>
ReadDbTokenOutput(const KvStore &store, const ReadTxn &txn, TxNum tx_num,
                  uint32_t out_idx, bool is_token_index_enabled) {
    if (!is_token_index_enabled) {
        return std::nullopt;
    }
    const token_io::TokenReader token_reader(store, txn);
    const std::optional<token_io::DbTokenTx> db_token_tx =
        token_reader.TokenTx(tx_num);
    if (!db_token_tx) {
        return std::nullopt;
    }
    return db_token_tx->SpentToken(
        db_token_tx->outputs.at(out_idx), [&](TxNum token_tx_num) {
            std::optional<token::TokenMeta> meta =
                token_reader.TokenMeta(token_tx_num);
            if (!meta) {
                throw ChronikError("500: Inconsistent DB: Token num " +
                                   std::to_string(token_tx_num) +
                                   " not found");
            }
            return *meta;
        });
}

proto::TokenType MakeTokenTypeProto(const token::TokenType &token_type) {
    proto::TokenType result;
    if (token_type.IsSlp()) {
        result.set_slp(static_cast<proto::SlpTokenType>(token_type.slp.ToU8()));
    } else {
        result.set_alp(static_cast<proto::AlpTokenType>(token_type.alp.ToU8()));
    }
    return result;
}

proto::GenesisInfo MakeGenesisInfoProto(const token::GenesisInfo &info) {
    proto::GenesisInfo result;
    result.set_token_ticker(BytesStr(info.token_ticker));
    result.set_token_name(BytesStr(info.token_name));
    result.set_url(BytesStr(info.url));
    if (info.hash) {
        result.set_hash(BytesStr(*info.hash));
    }
    if (info.mint_vault_scripthash) {
        result.set_mint_vault_scripthash(BytesStr(*info.mint_vault_scripthash));
    }
    if (info.data) {
        result.set_data(BytesStr(*info.data));
    }
    if (info.auth_pubkey) {
        result.set_auth_pubkey(BytesStr(*info.auth_pubkey));
    }
    result.set_decimals(info.decimals);
    return result;
}

proto::Token MakeUtxoTokenProto(const token::Token &token) {
    proto::Token result;
    result.set_token_id(token.meta.token_id.ToString());
    *result.mutable_token_type() = MakeTokenTypeProto(token.meta.token_type);
    result.set_entry_idx(-1);
    result.set_atoms(token.variant.atoms());
    result.set_is_mint_baton(token.variant.IsMintBaton());
    return result;
}

proto::OutPoint MakeOutpointProto(const OutPoint &outpoint) {
    proto::OutPoint result;
    result.set_txid(HashStr(outpoint.txid));
    result.set_out_idx(outpoint.out_idx);
    return result;
}

proto::Tx MakeTxProto(const MakeTxProtoParams &params) {
    const Tx &tx = params.tx;
    proto::Tx result;
    result.set_txid(HashStr(tx.txid));
    result.set_version(uint32_t(tx.version));
    for (size_t input_idx = 0; input_idx < tx.inputs.size(); ++input_idx) {
        const TxInput &input = tx.inputs[input_idx];
        proto::TxInput *p = result.add_inputs();
        *p->mutable_prev_out() = MakeOutpointProto(input.prev_out);
        p->set_input_script(BytesStr(input.script));
        if (input.coin) {
            p->set_output_script(BytesStr(input.coin->output.script));
            p->set_sats(input.coin->output.sats);
        }
        p->set_sequence_no(input.sequence);
        if (params.token) {
            if (auto token = params.token->InputTokenProto(input_idx)) {
                *p->mutable_token() = std::move(*token);
            }
        }
    }
    for (size_t output_idx = 0; output_idx < tx.outputs.size(); ++output_idx) {
        const TxOutput &output = tx.outputs[output_idx];
        proto::TxOutput *p = result.add_outputs();
        p->set_sats(output.sats);
        p->set_output_script(BytesStr(output.script));
        if (!output.state_root.empty()) {
            p->set_state_root(BytesStr(output.state_root));
        }
        if (auto spent_by = params.outputs_spent.SpentBy(uint32_t(output_idx))) {
            proto::SpentBy *sb = p->mutable_spent_by();
            sb->set_txid(HashStr(spent_by->txid));
            sb->set_input_idx(spent_by->input_idx);
        }
        if (params.token) {
            if (auto token = params.token->OutputTokenProto(output_idx)) {
                *p->mutable_token() = std::move(*token);
            }
        }
    }
    result.set_lock_time(tx.locktime);
    if (params.block) {
        proto::BlockMetadata *block = result.mutable_block();
        block->set_hash(HashStr(params.block->hash));
        block->set_height(params.block->height);
        block->set_timestamp(params.block->timestamp);
        block->set_is_final(
            params.avalanche.IsFinalHeight(params.block->height));
    }
    if (params.token) {
        params.token->EntriesProto(*result.mutable_token_entries());
        for (const token::FailedParsing &failed :
             params.token->tx.failed_parsings) {
            proto::TokenFailedParsing *fp = result.add_token_failed_parsings();
            fp->set_pushdata_idx(failed.pushdata_idx
                                     ? int32_t(*failed.pushdata_idx)
                                     : -1);
            fp->set_bytes(BytesStr(failed.bytes));
            fp->set_error(failed.error.ToString());
        }
        const bool all_normal = std::all_of(
            params.token->tx.entries.begin(), params.token->tx.entries.end(),
            [](const token::TokenTxEntry &entry) { return entry.IsNormal(); });
        result.set_token_status(params.token->tx.failed_parsings.empty() &&
                                        all_normal
                                    ? proto::TOKEN_STATUS_NORMAL
                                    : proto::TOKEN_STATUS_NOT_NORMAL);
    } else {
        result.set_token_status(proto::TOKEN_STATUS_NON_TOKEN);
    }
    result.set_time_first_seen(params.time_first_seen);
    result.set_size(tx.wire_size);
    result.set_is_coinbase(params.is_coinbase);
    result.set_is_final(
        params.is_final_preconsensus ||
        (params.block && params.avalanche.IsFinalHeight(params.block->height)));
    return result;
}

bool IsFinalPreconsensus(const Host &host, const TxId &txid) {
    return host.IsFinalizedPreConsensus(txid).value_or(false);
}

// -------------------------------------------------------- tx rendering ----

std::optional<MempoolTxJob> MakeMempoolJob(const IndexerSnapshot &snap,
                                           const TxId &txid) {
    const mem::MempoolTx *entry = snap.Mempool().GetTx(txid);
    if (!entry) {
        return std::nullopt;
    }
    MempoolTxJob job;
    job.tx = entry->tx;
    job.time_first_seen = entry->time_first_seen;
    job.mempool_spent = CopyMempoolSpent(snap, txid);
    job.token = TxTokenData::FromMempool(SnapshotMempoolTokens(snap), *entry->tx);
    return job;
}

proto::Tx RenderTx(const RenderCtx &ctx, const TxJob &job,
                   const RenderDbOpts &opts) {
    if (const auto *mjob = std::get_if<MempoolTxJob>(&job)) {
        const bool is_final_preconsensus =
            IsFinalPreconsensus(ctx.host, mjob->tx->txid);
        const OutputsSpent outputs_spent =
            OutputsSpent::NewMempool(mjob->mempool_spent);
        return MakeTxProto(MakeTxProtoParams{
            *mjob->tx, outputs_spent, mjob->time_first_seen, false, nullptr,
            ctx.avalanche, mjob->token ? &*mjob->token : nullptr,
            is_final_preconsensus});
    }
    const DbTxJob &djob = std::get<DbTxJob>(job);
    Tx tx;
    if (opts.wrap_read_failure) {
        try {
            tx = ctx.host.LoadTx(djob.block.file_num, djob.entry.data_pos,
                                 djob.entry.undo_pos);
        } catch (const std::exception &) {
            throw ChronikError("500: Reading " + HashToHex(djob.entry.txid) +
                               " failed");
        }
    } else {
        tx = ctx.host.LoadTx(djob.block.file_num, djob.entry.data_pos,
                             djob.entry.undo_pos);
    }
    OutputsSpent outputs_spent;
    if (opts.include_spent_by) {
        const index::SpentByReader spent_by_reader(ctx.store, ctx.txn);
        const index::TxReader tx_reader(ctx.store, ctx.txn);
        outputs_spent = OutputsSpent::Query(spent_by_reader, tx_reader,
                                            djob.mempool_spent, djob.tx_num);
    }
    const std::optional<TxTokenData> token = TxTokenData::FromDb(
        ctx.store, ctx.txn, djob.tx_num, tx, ctx.is_token_index_enabled);
    const bool is_final_preconsensus =
        IsFinalPreconsensus(ctx.host, djob.entry.txid);
    return MakeTxProto(MakeTxProtoParams{
        tx, outputs_spent, djob.entry.time_first_seen, djob.entry.is_coinbase,
        &djob.block, ctx.avalanche, token ? &*token : nullptr,
        is_final_preconsensus});
}

proto::TxHistoryPage RenderTxPage(const RenderCtx &ctx, TxPagePlan plan) {
    std::vector<proto::Tx> txs;
    txs.reserve(plan.jobs.size());
    for (const TxJob &job : plan.jobs) {
        txs.push_back(RenderTx(ctx, job, plan.db_opts));
    }
    if (plan.deferred) {
        std::rethrow_exception(plan.deferred);
    }
    if (plan.sort_db_from) {
        // We use stable sort, so the block order is retained when timestamps
        // are identical.
        const auto key = [](const proto::Tx &tx) {
            // Within blocks, sort txs without time_first_seen first
            if (tx.time_first_seen() == 0) {
                return std::make_pair(-int64_t(tx.block().height()),
                                      INT64_MIN);
            }
            // Otherwise, sort by time_first_seen within blocks
            return std::make_pair(-int64_t(tx.block().height()),
                                  -tx.time_first_seen());
        };
        std::stable_sort(txs.begin() + std::ptrdiff_t(*plan.sort_db_from),
                         txs.end(),
                         [&](const proto::Tx &a, const proto::Tx &b) {
                             return key(a) < key(b);
                         });
    }
    if (plan.sort_by_time_txid) {
        const auto txid_of = [](const proto::Tx &tx) {
            return Hash32::FromBytes(AsBytes(tx.txid()));
        };
        std::stable_sort(txs.begin(), txs.end(),
                         [&](const proto::Tx &a, const proto::Tx &b) {
                             return TimeTxidLessBe(
                                 {a.time_first_seen(), txid_of(a)},
                                 {b.time_first_seen(), txid_of(b)});
                         });
    }
    proto::TxHistoryPage page;
    if (plan.counts_from_txs) {
        page.set_num_pages(txs.empty() ? 0 : 1);
        page.set_num_txs(uint32_t(txs.size()));
    } else {
        page.set_num_pages(plan.num_pages);
        page.set_num_txs(plan.num_txs);
    }
    for (proto::Tx &tx : txs) {
        *page.add_txs() = std::move(tx);
    }
    return page;
}

} // namespace chronik::native::query
