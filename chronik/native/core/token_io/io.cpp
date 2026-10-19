// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token_io/io.h>

#include <chronik/native/index/txs.h>
#include <chronik/native/schema.h>

#include <algorithm>
#include <map>

namespace chronik::native::token_io {

using index::IndexTx;
using index::TxNumToBytes;

TokenIndexError TokenIndexError::TokenTxNumNotFound(TxNum tx_num) {
    return TokenIndexError("Inconsistent DB: Token TxNum " +
                           std::to_string(tx_num) + " not found in DB");
}

namespace {

ByteView KeyView(const std::array<uint8_t, 8> &key) {
    return ByteView(key.data(), key.size());
}

std::vector<std::pair<TxNum, DbTokenTx>>
FetchTokenTxs(const ReadTxn &txn, TableId cf,
              const std::set<TxNum> &tx_nums) {
    std::vector<std::pair<TxNum, DbTokenTx>> result;
    for (const TxNum tx_num : tx_nums) {
        const auto key = TxNumToBytes(tx_num);
        if (const auto value = txn.Get(cf, KeyView(key))) {
            result.emplace_back(tx_num, DeserializeDbTokenTx(*value));
        }
    }
    return result;
}

std::vector<std::pair<TxNum, token::TokenMeta>>
FetchTokenMetas(const ReadTxn &txn, TableId cf,
                const std::set<TxNum> &token_tx_nums) {
    std::vector<std::pair<TxNum, token::TokenMeta>> result;
    for (const TxNum token_tx_num : token_tx_nums) {
        const auto key = TxNumToBytes(token_tx_num);
        const auto value = txn.Get(cf, KeyView(key));
        if (!value) {
            throw TokenIndexError::TokenTxNumNotFound(token_tx_num);
        }
        result.emplace_back(token_tx_num, DeserializeTokenMeta(*value));
    }
    return result;
}

std::optional<token::GenesisInfo> FetchGenesisInfo(const ReadTxn &txn,
                                                   TableId cf,
                                                   TxNum tx_num) {
    const auto key = TxNumToBytes(tx_num);
    const auto value = txn.Get(cf, KeyView(key));
    if (!value) {
        return std::nullopt;
    }
    return DeserializeGenesisInfo(*value);
}

bool HasAnyTokensIn(const ReadTxn &txn, TableId cf_token_meta) {
    auto cursor = txn.OpenCursor(cf_token_meta);
    return cursor->SeekFirst();
}

} // namespace

// ---- TokenWriter ----

TokenWriter::TokenWriter(const KvStore &store)
    : m_store(store), m_genesis_info(store.Table(schema::kTokenGenesisInfo)),
      m_token_meta(store.Table(schema::kTokenMeta)),
      m_token_tx(store.Table(schema::kTokenTx)) {}

ProcessedTokenTxBatch
TokenWriter::Insert(WriteTxn &txn, std::span<const IndexTx> txs) const {
    BatchProcessor batch_processor = BatchProcessor::Prepare(txs);
    if (!HasAnyTokensIn(txn, m_token_meta) &&
        !batch_processor.has_any_genesis) {
        // Short circuit: No tokens in the DB and no GENESIS in the batch
        return ProcessedTokenTxBatch{};
    }

    // Collect all input tx num into a sorted set. There may be duplicates,
    // so here we avoid querying the DB twice.
    std::set<TxNum> all_input_tx_nums;
    for (const IndexTx &tx : txs) {
        all_input_tx_nums.insert(tx.input_nums.begin(), tx.input_nums.end());
    }
    // Collect all input token txs. Note that we query this for *all* txs,
    // even those that don't look like token txs, so we can account for
    // burns.
    BatchDbData batch_db_data;
    for (auto &[tx_num, db_tx] :
         FetchTokenTxs(txn, m_token_tx, all_input_tx_nums)) {
        batch_db_data.token_txs.insert_or_assign(tx_num, std::move(db_tx));
    }

    // Collect all token metas used by the inputs
    std::set<TxNum> all_token_tx_nums;
    for (const auto &[tx_num, db_tx] : batch_db_data.token_txs) {
        all_token_tx_nums.insert(db_tx.token_tx_nums.begin(),
                                 db_tx.token_tx_nums.end());
    }

    // Collect GENESIS info for SLP V2 Mint Vault txs. The Rust reads the DB
    // without the pending batch, so txs of this batch (already in `txn`) must
    // not be found here.
    const std::optional<TxNum> first_batch_tx_num =
        txs.empty() ? std::nullopt : std::optional<TxNum>(txs.front().tx_num);
    const index::TxReader tx_reader(m_store, txn);
    for (const token::TokenMeta &meta :
         batch_processor.CollectMintVaultMetas()) {
        const std::optional<TxNum> tx_num =
            tx_reader.TxNumByTxid(meta.token_id.txid);
        if (!tx_num ||
            (first_batch_tx_num && *tx_num >= *first_batch_tx_num)) {
            continue;
        }
        if (auto info = FetchGenesisInfo(txn, m_genesis_info, *tx_num)) {
            batch_db_data.genesis_infos.insert_or_assign(meta,
                                                         std::move(*info));
        }
        // Also add their token_tx_nums to all_token_tx_nums to ensure their
        // metas are loaded.
        all_token_tx_nums.insert(*tx_num);
    }

    // Fetch token metas by tx_nums
    for (const auto &[tx_num, meta] :
         FetchTokenMetas(txn, m_token_meta, all_token_tx_nums)) {
        batch_db_data.token_metas.Insert(tx_num, meta);
    }

    // Verify tx batch
    ProcessedTokenTxBatch processed_batch =
        batch_processor.Verify(std::move(batch_db_data));

    // Insert token txs to DB
    for (const auto &[tx_num, db_token_tx] : processed_batch.db_token_txs) {
        const auto key = TxNumToBytes(tx_num);
        txn.Put(m_token_tx, KeyView(key), SerializeDbTokenTx(db_token_tx));
    }
    // Insert new tokens created in this batch to the DB
    for (const auto &[tx_num, token_meta, genesis_info] :
         processed_batch.new_tokens) {
        const auto key = TxNumToBytes(tx_num);
        txn.Put(m_token_meta, KeyView(key), SerializeTokenMeta(token_meta));
        txn.Put(m_genesis_info, KeyView(key),
                SerializeGenesisInfo(genesis_info));
    }

    return processed_batch;
}

void TokenWriter::Delete(WriteTxn &txn, std::span<const IndexTx> txs) const {
    for (const IndexTx &tx : txs) {
        const auto key = TxNumToBytes(tx.tx_num);
        txn.Del(m_token_tx, KeyView(key));
        txn.Del(m_token_meta, KeyView(key));
        txn.Del(m_genesis_info, KeyView(key));
    }
}

void TokenWriter::Wipe(WriteTxn &txn) const {
    // Rust: delete_range_cf(.., [], [0xff; 16]) over 8-byte keys
    txn.Clear(m_genesis_info);
    txn.Clear(m_token_meta);
    txn.Clear(m_token_tx);
}

// ---- TokenReader ----

TokenReader::TokenReader(const KvStore &store, const ReadTxn &txn)
    : m_txn(txn), m_genesis_info(store.Table(schema::kTokenGenesisInfo)),
      m_token_meta(store.Table(schema::kTokenMeta)),
      m_token_tx(store.Table(schema::kTokenTx)) {}

std::optional<token::TokenMeta>
TokenReader::TokenMeta(TxNum token_tx_num) const {
    const auto key = TxNumToBytes(token_tx_num);
    const auto value = m_txn.Get(m_token_meta, KeyView(key));
    if (!value) {
        return std::nullopt;
    }
    return DeserializeTokenMeta(*value);
}

std::vector<std::pair<TxNum, token::TokenMeta>>
TokenReader::TokenMetas(const std::set<TxNum> &token_tx_nums) const {
    return FetchTokenMetas(m_txn, m_token_meta, token_tx_nums);
}

std::optional<DbTokenTx> TokenReader::TokenTx(TxNum tx_num) const {
    const auto key = TxNumToBytes(tx_num);
    const auto value = m_txn.Get(m_token_tx, KeyView(key));
    if (!value) {
        return std::nullopt;
    }
    return DeserializeDbTokenTx(*value);
}

std::vector<std::pair<TxNum, DbTokenTx>>
TokenReader::TokenTxs(const std::set<TxNum> &tx_nums) const {
    return FetchTokenTxs(m_txn, m_token_tx, tx_nums);
}

std::optional<token::GenesisInfo>
TokenReader::GenesisInfo(TxNum tx_num) const {
    return FetchGenesisInfo(m_txn, m_genesis_info, tx_num);
}

bool TokenReader::HasAnyTokens() const {
    return HasAnyTokensIn(m_txn, m_token_meta);
}

std::optional<
    std::pair<std::vector<std::optional<token::SpentToken>>, DbTokenTx>>
TokenReader::SpentTokensAndDbTx(TxNum tx_num) const {
    std::optional<DbTokenTx> db_token_tx = TokenTx(tx_num);
    if (!db_token_tx) {
        return std::nullopt;
    }
    const std::set<TxNum> token_tx_nums(db_token_tx->token_tx_nums.begin(),
                                        db_token_tx->token_tx_nums.end());
    std::map<TxNum, token::TokenMeta> token_metas;
    for (auto &[num, meta] : TokenMetas(token_tx_nums)) {
        token_metas.insert_or_assign(num, meta);
    }
    std::vector<std::optional<token::SpentToken>> spent_inputs;
    spent_inputs.reserve(db_token_tx->inputs.size());
    for (const DbToken &input : db_token_tx->inputs) {
        spent_inputs.push_back(
            db_token_tx->SpentToken(input, [&](TxNum meta_tx_num) {
                const auto it = token_metas.find(meta_tx_num);
                if (it == token_metas.end()) {
                    throw TokenIndexError::TokenTxNumNotFound(meta_tx_num);
                }
                return it->second;
            }));
    }
    return std::make_pair(std::move(spent_inputs), std::move(*db_token_tx));
}

} // namespace chronik::native::token_io
