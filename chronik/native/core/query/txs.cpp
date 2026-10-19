// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/txs.rs (QueryTxs) and read_token_info of
// query/tx_token_data.rs.

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/token_io/io.h>
#include <chronik/native/tx/legacy_tx.h>

namespace chronik::native::query {

namespace {

[[noreturn]] void TxNotFound(const TxId &txid) {
    throw ChronikError("404: Transaction " + HashToHex(txid) +
                       " not found in the index");
}

[[noreturn]] void DbTxHasNoBlock(const TxId &txid) {
    throw ChronikError("500: Inconsistent DB: " + HashToHex(txid) +
                       " has no block");
}

RenderCtx MakeRenderCtx(const IndexerSnapshot &snap, const Host &host) {
    return RenderCtx{snap.Store(), snap.Txn(), host, snap.GetAvalanche(),
                     snap.Indexer().IsTokenIndexEnabled()};
}

} // namespace

proto::Tx TxById(IndexerSnapshot &snap, const Host &host, const TxId &txid) {
    const RenderCtx ctx = MakeRenderCtx(snap, host);
    if (std::optional<MempoolTxJob> job = MakeMempoolJob(snap, txid)) {
        snap.Unlock();
        return RenderTx(ctx, *job);
    }
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const auto tx_and_num = tx_reader.TxAndNumByTxid(txid);
    if (!tx_and_num) {
        TxNotFound(txid);
    }
    const auto &[tx_num, block_tx] = *tx_and_num;
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const std::optional<index::DbBlock> block =
        block_reader.ByHeight(block_tx.block_height);
    if (!block) {
        DbTxHasNoBlock(txid);
    }
    DbTxJob job;
    job.tx_num = tx_num;
    job.entry = block_tx.entry;
    job.block = *block;
    job.mempool_spent = CopyMempoolSpent(snap, txid);
    snap.Unlock();
    return RenderTx(ctx, job);
}

proto::RawTx RawTxById(IndexerSnapshot &snap, const Host &host,
                       const TxId &txid) {
    proto::RawTx result;
    if (const mem::MempoolTx *mempool_tx = snap.Mempool().GetTx(txid)) {
        const TxRef tx = mempool_tx->tx;
        snap.Unlock();
        result.set_raw_tx(BytesStr(tx->raw.empty() ? SerializeLegacyTx(*tx)
                                                   : tx->raw));
        return result;
    }
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const std::optional<index::BlockTx> block_tx = tx_reader.TxByTxid(txid);
    if (!block_tx) {
        TxNotFound(txid);
    }
    const std::optional<index::DbBlock> block =
        block_reader.ByHeight(block_tx->block_height);
    if (!block) {
        DbTxHasNoBlock(txid);
    }
    snap.Unlock();
    Bytes raw_tx;
    try {
        raw_tx = host.LoadRawTx(block->file_num, block_tx->entry.data_pos);
    } catch (const std::exception &) {
        throw ChronikError("500: Reading " + HashToHex(txid) + " failed");
    }
    result.set_raw_tx(BytesStr(raw_tx));
    return result;
}

proto::TokenInfo TokenInfoById(const IndexerSnapshot &snap,
                               const TxId &token_id_txid) {
    proto::TokenInfo result;
    const auto fill = [&](const token::TokenMeta &meta,
                          const token::GenesisInfo &genesis_info,
                          int64_t time_first_seen) {
        result.set_token_id(meta.token_id.ToString());
        *result.mutable_token_type() = MakeTokenTypeProto(meta.token_type);
        *result.mutable_genesis_info() = MakeGenesisInfoProto(genesis_info);
        result.set_time_first_seen(time_first_seen);
    };
    const mem::MempoolTokens *tokens = SnapshotMempoolTokens(snap);
    if (const token::GenesisInfo *genesis_info =
            tokens ? tokens->GenesisInfo(token_id_txid) : nullptr) {
        const token::TokenTx *token_tx = tokens->TokenTx(token_id_txid);
        if (!token_tx) {
            throw ChronikError(
                "500: Inconsistent DB: TxData for token " +
                HashToHex(token_id_txid) + " not in mempool");
        }
        const mem::MempoolTx *mempool_tx =
            snap.Mempool().GetTx(token_id_txid);
        if (!mempool_tx) {
            throw ChronikError(
                "500: Inconsistent DB: MempoolTx for token " +
                HashToHex(token_id_txid) + " not in mempool");
        }
        fill(token_tx->entries.at(0).meta, *genesis_info,
             mempool_tx->time_first_seen);
        return result;
    }
    const auto token_not_found = [&]() {
        throw ChronikError("404: Token " + HashToHex(token_id_txid) +
                           " not found in the index");
    };
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const token_io::TokenReader token_reader(snap.Store(), snap.Txn());
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const auto tx_and_num = tx_reader.TxAndNumByTxid(token_id_txid);
    if (!tx_and_num) {
        token_not_found();
    }
    const auto &[tx_num, block_tx] = *tx_and_num;
    const std::optional<index::DbBlock> block =
        block_reader.ByHeight(block_tx.block_height);
    if (!block) {
        throw ChronikError("500: Inconsistent DB: Missing block for height " +
                           std::to_string(block_tx.block_height));
    }
    const std::optional<token::GenesisInfo> genesis_info =
        token_reader.GenesisInfo(tx_num);
    if (!genesis_info) {
        token_not_found();
    }
    const std::optional<token::TokenMeta> meta = token_reader.TokenMeta(tx_num);
    if (!meta) {
        throw ChronikError("500: Inconsistent DB: Token num " +
                           std::to_string(tx_num) + " not found");
    }
    // Field order of prost (tag order): token_id, token_type, genesis_info,
    // block, time_first_seen; set_* order is irrelevant for libprotobuf.
    fill(*meta, *genesis_info, block_tx.entry.time_first_seen);
    proto::BlockMetadata *meta_block = result.mutable_block();
    meta_block->set_height(block_tx.block_height);
    meta_block->set_hash(HashStr(block->hash));
    meta_block->set_timestamp(block->timestamp);
    meta_block->set_is_final(
        snap.GetAvalanche().IsFinalHeight(block_tx.block_height));
    return result;
}

TxPagePlan PlanUnconfirmedTxs(const IndexerSnapshot &snap) {
    TxPagePlan plan;
    const mem::MempoolTokens *tokens = SnapshotMempoolTokens(snap);
    for (const auto &[txid, entry] : snap.Mempool().Txs()) {
        MempoolTxJob job;
        job.tx = entry.tx;
        job.time_first_seen = entry.time_first_seen;
        job.mempool_spent = CopyMempoolSpent(snap, txid);
        job.token = TxTokenData::FromMempool(tokens, *entry.tx);
        plan.jobs.emplace_back(std::move(job));
    }
    plan.sort_by_time_txid = true;
    plan.counts_from_txs = true;
    return plan;
}

} // namespace chronik::native::query
