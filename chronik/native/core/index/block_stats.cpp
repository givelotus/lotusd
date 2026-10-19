// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/block_stats.h>

#include <chronik/native/codec/postcard.h>
#include <chronik/native/schema.h>

namespace chronik::native::index {

namespace {
// Script::is_opreturn
bool IsOpReturn(const Bytes &script) {
    return !script.empty() && script[0] == 0x6a;
}
} // namespace

Bytes SerializeBlockStats(const BlockStats &stats) {
    Bytes out;
    postcard::Writer w(out);
    w.U64(stats.block_size);
    w.U64(stats.num_txs);
    w.U64(stats.num_inputs);
    w.U64(stats.num_outputs);
    w.I64(stats.sum_input_sats);
    w.I64(stats.sum_coinbase_output_sats);
    w.I64(stats.sum_normal_output_sats);
    w.I64(stats.sum_burned_sats);
    return out;
}

BlockStats DeserializeBlockStats(ByteView bytes) {
    return postcard::DbDeserialize(
        bytes, kBlockStatsTypeName, [](postcard::Reader &r) {
            BlockStats stats;
            stats.block_size = r.U64();
            stats.num_txs = r.U64();
            stats.num_inputs = r.U64();
            stats.num_outputs = r.U64();
            stats.sum_input_sats = r.I64();
            stats.sum_coinbase_output_sats = r.I64();
            stats.sum_normal_output_sats = r.I64();
            stats.sum_burned_sats = r.I64();
            return stats;
        });
}

BlockStatsWriter::BlockStatsWriter(const KvStore &store)
    : m_cf(store.Table(schema::kBlkStats)) {}

void BlockStatsWriter::Insert(WriteTxn &txn, BlockHeight block_height,
                              uint64_t block_size,
                              std::span<const IndexTx> txs) const {
    uint64_t num_inputs = 0;
    uint64_t num_outputs = 0;
    int64_t sum_input_sats = 0;
    int64_t sum_normal_output_sats = 0;
    int64_t sum_coinbase_output_sats = 0;
    int64_t sum_burned_sats = 0;
    for (const IndexTx &tx : txs) {
        int64_t tx_output_sats = 0;
        for (const TxOutput &output : tx.tx->outputs) {
            if (IsOpReturn(output.script)) {
                sum_burned_sats += output.sats;
            }
            tx_output_sats += output.sats;
        }
        if (tx.is_coinbase) {
            sum_coinbase_output_sats += tx_output_sats;
        } else {
            sum_normal_output_sats += tx_output_sats;
            for (const TxInput &input : tx.tx->inputs) {
                if (input.coin) {
                    sum_input_sats += input.coin->output.sats;
                }
            }
        }
        num_inputs += tx.tx->inputs.size();
        num_outputs += tx.tx->outputs.size();
    }
    const BlockStats stats{
        block_size,
        uint64_t(txs.size()),
        num_inputs,
        num_outputs,
        sum_input_sats,
        sum_coinbase_output_sats,
        sum_normal_output_sats,
        sum_burned_sats,
    };
    txn.Put(m_cf, BhToBytes(block_height), SerializeBlockStats(stats));
}

void BlockStatsWriter::Delete(WriteTxn &txn, BlockHeight block_height) const {
    txn.Del(m_cf, BhToBytes(block_height));
}

BlockStatsReader::BlockStatsReader(const KvStore &store, const ReadTxn &txn)
    : m_txn(txn), m_cf(store.Table(schema::kBlkStats)) {}

std::optional<BlockStats>
BlockStatsReader::ByHeight(BlockHeight block_height) const {
    const std::optional<ByteView> bytes =
        m_txn.Get(m_cf, BhToBytes(block_height));
    if (!bytes) {
        return std::nullopt;
    }
    return DeserializeBlockStats(*bytes);
}

} // namespace chronik::native::index
