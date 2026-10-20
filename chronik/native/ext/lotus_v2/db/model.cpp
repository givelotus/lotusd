// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/db/model.h>

#include <stdexcept>

namespace chronik::native::lotus_v2 {

void WireRange::Validate(uint64_t wire_size) const {
    if (offset > UINT64_MAX - length || offset + length > wire_size) {
        ThrowInvalid("explorer wire range");
    }
}

StoredInputMeta InputFact::Metadata() const {
    if (witnesses.size() > UINT32_MAX) {
        ThrowInvalid("witness count");
    }
    return StoredInputMeta{prev_txid,
                           prev_index,
                           sequence,
                           flags,
                           path_index,
                           has_coinbase_data,
                           coinbase_data,
                           uint32_t(witnesses.size())};
}

void MemTxSource::Record(const CommittedBlock &block) {
    std::lock_guard lock(m_mutex);
    for (const ConfirmedTx &tx : block.transactions) {
        m_txs.insert_or_assign(tx.location.txid,
                               std::make_pair(tx.pos, NodeTx::From(tx)));
    }
}

bool MemTxSource::Modify(const TxId &txid,
                         const std::function<void(NodeTx &)> &f) {
    std::lock_guard lock(m_mutex);
    auto it = m_txs.find(txid);
    if (it == m_txs.end()) {
        return false;
    }
    f(it->second.second);
    return true;
}

NodeTx MemTxSource::LoadTx(const TxPos &pos, const TxId &txid, bool) const {
    std::lock_guard lock(m_mutex);
    auto it = m_txs.find(txid);
    if (it == m_txs.end()) {
        throw std::runtime_error("unknown transaction");
    }
    if (it->second.first != pos) {
        throw std::runtime_error("transaction position mismatch");
    }
    return it->second.second;
}

namespace codec {

void Write(Writer &w, const Output &v) {
    auto bytes = v.Encode();
    if (!bytes) {
        ThrowCorrupt();
    }
    w.ByteVec(*bytes);
}
void Write(Writer &w, const OutPoint &v) {
    Write(w, v.txid.hash);
    w.U32(v.out_idx);
}
void Write(Writer &w, const TxLocation &v) {
    Write(w, v.block_id);
    w.U64(v.height);
    w.U32(v.tx_index);
    Write(w, v.txid.hash);
    Write(w, v.txhash.hash);
}
void Write(Writer &w, const Binding &v) {
    Write(w, v.chain_id);
    Write(w, v.genesis);
    Write(w, v.profile);
}
void Write(Writer &w, const Anchor &v) {
    Write(w, v.block_id);
    w.U64(v.height);
}
void Write(Writer &w, const WireRange &v) {
    w.U64(v.offset);
    w.U64(v.length);
}
void Write(Writer &w, const WitnessFact &v) {
    Write(w, v.script);
    Write(w, v.siblings_table);
    w.U32(v.siblings_count);
    Write(w, v.arguments_table);
    w.U32(v.arguments_count);
}
void Write(Writer &w, const ResolvedCreation &v) {
    Write(w, v.outpoint);
    Write(w, v.output);
    Write(w, v.creation);
}
void Write(Writer &w, const InputFact &v) {
    Write(w, v.prev_txid);
    w.U32(v.prev_index);
    w.U32(v.sequence);
    w.U8(v.flags);
    w.U8(v.path_index);
    w.Bool(v.has_coinbase_data);
    Write(w, v.coinbase_data);
    Write(w, v.witnesses);
}
void Write(Writer &w, const ExplorerTxFacts &v) {
    w.ByteVec(v.wire);
    w.U64(v.lock);
    Write(w, v.inputs);
}
void Write(Writer &w, const ExplorerBlockFacts &v) {
    // native_serde::header uses serialize_bytes: length then bytes.
    w.ByteVec(v.header_wire);
}
void Write(Writer &w, const TxMeta &v) {
    Write(w, v.location);
    w.U64(v.lock);
    w.U32(v.input_count);
    w.U32(v.output_count);
    w.U32(v.file_num);
    w.U32(v.data_pos);
    w.U64(v.wire_size);
    w.U64(v.wire_checksum);
}
void Write(Writer &w, const BlockMeta &v) {
    Write(w, v.anchor);
    w.ByteVec(v.header_wire);
    w.U32(v.tx_count);
}
void Write(Writer &w, const InputMeta &v) {
    Write(w, v.prev_txid);
    w.U32(v.prev_index);
    w.U32(v.sequence);
    w.U8(v.flags);
    w.U8(v.path_index);
    w.Bool(v.has_coinbase_data);
    Write(w, v.coinbase_data);
    w.U32(v.witness_count);
    Write(w, v.resolved_creation);
}
void Write(Writer &w, const StoredInputMeta &v) {
    Write(w, v.prev_txid);
    w.U32(v.prev_index);
    w.U32(v.sequence);
    w.U8(v.flags);
    w.U8(v.path_index);
    w.Bool(v.has_coinbase_data);
    Write(w, v.coinbase_data);
    w.U32(v.witness_count);
}
void Write(Writer &w, const AssetEvent &v) {
    Write(w, v.token_id);
    Write(w, v.location);
    w.U128(v.spent_units);
    w.U128(v.output_units);
    w.U128(v.explicit_burn_units);
    w.U128(v.minted_units);
    w.U128(v.implicit_burn_units);
    w.Bool(v.has_mint_input);
}
void Write(Writer &w, const AssetSummary &v) {
    Write(w, v.token_id);
    Write(w, v.first_seen);
    w.U64(v.event_count);
    w.U64(v.output_count);
}

void Read(Reader &r, Bytes32 &v) { v = r.Array<32>(); }
void Read(Reader &r, Hash32 &v) { v.b = r.Array<32>(); }
void Read(Reader &r, Output &v) {
    const Bytes bytes = r.ByteVec();
    auto output = Output::Decode(bytes);
    if (!output) {
        ThrowCorrupt();
    }
    v = std::move(*output);
}
void Read(Reader &r, OutPoint &v) {
    Read(r, v.txid.hash);
    v.out_idx = r.U32();
}
void Read(Reader &r, TxLocation &v) {
    Read(r, v.block_id);
    v.height = r.U64();
    v.tx_index = r.U32();
    Read(r, v.txid.hash);
    Read(r, v.txhash.hash);
}
void Read(Reader &r, Binding &v) {
    Read(r, v.chain_id);
    Read(r, v.genesis);
    Read(r, v.profile);
}
void Read(Reader &r, Anchor &v) {
    Read(r, v.block_id);
    v.height = r.U64();
}
void Read(Reader &r, WireRange &v) {
    v.offset = r.U64();
    v.length = r.U64();
}
void Read(Reader &r, WitnessFact &v) {
    Read(r, v.script);
    Read(r, v.siblings_table);
    v.siblings_count = r.U32();
    Read(r, v.arguments_table);
    v.arguments_count = r.U32();
}
void Read(Reader &r, ResolvedCreation &v) {
    Read(r, v.outpoint);
    Read(r, v.output);
    Read(r, v.creation);
}
void Read(Reader &r, InputFact &v) {
    Read(r, v.prev_txid);
    v.prev_index = r.U32();
    v.sequence = r.U32();
    v.flags = r.U8();
    v.path_index = r.U8();
    v.has_coinbase_data = r.Bool();
    Read(r, v.coinbase_data);
    Read(r, v.witnesses);
}
void Read(Reader &r, ExplorerTxFacts &v) {
    v.wire = r.ByteVec();
    v.lock = r.U64();
    Read(r, v.inputs);
}
namespace {
void ReadHeader(Reader &r, HeaderWire &v) {
    const Bytes bytes = r.ByteVec();
    if (bytes.size() != HEADER_BYTES) {
        // serde custom "header length"
        throw postcard::Error(std::string(postcard::kSerdeDeCustom));
    }
    std::copy(bytes.begin(), bytes.end(), v.begin());
}
} // namespace
void Read(Reader &r, ExplorerBlockFacts &v) { ReadHeader(r, v.header_wire); }
void Read(Reader &r, TxMeta &v) {
    Read(r, v.location);
    v.lock = r.U64();
    v.input_count = r.U32();
    v.output_count = r.U32();
    v.file_num = r.U32();
    v.data_pos = r.U32();
    v.wire_size = r.U64();
    v.wire_checksum = r.U64();
}
void Read(Reader &r, BlockMeta &v) {
    Read(r, v.anchor);
    ReadHeader(r, v.header_wire);
    v.tx_count = r.U32();
}
void Read(Reader &r, InputMeta &v) {
    Read(r, v.prev_txid);
    v.prev_index = r.U32();
    v.sequence = r.U32();
    v.flags = r.U8();
    v.path_index = r.U8();
    v.has_coinbase_data = r.Bool();
    Read(r, v.coinbase_data);
    v.witness_count = r.U32();
    Read(r, v.resolved_creation);
}
void Read(Reader &r, StoredInputMeta &v) {
    Read(r, v.prev_txid);
    v.prev_index = r.U32();
    v.sequence = r.U32();
    v.flags = r.U8();
    v.path_index = r.U8();
    v.has_coinbase_data = r.Bool();
    Read(r, v.coinbase_data);
    v.witness_count = r.U32();
}
void Read(Reader &r, AssetEvent &v) {
    Read(r, v.token_id);
    Read(r, v.location);
    v.spent_units = r.U128();
    v.output_units = r.U128();
    v.explicit_burn_units = r.U128();
    v.minted_units = r.U128();
    v.implicit_burn_units = r.U128();
    v.has_mint_input = r.Bool();
}
void Read(Reader &r, AssetSummary &v) {
    Read(r, v.token_id);
    Read(r, v.first_seen);
    v.event_count = r.U64();
    v.output_count = r.U64();
}

} // namespace codec
} // namespace chronik::native::lotus_v2
