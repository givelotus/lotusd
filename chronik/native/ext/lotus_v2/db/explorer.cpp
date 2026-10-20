// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/db/explorer.h>

#include <chronik/native/codec/seahash.h>
#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/db/env.h>

#include <algorithm>

namespace chronik::native::lotus_v2 {

namespace {

Bytes Key2(std::string_view prefix, ByteView suffix) {
    Bytes k(prefix.begin(), prefix.end());
    k.insert(k.end(), suffix.begin(), suffix.end());
    return k;
}

void PushBe32(Bytes &k, uint32_t v) {
    for (int i = 3; i >= 0; --i) {
        k.push_back(uint8_t(v >> (8 * i)));
    }
}

uint64_t LeU64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= uint64_t(p[i]) << (8 * i);
    }
    return v;
}

void AddSize(size_t &total, size_t amount) {
    if (amount > SIZE_MAX - total) {
        ThrowInvalid("explorer batch bound");
    }
    total += amount;
}

/** Owner-side input checks before entries are planned. */
void ValidateInput(const InputFact &input, uint64_t size) {
    if (input.flags < 1 || input.flags > 3) {
        ThrowInvalid("input flags");
    }
    input.coinbase_data.Validate(size);
    if (!input.has_coinbase_data && input.coinbase_data != WireRange{}) {
        ThrowInvalid("absent coinbase range");
    }
    for (const WitnessFact &witness : input.witnesses) {
        witness.script.Validate(size);
        witness.siblings_table.Validate(size);
        witness.arguments_table.Validate(size);
        if (witness.siblings_table.length == 0 ||
            witness.arguments_table.length == 0) {
            ThrowInvalid("missing witness table framing");
        }
    }
}

bool ValidRange(const WireRange &range, uint64_t wire_size) {
    try {
        range.Validate(wire_size);
        return true;
    } catch (const V2Error &) {
        return false;
    }
}

} // namespace

Bytes HeightKey(uint64_t height) {
    Bytes k{'e', 'H'};
    for (int i = 7; i >= 0; --i) {
        k.push_back(uint8_t(height >> (8 * i)));
    }
    return k;
}
Bytes BlockKey(const Hash32 &id) { return Key2("eB", id.b); }
Bytes BlockTxKey(const Hash32 &id, uint32_t index) {
    Bytes k = Key2("eO", id.b);
    PushBe32(k, index);
    return k;
}
Bytes TxKey(const TxId &id) { return Key2("eT", id.hash.b); }
Bytes TxHashKey(const TxHash &id) { return Key2("eX", id.hash.b); }
Bytes InputKey(const TxId &id, uint32_t index) {
    Bytes k = Key2("eI", id.hash.b);
    PushBe32(k, index);
    return k;
}
Bytes WitnessKey(const TxId &id, uint32_t input, uint32_t index) {
    Bytes k = Key2("eW", id.hash.b);
    PushBe32(k, input);
    PushBe32(k, index);
    return k;
}

size_t PreflightExplorerBlock(const CommittedBlock &block) {
    size_t size = RESERVE_EXPLORER_BLOCK;
    for (const ConfirmedTx &tx : block.transactions) {
        const size_t wire = tx.explorer.wire.size();
        if (wire > SIZE_MAX / RESERVE_EXPLORER_PER_WIRE_BYTE) {
            ThrowInvalid("wire bound");
        }
        AddSize(size, wire * RESERVE_EXPLORER_PER_WIRE_BYTE);
        AddSize(size, RESERVE_EXPLORER_TX);
        for (const InputFact &input : tx.explorer.inputs) {
            AddSize(size, RESERVE_EXPLORER_INPUT);
            if (input.witnesses.size() > SIZE_MAX / RESERVE_EXPLORER_WITNESS) {
                ThrowInvalid("witness bound");
            }
            AddSize(size, input.witnesses.size() * RESERVE_EXPLORER_WITNESS);
        }
        AddSize(size, (wire / WIRE_CHUNK_BYTES + 1) * RESERVE_EXPLORER_CHUNK);
    }
    return size;
}

void ValidateInputMeta(const InputMeta &input, uint64_t wire_size) {
    if (!ValidRange(input.coinbase_data, wire_size)) {
        ThrowCorrupt();
    }
    if (!input.has_coinbase_data && input.coinbase_data != WireRange{}) {
        ThrowCorrupt();
    }
    bool valid = false;
    switch (input.flags) {
        case 1: {
            const auto &coin = input.resolved_creation;
            valid = !input.has_coinbase_data && input.path_index < 16 &&
                    input.witness_count >= 1 && input.witness_count <= 16 &&
                    (input.sequence == UINT32_MAX ||
                     (input.sequence & ~uint32_t(0x40ffff)) == 0) &&
                    coin && coin->outpoint.txid.hash.b == input.prev_txid &&
                    coin->outpoint.out_idx == input.prev_index &&
                    coin->creation.txid == coin->outpoint.txid &&
                    !coin->output.IsBurn() && !coin->output.Validate();
            break;
        }
        case 2:
            valid = input.path_index == 0 && input.sequence == UINT32_MAX &&
                    input.witness_count == 0 && !input.resolved_creation &&
                    (!input.has_coinbase_data ||
                     (input.coinbase_data.length >= 1 &&
                      input.coinbase_data.length <= 8192));
            break;
        case 3:
            valid = input.path_index == 0 && input.sequence == UINT32_MAX &&
                    input.witness_count == 1 && input.prev_index == 0 &&
                    input.prev_txid != Bytes32{} &&
                    !input.has_coinbase_data && !input.resolved_creation;
            break;
        default:
            break;
    }
    if (!valid) {
        ThrowCorrupt();
    }
}

void ValidateWitnessFact(const WitnessFact &witness, uint64_t wire_size) {
    for (const WireRange *range :
         {&witness.script, &witness.siblings_table, &witness.arguments_table}) {
        if (!ValidRange(*range, wire_size)) {
            ThrowCorrupt();
        }
    }
    if (witness.siblings_count > 64 || witness.arguments_count > 65535 ||
        witness.siblings_table.length == 0 ||
        witness.arguments_table.length == 0 ||
        uint64_t(witness.arguments_count) >
            witness.arguments_table.length - 1) {
        ThrowCorrupt();
    }
}

std::vector<std::pair<Bytes, Bytes>>
PlanExplorerBlock(const CommittedBlock &block) {
    PreflightExplorerBlock(block);
    const HeaderWire &h = block.explorer.header_wire;
    if (LeU64(h.data() + 62) != block.anchor.height) {
        ThrowInvalid("explorer header height");
    }
    const bool zero_parent =
        std::all_of(h.begin(), h.begin() + 32, [](uint8_t b) { return !b; });
    if ((block.anchor.height == 0 && !zero_parent) ||
        (block.anchor.height != 0 &&
         !std::equal(h.begin(), h.begin() + 32,
                     block.parent.block_id.begin()))) {
        ThrowInvalid("explorer header parent");
    }
    if (block.transactions.size() > UINT32_MAX) {
        ThrowInvalid("transaction count");
    }
    std::vector<std::pair<Bytes, Bytes>> entries;
    entries.emplace_back(HeightKey(block.anchor.height),
                         Bytes(block.anchor.block_id.begin(),
                               block.anchor.block_id.end()));
    entries.emplace_back(
        BlockKey(H(block.anchor.block_id)),
        EncodeRecord(BlockMeta{block.anchor, h,
                               uint32_t(block.transactions.size())}));
    for (size_t index = 0; index < block.transactions.size(); ++index) {
        const ConfirmedTx &tx = block.transactions[index];
        const TxLocation &loc = tx.location;
        if (loc.block_id.b != block.anchor.block_id ||
            loc.height != block.anchor.height || loc.tx_index != index) {
            ThrowInvalid("explorer transaction location");
        }
        const ExplorerTxFacts &facts = tx.explorer;
        if (facts.wire.empty()) {
            ThrowInvalid("empty transaction frame");
        }
        const uint64_t wire_size = facts.wire.size();
        const uint64_t wire_checksum = SeaHash(facts.wire);

        if (facts.inputs.size() > UINT32_MAX) {
            ThrowInvalid("input count");
        }
        if (tx.outputs.size() > UINT32_MAX) {
            ThrowInvalid("output count");
        }
        const TxMeta meta{loc,
                          facts.lock,
                          uint32_t(facts.inputs.size()),
                          uint32_t(tx.outputs.size()),
                          tx.pos.file_num,
                          tx.pos.data_pos,
                          wire_size,
                          wire_checksum};
        entries.emplace_back(TxKey(loc.txid), EncodeRecord(meta));
        entries.emplace_back(TxHashKey(loc.txhash),
                             Bytes(loc.txid.hash.b.begin(),
                                   loc.txid.hash.b.end()));
        Bytes ids(loc.txid.hash.b.begin(), loc.txid.hash.b.end());
        ids.insert(ids.end(), loc.txhash.hash.b.begin(),
                   loc.txhash.hash.b.end());
        entries.emplace_back(BlockTxKey(loc.block_id, loc.tx_index),
                             std::move(ids));
        // The spends must be exactly the flags==1 inputs, in order.
        size_t n_spends = 0;
        bool subset_ok = true;
        for (size_t i = 0; i < facts.inputs.size(); ++i) {
            const InputFact &input = facts.inputs[i];
            if (input.flags != 1) {
                continue;
            }
            if (n_spends >= tx.spends.size() ||
                tx.spends[n_spends].input_index != uint32_t(i) ||
                tx.spends[n_spends].outpoint !=
                    OutPoint{TxId{H(input.prev_txid)}, input.prev_index}) {
                subset_ok = false;
            }
            ++n_spends;
        }
        if (!subset_ok || n_spends != tx.spends.size()) {
            ThrowInvalid("explorer spend subset");
        }
        for (size_t i = 0; i < facts.inputs.size(); ++i) {
            const InputFact &input = facts.inputs[i];
            ValidateInput(input, meta.wire_size);
            entries.emplace_back(InputKey(loc.txid, uint32_t(i)),
                                 EncodeRecord(input.Metadata()));
            for (size_t w = 0; w < input.witnesses.size(); ++w) {
                entries.emplace_back(
                    WitnessKey(loc.txid, uint32_t(i), uint32_t(w)),
                    EncodeRecord(input.witnesses[w]));
            }
        }
    }
    std::stable_sort(entries.begin(), entries.end(),
                     [](const auto &a, const auto &b) {
                         return a.first < b.first;
                     });
    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i - 1].first == entries[i].first) {
            ThrowInvalid("duplicate explorer identity");
        }
    }
    return entries;
}

// ---- ReadSnapshot explorer readers ----

std::optional<BlockMeta> ReadSnapshot::ExplorerBlock(const Hash32 &id) const {
    const auto bytes = m_inner.Get(BlockKey(id));
    if (!bytes) {
        return std::nullopt;
    }
    const auto meta = DecodeRecord<BlockMeta>(*bytes);
    if (meta.anchor.block_id != id.b || meta.anchor.height > anchor.height) {
        ThrowCorrupt();
    }
    const auto at_height = m_inner.Get(HeightKey(meta.anchor.height));
    if (!at_height || !std::ranges::equal(*at_height, id.b)) {
        ThrowCorrupt();
    }
    if (LeU64(meta.header_wire.data() + 62) != meta.anchor.height) {
        ThrowCorrupt();
    }
    if (meta.anchor.height == 0) {
        if (!std::all_of(meta.header_wire.begin(),
                         meta.header_wire.begin() + 32,
                         [](uint8_t b) { return !b; })) {
            ThrowCorrupt();
        }
    } else {
        const auto parent = m_inner.Get(HeightKey(meta.anchor.height - 1));
        if (!parent ||
            !std::ranges::equal(*parent, ByteView(meta.header_wire.data(), 32))) {
            ThrowCorrupt();
        }
    }
    return meta;
}

std::optional<BlockMeta>
ReadSnapshot::ExplorerBlockAtHeight(uint64_t height) const {
    const auto bytes = m_inner.Get(HeightKey(height));
    if (!bytes) {
        return std::nullopt;
    }
    if (bytes->size() != 32) {
        ThrowCorrupt();
    }
    const auto meta = ExplorerBlock(Hash32::FromBytes(*bytes));
    if (!meta || meta->anchor.height != height) {
        ThrowCorrupt();
    }
    return meta;
}

std::optional<TxMeta> ReadSnapshot::ExplorerTx(const TxId &id) const {
    const auto bytes = m_inner.Get(TxKey(id));
    if (!bytes) {
        return std::nullopt;
    }
    const auto meta = DecodeRecord<TxMeta>(*bytes);
    const TxLocation &loc = meta.location;
    if (meta.input_count > 65535 || meta.output_count > 65535 ||
        meta.wire_size == 0 || meta.wire_size > bounds.BlockBytes()) {
        ThrowCorrupt();
    }
    if (loc.txid != id || Transaction(id) != loc) {
        ThrowCorrupt();
    }
    const auto block = ExplorerBlock(loc.block_id);
    if (!block) {
        ThrowCorrupt();
    }
    if (block->anchor.height != loc.height || loc.tx_index >= block->tx_count ||
        ExplorerBlockTx(loc.block_id, loc.tx_index) !=
            std::make_pair(id, loc.txhash)) {
        ThrowCorrupt();
    }
    return meta;
}

std::optional<TxMeta>
ReadSnapshot::ExplorerTxByHash(const TxHash &hash) const {
    const auto bytes = m_inner.Get(TxHashKey(hash));
    if (!bytes) {
        return std::nullopt;
    }
    if (bytes->size() != 32) {
        ThrowCorrupt();
    }
    const auto meta = ExplorerTx(TxId{Hash32::FromBytes(*bytes)});
    if (!meta || meta->location.txhash != hash) {
        ThrowCorrupt();
    }
    return meta;
}

std::optional<std::pair<TxId, TxHash>>
ReadSnapshot::ExplorerBlockTx(const Hash32 &block, uint32_t index) const {
    const auto bytes = m_inner.Get(BlockTxKey(block, index));
    if (!bytes) {
        return std::nullopt;
    }
    if (bytes->size() != 64) {
        ThrowCorrupt();
    }
    return std::make_pair(
        TxId{Hash32::FromBytes(ByteView(*bytes).first(32))},
        TxHash{Hash32::FromBytes(ByteView(*bytes).subspan(32))});
}

std::optional<InputMeta> ReadSnapshot::ExplorerInput(const TxId &id,
                                                     uint32_t index) const {
    const auto tx = ExplorerTx(id);
    if (!tx) {
        return std::nullopt;
    }
    const auto bytes = m_inner.Get(InputKey(id, index));
    if (!bytes) {
        if (index < tx->input_count) {
            ThrowCorrupt();
        }
        return std::nullopt;
    }
    if (index >= tx->input_count) {
        ThrowCorrupt();
    }
    const auto stored = DecodeRecord<StoredInputMeta>(*bytes);
    std::optional<ResolvedCreation> creation;
    if (stored.flags == 1) {
        const OutPoint outpoint{TxId{H(stored.prev_txid)}, stored.prev_index};
        auto record = GetOutput(outpoint);
        if (!record) {
            ThrowCorrupt();
        }
        creation = ResolvedCreation{outpoint, std::move(record->output),
                                    record->creation};
    }
    const InputMeta input = InputMeta::WithCreation(stored, std::move(creation));
    ValidateInputMeta(input, tx->wire_size);
    // A descriptor count must reach an existing final ordinal and stop at
    // the next key. Missing interior ordinals fail when that page is read.
    if (input.witness_count > 0) {
        const auto last =
            m_inner.Get(WitnessKey(id, index, input.witness_count - 1));
        if (!last) {
            ThrowCorrupt();
        }
        ValidateWitnessFact(DecodeRecord<WitnessFact>(*last), tx->wire_size);
    }
    if (m_inner.Get(WitnessKey(id, index, input.witness_count))) {
        ThrowCorrupt();
    }
    if (const auto &coin = input.resolved_creation) {
        const auto historical = GetOutput(coin->outpoint);
        if (!historical) {
            ThrowCorrupt();
        }
        if (historical->output != coin->output ||
            historical->creation != coin->creation ||
            !historical->spend ||
            historical->spend->transaction != tx->location ||
            historical->spend->input_index != index) {
            ThrowCorrupt();
        }
        const auto creation_tx = ExplorerTx(coin->creation.txid);
        if (!creation_tx || creation_tx->location != coin->creation ||
            coin->outpoint.out_idx >= creation_tx->output_count ||
            // Created earlier, or elsewhere in the same block (which may be
            // in canonical, not topological, order).
            coin->creation.height > tx->location.height ||
            (coin->creation.height == tx->location.height &&
             coin->creation.tx_index == tx->location.tx_index)) {
            ThrowCorrupt();
        }
    }
    return input;
}

std::optional<WitnessFact>
ReadSnapshot::ExplorerWitness(const TxId &id, uint32_t input_index,
                              uint32_t index) const {
    const auto input = ExplorerInput(id, input_index);
    if (!input) {
        return std::nullopt;
    }
    const auto bytes = m_inner.Get(WitnessKey(id, input_index, index));
    if (!bytes) {
        if (index < input->witness_count) {
            ThrowCorrupt();
        }
        return std::nullopt;
    }
    if (index >= input->witness_count) {
        ThrowCorrupt();
    }
    const auto tx = ExplorerTx(id);
    if (!tx) {
        ThrowCorrupt();
    }
    const auto witness = DecodeRecord<WitnessFact>(*bytes);
    ValidateWitnessFact(witness, tx->wire_size);
    const auto [siblings, count_bytes] =
        ExplorerTableCount(id, tx->wire_size, witness.siblings_table);
    const auto [arguments, unused] =
        ExplorerTableCount(id, tx->wire_size, witness.arguments_table);
    (void)unused;
    const bool table_ok =
        siblings <= (UINT64_MAX - count_bytes) / 32 &&
        siblings * 32 + count_bytes == witness.siblings_table.length;
    if (siblings != witness.siblings_count ||
        arguments != witness.arguments_count || !table_ok) {
        ThrowCorrupt();
    }
    return witness;
}

std::pair<uint64_t, uint64_t>
ReadSnapshot::ExplorerTableCount(const TxId &id, uint64_t wire_size,
                                 const WireRange &range) const {
    if (!ValidRange(range, wire_size) || range.length == 0) {
        ThrowCorrupt();
    }
    const size_t needed = size_t(std::min<uint64_t>(range.length, 9));
    const auto slice = ExplorerWireSlice(id, range.offset, needed);
    if (!slice || slice->size() != needed) {
        ThrowCorrupt();
    }
    uint8_t b[9] = {};
    std::copy(slice->begin(), slice->end(), b);
    uint64_t value = 0;
    uint64_t width = 0;
    if (b[0] <= 252) {
        value = b[0];
        width = 1;
    } else if (b[0] == 253 && needed >= 3) {
        value = uint64_t(b[1]) | uint64_t(b[2]) << 8;
        width = 3;
    } else if (b[0] == 254 && needed >= 5) {
        for (int i = 0; i < 4; ++i) {
            value |= uint64_t(b[1 + i]) << (8 * i);
        }
        width = 5;
    } else if (b[0] == 255 && needed >= 9) {
        value = LeU64(b + 1);
        width = 9;
    } else {
        ThrowCorrupt();
    }
    if ((width == 3 && value < 253) || (width == 5 && value <= UINT16_MAX) ||
        (width == 9 && value <= UINT32_MAX)) {
        ThrowCorrupt();
    }
    return {value, width};
}

std::optional<Bytes> ReadSnapshot::ExplorerWireSlice(const TxId &id,
                                                     uint64_t offset,
                                                     uint64_t length) const {
    const auto tx = ExplorerTx(id);
    if (!tx) {
        return std::nullopt;
    }
    if (offset > tx->wire_size) {
        ThrowCorrupt();
    }
    const auto node = NodeTxOf(*tx);
    const Bytes &full = node->explorer.wire;
    const uint64_t end =
        std::min(offset > UINT64_MAX - length ? UINT64_MAX : offset + length,
                 tx->wire_size);
    return Bytes(full.begin() + offset, full.begin() + end);
}

std::optional<Bytes> ReadSnapshot::ExplorerWireChunk(const TxId &id,
                                                     uint32_t index) const {
    const auto tx = ExplorerTx(id);
    if (!tx) {
        return std::nullopt;
    }
    const uint64_t start = uint64_t(index) * WIRE_CHUNK_BYTES;
    if (start >= tx->wire_size) {
        return std::nullopt;
    }
    auto bytes = ExplorerWireSlice(id, start, WIRE_CHUNK_BYTES);
    if (bytes && (bytes->empty() || bytes->size() > WIRE_CHUNK_BYTES)) {
        ThrowCorrupt();
    }
    return bytes;
}

std::optional<std::pair<Bytes, Bytes>>
ReadSnapshot::ExplorerNextRaw(ByteView prefix, size_t key_len,
                              std::optional<ByteView> after) const {
    auto family = [&](std::string_view f, size_t plen, size_t klen) {
        return prefix.size() == plen && key_len == klen &&
               prefix[0] == uint8_t(f[0]) && prefix[1] == uint8_t(f[1]);
    };
    const bool allowed = family("eH", 2, 10) || family("eO", 34, 38) ||
                         family("eI", 34, 38) || family("eW", 38, 42);
    if (!allowed ||
        (after && (after->size() != key_len ||
                   !std::equal(prefix.begin(), prefix.end(),
                               after->begin())))) {
        ThrowInvalid("explorer continuation key");
    }
    auto item = m_inner.SeekNextRegular(prefix, after, [] {});
    if (!item) {
        return std::nullopt;
    }
    if (item->first.size() != key_len ||
        item->second.size() > MAX_EXPLORER_RECORD_BYTES) {
        ThrowCorrupt();
    }
    return item;
}

} // namespace chronik::native::lotus_v2
