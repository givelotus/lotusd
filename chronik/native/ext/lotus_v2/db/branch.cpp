// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/db/branch.h>

#include <chronik/native/codec/seahash.h>
#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/explorer.h>

#include <algorithm>
#include <map>
#include <queue>
#include <set>
#include <tuple>

namespace chronik::native::lotus_v2 {

using codec::Reader;
using codec::Writer;

namespace {

using FlatPos = std::pair<uint32_t, uint64_t>;

/** v2_branch.rs `Record`. */
struct Record {
    Bytes output;
    TxLocation creation;
    std::optional<std::pair<TxLocation, uint32_t>> spend;
};

/** v2_branch.rs `ReceiptTx`. */
struct ReceiptTx {
    TxLocation location;
    std::vector<Bytes> outputs;
    std::vector<std::tuple<Bytes32, uint32_t, uint32_t>> spends;
    uint64_t lock = 0;
    std::vector<InputFact> inputs;
    uint32_t file_num = 0;
    uint64_t data_pos = 0;
    uint64_t wire_size = 0;
    uint64_t wire_checksum = 0;
};

/** The block receipt tuple (anchor, parent, explorer, transactions). */
struct Receipt {
    Anchor anchor;
    Anchor parent;
    ExplorerBlockFacts explorer;
    std::vector<ReceiptTx> transactions;
};

/** v2_branch.rs `Undo`. */
struct Undo {
    Binding binding;
    Anchor anchor;
    std::optional<Anchor> parent;
    FlatPos prev_flat_pos;
    std::vector<std::pair<Bytes, std::optional<Bytes>>> entries;
};

void Write(Writer &w, const Record &v) {
    w.ByteVec(v.output);
    codec::Write(w, v.creation);
    w.OptionTag(v.spend.has_value());
    if (v.spend) {
        codec::Write(w, v.spend->first);
        w.U32(v.spend->second);
    }
}
void Read(Reader &r, Record &v) {
    v.output = r.ByteVec();
    codec::Read(r, v.creation);
    v.spend.reset();
    if (r.OptionTag()) {
        TxLocation loc;
        codec::Read(r, loc);
        v.spend.emplace(loc, r.U32());
    }
}
void Write(Writer &w, const FlatPos &v) {
    w.U32(v.first);
    w.U64(v.second);
}
void Read(Reader &r, FlatPos &v) {
    v.first = r.U32();
    v.second = r.U64();
}
void Write(Writer &w, const ReceiptTx &v) {
    codec::Write(w, v.location);
    w.SeqLen(v.outputs.size());
    for (const Bytes &o : v.outputs) {
        w.ByteVec(o);
    }
    w.SeqLen(v.spends.size());
    for (const auto &[txid, out_idx, input_index] : v.spends) {
        w.Raw(txid);
        w.U32(out_idx);
        w.U32(input_index);
    }
    w.U64(v.lock);
    codec::Write(w, v.inputs);
    w.U32(v.file_num);
    w.U64(v.data_pos);
    w.U64(v.wire_size);
    w.U64(v.wire_checksum);
}
void Read(Reader &r, ReceiptTx &v) {
    codec::Read(r, v.location);
    v.outputs.clear();
    for (uint64_t n = r.SeqLen(), i = 0; i < n; ++i) {
        v.outputs.push_back(r.ByteVec());
    }
    v.spends.clear();
    for (uint64_t n = r.SeqLen(), i = 0; i < n; ++i) {
        const Bytes32 txid = r.Array<32>();
        const uint32_t out_idx = r.U32();
        v.spends.emplace_back(txid, out_idx, r.U32());
    }
    v.lock = r.U64();
    codec::Read(r, v.inputs);
    v.file_num = r.U32();
    v.data_pos = r.U64();
    v.wire_size = r.U64();
    v.wire_checksum = r.U64();
}
void Write(Writer &w, const Receipt &v) {
    codec::Write(w, v.anchor);
    codec::Write(w, v.parent);
    codec::Write(w, v.explorer);
    w.SeqLen(v.transactions.size());
    for (const ReceiptTx &tx : v.transactions) {
        Write(w, tx);
    }
}
void Read(Reader &r, Receipt &v) {
    codec::Read(r, v.anchor);
    codec::Read(r, v.parent);
    codec::Read(r, v.explorer);
    v.transactions.clear();
    for (uint64_t n = r.SeqLen(), i = 0; i < n; ++i) {
        ReceiptTx tx;
        Read(r, tx);
        v.transactions.push_back(std::move(tx));
    }
}
void Write(Writer &w, const Undo &v) {
    codec::Write(w, v.binding);
    codec::Write(w, v.anchor);
    codec::Write(w, v.parent);
    Write(w, v.prev_flat_pos);
    w.SeqLen(v.entries.size());
    for (const auto &[k, value] : v.entries) {
        w.ByteVec(k);
        w.OptionTag(value.has_value());
        if (value) {
            w.ByteVec(*value);
        }
    }
}
void Read(Reader &r, Undo &v) {
    codec::Read(r, v.binding);
    codec::Read(r, v.anchor);
    codec::Read(r, v.parent);
    Read(r, v.prev_flat_pos);
    v.entries.clear();
    for (uint64_t n = r.SeqLen(), i = 0; i < n; ++i) {
        Bytes k = r.ByteVec();
        std::optional<Bytes> value;
        if (r.OptionTag()) {
            value = r.ByteVec();
        }
        v.entries.emplace_back(std::move(k), std::move(value));
    }
}

template <typename T> Bytes Enc(const T &v) {
    Bytes out;
    Writer w(out);
    Write(w, v);
    return out;
}
template <typename T> T Dec(ByteView bytes) {
    T v{};
    try {
        Reader r(bytes);
        Read(r, v);
    } catch (const postcard::Error &) {
        ThrowCorrupt();
    }
    return v;
}

Bytes Identity(const Binding &binding) {
    Bytes out;
    Writer w(out);
    w.U32(SCHEMA_VERSION);
    codec::Write(w, binding);
    return out;
}

ByteView Str(std::string_view s) {
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}
Bytes StrBytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

bool StartsWith(ByteView bytes, std::string_view prefix) {
    return bytes.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), bytes.begin());
}

Output DecodeOutputOrCorrupt(ByteView wire) {
    auto output = Output::Decode(wire);
    if (!output) {
        ThrowCorrupt();
    }
    return std::move(*output);
}

Bytes EncodeOutputOr(const Output &output, std::string_view invalid) {
    auto bytes = output.Encode();
    if (!bytes) {
        if (invalid.empty()) {
            ThrowCorrupt();
        }
        ThrowInvalid(invalid);
    }
    return std::move(*bytes);
}

/** Bounded record decode: checks the cap BEFORE vector allocation. */
Record DecodeRecord(ByteView bytes) {
    if (bytes.size() > MAX_BRANCH_RECORD_BYTES) {
        ThrowCorrupt();
    }
    Record record = Dec<Record>(bytes);
    DecodeOutputOrCorrupt(record.output);
    return record;
}

OutputRecord Public(Record record, const OutPoint &outpoint) {
    if (record.creation.txid != outpoint.txid) {
        ThrowCorrupt();
    }
    OutputRecord out{outpoint, DecodeOutputOrCorrupt(record.output),
                     record.creation, std::nullopt};
    if (record.spend) {
        out.spend = SpendLocation{record.spend->first, record.spend->second};
    }
    return out;
}

void Reserve(size_t &total, size_t bytes) {
    if (bytes > MAX_BATCH_BYTES || total + bytes > MAX_BATCH_BYTES) {
        ThrowInvalid("staging capacity");
    }
    total += bytes;
}

void WriteBatch(V2Env &db, const V2WriteBatch &batch) {
    if (batch.SizeInBytes() > MAX_BATCH_BYTES) {
        ThrowInvalid("serialized batch bound");
    }
    db.Write(batch);
}

Bytes PostingKey(const Hash32 &root, uint8_t position, const OutPoint &op) {
    Bytes k = PostingPrefix(root, position);
    const Bytes ob = OutPointBytes(op);
    k.insert(k.end(), ob.begin(), ob.end());
    return k;
}

std::vector<SpentInput> ReceiptSpends(const ReceiptTx &tx) {
    std::vector<SpentInput> out;
    for (const auto &[txid, out_idx, input_index] : tx.spends) {
        out.push_back(SpentInput{OutPoint{TxId{H(txid)}, out_idx}, input_index});
    }
    return out;
}

using OldValueFn = std::function<std::optional<Bytes>(const Bytes &)>;

} // namespace

std::vector<size_t>
ProcessingOrder(const std::vector<ConfirmedTx> &transactions) {
    std::map<TxId, size_t> index;
    for (size_t i = 0; i < transactions.size(); ++i) {
        index.emplace(transactions[i].location.txid, i);
    }
    std::vector<size_t> pending(transactions.size(), 0);
    std::vector<std::vector<size_t>> children(transactions.size());
    for (size_t child = 0; child < transactions.size(); ++child) {
        for (const SpentInput &spend : transactions[child].spends) {
            const auto it = index.find(spend.outpoint.txid);
            if (it != index.end() && it->second != child) {
                ++pending[child];
                children[it->second].push_back(child);
            }
        }
    }
    std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>>
        ready;
    for (size_t i = 0; i < transactions.size(); ++i) {
        if (pending[i] == 0) {
            ready.push(i);
        }
    }
    std::vector<size_t> order;
    order.reserve(transactions.size());
    while (!ready.empty()) {
        const size_t i = ready.top();
        ready.pop();
        order.push_back(i);
        for (const size_t child : children[i]) {
            if (--pending[child] == 0) {
                ready.push(child);
            }
        }
    }
    if (order.size() < transactions.size()) {
        std::vector<bool> placed(transactions.size(), false);
        for (const size_t i : order) {
            placed[i] = true;
        }
        for (size_t i = 0; i < transactions.size(); ++i) {
            if (!placed[i]) {
                order.push_back(i);
            }
        }
    }
    return order;
}

namespace {

std::map<Bytes, Bytes> AssetEntries(const CommittedBlock &block,
                                    const std::vector<size_t> &order,
                                    const OldValueFn &old_value) {
    std::map<Bytes, Bytes> entries;
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = block.transactions[tx_index];
        std::vector<ResolvedCreation> resolved_spends;
        std::vector<Hash32> mint_token_ids;
        for (const InputFact &input : tx.explorer.inputs) {
            if (input.resolved_creation) {
                resolved_spends.push_back(*input.resolved_creation);
            }
            if (input.flags == 3) {
                mint_token_ids.push_back(H(input.prev_txid));
            }
        }
        const AssetTxView view{tx.location, tx.outputs, resolved_spends,
                               mint_token_ids};
        OldAssetSummaries summaries;
        for (const AssetEvent &event : DeriveAssetEvents(view)) {
            const Bytes k = AssetSummaryKey(event.token_id);
            std::optional<Bytes> bytes;
            if (auto it = entries.find(k); it != entries.end()) {
                bytes = it->second;
            } else {
                bytes = old_value(k);
            }
            summaries[event.token_id] =
                bytes ? std::optional<AssetSummary>(DecodeAssetSummary(*bytes))
                      : std::nullopt;
        }
        for (auto &[k, v] : PlanAssetTx(view, summaries)) {
            entries[k] = std::move(v);
        }
    }
    return entries;
}

/** Validates the stored undo of the tip block before applying it. */
void ValidateUndo(const V2Env &db, const Binding &binding, const Anchor &anchor,
                  const Undo &undo) {
    if (!undo.parent) {
        ThrowCorrupt();
    }
    const Anchor parent = *undo.parent;
    if (undo.binding != binding || undo.anchor != anchor ||
        parent.height == UINT64_MAX || parent.height + 1 != anchor.height ||
        (parent.height == 0 && parent.block_id != binding.genesis) ||
        undo.entries.size() > MAX_BATCH_BYTES / 40) {
        ThrowCorrupt();
    }
    const auto receipt_bytes = db.Get(PrefixKey('b', anchor.block_id));
    if (!receipt_bytes || receipt_bytes->size() > MAX_BATCH_BYTES) {
        ThrowCorrupt();
    }
    const Receipt receipt = Dec<Receipt>(*receipt_bytes);
    const auto &transactions = receipt.transactions;
    if (receipt.anchor != anchor || receipt.parent != parent ||
        transactions.size() > MAX_TRANSACTIONS) {
        ThrowCorrupt();
    }
    auto reserve = [](size_t &total, size_t bytes) {
        try {
            Reserve(total, bytes);
        } catch (const V2Error &) {
            ThrowCorrupt();
        }
    };
    std::set<Bytes> expected;
    size_t reservation = 1024;
    for (size_t index = 0; index < transactions.size(); ++index) {
        const ReceiptTx &tx = transactions[index];
        if (tx.location.block_id.b != anchor.block_id ||
            tx.location.height != anchor.height ||
            tx.location.tx_index != index) {
            ThrowCorrupt();
        }
        constexpr size_t per_spend = 6 * MAX_BRANCH_RECORD_BYTES + 1024;
        if (tx.spends.size() > SIZE_MAX / per_spend) {
            ThrowCorrupt();
        }
        reserve(reservation, 512 + tx.spends.size() * per_spend);
        if (!expected.insert(PrefixKey('t', tx.location.txid.hash.b)).second) {
            ThrowCorrupt();
        }
        for (const auto &[txid, out_idx, input_index] : tx.spends) {
            (void)input_index;
            expected.insert(
                PrefixKey('o', OutPointBytes(OutPoint{TxId{H(txid)}, out_idx})));
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const Output output = DecodeOutputOrCorrupt(tx.outputs[i]);
            reserve(reservation, 6 * MAX_BRANCH_RECORD_BYTES +
                                     output.branches.size() * 2 * 512);
            if (i > UINT32_MAX) {
                ThrowCorrupt();
            }
            const OutPoint op{tx.location.txid, uint32_t(i)};
            expected.insert(PrefixKey('o', OutPointBytes(op)));
            for (size_t position = 0; position < output.branches.size();
                 ++position) {
                for (uint8_t pos : {uint8_t(position), uint8_t(255)}) {
                    expected.insert(
                        PostingKey(output.branches[position], pos, op));
                }
            }
        }
    }
    CommittedBlock restored{anchor, parent, {}, receipt.explorer};
    for (const ReceiptTx &tx : transactions) {
        if (tx.wire_size == 0 || tx.wire_size > MAX_BATCH_BYTES) {
            ThrowCorrupt();
        }
        Bytes wire;
        try {
            wire = db.Flat().ReadAt(tx.file_num, tx.data_pos,
                                    size_t(tx.wire_size));
        } catch (const V2Error &) {
            ThrowCorrupt();
        }
        if (SeaHash(wire) != tx.wire_checksum) {
            ThrowCorrupt();
        }
        ConfirmedTx ctx;
        ctx.location = tx.location;
        for (const Bytes &o : tx.outputs) {
            ctx.outputs.push_back(DecodeOutputOrCorrupt(o));
        }
        ctx.spends = ReceiptSpends(tx);
        ctx.explorer = ExplorerTxFacts{std::move(wire), tx.lock, tx.inputs};
        restored.transactions.push_back(std::move(ctx));
    }
    reserve(reservation, PreflightExplorerBlock(restored));
    std::map<Bytes, Bytes> legacy_current;
    std::map<Bytes, std::optional<Bytes>> legacy_previous;
    const std::vector<size_t> order = ProcessingOrder(restored.transactions);
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = restored.transactions[tx_index];
        const Bytes tk = PrefixKey('t', tx.location.txid.hash.b);
        legacy_current[tk] = codec::Encode(tx.location);
        legacy_previous[tk] = std::nullopt;
        for (const SpentInput &spend : tx.spends) {
            if (spend.input_index >= tx.explorer.inputs.size() ||
                !tx.explorer.inputs[spend.input_index].resolved_creation) {
                ThrowCorrupt();
            }
            const ResolvedCreation &creation =
                *tx.explorer.inputs[spend.input_index].resolved_creation;
            if (creation.outpoint != spend.outpoint) {
                ThrowCorrupt();
            }
            const Bytes k = PrefixKey('o', OutPointBytes(spend.outpoint));
            Record record{EncodeOutputOr(creation.output, ""),
                          creation.creation, std::nullopt};
            if (!legacy_previous.count(k)) {
                legacy_previous[k] = Enc(record);
            }
            record.spend = std::make_pair(tx.location, spend.input_index);
            legacy_current[k] = Enc(record);
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const Output &output = tx.outputs[i];
            const OutPoint op{tx.location.txid, uint32_t(i)};
            const Bytes k = PrefixKey('o', OutPointBytes(op));
            legacy_previous[k] = std::nullopt;
            legacy_current[k] =
                Enc(Record{EncodeOutputOr(output, ""), tx.location, {}});
            for (size_t b = 0; b < output.branches.size(); ++b) {
                for (uint8_t pos : {uint8_t(b), uint8_t(255)}) {
                    const Bytes pk = PostingKey(output.branches[b], pos, op);
                    legacy_previous[pk] = std::nullopt;
                    legacy_current[pk] = Bytes{};
                }
            }
        }
    }
    for (const auto &[k, v] : legacy_current) {
        if (db.Get(k) != v) {
            ThrowCorrupt();
        }
    }
    const ExplorerPlan planned = PlanExplorerBlockAt(
        restored, undo.prev_flat_pos.first, undo.prev_flat_pos.second);
    const auto flat_bytes = db.Get(Str("flat_pos"));
    if (!flat_bytes) {
        ThrowCorrupt();
    }
    if (Dec<FlatPos>(*flat_bytes) != planned.next_flat_pos) {
        ThrowCorrupt();
    }
    for (size_t i = 0;
         i < transactions.size() && i < planned.flat_writes.size(); ++i) {
        if (transactions[i].file_num != planned.flat_writes[i].file_num ||
            transactions[i].data_pos != planned.flat_writes[i].data_pos) {
            ThrowCorrupt();
        }
    }
    const std::map<Bytes, Bytes> explorer_entries(planned.entries.begin(),
                                                  planned.entries.end());
    std::map<Bytes, std::optional<Bytes>> undo_map;
    for (const auto &[k, v] : undo.entries) {
        undo_map.emplace(k, v);
    }
    const auto asset_entries =
        AssetEntries(restored, order,
                     [&](const Bytes &k) -> std::optional<Bytes> {
                         auto it = undo_map.find(k);
                         return it == undo_map.end() ? std::nullopt
                                                     : it->second;
                     });
    for (const auto &[k, v] : asset_entries) {
        if (!expected.insert(k).second || db.Get(k) != v) {
            ThrowCorrupt();
        }
    }
    for (const auto &[k, v] : explorer_entries) {
        if (!expected.insert(k).second || db.Get(k) != v) {
            ThrowCorrupt();
        }
    }
    if (expected.size() != undo.entries.size()) {
        ThrowCorrupt();
    }
    std::set<Bytes> seen;
    for (const auto &[k, previous] : undo.entries) {
        if (!expected.count(k) || !seen.insert(k).second) {
            ThrowCorrupt();
        }
        if (auto it = legacy_previous.find(k); it != legacy_previous.end()) {
            if (previous != it->second) {
                ThrowCorrupt();
            }
        }
        if (asset_entries.count(k)) {
            if (!StartsWith(k, "eA") && previous) {
                ThrowCorrupt();
            }
            continue;
        }
        if (explorer_entries.count(k)) {
            if (previous) {
                ThrowCorrupt();
            }
            continue;
        }
        if (!k.empty() && k[0] == 'o' && k.size() == 37) {
            const OutPoint op = OutPointDecode(ByteView(k).subspan(1));
            const auto cur_bytes = db.Get(k);
            if (!cur_bytes) {
                ThrowCorrupt();
            }
            const Record current = DecodeRecord(*cur_bytes);
            if (current.creation.txid != op.txid) {
                ThrowCorrupt();
            }
            if (!previous) {
                if (current.creation.block_id.b != anchor.block_id ||
                    current.creation.height != anchor.height) {
                    ThrowCorrupt();
                }
            } else {
                const Record old = DecodeRecord(*previous);
                if (old.creation.txid != op.txid ||
                    old.creation.height > parent.height || old.spend ||
                    DecodeOutputOrCorrupt(old.output).IsBurn() ||
                    codec::Encode(old.creation) !=
                        codec::Encode(current.creation) ||
                    old.output != current.output || !current.spend ||
                    current.spend->first.block_id.b != anchor.block_id ||
                    current.spend->first.height != anchor.height) {
                    ThrowCorrupt();
                }
            }
        } else if (!k.empty() && k[0] == 't' && k.size() == 33 && !previous) {
            const auto value = db.Get(k);
            if (!value || value->size() > 128) {
                ThrowCorrupt();
            }
            const auto loc = codec::Decode<TxLocation>(*value);
            if (!std::equal(loc.txid.hash.b.begin(), loc.txid.hash.b.end(),
                            k.begin() + 1) ||
                loc.block_id.b != anchor.block_id ||
                loc.height != anchor.height) {
                ThrowCorrupt();
            }
        } else if (!k.empty() && k[0] == 'p' && k.size() == 70 && !previous) {
            const OutPoint op = OutPointDecode(ByteView(k).subspan(34));
            const auto rec_bytes = db.Get(PrefixKey('o', OutPointBytes(op)));
            if (!rec_bytes) {
                ThrowCorrupt();
            }
            const Record record = DecodeRecord(*rec_bytes);
            const Output output = DecodeOutputOrCorrupt(record.output);
            const Hash32 root = Hash32::FromBytes(ByteView(k).subspan(1, 32));
            const uint8_t position = k[33];
            const bool root_ok =
                position == 255
                    ? std::find(output.branches.begin(), output.branches.end(),
                                root) != output.branches.end()
                    : position < output.branches.size() &&
                          output.branches[position] == root;
            const auto posting = db.Get(k);
            if (record.creation.block_id.b != anchor.block_id ||
                record.creation.height != anchor.height || !root_ok ||
                !posting || !posting->empty()) {
                ThrowCorrupt();
            }
        } else {
            ThrowCorrupt();
        }
    }
}

} // namespace

Bytes OutPointBytes(const OutPoint &op) {
    Bytes b(op.txid.hash.b.begin(), op.txid.hash.b.end());
    for (int i = 3; i >= 0; --i) {
        b.push_back(uint8_t(op.out_idx >> (8 * i)));
    }
    return b;
}

OutPoint OutPointDecode(ByteView b) {
    if (b.size() != 36) {
        ThrowCorrupt();
    }
    OutPoint op;
    op.txid.hash = Hash32::FromBytes(b.first(32));
    op.out_idx = uint32_t(b[32]) << 24 | uint32_t(b[33]) << 16 |
                 uint32_t(b[34]) << 8 | uint32_t(b[35]);
    return op;
}

Bytes PrefixKey(uint8_t prefix, ByteView bytes) {
    Bytes k{prefix};
    k.insert(k.end(), bytes.begin(), bytes.end());
    return k;
}

Bytes PostingPrefix(const Hash32 &root, std::optional<uint8_t> position) {
    Bytes k = PrefixKey('p', root.b);
    k.push_back(position.value_or(255));
    return k;
}

// ---- V2Db ----

V2Db::V2Db(const std::filesystem::path &path, const Binding &binding)
    : m_db(std::make_unique<V2Env>(path)), m_binding(binding) {
    const Bytes identity = Identity(binding);
    const auto existing = m_db->Get(Str("v2-binding"));
    if (existing) {
        if (*existing != identity) {
            ThrowInvalid("binding/schema mismatch");
        }
        return;
    }
    if (!m_db->IsEmpty()) {
        ThrowInvalid("nonempty foreign database");
    }
    V2WriteBatch batch;
    batch.Put(StrBytes("v2-binding"), identity);
    WriteBatch(*m_db, batch);
}

std::optional<Anchor> V2Db::Checkpoint() const {
    const auto bytes = m_db->Get(Str("tip"));
    if (!bytes) {
        return std::nullopt;
    }
    return codec::Decode<Anchor>(*bytes);
}

void V2Db::InitializeGenesis(const CommittedBlock &block) {
    if (block.parent != block.anchor) {
        ThrowInvalid("genesis parent");
    }
    ConnectImpl(block, true);
}

ReadSnapshot V2Db::Snapshot() const {
    V2EnvSnapshot inner = m_db->Snapshot();
    const auto tip = inner.Get(Str("tip"));
    if (!tip) {
        ThrowInvalid("uninitialized index");
    }
    const Anchor anchor = codec::Decode<Anchor>(*tip);
    return ReadSnapshot(std::move(inner), anchor, m_binding);
}

void V2Db::Connect(const CommittedBlock &block) { ConnectImpl(block, false); }

void V2Db::ConnectImpl(const CommittedBlock &block, bool genesis) {
    if (block.transactions.size() > MAX_TRANSACTIONS) {
        ThrowInvalid("transaction bound");
    }
    if ((!genesis &&
         (block.parent.height == UINT64_MAX ||
          block.parent.height + 1 != block.anchor.height ||
          block.anchor.block_id == block.parent.block_id)) ||
        (genesis && (block.anchor.height != 0 ||
                     block.anchor.block_id != m_binding.genesis))) {
        ThrowInvalid("block identity");
    }
    // Conservative staging reservation includes receipt, old/new records,
    // map nodes, posting keys, undo encoding and batch framing. Reject before
    // allocating receipt/maps rather than constructing a huge rejected batch.
    size_t reserved = 1024;
    Reserve(reserved, PreflightExplorerBlock(block));
    for (const ConfirmedTx &tx : block.transactions) {
        Reserve(reserved, 512);
        const size_t items = tx.outputs.size() + tx.spends.size() +
                             tx.explorer.inputs.size();
        if (items > SIZE_MAX / 8192) {
            ThrowInvalid("asset staging capacity");
        }
        Reserve(reserved, items * 8192);
        constexpr size_t per_spend = 6 * MAX_BRANCH_RECORD_BYTES + 1024;
        if (tx.spends.size() > SIZE_MAX / per_spend) {
            ThrowInvalid("staging capacity");
        }
        Reserve(reserved, tx.spends.size() * per_spend);
        for (const Output &output : tx.outputs) {
            if (output.Validate()) {
                ThrowInvalid("output");
            }
            Reserve(reserved, 6 * MAX_BRANCH_RECORD_BYTES +
                                  output.branches.size() * 2 * 512);
        }
    }
    size_t changes = 0;
    std::set<TxId> txids;
    std::vector<ReceiptTx> receipt;
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        const ConfirmedTx &tx = block.transactions[i];
        changes += tx.outputs.size() + tx.spends.size();
        if (changes > MAX_CHANGES) {
            ThrowInvalid("change bound");
        }
        if (tx.location.block_id.b != block.anchor.block_id ||
            tx.location.height != block.anchor.height ||
            tx.location.tx_index != i ||
            !txids.insert(tx.location.txid).second) {
            ThrowInvalid("transaction identity/order");
        }
        ReceiptTx r;
        r.location = tx.location;
        for (const Output &o : tx.outputs) {
            r.outputs.push_back(EncodeOutputOr(o, "output"));
        }
        for (const SpentInput &s : tx.spends) {
            r.spends.emplace_back(s.outpoint.txid.hash.b, s.outpoint.out_idx,
                                  s.input_index);
        }
        r.lock = tx.explorer.lock;
        r.inputs = tx.explorer.inputs;
        r.wire_size = tx.explorer.wire.size();
        r.wire_checksum = SeaHash(tx.explorer.wire);
        receipt.push_back(std::move(r));
    }
    const auto tip = Checkpoint();
    const Bytes block_key = PrefixKey('b', block.anchor.block_id);
    if (tip == block.anchor) {
        const auto stored = m_db->Get(block_key);
        if (!stored || stored->size() > MAX_BATCH_BYTES) {
            ThrowCorrupt();
        }
        Receipt prior = Dec<Receipt>(*stored);
        if (prior.transactions.size() != receipt.size()) {
            ThrowInvalid("conflicting replay");
        }
        for (size_t i = 0; i < receipt.size(); ++i) {
            ReceiptTx &incoming = receipt[i];
            ReceiptTx &old = prior.transactions[i];
            if (incoming.inputs.size() != old.inputs.size() ||
                incoming.wire_size != old.wire_size ||
                incoming.wire_checksum != old.wire_checksum) {
                ThrowInvalid("conflicting replay");
            }
            Bytes disk_wire;
            try {
                disk_wire = m_db->Flat().ReadAt(old.file_num, old.data_pos,
                                                size_t(old.wire_size));
            } catch (const V2Error &) {
                ThrowCorrupt();
            }
            if (disk_wire != block.transactions[i].explorer.wire) {
                ThrowInvalid("conflicting replay");
            }
            incoming.file_num = old.file_num;
            incoming.data_pos = old.data_pos;
            for (size_t j = 0; j < incoming.inputs.size(); ++j) {
                auto &input = incoming.inputs[j];
                auto &old_input = old.inputs[j];
                if (input.resolved_creation &&
                    input.resolved_creation != old_input.resolved_creation) {
                    ThrowInvalid("caller resolved coin");
                }
                input.resolved_creation = old_input.resolved_creation;
            }
        }
        if (Enc(Receipt{block.anchor, block.parent, block.explorer,
                        std::move(receipt)}) != *stored) {
            ThrowInvalid("conflicting replay");
        }
        return;
    }
    // Resolve and apply in-block parents before their children: the host
    // may confirm blocks in canonical (txid) order, where a child can precede
    // the parent whose output it spends.
    const std::vector<size_t> order = ProcessingOrder(block.transactions);
    CommittedBlock resolved = block;
    std::map<OutPoint, ResolvedCreation> creations;
    for (const size_t tx_index : order) {
        ConfirmedTx &tx = resolved.transactions[tx_index];
        for (size_t index = 0; index < tx.explorer.inputs.size(); ++index) {
            InputFact &input = tx.explorer.inputs[index];
            if (input.flags == 1) {
                const OutPoint op{TxId{H(input.prev_txid)}, input.prev_index};
                if (std::none_of(tx.spends.begin(), tx.spends.end(),
                                 [&](const SpentInput &s) {
                                     return s.input_index == index &&
                                            s.outpoint == op;
                                 })) {
                    ThrowInvalid("full spend mismatch");
                }
                ResolvedCreation creation;
                if (auto it = creations.find(op); it != creations.end()) {
                    creation = it->second;
                } else {
                    const auto bytes =
                        m_db->Get(PrefixKey('o', OutPointBytes(op)));
                    if (!bytes) {
                        ThrowInvalid("missing coin");
                    }
                    OutputRecord r = Public(DecodeRecord(*bytes), op);
                    creation = ResolvedCreation{op, std::move(r.output),
                                                r.creation};
                }
                if (input.resolved_creation &&
                    *input.resolved_creation != creation) {
                    ThrowInvalid("caller resolved coin");
                }
                input.resolved_creation = std::move(creation);
            } else if (input.resolved_creation) {
                ThrowInvalid("nonspend resolved coin");
            }
        }
        for (const SpentInput &s : tx.spends) {
            if (s.input_index >= tx.explorer.inputs.size() ||
                tx.explorer.inputs[s.input_index].flags != 1) {
                ThrowInvalid("full spend missing");
            }
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const OutPoint op{tx.location.txid, uint32_t(i)};
            creations[op] = ResolvedCreation{op, tx.outputs[i], tx.location};
        }
    }
    if ((genesis ? tip.has_value() : tip != block.parent) ||
        m_db->Get(block_key)) {
        ThrowInvalid("checkpoint/duplicate block");
    }
    FlatPos prev_flat_pos{0, 0};
    if (const auto bytes = m_db->Get(Str("flat_pos"))) {
        prev_flat_pos = Dec<FlatPos>(*bytes);
    }
    ExplorerPlan plan = PlanExplorerBlockAt(resolved, prev_flat_pos.first,
                                            prev_flat_pos.second);
    for (size_t i = 0;
         i < receipt.size() && i < plan.flat_writes.size(); ++i) {
        receipt[i].inputs = resolved.transactions[i].explorer.inputs;
        receipt[i].file_num = plan.flat_writes[i].file_num;
        receipt[i].data_pos = plan.flat_writes[i].data_pos;
    }
    const Bytes receipt_bytes =
        Enc(Receipt{block.anchor, block.parent, block.explorer, receipt});
    if (receipt_bytes.size() > MAX_BATCH_BYTES) {
        ThrowInvalid("receipt bound");
    }
    std::map<Bytes, std::optional<Bytes>> state;
    std::map<Bytes, std::optional<Bytes>> undo;
    std::set<OutPoint> spent;
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = block.transactions[tx_index];
        const Bytes tx_key = PrefixKey('t', tx.location.txid.hash.b);
        if (m_db->Get(tx_key)) {
            ThrowInvalid("duplicate transaction");
        }
        undo[tx_key] = std::nullopt;
        state[tx_key] = codec::Encode(tx.location);
        for (size_t i = 1; i < tx.spends.size(); ++i) {
            if (tx.spends[i - 1].input_index >= tx.spends[i].input_index) {
                ThrowInvalid("input ordinal order");
            }
        }
        std::set<uint32_t> input_ordinals;
        for (const SpentInput &input : tx.spends) {
            const OutPoint &op = input.outpoint;
            if (!input_ordinals.insert(input.input_index).second) {
                ThrowInvalid("duplicate input ordinal");
            }
            if (!spent.insert(op).second) {
                ThrowInvalid("double spend");
            }
            const Bytes k = PrefixKey('o', OutPointBytes(op));
            std::optional<Bytes> previous;
            if (auto it = state.find(k); it != state.end()) {
                previous = it->second;
            } else {
                previous = m_db->Get(k);
            }
            if (!previous) {
                ThrowInvalid("missing coin");
            }
            Record record = DecodeRecord(*previous);
            if (record.spend || DecodeOutputOrCorrupt(record.output).IsBurn()) {
                ThrowInvalid("spent/burn coin");
            }
            if (!undo.count(k)) {
                undo[k] = m_db->Get(k);
            }
            record.spend = std::make_pair(tx.location, input.input_index);
            state[k] = Enc(record);
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const Output &output = tx.outputs[i];
            if (i > UINT32_MAX) {
                ThrowInvalid("output index");
            }
            const OutPoint op{tx.location.txid, uint32_t(i)};
            const Bytes k = PrefixKey('o', OutPointBytes(op));
            if (state.count(k) || m_db->Get(k)) {
                ThrowInvalid("duplicate outpoint");
            }
            undo[k] = std::nullopt;
            state[k] = Enc(Record{EncodeOutputOr(output, "output"),
                                  tx.location, std::nullopt});
            for (size_t position = 0; position < output.branches.size();
                 ++position) {
                for (uint8_t pos : {uint8_t(position), uint8_t(255)}) {
                    const Bytes pk =
                        PostingKey(output.branches[position], pos, op);
                    undo[pk] = std::nullopt;
                    state[pk] = Bytes{};
                }
            }
        }
    }
    for (auto &[k, v] : plan.entries) {
        if (state.count(k) || m_db->Get(k)) {
            ThrowInvalid("duplicate explorer key");
        }
        undo[k] = std::nullopt;
        state[k] = std::move(v);
    }
    for (auto &[k, v] : AssetEntries(resolved, order, [&](const Bytes &key) {
             return m_db->Get(key);
         })) {
        auto old = m_db->Get(k);
        if (!StartsWith(k, "eA") && old) {
            ThrowInvalid("duplicate asset entry");
        }
        if (!undo.count(k)) {
            undo[k] = std::move(old);
        }
        state[k] = std::move(v);
    }
    Undo undo_record{m_binding,
                     block.anchor,
                     genesis ? std::nullopt : std::optional<Anchor>(block.parent),
                     prev_flat_pos,
                     {}};
    for (auto &[k, v] : undo) {
        undo_record.entries.emplace_back(k, std::move(v));
    }
    const Bytes undo_bytes = Enc(undo_record);
    size_t flat_bytes = 0;
    for (const FlatWrite &w : plan.flat_writes) {
        flat_bytes += w.wire.size();
    }
    size_t size = receipt_bytes.size() + undo_bytes.size() + flat_bytes;
    for (const auto &[k, v] : state) {
        size += k.size() + (v ? v->size() : 0);
    }
    if (size > MAX_BATCH_BYTES) {
        ThrowInvalid("batch bound");
    }
    std::set<uint32_t> synced_files;
    for (const FlatWrite &w : plan.flat_writes) {
        m_db->Flat().WriteAt(w.file_num, w.data_pos, w.wire);
        synced_files.insert(w.file_num);
    }
    for (uint32_t file_num : synced_files) {
        m_db->Flat().SyncFile(file_num);
    }
    V2WriteBatch batch;
    for (auto &[k, v] : state) {
        if (v) {
            batch.Put(k, std::move(*v));
        }
    }
    batch.Put(block_key, receipt_bytes);
    batch.Put(PrefixKey('u', block.anchor.block_id), undo_bytes);
    batch.Put(StrBytes("flat_pos"), Enc(plan.next_flat_pos));
    batch.Put(StrBytes("tip"), codec::Encode(block.anchor));
    batch.Delete(StrBytes("disconnected"));
    WriteBatch(*m_db, batch);
}

void V2Db::Disconnect(const Anchor &anchor) {
    if (anchor.height == 0) {
        ThrowInvalid("genesis disconnect");
    }
    const Anchor tip = Snapshot().anchor;
    if (tip != anchor) {
        if (m_db->Get(Str("disconnected")) == codec::Encode(anchor)) {
            return;
        }
        ThrowInvalid("disconnect checkpoint");
    }
    const auto bytes = m_db->Get(PrefixKey('u', anchor.block_id));
    if (!bytes) {
        ThrowInvalid("missing undo");
    }
    if (bytes->size() > MAX_BATCH_BYTES) {
        ThrowCorrupt();
    }
    Undo undo = Dec<Undo>(*bytes);
    ValidateUndo(*m_db, m_binding, anchor, undo);
    if (!undo.parent) {
        ThrowCorrupt();
    }
    const Anchor parent = *undo.parent;
    V2WriteBatch batch;
    for (auto &[k, v] : undo.entries) {
        if (v) {
            batch.Put(k, std::move(*v));
        } else {
            batch.Delete(k);
        }
    }
    batch.Delete(PrefixKey('b', anchor.block_id));
    batch.Delete(PrefixKey('u', anchor.block_id));
    batch.Put(StrBytes("flat_pos"), Enc(undo.prev_flat_pos));
    batch.Put(StrBytes("tip"), codec::Encode(parent));
    batch.Put(StrBytes("disconnected"), codec::Encode(anchor));
    WriteBatch(*m_db, batch);
    m_db->Flat().TruncateTo(undo.prev_flat_pos.first,
                            undo.prev_flat_pos.second);
}

// ---- ReadSnapshot branch readers ----

std::optional<TxLocation> ReadSnapshot::Transaction(const TxId &txid) const {
    AssetReadBudget budget(SIZE_MAX);
    return TransactionCounted(txid, budget);
}

std::optional<TxLocation>
ReadSnapshot::TransactionCounted(const TxId &txid,
                                 AssetReadBudget &budget) const {
    budget.Charge();
    const auto bytes = m_inner.Get(PrefixKey('t', txid.hash.b));
    if (!bytes) {
        return std::nullopt;
    }
    if (bytes->size() > 128) {
        ThrowCorrupt();
    }
    const auto location = codec::Decode<TxLocation>(*bytes);
    if (location.txid != txid || location.height > anchor.height) {
        ThrowCorrupt();
    }
    budget.Charge();
    const auto block = m_inner.Get(HeightKey(location.height));
    if (!block || !std::ranges::equal(*block, location.block_id.b)) {
        ThrowCorrupt();
    }
    return location;
}

std::optional<OutputRecord> ReadSnapshot::GetOutput(const OutPoint &op) const {
    AssetReadBudget budget(SIZE_MAX);
    return OutputCounted(op, budget);
}

std::optional<OutputRecord>
ReadSnapshot::OutputCounted(const OutPoint &op, AssetReadBudget &budget) const {
    budget.Charge();
    const auto bytes = m_inner.Get(PrefixKey('o', OutPointBytes(op)));
    if (!bytes) {
        return std::nullopt;
    }
    OutputRecord record = Public(DecodeRecord(*bytes), op);
    if (TransactionCounted(record.creation.txid, budget) != record.creation ||
        record.creation.height > anchor.height) {
        ThrowCorrupt();
    }
    if (record.spend) {
        const TxLocation &spender = record.spend->transaction;
        if (TransactionCounted(spender.txid, budget) != spender ||
            spender.height > anchor.height) {
            ThrowCorrupt();
        }
    }
    return record;
}

std::optional<OutputRecord> ReadSnapshot::Utxo(const OutPoint &op) const {
    auto record = GetOutput(op);
    if (record && (record->spend || record->output.IsBurn())) {
        return std::nullopt;
    }
    return record;
}

namespace {
std::optional<std::array<uint8_t, 36>>
OpArray(const std::optional<OutPoint> &op) {
    if (!op) {
        return std::nullopt;
    }
    const Bytes b = OutPointBytes(*op);
    std::array<uint8_t, 36> a;
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}
} // namespace

std::optional<OutPoint>
ReadSnapshot::NextPosting(const Hash32 &root, std::optional<uint8_t> position,
                          std::optional<OutPoint> after) const {
    if (position && *position >= 16) {
        ThrowInvalid("position");
    }
    const auto bytes = m_inner.NextPostingDupfixed(
        root.b, position.value_or(255), OpArray(after));
    if (!bytes) {
        return std::nullopt;
    }
    return OutPointDecode(*bytes);
}

std::vector<OutPoint>
ReadSnapshot::PostingsAfter(const Hash32 &root, std::optional<uint8_t> position,
                            std::optional<OutPoint> after) const {
    if (position && *position >= 16) {
        ThrowInvalid("position");
    }
    std::vector<OutPoint> out;
    for (const auto &raw : m_inner.PostingsDupfixedAfter(
             root.b, position.value_or(255), OpArray(after))) {
        out.push_back(OutPointDecode(raw));
    }
    return out;
}

} // namespace chronik::native::lotus_v2
