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

/**
 * v2_branch.rs `Coin`: coin facts of one output and its spend. The complete
 * output is read from its creating transaction through the node; creation
 * and spend locations are joined from the transaction location index.
 */
struct Coin {
    uint8_t flags = 0;
    uint64_t value = 0;
    std::optional<Bytes32> token_id;
    std::optional<std::pair<Bytes32, uint32_t>> spend;
    bool operator==(const Coin &) const = default;

    static Coin New(const Output &output) {
        Coin c{output.flags, output.value, std::nullopt, std::nullopt};
        if (output.HasToken()) {
            c.token_id = output.token_id.b;
        }
        return c;
    }
    bool Matches(const Output &output) const {
        return flags == output.flags && value == output.value &&
               token_id == (output.HasToken()
                                ? std::optional<Bytes32>(output.token_id.b)
                                : std::nullopt);
    }
    bool IsBurn() const { return (flags & 2) != 0; }
    SpentCoin Spent(const OutPoint &outpoint) const {
        return SpentCoin{outpoint, flags, value,
                         token_id ? H(*token_id) : Hash32{}};
    }
};
/** Largest encoded Coin: flags, value, token and spend reference. */
constexpr size_t MAX_COIN_BYTES = 96;

/** v2_branch.rs `ReceiptTx`. */
struct ReceiptTx {
    TxLocation location;
    uint32_t file_num = 0;
    uint32_t data_pos = 0;
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
    std::vector<std::pair<Bytes, std::optional<Bytes>>> entries;
};

void Write(Writer &w, const Coin &v) {
    w.U8(v.flags);
    w.U64(v.value);
    w.OptionTag(v.token_id.has_value());
    if (v.token_id) {
        w.Raw(*v.token_id);
    }
    w.OptionTag(v.spend.has_value());
    if (v.spend) {
        w.Raw(v.spend->first);
        w.U32(v.spend->second);
    }
}
void Read(Reader &r, Coin &v) {
    v.flags = r.U8();
    v.value = r.U64();
    v.token_id.reset();
    if (r.OptionTag()) {
        v.token_id = r.Array<32>();
    }
    v.spend.reset();
    if (r.OptionTag()) {
        const Bytes32 txid = r.Array<32>();
        v.spend.emplace(txid, r.U32());
    }
}
void Write(Writer &w, const ReceiptTx &v) {
    codec::Write(w, v.location);
    w.U32(v.file_num);
    w.U32(v.data_pos);
    w.U64(v.wire_size);
    w.U64(v.wire_checksum);
}
void Read(Reader &r, ReceiptTx &v) {
    codec::Read(r, v.location);
    v.file_num = r.U32();
    v.data_pos = r.U32();
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

Coin DecodeCoin(ByteView bytes) {
    if (bytes.size() > MAX_COIN_BYTES) {
        ThrowCorrupt();
    }
    Coin coin = Dec<Coin>(bytes);
    if ((coin.flags & ~7) != 0 ||
        coin.token_id.has_value() != ((coin.flags & 1) != 0)) {
        ThrowCorrupt();
    }
    return coin;
}

/**
 * Load a recorded transaction through the node, checking that it is the
 * transaction the index recorded at that position.
 */
NodeTx LoadChecked(const TxSource &source, const TxLocation &location,
                   const TxPos &pos, uint64_t wire_size,
                   uint64_t wire_checksum) {
    NodeTx tx;
    try {
        tx = source.LoadTx(pos, location.txid, location.tx_index == 0);
    } catch (const V2Error &) {
        throw;
    } catch (const std::exception &e) {
        throw V2Error::Node(e.what());
    }
    if (tx.txid != location.txid || tx.txhash != location.txhash ||
        tx.explorer.wire.size() != wire_size ||
        SeaHash(tx.explorer.wire) != wire_checksum) {
        ThrowCorrupt();
    }
    return tx;
}

void Reserve(size_t &total, size_t bytes, const Bounds &bounds) {
    if (bytes > bounds.BatchBytes() || total + bytes > bounds.BatchBytes()) {
        ThrowInvalid("staging capacity");
    }
    total += bytes;
}

void WriteBatch(V2Env &db, const V2WriteBatch &batch, const Bounds &bounds) {
    if (batch.SizeInBytes() > bounds.BatchBytes()) {
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

/**
 * Asset entries of a block; `spent_coins[i]` holds the resolved spends of
 * transaction i in input order.
 */
std::map<Bytes, Bytes>
AssetEntries(const CommittedBlock &block, const std::vector<size_t> &order,
             const std::vector<std::vector<SpentCoin>> &spent_coins,
             const OldValueFn &old_value) {
    std::map<Bytes, Bytes> entries;
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = block.transactions[tx_index];
        std::vector<Hash32> mint_token_ids;
        for (const InputFact &input : tx.explorer.inputs) {
            if (input.flags == 3) {
                mint_token_ids.push_back(H(input.prev_txid));
            }
        }
        const AssetTxView view{tx.location, tx.outputs, spent_coins[tx_index],
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

/**
 * Check that an undo log inverts exactly the indexed tip block. The block is
 * rebuilt from the node through `source` (its receipt keeps only positions),
 * and every key the block wrote must hold the value it wrote, with the
 * undo's prior value being the one connect replaced.
 */
void ValidateUndo(const V2Env &db, const TxSource &source,
                  const Binding &binding, const Bounds &bounds,
                  const Anchor &anchor, const Undo &undo) {
    if (!undo.parent) {
        ThrowCorrupt();
    }
    const Anchor parent = *undo.parent;
    if (undo.binding != binding || undo.anchor != anchor ||
        parent.height == UINT64_MAX || parent.height + 1 != anchor.height ||
        (parent.height == 0 && parent.block_id != binding.genesis) ||
        undo.entries.size() > bounds.BatchBytes() / 40) {
        ThrowCorrupt();
    }
    const auto receipt_bytes = db.Get(PrefixKey('b', anchor.block_id));
    if (!receipt_bytes || receipt_bytes->size() > bounds.BatchBytes()) {
        ThrowCorrupt();
    }
    const Receipt receipt = Dec<Receipt>(*receipt_bytes);
    const auto &transactions = receipt.transactions;
    if (receipt.anchor != anchor || receipt.parent != parent ||
        transactions.size() > bounds.Transactions()) {
        ThrowCorrupt();
    }
    auto reserve = [&bounds](size_t &total, size_t bytes) {
        try {
            Reserve(total, bytes, bounds);
        } catch (const V2Error &) {
            ThrowCorrupt();
        }
    };
    size_t reservation = 1024;
    CommittedBlock block{anchor, parent, {}, receipt.explorer};
    for (size_t index = 0; index < transactions.size(); ++index) {
        const ReceiptTx &tx = transactions[index];
        if (tx.location.block_id.b != anchor.block_id ||
            tx.location.height != anchor.height ||
            tx.location.tx_index != index || tx.wire_size == 0 ||
            tx.wire_size > bounds.BlockBytes()) {
            ThrowCorrupt();
        }
        const TxPos pos{tx.file_num, tx.data_pos};
        NodeTx node =
            LoadChecked(source, tx.location, pos, tx.wire_size,
                        tx.wire_checksum);
        if (node.spends.size() > SIZE_MAX / RESERVE_SPEND) {
            ThrowCorrupt();
        }
        reserve(reservation, RESERVE_TX + node.spends.size() * RESERVE_SPEND);
        for (const Output &output : node.outputs) {
            reserve(reservation,
                    RESERVE_OUTPUT + output.branches.size() * RESERVE_BRANCH);
        }
        block.transactions.push_back(ConfirmedTx{
            tx.location, std::move(node.outputs), std::move(node.spends),
            std::move(node.explorer), pos});
    }
    reserve(reservation, PreflightExplorerBlock(block));
    std::map<Bytes, std::optional<Bytes>> undo_map;
    for (const auto &[k, v] : undo.entries) {
        undo_map.emplace(k, v);
    }
    if (undo_map.size() != undo.entries.size()) {
        ThrowCorrupt();
    }
    std::set<TxId> in_block;
    for (const ConfirmedTx &tx : block.transactions) {
        in_block.insert(tx.location.txid);
    }
    const std::vector<size_t> order = ProcessingOrder(block.transactions);
    // Value of every key the block wrote, and the prior value its undo must
    // restore.
    std::map<Bytes, Bytes> current;
    std::map<Bytes, std::optional<Bytes>> previous;
    std::vector<std::vector<SpentCoin>> spent_coins(block.transactions.size());
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = block.transactions[tx_index];
        const Bytes tk = PrefixKey('t', tx.location.txid.hash.b);
        current[tk] = codec::Encode(tx.location);
        previous[tk] = std::nullopt;
        for (const SpentInput &spend : tx.spends) {
            const OutPoint &op = spend.outpoint;
            const Bytes k = PrefixKey('o', OutPointBytes(op));
            Coin before;
            if (auto it = current.find(k); it != current.end()) {
                before = DecodeCoin(it->second);
            } else {
                // A coin created before this block: its undo value is the
                // unspent coin, created at or below the parent.
                auto u = undo_map.find(k);
                if (u == undo_map.end() || !u->second) {
                    ThrowCorrupt();
                }
                const auto loc_bytes = db.Get(PrefixKey('t', op.txid.hash.b));
                if (!loc_bytes) {
                    ThrowCorrupt();
                }
                const auto creation = codec::Decode<TxLocation>(*loc_bytes);
                if (in_block.count(op.txid) || creation.txid != op.txid ||
                    creation.height > parent.height) {
                    ThrowCorrupt();
                }
                before = DecodeCoin(*u->second);
                previous[k] = u->second;
            }
            if (before.spend || before.IsBurn()) {
                ThrowCorrupt();
            }
            spent_coins[tx_index].push_back(before.Spent(op));
            Coin after = before;
            after.spend = std::make_pair(tx.location.txid.hash.b,
                                         spend.input_index);
            current[k] = Enc(after);
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const Output &output = tx.outputs[i];
            if (i > UINT32_MAX) {
                ThrowCorrupt();
            }
            const OutPoint op{tx.location.txid, uint32_t(i)};
            const Bytes k = PrefixKey('o', OutPointBytes(op));
            if (!current.emplace(k, Enc(Coin::New(output))).second) {
                ThrowCorrupt();
            }
            previous[k] = std::nullopt;
            for (size_t b = 0; b < output.branches.size(); ++b) {
                for (uint8_t pos : {uint8_t(b), uint8_t(255)}) {
                    const Bytes pk = PostingKey(output.branches[b], pos, op);
                    current[pk] = Bytes{};
                    previous[pk] = std::nullopt;
                }
            }
        }
    }
    for (auto &[k, v] : PlanExplorerBlock(block)) {
        if (!current.emplace(k, std::move(v)).second) {
            ThrowCorrupt();
        }
        previous[k] = std::nullopt;
    }
    for (auto &[k, v] :
         AssetEntries(block, order, spent_coins,
                      [&](const Bytes &key) -> std::optional<Bytes> {
                          auto it = undo_map.find(key);
                          return it == undo_map.end() ? std::nullopt
                                                      : it->second;
                      })) {
        auto prior = undo_map.find(k);
        if (prior == undo_map.end() ||
            !current.emplace(k, std::move(v)).second ||
            (!StartsWith(k, "eA") && prior->second)) {
            ThrowCorrupt();
        }
        previous[k] = prior->second;
    }
    if (previous != undo_map) {
        ThrowCorrupt();
    }
    for (const auto &[k, v] : current) {
        if (db.Get(k) != v) {
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

V2Db::V2Db(const std::filesystem::path &path, const Binding &binding,
           const Bounds &bounds)
    : V2Db(path, binding, bounds, std::make_shared<MemTxSource>()) {}

V2Db::V2Db(const std::filesystem::path &path, const Binding &binding,
           const Bounds &bounds, std::shared_ptr<MemTxSource> recorder)
    : V2Db(path, binding, bounds,
           std::static_pointer_cast<const TxSource>(recorder)) {
    m_recorder = std::move(recorder);
}

V2Db::V2Db(const std::filesystem::path &path, const Binding &binding,
           const Bounds &bounds, std::shared_ptr<const TxSource> source)
    : m_db(std::make_unique<V2Env>(path)), m_binding(binding),
      m_bounds(bounds), m_source(std::move(source)) {
    const Bytes identity = Identity(binding);
    const auto existing = m_db->Get(Str("v2-binding"));
    if (existing) {
        uint32_t version = 0;
        Binding stored;
        try {
            Reader r(*existing);
            version = r.U32();
            codec::Read(r, stored);
        } catch (const postcard::Error &) {
            ThrowCorrupt();
        }
        if (version != SCHEMA_VERSION) {
            throw V2Error::Schema(version, SCHEMA_VERSION);
        }
        if (stored != binding || *existing != identity) {
            ThrowInvalid("binding/schema mismatch");
        }
        return;
    }
    if (!m_db->IsEmpty()) {
        ThrowInvalid("nonempty foreign database");
    }
    V2WriteBatch batch;
    batch.Put(StrBytes("v2-binding"), identity);
    WriteBatch(*m_db, batch, m_bounds);
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
    return ReadSnapshot(std::move(inner), anchor, m_binding, m_bounds,
                        m_source);
}

void V2Db::Connect(const CommittedBlock &block) { ConnectImpl(block, false); }

void V2Db::ConnectImpl(const CommittedBlock &block, bool genesis) {
    if (block.transactions.size() > m_bounds.Transactions()) {
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
    Reserve(reserved, PreflightExplorerBlock(block), m_bounds);
    for (const ConfirmedTx &tx : block.transactions) {
        Reserve(reserved, RESERVE_TX, m_bounds);
        const size_t items = tx.outputs.size() + tx.spends.size() +
                             tx.explorer.inputs.size();
        if (items > SIZE_MAX / RESERVE_ASSET_ELEMENT) {
            ThrowInvalid("asset staging capacity");
        }
        Reserve(reserved, items * RESERVE_ASSET_ELEMENT, m_bounds);
        if (tx.spends.size() > SIZE_MAX / RESERVE_SPEND) {
            ThrowInvalid("staging capacity");
        }
        Reserve(reserved, tx.spends.size() * RESERVE_SPEND, m_bounds);
        for (const Output &output : tx.outputs) {
            if (output.Validate()) {
                ThrowInvalid("output");
            }
            Reserve(reserved,
                    RESERVE_OUTPUT + output.branches.size() * RESERVE_BRANCH,
                    m_bounds);
        }
    }
    size_t changes = 0;
    std::set<TxId> txids;
    std::vector<ReceiptTx> receipt;
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        const ConfirmedTx &tx = block.transactions[i];
        changes += tx.outputs.size() + tx.spends.size();
        if (changes > m_bounds.Changes()) {
            ThrowInvalid("change bound");
        }
        if (tx.location.block_id.b != block.anchor.block_id ||
            tx.location.height != block.anchor.height ||
            tx.location.tx_index != i ||
            !txids.insert(tx.location.txid).second) {
            ThrowInvalid("transaction identity/order");
        }
        for (const Output &o : tx.outputs) {
            if (!o.Encode()) {
                ThrowInvalid("output");
            }
        }
        receipt.push_back(ReceiptTx{tx.location, tx.pos.file_num,
                                    tx.pos.data_pos, tx.explorer.wire.size(),
                                    SeaHash(tx.explorer.wire)});
    }
    const Bytes receipt_bytes =
        Enc(Receipt{block.anchor, block.parent, block.explorer, receipt});
    if (receipt_bytes.size() > m_bounds.BatchBytes()) {
        ThrowInvalid("receipt bound");
    }
    const auto tip = Checkpoint();
    const Bytes block_key = PrefixKey('b', block.anchor.block_id);
    if (tip == block.anchor) {
        CheckReplay(block, block_key, receipt_bytes);
        return;
    }
    // Resolve the asset facts of every spend: from in-block parents, which
    // are applied before their children (the host may confirm blocks in
    // canonical (txid) order, where a child can precede the parent whose
    // output it spends), or from the coin index.
    const std::vector<size_t> order = ProcessingOrder(block.transactions);
    std::map<OutPoint, SpentCoin> created;
    std::vector<std::vector<SpentCoin>> spent_coins(block.transactions.size());
    for (const size_t tx_index : order) {
        const ConfirmedTx &tx = block.transactions[tx_index];
        for (size_t index = 0; index < tx.explorer.inputs.size(); ++index) {
            const InputFact &input = tx.explorer.inputs[index];
            if (input.flags != 1) {
                continue;
            }
            const OutPoint op{TxId{H(input.prev_txid)}, input.prev_index};
            if (std::none_of(tx.spends.begin(), tx.spends.end(),
                             [&](const SpentInput &s) {
                                 return s.input_index == index &&
                                        s.outpoint == op;
                             })) {
                ThrowInvalid("full spend mismatch");
            }
            if (auto it = created.find(op); it != created.end()) {
                spent_coins[tx_index].push_back(it->second);
            } else {
                const auto bytes = m_db->Get(PrefixKey('o', OutPointBytes(op)));
                if (!bytes) {
                    ThrowInvalid("missing coin");
                }
                spent_coins[tx_index].push_back(DecodeCoin(*bytes).Spent(op));
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
            created[op] = SpentCoin::FromOutput(op, tx.outputs[i]);
        }
    }
    if ((genesis ? tip.has_value() : tip != block.parent) ||
        m_db->Get(block_key)) {
        ThrowInvalid("checkpoint/duplicate block");
    }
    std::vector<std::pair<Bytes, Bytes>> explorer_entries =
        PlanExplorerBlock(block);
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
            Coin coin = DecodeCoin(*previous);
            if (coin.spend || coin.IsBurn()) {
                ThrowInvalid("spent/burn coin");
            }
            if (!undo.count(k)) {
                undo[k] = m_db->Get(k);
            }
            coin.spend = std::make_pair(tx.location.txid.hash.b,
                                        input.input_index);
            state[k] = Enc(coin);
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
            state[k] = Enc(Coin::New(output));
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
    for (auto &[k, v] : explorer_entries) {
        if (state.count(k) || m_db->Get(k)) {
            ThrowInvalid("duplicate explorer key");
        }
        undo[k] = std::nullopt;
        state[k] = std::move(v);
    }
    for (auto &[k, v] :
         AssetEntries(block, order, spent_coins,
                      [&](const Bytes &key) { return m_db->Get(key); })) {
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
                     {}};
    for (auto &[k, v] : undo) {
        undo_record.entries.emplace_back(k, std::move(v));
    }
    const Bytes undo_bytes = Enc(undo_record);
    size_t size = receipt_bytes.size() + undo_bytes.size();
    for (const auto &[k, v] : state) {
        size += k.size() + (v ? v->size() : 0);
    }
    if (size > m_bounds.BatchBytes()) {
        ThrowInvalid("batch bound");
    }
    V2WriteBatch batch;
    for (auto &[k, v] : state) {
        if (v) {
            batch.Put(k, std::move(*v));
        }
    }
    batch.Put(block_key, receipt_bytes);
    batch.Put(PrefixKey('u', block.anchor.block_id), undo_bytes);
    batch.Put(StrBytes("tip"), codec::Encode(block.anchor));
    batch.Delete(StrBytes("disconnected"));
    WriteBatch(*m_db, batch, m_bounds);
    if (m_recorder) {
        m_recorder->Record(block);
    }
}

void V2Db::CheckReplay(const CommittedBlock &block, const Bytes &block_key,
                       const Bytes &receipt_bytes) const {
    const auto stored = m_db->Get(block_key);
    if (!stored || stored->size() > m_bounds.BatchBytes()) {
        ThrowCorrupt();
    }
    if (*stored != receipt_bytes) {
        ThrowInvalid("conflicting replay");
    }
    for (const auto &[k, v] : PlanExplorerBlock(block)) {
        if (m_db->Get(k) != v) {
            ThrowInvalid("conflicting replay");
        }
    }
    for (const ConfirmedTx &tx : block.transactions) {
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const auto bytes = m_db->Get(PrefixKey(
                'o', OutPointBytes(OutPoint{tx.location.txid, uint32_t(i)})));
            if (!bytes || !DecodeCoin(*bytes).Matches(tx.outputs[i])) {
                ThrowInvalid("conflicting replay");
            }
        }
        for (const SpentInput &spend : tx.spends) {
            const auto bytes =
                m_db->Get(PrefixKey('o', OutPointBytes(spend.outpoint)));
            if (!bytes ||
                DecodeCoin(*bytes).spend !=
                    std::make_optional(std::make_pair(
                        tx.location.txid.hash.b, spend.input_index))) {
                ThrowInvalid("conflicting replay");
            }
        }
    }
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
    if (bytes->size() > m_bounds.BatchBytes()) {
        ThrowCorrupt();
    }
    Undo undo = Dec<Undo>(*bytes);
    ValidateUndo(*m_db, *m_source, m_binding, m_bounds, anchor, undo);
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
    batch.Put(StrBytes("tip"), codec::Encode(parent));
    batch.Put(StrBytes("disconnected"), codec::Encode(anchor));
    WriteBatch(*m_db, batch, m_bounds);
}

// ---- ReadSnapshot branch readers ----

std::shared_ptr<const NodeTx> ReadSnapshot::NodeTxOf(const TxMeta &meta) const {
    {
        std::lock_guard lock(*m_last_mutex);
        if (m_last && m_last->first == meta) {
            return m_last->second;
        }
    }
    auto tx = std::make_shared<const NodeTx>(LoadChecked(
        *m_source, meta.location, TxPos{meta.file_num, meta.data_pos},
        meta.wire_size, meta.wire_checksum));
    if (tx->outputs.size() != meta.output_count ||
        tx->explorer.inputs.size() != meta.input_count ||
        tx->explorer.lock != meta.lock) {
        ThrowCorrupt();
    }
    std::lock_guard lock(*m_last_mutex);
    m_last = std::make_pair(meta, tx);
    return tx;
}

Output ReadSnapshot::CreationOutput(const OutPoint &op,
                                    const TxLocation &creation) const {
    const auto bytes = m_inner.Get(TxKey(op.txid));
    if (!bytes) {
        ThrowCorrupt();
    }
    const TxMeta meta = DecodeRecord<TxMeta>(*bytes);
    if (meta.location != creation || op.out_idx >= meta.output_count) {
        ThrowCorrupt();
    }
    const auto tx = NodeTxOf(meta);
    if (op.out_idx >= tx->outputs.size()) {
        ThrowCorrupt();
    }
    const Output &output = tx->outputs[op.out_idx];
    if (output.Validate()) {
        ThrowCorrupt();
    }
    return output;
}

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
    const Coin coin = DecodeCoin(*bytes);
    const auto creation = TransactionCounted(op.txid, budget);
    if (!creation) {
        ThrowCorrupt();
    }
    std::optional<SpendLocation> spend;
    if (coin.spend) {
        const auto spender = TransactionCounted(TxId{H(coin.spend->first)}, budget);
        if (!spender) {
            ThrowCorrupt();
        }
        spend = SpendLocation{*spender, coin.spend->second};
    }
    Output output = CreationOutput(op, *creation);
    if (!coin.Matches(output)) {
        ThrowCorrupt();
    }
    return OutputRecord{op, std::move(output), *creation, std::move(spend)};
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
