// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx_merklix.h"

#include "tagged_hash.h"

#include <algorithm>
#include <cassert>
#include <future>
#include <limits>
#include <new>
#include <stdexcept>
#include <system_error>
#include <thread>

namespace lotus::v2::txmerklix {

namespace {
constexpr uint32_t kGeomChunks = 11;
constexpr uint32_t kGeomSlots = 64u * ((1u << kGeomChunks) - 1u); // 131008
constexpr uint32_t kLinearChunk = 1u << 16;
//! Explicit DFS bound for releases: <= 257 branch levels, one pending sibling each.
constexpr size_t kReleaseStack = 2 * 260;
constexpr size_t kFreeBatch = 1024;
//! Parallel completion only pays for itself on large dirty trees.
constexpr uint32_t kParallelCompleteMin = 4096;

unsigned FirstDiff(const Hash &a, const Hash &b, unsigned from, unsigned to) noexcept {
    unsigned bit = from;
    while (bit < to) {
        if ((bit & 7) == 0 && bit + 8 <= to) {
            const uint8_t x = a[bit >> 3] ^ b[bit >> 3];
            if (x == 0) {
                bit += 8;
                continue;
            }
            return bit + unsigned(__builtin_ctz(x));
        }
        if (KeyBit(a, bit) != KeyBit(b, bit)) return bit;
        ++bit;
    }
    return to;
}

template <typename Node>
bool Publish(const Node &node, const Hash &digest) noexcept {
    uint8_t expected = kDirty;
    if (node.hash_state.compare_exchange_strong(expected, kBusy,
                                                std::memory_order_acquire,
                                                std::memory_order_relaxed)) {
        node.digest = digest;
        node.hash_state.store(kClean, std::memory_order_release);
        return true;
    }
    Stats().hash_cas_losses.fetch_add(1, std::memory_order_relaxed);
    return false;
}
} // namespace

GlobalStats &Stats() noexcept {
    static GlobalStats stats;
    return stats;
}

Hash EmptyDigest() {
    static const Hash digest =
        TaggedHash(HashDomain::TxRoot, std::array<uint8_t, 1>{0x02});
    return digest;
}

Hash LeafDigest(const Hash &tx_id, const Hash &tx_hash) {
    std::array<uint8_t, 65> buf{};
    buf[0] = 0x00;
    std::copy(tx_id.begin(), tx_id.end(), buf.begin() + 1);
    std::copy(tx_hash.begin(), tx_hash.end(), buf.begin() + 33);
    return TaggedHash(HashDomain::TxRoot, buf);
}

Hash BranchDigest(unsigned depth, const Hash &left, const Hash &right) {
    std::array<uint8_t, 67> buf{};
    buf[0] = 0x01;
    buf[1] = static_cast<uint8_t>(depth & 0xff);
    buf[2] = static_cast<uint8_t>((depth >> 8) & 0xff);
    std::copy(left.begin(), left.end(), buf.begin() + 3);
    std::copy(right.begin(), right.end(), buf.begin() + 35);
    return TaggedHash(HashDomain::TxRoot, buf);
}

// ===========================================================================
// Slab
// ===========================================================================

template <typename T> Slab<T>::Slab() : m_chunks(new std::atomic<T *>[kChunks]) {
    for (uint32_t i = 0; i < kChunks; ++i) {
        m_chunks[i].store(nullptr, std::memory_order_relaxed);
    }
}

template <typename T> Slab<T>::~Slab() {
    for (uint32_t slot = 0; slot < m_constructed; ++slot) At(slot).~T();
    for (uint32_t i = 0; i < kChunks; ++i) {
        if (T *chunk = m_chunks[i].load(std::memory_order_relaxed)) {
            ::operator delete(chunk, std::align_val_t{alignof(T)});
        }
    }
}

template <typename T>
typename Slab<T>::Location Slab<T>::Locate(uint32_t slot) noexcept {
    if (slot < kGeomSlots) {
        const uint32_t t = slot / 64 + 1;
        const uint32_t k = 31u - uint32_t(__builtin_clz(t));
        return {k, slot - 64u * ((1u << k) - 1u)};
    }
    const uint32_t r = slot - kGeomSlots;
    return {kGeomChunks + r / kLinearChunk, r % kLinearChunk};
}

template <typename T> uint32_t Slab<T>::ChunkSize(uint32_t chunk) noexcept {
    return chunk < kGeomChunks ? (64u << chunk) : kLinearChunk;
}

template <typename T> T &Slab<T>::At(uint32_t slot) const noexcept {
    const Location loc = Locate(slot);
    T *chunk = m_chunks[loc.chunk].load(std::memory_order_acquire);
    return chunk[loc.offset];
}

template <typename T> uint32_t Slab<T>::Allocate(bool &reused) {
    if (!m_free.empty()) {
        const uint32_t slot = m_free.back();
        m_free.pop_back();
        reused = true;
        return slot;
    }
    reused = false;
    if (m_constructed >= kMaxSlots) throw std::length_error("txmerklix slab full");
    const Location loc = Locate(m_constructed);
    T *chunk = m_chunks[loc.chunk].load(std::memory_order_relaxed);
    if (!chunk) {
        chunk = static_cast<T *>(::operator new(sizeof(T) * ChunkSize(loc.chunk),
                                                std::align_val_t{alignof(T)}));
        m_chunks[loc.chunk].store(chunk, std::memory_order_release);
    }
    // The free list's capacity always covers every constructed slot, so the
    // non-throwing Free() path never allocates. Grow geometrically.
    if (m_free.capacity() < size_t(m_constructed) + 1) {
        m_free.reserve(std::max<size_t>(64, m_free.capacity() * 2));
    }
    new (&chunk[loc.offset]) T();
    return m_constructed++;
}

template <typename T> void Slab<T>::Free(uint32_t slot) {
    m_free.push_back(slot);
}

template <typename T> void Slab<T>::ReleaseChunksIfUnused() {
    for (uint32_t slot = 0; slot < m_constructed; ++slot) At(slot).~T();
    for (uint32_t i = 0; i < kChunks; ++i) {
        if (T *chunk = m_chunks[i].load(std::memory_order_relaxed)) {
            ::operator delete(chunk, std::align_val_t{alignof(T)});
            m_chunks[i].store(nullptr, std::memory_order_relaxed);
        }
    }
    m_constructed = 0;
    m_free.clear();
    m_free.shrink_to_fit();
}

template class Slab<Branch>;
template class Slab<Leaf>;

// ===========================================================================
// Store
// ===========================================================================

std::shared_ptr<Store> Store::Create() {
    return std::shared_ptr<Store>(new Store());
}

Store::Store() {
    // Branch slot 0 is the null handle and is never handed out.
    bool reused{false};
    (void)m_branches.Allocate(reused);
    Stats().stores.fetch_add(1, std::memory_order_relaxed);
    Stats().retained_branch_slots.fetch_add(1, std::memory_order_relaxed);
}

Store::~Store() {
    auto &s = Stats();
    s.stores.fetch_sub(1, std::memory_order_relaxed);
    s.retained_branch_slots.fetch_sub(int64_t(m_branches.Constructed()),
                                      std::memory_order_relaxed);
    s.retained_leaf_slots.fetch_sub(int64_t(m_leaves.Constructed()),
                                    std::memory_order_relaxed);
}

NodeId Store::NewLeaf(const Hash &id, const Hash &hash, uint64_t minhash,
                      std::shared_ptr<const void> payload, uint32_t payload_bytes) {
    bool reused{false};
    uint32_t slot;
    {
        std::lock_guard<std::mutex> lock(m_alloc_mutex);
        if (m_next_generation == std::numeric_limits<uint64_t>::max())
            throw std::length_error("txmerklix generation exhausted");
        slot = m_leaves.Allocate(reused);
        m_leaves.At(slot).generation.store(m_next_generation++, std::memory_order_release);
    }
    auto &s = Stats();
    s.leaf_allocs.fetch_add(1, std::memory_order_relaxed);
    s.live_leaves.fetch_add(1, std::memory_order_relaxed);
    if (reused) s.slot_reuses.fetch_add(1, std::memory_order_relaxed);
    else s.retained_leaf_slots.fetch_add(1, std::memory_order_relaxed);
    Leaf &leaf = m_leaves.At(slot);
    leaf.key = id;
    leaf.tx_hash = hash;
    leaf.minhash = minhash;
    leaf.payload = std::move(payload);
    leaf.payload_bytes = payload_bytes;
    leaf.hash_state.store(kDirty, std::memory_order_relaxed);
    leaf.refs.store(1, std::memory_order_release);
    return kLeafBit | slot;
}

NodeId Store::NewBranch(const Branch &shape) {
    bool reused{false};
    uint32_t slot;
    {
        std::lock_guard<std::mutex> lock(m_alloc_mutex);
        if (m_next_generation == std::numeric_limits<uint64_t>::max())
            throw std::length_error("txmerklix generation exhausted");
        slot = m_branches.Allocate(reused);
        m_branches.At(slot).generation.store(m_next_generation++, std::memory_order_release);
    }
    auto &s = Stats();
    s.branch_allocs.fetch_add(1, std::memory_order_relaxed);
    s.live_branches.fetch_add(1, std::memory_order_relaxed);
    if (reused) s.slot_reuses.fetch_add(1, std::memory_order_relaxed);
    else s.retained_branch_slots.fetch_add(1, std::memory_order_relaxed);
    Branch &b = m_branches.At(slot);
    b.child = shape.child;
    b.count = shape.count;
    b.split = shape.split;
    b.key = shape.key;
    b.hash_state.store(kDirty, std::memory_order_relaxed);
    b.refs.store(1, std::memory_order_release);
    return slot;
}

uint32_t Store::Refs(NodeId n) const noexcept {
    if (n == kNull) return 0;
    return IsLeaf(n) ? L(n).refs.load(std::memory_order_acquire)
                     : B(n).refs.load(std::memory_order_acquire);
}

void Store::Retain(NodeId n) const noexcept {
    if (n == kNull) return;
    if (IsLeaf(n)) m_leaves.At(n & ~kLeafBit).refs.fetch_add(1, std::memory_order_relaxed);
    else m_branches.At(n).refs.fetch_add(1, std::memory_order_relaxed);
}

void Store::FreeBatch(const NodeId *dead, size_t count) const noexcept {
    if (count == 0) return;
    size_t leaves{0};
    {
        std::lock_guard<std::mutex> lock(m_alloc_mutex);
        for (size_t i = 0; i < count; ++i) {
            const NodeId n = dead[i];
            if (IsLeaf(n)) {
                m_leaves.Free(n & ~kLeafBit);
                ++leaves;
            } else {
                m_branches.Free(n);
            }
        }
    }
    auto &s = Stats();
    s.frees.fetch_add(count, std::memory_order_relaxed);
    s.live_leaves.fetch_sub(int64_t(leaves), std::memory_order_relaxed);
    s.live_branches.fetch_sub(int64_t(count - leaves), std::memory_order_relaxed);
}

void Store::Release(NodeId n) const noexcept {
    if (n == kNull) return;
    // Fast path: most releases only drop a shared reference.
    if (IsLeaf(n) ? m_leaves.At(n & ~kLeafBit).refs.fetch_sub(1, std::memory_order_acq_rel) != 1
                  : m_branches.At(n).refs.fetch_sub(1, std::memory_order_acq_rel) != 1) {
        return;
    }
    // n is dead and exclusively ours. Walk its exclusively owned descendants
    // with a bounded explicit stack; freed handles are returned in batches to
    // bound allocation-mutex hold times. No heap allocation on this path.
    std::array<NodeId, kReleaseStack> stack;
    std::array<NodeId, kFreeBatch> dead;
    size_t top{0}, ndead{0};
    auto bury = [&](NodeId x) {
        if (IsLeaf(x)) {
            m_leaves.At(x & ~kLeafBit).payload.reset();
        } else {
            Branch &b = m_branches.At(x);
            assert(top + 2 <= kReleaseStack);
            if (b.child[1] != kNull) stack[top++] = b.child[1];
            if (b.child[0] != kNull) stack[top++] = b.child[0];
            b.child = {kNull, kNull};
        }
        if (ndead == dead.size()) {
            FreeBatch(dead.data(), ndead);
            ndead = 0;
        }
        dead[ndead++] = x;
    };
    bury(n);
    while (top) {
        const NodeId x = stack[--top];
        const bool last = IsLeaf(x)
            ? m_leaves.At(x & ~kLeafBit).refs.fetch_sub(1, std::memory_order_acq_rel) == 1
            : m_branches.At(x).refs.fetch_sub(1, std::memory_order_acq_rel) == 1;
        if (last) bury(x);
    }
    FreeBatch(dead.data(), ndead);
}

Store::WeakRef Store::Weak(NodeId n) const noexcept {
    if (n == kNull) return {};
    const uint64_t gen = IsLeaf(n) ? L(n).generation.load(std::memory_order_acquire)
                                   : B(n).generation.load(std::memory_order_acquire);
    return {n, gen};
}

NodeId Store::TryRetain(const WeakRef &weak) const noexcept {
    if (weak.node == kNull) return kNull;
    // The family writer lock excludes mutation while a weak owner is added;
    // allocation lock also excludes slot reuse and slab trimming during lookup.
    std::lock_guard<std::mutex> lock(m_alloc_mutex);
    const uint32_t slot = weak.node & ~kLeafBit;
    if (IsLeaf(weak.node) ? slot >= m_leaves.Constructed()
                          : (slot == 0 || slot >= m_branches.Constructed())) {
        return kNull;
    }
    auto attempt = [&](auto &node) -> NodeId {
        if (node.generation.load(std::memory_order_acquire) != weak.generation) return kNull;
        uint32_t refs = node.refs.load(std::memory_order_relaxed);
        do {
            if (refs == 0) return kNull;
        } while (!node.refs.compare_exchange_weak(refs, refs + 1,
                                                  std::memory_order_acquire,
                                                  std::memory_order_relaxed));
        return weak.node;
    };
    if (IsLeaf(weak.node)) return attempt(m_leaves.At(slot));
    return attempt(m_branches.At(slot));
}

size_t Store::LiveLeaves() const noexcept {
    std::lock_guard<std::mutex> lock(m_alloc_mutex);
    return m_leaves.Constructed() - m_leaves.FreeSlots();
}

size_t Store::LiveBranches() const noexcept {
    std::lock_guard<std::mutex> lock(m_alloc_mutex);
    return m_branches.Constructed() - 1 - m_branches.FreeSlots();
}

size_t Store::RetainedBytes() const noexcept {
    std::lock_guard<std::mutex> lock(m_alloc_mutex);
    return m_leaves.Constructed() * sizeof(Leaf) +
           m_branches.Constructed() * sizeof(Branch);
}

bool Store::TrimIfUnused() noexcept {
    std::lock_guard<std::mutex> lock(m_alloc_mutex);
    if (m_leaves.Constructed() != m_leaves.FreeSlots() ||
        m_branches.Constructed() != m_branches.FreeSlots() + 1) {
        return false;
    }
    auto &s = Stats();
    s.retained_leaf_slots.fetch_sub(int64_t(m_leaves.Constructed()), std::memory_order_relaxed);
    s.retained_branch_slots.fetch_sub(int64_t(m_branches.Constructed()) - 1,
                                      std::memory_order_relaxed);
    m_leaves.ReleaseChunksIfUnused();
    m_branches.ReleaseChunksIfUnused();
    bool reused{false};
    try {
        (void)m_branches.Allocate(reused); // re-reserve the null handle
    } catch (...) {
        // Unreachable: the first chunk is 64 slots of a fresh slab.
        std::terminate();
    }
    return true;
}

Hash Store::NodeDigestCounted(NodeId n, uint64_t &hashes) const {
    if (IsLeaf(n)) {
        const Leaf &leaf = L(n);
        if (leaf.hash_state.load(std::memory_order_acquire) == kClean) return leaf.digest;
        const Hash h = LeafDigest(leaf.key, leaf.tx_hash);
        ++hashes;
        Publish(leaf, h);
        return h;
    }
    const Branch &b = B(n);
    if (b.hash_state.load(std::memory_order_acquire) == kClean) return b.digest;
    const unsigned below = unsigned(b.split) + 1;
    const Hash left = DigestAtCounted(b.child[0], below, hashes);
    const Hash right = DigestAtCounted(b.child[1], below, hashes);
    const Hash h = BranchDigest(b.split, left, right);
    ++hashes;
    Publish(b, h);
    return h;
}

Hash Store::DigestAtCounted(NodeId n, unsigned depth, uint64_t &hashes) const {
    if (n == kNull) return EmptyDigest();
    Hash x = NodeDigestCounted(n, hashes);
    if (IsLeaf(n)) return x;
    const Branch &b = B(n);
    for (unsigned d = b.split; d-- > depth;) {
        x = KeyBit(b.key, d) ? BranchDigest(d, EmptyDigest(), x)
                             : BranchDigest(d, x, EmptyDigest());
        ++hashes;
    }
    return x;
}

Hash Store::NodeDigest(NodeId n) const {
    uint64_t hashes{0};
    const Hash h = NodeDigestCounted(n, hashes);
    if (hashes) Stats().node_hashes.fetch_add(hashes, std::memory_order_relaxed);
    return h;
}

Hash Store::DigestAt(NodeId n, unsigned depth) const {
    uint64_t hashes{0};
    const Hash h = DigestAtCounted(n, depth, hashes);
    if (hashes) Stats().node_hashes.fetch_add(hashes, std::memory_order_relaxed);
    return h;
}

void Store::Complete(NodeId n) const {
    if (n == kNull || IsLeaf(n)) return;
    const Branch &root = B(n);
    if (root.hash_state.load(std::memory_order_acquire) == kClean ||
        root.count < kParallelCompleteMin) {
        return;
    }
    // Frontier: dirty subtrees whose split is at least 4 bits deep (<= 16).
    std::vector<NodeId> frontier;
    std::vector<NodeId> pending{n};
    while (!pending.empty()) {
        const NodeId x = pending.back();
        pending.pop_back();
        if (x == kNull || IsLeaf(x)) continue;
        const Branch &b = B(x);
        if (b.hash_state.load(std::memory_order_acquire) == kClean) continue;
        if (b.split >= 4) {
            frontier.push_back(x);
        } else {
            pending.push_back(b.child[0]);
            pending.push_back(b.child[1]);
        }
    }
    if (frontier.size() < 2) return;
    Stats().parallel_completions.fetch_add(1, std::memory_order_relaxed);
    std::vector<std::future<void>> tasks;
    tasks.reserve(frontier.size() - 1);
    try {
        for (size_t i = 1; i < frontier.size(); ++i) {
            tasks.push_back(std::async(std::launch::async, [this, x = frontier[i]] {
                (void)NodeDigest(x);
            }));
        }
    } catch (const std::system_error &) {
        // Thread exhaustion: whatever was not started is hashed serially by
        // the caller's ordinary traversal.
    }
    (void)NodeDigest(frontier[0]);
    for (auto &task : tasks) task.get();
}

// ===========================================================================
// Tree
// ===========================================================================

Tree::Tree(std::shared_ptr<Store> store)
    : m_store(store ? std::move(store) : Store::Create()) {}

Tree::Tree(const Tree &other)
    : m_store(other.m_store), m_root(other.m_root), m_version(other.m_version),
      m_payload_bytes(other.m_payload_bytes), m_sketch(other.m_sketch) {
    m_store->Retain(m_root);
}

Tree &Tree::operator=(const Tree &other) {
    if (this == &other) return *this;
    other.m_store->Retain(other.m_root);
    const auto old_store = m_store;
    const NodeId old_root = m_root;
    m_store = other.m_store;
    m_root = other.m_root;
    m_version = other.m_version;
    m_payload_bytes = other.m_payload_bytes;
    m_sketch = other.m_sketch;
    old_store->Release(old_root);
    return *this;
}

Tree::Tree(Tree &&other) noexcept
    : m_store(other.m_store), m_root(other.m_root), m_version(other.m_version),
      m_payload_bytes(other.m_payload_bytes), m_sketch(std::move(other.m_sketch)) {
    other.m_root = kNull;
    other.m_payload_bytes = 0;
    other.m_sketch.Clear();
}

Tree &Tree::operator=(Tree &&other) noexcept {
    if (this == &other) return *this;
    const auto old_store = m_store;
    const NodeId old_root = m_root;
    m_store = other.m_store;
    m_root = other.m_root;
    m_version = other.m_version;
    m_payload_bytes = other.m_payload_bytes;
    m_sketch = std::move(other.m_sketch);
    other.m_root = kNull;
    other.m_payload_bytes = 0;
    other.m_sketch.Clear();
    old_store->Release(old_root);
    return *this;
}

Tree::~Tree() { m_store->Release(m_root); }

NodeId Tree::Touch(NodeId b) {
    // A descendant changed in place, which implies this whole path is
    // unique: refresh the derived count and invalidate the cached digest.
    Branch &m = m_store->MutB(b);
    assert(m.refs.load(std::memory_order_relaxed) == 1);
    m.count = m_store->Count(m.child[0]) + m_store->Count(m.child[1]);
    m.hash_state.store(kDirty, std::memory_order_relaxed);
    Stats().inplace_updates.fetch_add(1, std::memory_order_relaxed);
    return b;
}

NodeId Tree::ReplaceChild(NodeId b, bool unique, unsigned bit, NodeId new_child) {
    if (unique) {
        Branch &m = m_store->MutB(b);
        const NodeId old = m.child[bit];
        m.child[bit] = new_child;
        m.count = m_store->Count(m.child[0]) + m_store->Count(m.child[1]);
        m.hash_state.store(kDirty, std::memory_order_relaxed);
        m_store->Release(old);
        Stats().inplace_updates.fetch_add(1, std::memory_order_relaxed);
        return b;
    }
    const Branch &src = m_store->B(b);
    Branch shape;
    shape.child = src.child;
    shape.split = src.split;
    shape.key = src.key;
    shape.child[bit] = new_child;
    shape.count = m_store->Count(shape.child[0]) + m_store->Count(shape.child[1]);
    m_store->Retain(shape.child[bit ^ 1]);
    Stats().path_copies.fetch_add(1, std::memory_order_relaxed);
    try {
        return m_store->NewBranch(shape);
    } catch (...) {
        m_store->Release(shape.child[bit ^ 1]);
        m_store->Release(new_child); // recursive result ownership was transferred here
        throw;
    }
}

NodeId Tree::InsertAt(NodeId n, unsigned depth, bool unique, const Hash &id,
                      const Hash &hash, uint64_t minhash,
                      std::shared_ptr<const void> &payload,
                      uint32_t payload_bytes, Change &change, Outgoing &old) {
    if (n == kNull) {
        change = Change::Inserted;
        return m_store->NewLeaf(id, hash, minhash, std::move(payload), payload_bytes);
    }
    Branch shape;
    if (Store::IsLeaf(n)) {
        const Leaf &leaf = m_store->L(n);
        if (leaf.key == id) {
            if (leaf.tx_hash == hash) return n;
            change = Change::Replaced;
            old = {true, leaf.minhash, leaf.payload_bytes};
            return m_store->NewLeaf(id, hash, minhash, std::move(payload), payload_bytes);
        }
        shape.split = uint16_t(FirstDiff(leaf.key, id, depth, 256));
        shape.count = 2;
    } else {
        const Branch &b = m_store->B(n);
        const unsigned split = FirstDiff(b.key, id, depth, b.split);
        if (split == b.split) {
            const unsigned bit = KeyBit(id, b.split);
            const NodeId c = b.child[bit];
            const NodeId r = InsertAt(c, unsigned(b.split) + 1, ChildUnique(unique, c),
                                      id, hash, minhash, payload, payload_bytes,
                                      change, old);
            if (change == Change::Unchanged) return n;
            if (r == c) return Touch(n);
            return ReplaceChild(n, unique, bit, r);
        }
        shape.split = uint16_t(split);
        shape.count = b.count + 1;
    }
    // The new key diverges from everything under n at shape.split: n keeps
    // its contents and becomes one child of a new branch point.
    shape.key = id;
    const NodeId added =
        m_store->NewLeaf(id, hash, minhash, std::move(payload), payload_bytes);
    const bool added_right = KeyBit(id, shape.split);
    shape.child = added_right ? std::array<NodeId, 2>{n, added}
                              : std::array<NodeId, 2>{added, n};
    m_store->Retain(n);
    change = Change::Inserted;
    try {
        return m_store->NewBranch(shape);
    } catch (...) {
        m_store->Release(n);
        m_store->Release(added);
        throw;
    }
}

Tree::Change Tree::Insert(const Hash &tx_id, const Hash &tx_hash,
                          std::shared_ptr<const void> payload,
                          uint32_t payload_bytes) {
    const uint64_t value = minhash::Value(tx_id, tx_hash);
    Change change{Change::Unchanged};
    Outgoing old;
    const NodeId r = InsertAt(m_root, 0, ChildUnique(true, m_root), tx_id, tx_hash,
                              value, payload, payload_bytes, change, old);
    if (r != m_root) {
        const NodeId prev = m_root;
        m_root = r;
        m_store->Release(prev);
    }
    if (change == Change::Unchanged) return change;
    ++m_version;
    if (change == Change::Replaced) {
        m_sketch.Erase(old.minhash);
        m_payload_bytes -= old.payload_bytes;
    }
    m_sketch.Insert(value);
    m_payload_bytes += payload_bytes;
    return change;
}

NodeId Tree::EraseAt(NodeId n, unsigned depth, bool unique, const Hash &id,
                     Outgoing &old) {
    if (n == kNull) return n;
    if (Store::IsLeaf(n)) {
        const Leaf &leaf = m_store->L(n);
        if (leaf.key != id) return n;
        old = {true, leaf.minhash, leaf.payload_bytes};
        return kNull;
    }
    const Branch &b = m_store->B(n);
    if (FirstDiff(b.key, id, depth, b.split) != b.split) return n;
    const unsigned bit = KeyBit(id, b.split);
    const NodeId c = b.child[bit];
    const NodeId r = EraseAt(c, unsigned(b.split) + 1, ChildUnique(unique, c), id, old);
    if (!old.found) return n;
    if (r == c) return Touch(n);
    if (r == kNull) {
        // The branch point disappears; the sibling moves up unchanged. Its
        // digest at its own split stays valid (unary runs are recomputed).
        const NodeId other = b.child[bit ^ 1];
        m_store->Retain(other);
        return other;
    }
    return ReplaceChild(n, unique, bit, r);
}

bool Tree::Erase(const Hash &tx_id) {
    Outgoing old;
    const NodeId r = EraseAt(m_root, 0, ChildUnique(true, m_root), tx_id, old);
    if (!old.found) return false;
    if (r != m_root) {
        const NodeId prev = m_root;
        m_root = r;
        m_store->Release(prev);
    }
    ++m_version;
    m_sketch.Erase(old.minhash);
    m_payload_bytes -= old.payload_bytes;
    return true;
}

void Tree::Clear() {
    const NodeId prev = m_root;
    m_root = kNull;
    if (prev != kNull) ++m_version;
    m_payload_bytes = 0;
    m_sketch.Clear();
    m_store->Release(prev);
    // Sole owner of the store: no other tree or snapshot can hold a node, so
    // a fully free store returns its slab chunks (bounded retained memory
    // after a mempool spike). use_count()==1 cannot grow concurrently because
    // copying requires access to this owner.
    if (m_store.use_count() == 1) m_store->TrimIfUnused();
}

std::optional<Hash> Tree::FindHash(const Hash &tx_id) const {
    NodeId n = m_root;
    while (n != kNull && !Store::IsLeaf(n)) {
        const Branch &b = m_store->B(n);
        n = b.child[KeyBit(tx_id, b.split)];
    }
    if (n == kNull) return std::nullopt;
    const Leaf &leaf = m_store->L(n);
    if (leaf.key != tx_id) return std::nullopt;
    return leaf.tx_hash;
}

Hash Tree::RootDigest() const {
    m_store->Complete(m_root);
    return m_store->DigestAt(m_root, 0);
}

void Tree::EnsureSketch() const {
    if (!m_sketch.NeedsRebuild()) return;
    std::vector<uint64_t> values;
    values.reserve(Count());
    ForEachLeaf([&](const Leaf &leaf) { values.push_back(leaf.minhash); });
    auto &s = Stats();
    s.sketch_rebuilds.fetch_add(1, std::memory_order_relaxed);
    s.sketch_rebuild_members.fetch_add(values.size(), std::memory_order_relaxed);
    m_sketch.Rebuild(std::move(values));
}

Sketch Tree::CurrentSketch() const {
    EnsureSketch();
    return Sketch{m_sketch.Export()};
}

std::shared_ptr<const Snapshot> Tree::Pin() const {
    const bool rebuild_sketch = m_sketch.NeedsRebuild();
    Sketch sketch = rebuild_sketch ? Sketch{} : Sketch{m_sketch.Export()};
    m_store->Retain(m_root);
    try {
        auto out = std::make_shared<const Snapshot>(m_store, m_root, m_version,
                                                    m_payload_bytes, std::move(sketch), rebuild_sketch);
        Stats().pins.fetch_add(1, std::memory_order_relaxed);
        return out;
    } catch (...) {
        m_store->Release(m_root);
        throw;
    }
}

// ===========================================================================
// Snapshot
// ===========================================================================

Snapshot::Snapshot(std::shared_ptr<Store> store, NodeId root, uint64_t version,
                   uint64_t payload_bytes, Sketch sketch, bool rebuild_sketch)
    : m_store(std::move(store)), m_root(root), m_version(version),
      m_payload_bytes(payload_bytes), m_sketch(std::move(sketch)),
      m_rebuild_sketch(rebuild_sketch) {}

Snapshot::~Snapshot() { m_store->Release(m_root); }

const Sketch &Snapshot::GetSketch() const {
    std::call_once(m_sketch_once, [this] {
        if (!m_rebuild_sketch) return;
        std::vector<uint64_t> values;
        values.reserve(Count());
        ForEachLeaf([&](const Leaf &leaf) { values.push_back(leaf.minhash); });
        const size_t members = values.size();
        minhash::Maintainer rebuilt;
        rebuilt.Rebuild(std::move(values));
        m_sketch.values = rebuilt.Export();
        Stats().sketch_rebuilds.fetch_add(1, std::memory_order_relaxed);
        Stats().sketch_rebuild_members.fetch_add(members, std::memory_order_relaxed);
    });
    return m_sketch;
}

Hash Snapshot::RootDigest() const {
    m_store->Complete(m_root);
    return m_store->DigestAt(m_root, 0);
}

NodeId Snapshot::Find(const Hash &prefix, unsigned depth) const {
    NodeId n = m_root;
    unsigned checked = 0;
    while (n != kNull) {
        if (Store::IsLeaf(n)) {
            return FirstDiff(m_store->L(n).key, prefix, checked, depth) == depth ? n : kNull;
        }
        const Branch &b = m_store->B(n);
        const unsigned limit = std::min<unsigned>(depth, b.split);
        if (FirstDiff(b.key, prefix, checked, limit) != limit) return kNull;
        if (depth <= b.split) return n;
        n = b.child[KeyBit(prefix, b.split)];
        checked = unsigned(b.split) + 1;
    }
    return kNull;
}

Snapshot::Descriptor Snapshot::At(const Hash &prefix, unsigned depth) const {
    const NodeId n = Find(prefix, depth);
    if (n == kNull) return {0, EmptyDigest()};
    return {m_store->Count(n), m_store->DigestAt(n, depth)};
}

std::optional<std::vector<const Leaf *>> Snapshot::Leaves(const Hash &prefix,
                                                          unsigned depth,
                                                          size_t max_leaves) const {
    std::vector<const Leaf *> out;
    const NodeId n = Find(prefix, depth);
    if (n == kNull) return out;
    if (m_store->Count(n) > max_leaves) return std::nullopt;
    out.reserve(m_store->Count(n));
    auto collect = [&](const Leaf &leaf) { out.push_back(&leaf); };
    detail::ForEachLeaf(*m_store, n, collect);
    return out;
}

std::optional<Hash> Snapshot::FindHash(const Hash &tx_id) const {
    NodeId n = m_root;
    while (n != kNull && !Store::IsLeaf(n)) {
        const Branch &b = m_store->B(n);
        n = b.child[KeyBit(tx_id, b.split)];
    }
    if (n == kNull) return std::nullopt;
    const Leaf &leaf = m_store->L(n);
    if (leaf.key != tx_id) return std::nullopt;
    return leaf.tx_hash;
}

} // namespace lotus::v2::txmerklix
