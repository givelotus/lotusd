// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_TX_MERKLIX_H
#define LOTUS_V2_TX_MERKLIX_H

#include "commitment.h"
#include "minhash.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

/**
 * Slab-backed, path-compressed, persistent transaction Merklix tree.
 *
 * Specification: daemon/docs/slab-merklix-snapshots-spec.md (monorepo).
 *
 * The tree commits exactly to consensus Transaction Subtree A: keys are
 * 256-bit TxIds routed LSB-first (bit d = (id[d/8] >> (d%8)) & 1), leaves are
 * TaggedHash(TxRoot, 0x00 || TxId || TxHash), a branch at depth d is
 * TaggedHash(TxRoot, 0x01 || u16le(d) || left || right), empty is
 * TaggedHash(TxRoot, 0x02) and a single-member subtree collapses to its leaf.
 * Only real branch points are stored; a unary run between a parent's split and
 * a child's split is hashed on demand with empty siblings.
 *
 * Ownership model:
 *  - Nodes live in per-family Store slabs addressed by 32-bit handles and are
 *    reference counted. A parent owns one reference per child; a Tree or a
 *    Snapshot owns one reference to its root.
 *  - Trees are single-writer views. All Trees sharing one Store must be
 *    mutated under one external writer lock (the mempool lock in production).
 *    A node is mutated in place only when every node on the path from the
 *    writer's root to it has refcount 1 ("path-unique"). Otherwise the path is
 *    copied. No other thread can raise a refcount without that lock.
 *  - Snapshots are immutable, thread-safe, and may be read, hashed and released
 *    on any thread. Pinning a Tree is O(1) (one reference on the root) plus a
 *    K-value MinHash copy and must happen under the writer lock. A pending
 *    sketch refill is computed lazily from the immutable snapshot.
 *  - Digests are derived caches with an atomic Dirty/Busy/Clean state. Readers
 *    never need digests; hashing fills caches without changing logical contents.
 *    Concurrent hashers race through compare-and-swap; a loser uses its own
 *    computed value and never writes. Nothing here is claimed lock-free:
 *    slab allocation and batched slot return take a short mutex.
 */
namespace lotus::v2::txmerklix {

using NodeId = uint32_t;
inline constexpr NodeId kNull = 0;
inline constexpr NodeId kLeafBit = 0x80000000u;
inline constexpr uint32_t kMaxSlots = uint32_t{1} << 26;

inline bool KeyBit(const Hash &key, unsigned bit) noexcept {
    return (key[bit >> 3] >> (bit & 7)) & 1;
}
Hash EmptyDigest();
Hash LeafDigest(const Hash &tx_id, const Hash &tx_hash);
Hash BranchDigest(unsigned depth, const Hash &left, const Hash &right);

enum HashState : uint8_t { kDirty = 0, kBusy = 1, kClean = 2 };

struct Branch {
    std::atomic<uint32_t> refs{0};
    std::atomic<uint64_t> generation{0};
    std::array<NodeId, 2> child{kNull, kNull};
    uint32_t count{0};
    uint16_t split{0};
    mutable std::atomic<uint8_t> hash_state{kDirty};
    Hash key{};            // any member key; bits below split are the prefix
    mutable Hash digest{}; // digest at split; valid only when Clean
};

struct Leaf {
    std::atomic<uint32_t> refs{0};
    std::atomic<uint64_t> generation{0};
    mutable std::atomic<uint8_t> hash_state{kDirty};
    uint32_t payload_bytes{0};
    uint64_t minhash{0};
    Hash key{};
    Hash tx_hash{};
    mutable Hash digest{};
    std::shared_ptr<const void> payload;
};

/** Process-wide counters (relaxed). Exported to Prometheus by the node. */
struct GlobalStats {
    std::atomic<uint64_t> leaf_allocs{0}, branch_allocs{0}, slot_reuses{0};
    std::atomic<uint64_t> path_copies{0}, inplace_updates{0}, frees{0};
    std::atomic<uint64_t> node_hashes{0}, hash_cas_losses{0};
    std::atomic<uint64_t> pins{0}, sketch_rebuilds{0}, sketch_rebuild_members{0};
    std::atomic<uint64_t> parallel_completions{0};
    std::atomic<int64_t> live_leaves{0}, live_branches{0};
    std::atomic<int64_t> retained_leaf_slots{0}, retained_branch_slots{0};
    std::atomic<int64_t> stores{0};
};
GlobalStats &Stats() noexcept;

/** Fixed-size slot storage with stable addresses and generation counters. */
template <typename T> class Slab {
public:
    Slab();
    ~Slab();
    Slab(const Slab &) = delete;
    Slab &operator=(const Slab &) = delete;
    T &At(uint32_t slot) const noexcept;
    //! Caller holds the store allocation mutex.
    uint32_t Allocate(bool &reused);
    void Free(uint32_t slot);
    size_t Constructed() const noexcept { return m_constructed; }
    size_t FreeSlots() const noexcept { return m_free.size(); }
    void ReleaseChunksIfUnused();

private:
    struct Location { uint32_t chunk, offset; };
    static Location Locate(uint32_t slot) noexcept;
    static uint32_t ChunkSize(uint32_t chunk) noexcept;
    static constexpr uint32_t kChunks = 11 + ((kMaxSlots - 131008) >> 16) + 1;
    std::unique_ptr<std::atomic<T *>[]> m_chunks;
    uint32_t m_constructed{0};
    std::vector<uint32_t> m_free;
};

class Snapshot;

/** Node storage for a family of trees and their snapshots. */
class Store : public std::enable_shared_from_this<Store> {
public:
    static std::shared_ptr<Store> Create();
    ~Store();
    Store(const Store &) = delete;
    Store &operator=(const Store &) = delete;

    static bool IsLeaf(NodeId n) noexcept { return n & kLeafBit; }
    const Branch &B(NodeId n) const noexcept { return m_branches.At(n); }
    const Leaf &L(NodeId n) const noexcept { return m_leaves.At(n & ~kLeafBit); }
    Branch &MutB(NodeId n) noexcept { return m_branches.At(n); }

    NodeId NewLeaf(const Hash &id, const Hash &hash, uint64_t minhash,
                   std::shared_ptr<const void> payload, uint32_t payload_bytes);
    NodeId NewBranch(const Branch &shape); // copies shape, refs = 1, Dirty
    void Retain(NodeId n) const noexcept;
    void Release(NodeId n) const noexcept;
    uint32_t Refs(NodeId n) const noexcept;
    uint32_t Count(NodeId n) const noexcept {
        return n == kNull ? 0 : IsLeaf(n) ? 1 : B(n).count;
    }
    const Hash &AnyKey(NodeId n) const noexcept {
        return IsLeaf(n) ? L(n).key : B(n).key;
    }

    /** Digest of n as the subtree rooted at depth (folds unary runs). */
    Hash DigestAt(NodeId n, unsigned depth) const;
    /** Digest at n's own split (leaf digest for leaves), cached. */
    Hash NodeDigest(NodeId n) const;
    /** Complete caches below n, in parallel for large dirty trees. */
    void Complete(NodeId n) const;

    /** Weak reference with ABA protection through slot generations. */
    struct WeakRef { NodeId node{kNull}; uint64_t generation{0}; };
    WeakRef Weak(NodeId n) const noexcept;
    //! Caller holds the family writer lock, including against mutation/trim.
    //! Returns a retained node (caller releases) or kNull if stale.
    NodeId TryRetain(const WeakRef &weak) const noexcept;

    size_t LiveLeaves() const noexcept;
    size_t LiveBranches() const noexcept;
    size_t RetainedBytes() const noexcept;
    /** Return all slab chunks when no node is live (no tree/snapshot holds one). */
    bool TrimIfUnused() noexcept;

private:
    Store();
    void FreeBatch(const NodeId *dead, size_t count) const noexcept;
    Hash NodeDigestCounted(NodeId n, uint64_t &hashes) const;
    Hash DigestAtCounted(NodeId n, unsigned depth, uint64_t &hashes) const;
    uint64_t m_next_generation{1}; // never reset when empty slabs are trimmed
    mutable std::mutex m_alloc_mutex;
    mutable Slab<Branch> m_branches;
    mutable Slab<Leaf> m_leaves;
};

/** Copyable pinned summary of a membership version. */
struct Sketch {
    std::vector<uint64_t> values; // bottom-k, ascending
};

/**
 * Writable working view. Not thread-safe; see the writer-lock contract above.
 * Copying a Tree shares all nodes (O(1)); both copies then copy-on-write.
 */
class Tree {
public:
    enum class Change { Unchanged, Inserted, Replaced };

    explicit Tree(std::shared_ptr<Store> store = Store::Create());
    Tree(const Tree &other);
    Tree &operator=(const Tree &other);
    Tree(Tree &&other) noexcept;
    Tree &operator=(Tree &&other) noexcept;
    ~Tree();

    Change Insert(const Hash &tx_id, const Hash &tx_hash,
                  std::shared_ptr<const void> payload = {},
                  uint32_t payload_bytes = 0);
    bool Erase(const Hash &tx_id);
    void Clear();

    std::optional<Hash> FindHash(const Hash &tx_id) const;
    bool Contains(const Hash &tx_id) const { return FindHash(tx_id).has_value(); }
    size_t Count() const noexcept { return m_store->Count(m_root); }
    uint64_t Version() const noexcept { return m_version; }
    uint64_t PayloadBytes() const noexcept { return m_payload_bytes; }
    const std::shared_ptr<Store> &GetStore() const noexcept { return m_store; }
    NodeId Root() const noexcept { return m_root; }

    /** Lazily completes dirty digests in place; caller holds the writer lock. */
    Hash RootDigest() const;
    /** Current bottom-k sketch (rebuilds if a deletion exhausted candidates). */
    Sketch CurrentSketch() const;
    /** O(1) structural pin + sketch; caller holds the writer lock. */
    std::shared_ptr<const Snapshot> Pin() const;

    /** Visit leaves in canonical (LSB-first trie) order. */
    template <typename F> void ForEachLeaf(F &&f) const;

private:
    struct Outgoing {
        bool found{false};
        uint64_t minhash{0};
        uint32_t payload_bytes{0};
    };
    NodeId InsertAt(NodeId n, unsigned depth, bool unique, const Hash &id,
                    const Hash &hash, uint64_t minhash,
                    std::shared_ptr<const void> &payload,
                    uint32_t payload_bytes, Change &change, Outgoing &old);
    NodeId EraseAt(NodeId n, unsigned depth, bool unique, const Hash &id,
                   Outgoing &old);
    NodeId ReplaceChild(NodeId b, bool unique, unsigned bit, NodeId new_child);
    NodeId Touch(NodeId b);
    bool ChildUnique(bool unique, NodeId c) const noexcept {
        return unique && c != kNull && m_store->Refs(c) == 1;
    }
    void EnsureSketch() const;

    std::shared_ptr<Store> m_store;
    NodeId m_root{kNull};
    uint64_t m_version{0};
    uint64_t m_payload_bytes{0};
    mutable minhash::Maintainer m_sketch;
};

/** Immutable pinned version. Safe for concurrent readers and hashers. */
class Snapshot {
public:
    struct Descriptor { uint64_t count{0}; Hash digest{}; };
    Snapshot(std::shared_ptr<Store> store, NodeId root, uint64_t version,
             uint64_t payload_bytes, Sketch sketch, bool rebuild_sketch = false);
    ~Snapshot();
    Snapshot(const Snapshot &) = delete;
    Snapshot &operator=(const Snapshot &) = delete;

    size_t Count() const noexcept { return m_store->Count(m_root); }
    uint64_t Version() const noexcept { return m_version; }
    uint64_t PayloadBytes() const noexcept { return m_payload_bytes; }
    const Sketch &GetSketch() const;
    const Store &GetStore() const noexcept { return *m_store; }
    NodeId Root() const noexcept { return m_root; }

    Hash RootDigest() const;
    /** Count and digest of the members whose first `depth` bits equal prefix. */
    Descriptor At(const Hash &prefix, unsigned depth) const;
    /** Leaves under the prefix in canonical order; nullopt if > max_leaves. */
    std::optional<std::vector<const Leaf *>> Leaves(const Hash &prefix,
                                                     unsigned depth,
                                                     size_t max_leaves) const;
    std::optional<Hash> FindHash(const Hash &tx_id) const;
    template <typename F> void ForEachLeaf(F &&f) const;

private:
    NodeId Find(const Hash &prefix, unsigned depth) const;
    std::shared_ptr<Store> m_store;
    NodeId m_root;
    uint64_t m_version;
    uint64_t m_payload_bytes;
    mutable Sketch m_sketch;
    bool m_rebuild_sketch;
    mutable std::once_flag m_sketch_once;
};

namespace detail {
template <typename F>
void ForEachLeaf(const Store &store, NodeId n, F &f) {
    if (n == kNull) return;
    if (Store::IsLeaf(n)) {
        f(store.L(n));
        return;
    }
    const Branch &b = store.B(n);
    ForEachLeaf(store, b.child[0], f);
    ForEachLeaf(store, b.child[1], f);
}
} // namespace detail

template <typename F> void Tree::ForEachLeaf(F &&f) const {
    detail::ForEachLeaf(*m_store, m_root, f);
}
template <typename F> void Snapshot::ForEachLeaf(F &&f) const {
    detail::ForEachLeaf(*m_store, m_root, f);
}

} // namespace lotus::v2::txmerklix

#endif // LOTUS_V2_TX_MERKLIX_H
