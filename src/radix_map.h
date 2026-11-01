// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RADIX_MAP_H
#define BITCOIN_RADIX_MAP_H

#include <core_memusage.h>
#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <primitives/txid.h>
#include <radix.h>
#include <random.h>
#include <rcu.h>
#include <support/allocators/chunked_slab.h>
#include <uint256.h>
#include <uint256radixkey.h>

#include <atomic>
#include <cassert>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>

/**
 * 128-bit composite radix key for std::pair<uint64_t, uint64_t>.
 * Routes the first 64 bits through levels 31..16 and the second 64 bits
 * through levels 15..0 in big-endian nibble order.
 */
struct Uint128RadixKey {
    uint64_t hi{0};
    uint64_t lo{0};

    constexpr Uint128RadixKey() noexcept = default;
    constexpr Uint128RadixKey(uint64_t hi_in, uint64_t lo_in) noexcept
        : hi(hi_in), lo(lo_in) {}
    constexpr explicit Uint128RadixKey(
        const std::pair<uint64_t, uint64_t> &p) noexcept
        : hi(p.first), lo(p.second) {}

    constexpr uint32_t GetNibble(uint32_t level) const noexcept {
        if (level < 16) {
            return static_cast<uint32_t>((lo >> (4 * level)) & 0x0fULL);
        }
        if (level < 32) {
            return static_cast<uint32_t>((hi >> (4 * (level - 16))) & 0x0fULL);
        }
        return 0;
    }

    friend constexpr bool operator==(const Uint128RadixKey &a,
                                     const Uint128RadixKey &b) noexcept =
        default;
    friend constexpr auto operator<=>(const Uint128RadixKey &a,
                                      const Uint128RadixKey &b) noexcept =
        default;
};

static_assert(sizeof(Uint128RadixKey) == 16,
              "Uint128RadixKey size must be 16 bytes (128 bits)");

/**
 * Radix key for an outpoint in a long-lived index.
 *
 * Routing on the outpoint's own bytes would be wrong: (txid, 0) and (txid, 1)
 * differ only in their last nibble, so a pair of sibling outpoints would allocate
 * a node at nearly every level, and RadixTree never frees those nodes on removal.
 * Instead the upper levels route on a SipHash of the outpoint under a per-process
 * secret. Depth then follows log16(live entries) whatever outpoints the network
 * sends, and nobody can grind outpoints that share a path. The outpoint itself
 * only follows the route in the levels below, to keep keys unique if two routes
 * ever collide.
 *
 * Iteration order is arbitrary and differs between processes, and prefix scans
 * have no meaning here. A caller that needs every spender of a transaction looks
 * up each of its output indices.
 */
struct SaltedOutpointRadixKey {
    uint64_t route{0};
    Uint256RadixKey txid;
    uint32_t n{0};

    explicit SaltedOutpointRadixKey(const COutPoint &outpoint) noexcept
        : route(SipHashUint256Extra(Salt().first, Salt().second,
                                    outpoint.GetTxId(), outpoint.GetN())),
          txid(outpoint.GetTxId()), n(outpoint.GetN()) {}

    uint32_t GetNibble(uint32_t level) const noexcept {
        // The key is 96 nibbles wide because of padding: 16 of route at the top,
        // 8 unused, then 64 of txid and 8 of n.
        if (level < 8) {
            return (n >> (4 * level)) & 0x0fU;
        }
        if (level < 72) {
            return txid.GetNibble(level - 8);
        }
        if (level < 80) {
            return 0;
        }
        return static_cast<uint32_t>((route >> (4 * (level - 80))) & 0x0fULL);
    }

    bool operator==(const SaltedOutpointRadixKey &other) const noexcept {
        return route == other.route && n == other.n && txid == other.txid;
    }
    bool operator!=(const SaltedOutpointRadixKey &other) const noexcept {
        return !(*this == other);
    }

private:
    static const std::pair<uint64_t, uint64_t> &Salt() noexcept {
        static const std::pair<uint64_t, uint64_t> salt{
            FastRandomContext().rand64(), FastRandomContext().rand64()};
        return salt;
    }
};

static_assert(sizeof(SaltedOutpointRadixKey) == 48,
              "SaltedOutpointRadixKey must span the 96 nibbles it routes on");

template <typename Key> struct RadixKeyEncoder {
    static_assert(std::is_integral_v<Key>,
                  "Unsupported RadixTreeMap key type without specialization");
    using EncodedType = std::make_unsigned_t<Key>;
    static constexpr EncodedType encode(Key k) noexcept {
        return static_cast<EncodedType>(k);
    }
};

template <> struct RadixKeyEncoder<std::pair<uint64_t, uint64_t>> {
    using EncodedType = Uint128RadixKey;
    static constexpr Uint128RadixKey
    encode(const std::pair<uint64_t, uint64_t> &k) noexcept {
        return Uint128RadixKey(k);
    }
};

template <> struct RadixKeyEncoder<uint256> {
    using EncodedType = Uint256RadixKey;
    static Uint256RadixKey encode(const uint256 &k) noexcept {
        return Uint256RadixKey(k);
    }
};

template <> struct RadixKeyEncoder<TxId> {
    using EncodedType = Uint256RadixKey;
    static Uint256RadixKey encode(const TxId &k) noexcept {
        return Uint256RadixKey(k);
    }
};

template <> struct RadixKeyEncoder<Uint256RadixKey> {
    using EncodedType = Uint256RadixKey;
    static const Uint256RadixKey &encode(const Uint256RadixKey &k) noexcept {
        return k;
    }
};

/**
 * Pass this encoder explicitly for COutPoint keys. COutPoint has no default
 * encoder because its natural ordering is unsafe to route on; see
 * SaltedOutpointRadixKey.
 */
struct SaltedOutpointEncoder {
    using EncodedType = SaltedOutpointRadixKey;
    static SaltedOutpointRadixKey encode(const COutPoint &k) noexcept {
        return SaltedOutpointRadixKey(k);
    }
};

/**
 * RCU-backed ordered Key -> Value map with O(1) Copy-on-Write snapshots,
 * lower_bound range scans, and prefix subtree scans.
 *
 * Reads are lock-free. Writers must be serialized by the owner, and a compound
 * read of several keys is not atomic against them. Erasing never frees interior
 * nodes (see RadixTree), so a long-lived map needs keys that are uniformly
 * distributed and not attacker-chosen.
 */
template <typename Key, typename Value,
          typename KeyEncoder = RadixKeyEncoder<Key>,
          std::size_t SlabChunkElements = 1024>
class RadixTreeMap {
public:
    using EncodedKey = std::remove_cvref_t<decltype(KeyEncoder::encode(
        std::declval<const Key &>()))>;

    struct alignas(8) Entry {
        const EncodedKey encoded_key;
        const Key key;
        const Value value;

        template <typename V>
        Entry(const Key &k, V &&v)
            : encoded_key(KeyEncoder::encode(k)), key(k),
              value(std::forward<V>(v)) {}

        static void *operator new(std::size_t size) {
            assert(size == sizeof(Entry));
            return GlobalConcurrentSlabAllocator<Entry, SlabChunkElements>{}
                .allocate(1);
        }
        static void operator delete(void *ptr) noexcept {
            GlobalConcurrentSlabAllocator<Entry, SlabChunkElements>{}
                .deallocate(static_cast<Entry *>(ptr), 1);
        }

        IMPLEMENT_RCU_REFCOUNT(uint64_t);
    };

    struct EntryAdapter {
        const EncodedKey &getId(const Entry &e) const noexcept {
            return e.encoded_key;
        }
    };

    using Tree = RadixTree<
        Entry, EntryAdapter,
        GlobalConcurrentSlabAllocator<std::byte, SlabChunkElements>>;
    using ImmutableSnapshotTag = typename Tree::ImmutableSnapshotTag;

private:
    Tree m_tree;
    std::atomic<size_t> m_size{0};

    template <typename Callable>
    static bool invokeVisitor(Callable &fn, const RCUPtr<Entry> &entry) {
        if constexpr (std::is_invocable_r_v<bool, Callable, const Key &,
                                            const Value &>) {
            return fn(entry->key, entry->value);
        } else if constexpr (std::is_invocable_v<Callable, const Key &,
                                                 const Value &>) {
            fn(entry->key, entry->value);
            return true;
        } else if constexpr (std::is_invocable_r_v<bool, Callable,
                                                   const Entry &>) {
            return fn(*entry);
        } else if constexpr (std::is_invocable_v<Callable, const Entry &>) {
            fn(*entry);
            return true;
        } else if constexpr (std::is_invocable_r_v<bool, Callable,
                                                   const RCUPtr<Entry> &>) {
            return fn(entry);
        } else {
            fn(entry);
            return true;
        }
    }

public:
    RadixTreeMap() = default;

    RadixTreeMap(const RadixTreeMap &other)
        : m_tree(other.m_tree),
          m_size(other.m_size.load(std::memory_order_relaxed)) {}

    RadixTreeMap(const RadixTreeMap &other, ImmutableSnapshotTag tag) noexcept
        : m_tree(other.m_tree, tag),
          m_size(other.m_size.load(std::memory_order_relaxed)) {}

    RadixTreeMap(RadixTreeMap &&other) noexcept
        : m_tree(std::move(other.m_tree)),
          m_size(other.m_size.exchange(0, std::memory_order_relaxed)) {}

    RadixTreeMap &operator=(const RadixTreeMap &other) {
        if (this != &other) {
            m_tree = other.m_tree;
            m_size.store(other.m_size.load(std::memory_order_relaxed),
                         std::memory_order_relaxed);
        }
        return *this;
    }

    RadixTreeMap &operator=(RadixTreeMap &&other) noexcept {
        if (this != &other) {
            m_tree = std::move(other.m_tree);
            m_size.store(other.m_size.exchange(0, std::memory_order_relaxed),
                         std::memory_order_relaxed);
        }
        return *this;
    }

    /**
     * Insert (k, v) if k is not already present.
     * Returns true if inserted, false if k already existed.
     */
    bool insert(const Key &k, Value v) {
        if (m_tree.insert(RCUPtr<Entry>::make(k, std::move(v)))) {
            m_size.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    /**
     * Insert (k, v) or replace the existing value for k via Copy-on-Write.
     * Returns true if a new key was inserted, false if an existing key was
     * replaced.
     */
    bool insertOrAssign(const Key &k, Value v) {
        if (m_tree.insertOrAssign(RCUPtr<Entry>::make(k, std::move(v)))) {
            m_size.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    /**
     * Remove k from the map.
     * Returns true if an element was removed, false if k was not present.
     */
    bool erase(const Key &k) {
        if (m_tree.remove(KeyEncoder::encode(k)) != nullptr) {
            m_size.fetch_sub(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    /**
     * Remove and return the RCU-refcounted entry for k, or nullptr if absent.
     */
    RCUPtr<Entry> extractEntry(const Key &k) {
        auto removed = m_tree.remove(KeyEncoder::encode(k));
        if (removed != nullptr) {
            m_size.fetch_sub(1, std::memory_order_relaxed);
        }
        return removed;
    }

    /**
     * Lock-free point lookup returning a copy of Value if present.
     */
    std::optional<Value> get(const Key &k) const {
        RCUPtr<const Entry> entry = m_tree.get(KeyEncoder::encode(k));
        if (!entry) {
            return std::nullopt;
        }
        return entry->value;
    }

    /**
     * Lock-free point lookup returning the RCU-refcounted Entry directly.
     */
    RCUPtr<const Entry> getEntry(const Key &k) const {
        return m_tree.get(KeyEncoder::encode(k));
    }

    /**
     * Lock-free point lookup within an existing RCU read section.
     */
    RCUPtr<const Entry> getEntryWithinReadSection(const Key &k) const {
        return m_tree.getWithinReadSection(KeyEncoder::encode(k));
    }

    /**
     * Lock-free existence check.
     */
    bool contains(const Key &k) const {
        return m_tree.get(KeyEncoder::encode(k)) != nullptr;
    }

    /**
     * O(1) Copy-on-Write snapshot without RCULock::synchronize(). The caller
     * must exclude all writers to this map for the duration of the call.
     */
    RadixTreeMap pinSnapshot() const noexcept {
        return RadixTreeMap(*this, ImmutableSnapshotTag{});
    }

    size_t size() const noexcept {
        return m_size.load(std::memory_order_relaxed);
    }

    bool empty() const noexcept { return size() == 0; }

    void clear() {
        m_tree = Tree{};
        m_size.store(0, std::memory_order_relaxed);
    }

    /**
     * Bytes held by entries and interior nodes. Heap memory owned by a Value is
     * the caller's to add, because this map doesn't know what a Value retains.
     */
    size_t DynamicMemoryUsage() const noexcept {
        return size() * sizeof(Entry) + m_tree.nodeMemoryUsage();
    }

    size_t nodeCount() const noexcept { return m_tree.nodeCount(); }

    /**
     * What adding one entry can add to DynamicMemoryUsage in the common case:
     * the entry and one interior node. Keys that share a long prefix can add more.
     */
    static constexpr size_t EntryUsageUpperBound() noexcept {
        return sizeof(Entry) + Tree::NodeBytes();
    }

    /**
     * Traverse all entries in ascending key order.
     */
    template <typename Callable> bool forEach(Callable &&fn) const {
        return m_tree.forEachLeaf([&](const RCUPtr<Entry> &entry) {
            return invokeVisitor(fn, entry);
        });
    }

    /**
     * Traverse all entries with key >= lower_bound in ascending key order.
     */
    template <typename Callable>
    bool forEachFrom(const Key &lower_bound, Callable &&fn) const {
        return m_tree.forEachFrom(
            KeyEncoder::encode(lower_bound),
            [&](const RCUPtr<Entry> &entry) { return invokeVisitor(fn, entry); });
    }

    /**
     * Traverse all entries matching the top prefix_nibbles 4-bit nibbles of
     * prefix in ascending key order.
     */
    template <typename Callable>
    bool forEachPrefix(const Key &prefix, size_t prefix_nibbles,
                       Callable &&fn) const {
        return m_tree.forEachPrefix(
            KeyEncoder::encode(prefix), prefix_nibbles,
            [&](const RCUPtr<Entry> &entry) { return invokeVisitor(fn, entry); });
    }
};

namespace memusage {
template <typename Key, typename Value, typename KeyEncoder,
          std::size_t SlabChunkElements>
static inline size_t DynamicUsage(
    const RadixTreeMap<Key, Value, KeyEncoder, SlabChunkElements> &map) {
    return map.DynamicMemoryUsage();
}
} // namespace memusage

#endif // BITCOIN_RADIX_MAP_H
