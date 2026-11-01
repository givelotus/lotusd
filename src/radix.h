// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RADIX_H
#define BITCOIN_RADIX_H

#include <rcu.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

template <typename T> struct PassthroughAdapter {
    auto &&getId(const T &e) const { return e.getId(); }
};

/**
 * This is a radix tree storing values identified by a unique key.
 *
 * The tree is composed of nodes (RadixNode) containing an array of
 * RadixElement. The key is split into chunks of a few bits that serve as an
 * index into that array. RadixElement is a discriminated union of either a
 * RadixNode* representing the next level in the tree, or a T* representing a
 * leaf. New RadixNode are added lazily when two leaves would go in the same
 * slot.
 *
 * Reads walk the tree using sequential atomic loads, and insertions are done
 * using CAS, which ensures both can be executed lock free. Removing any
 * elements from the tree can also be done using CAS, but requires waiting for
 * other readers before being destroyed. The tree uses RCU to track which thread
 * is reading the tree, which allows deletion to wait for other readers to be up
 * to speed before destroying anything. It is therefore crucial that the lock be
 * taken before reading anything in the tree.
 *
 * Removal empties a leaf slot but never frees the nodes above it; nodes go away
 * only when the whole tree is released. Memory therefore follows the deepest
 * shape the keys have ever formed, not the number of live elements. Two keys
 * that share a prefix of d nibbles allocate d nodes that stay allocated after
 * both keys are gone, so a long-lived tree needs keys that are uniformly
 * distributed and that a third party cannot choose. Use nodeCount() to account
 * for this memory.
 */
template <typename T, typename Adapter = PassthroughAdapter<T>,
          typename NodeAllocator = std::allocator<std::byte>>
struct RadixTree : private Adapter {
private:
    static const int BITS = 4;
    static const int MASK = (1 << BITS) - 1;
    static const size_t CHILD_PER_LEVEL = 1 << BITS;

    using KeyType =
        typename std::remove_reference<decltype(std::declval<Adapter &>().getId(
            std::declval<T &>()))>::type;
    static const size_t KEY_BITS = 8 * sizeof(KeyType);
    static const uint32_t TOP_LEVEL = (KEY_BITS - 1) / BITS;

    struct RadixElement;
    struct RadixNode;

    std::atomic<RadixElement> root;
    // Nodes reachable from root. Copy-on-write clones replace a node one for
    // one, so only growth changes this count, and copies inherit it.
    std::atomic<size_t> m_node_count{0};

public:
    RadixTree() : root(RadixElement()) {}
    ~RadixTree() { root.load().decrementRefCount(); }

    /**
     * Copy semantic.
     */
    RadixTree(const RadixTree &src) : RadixTree() {
        {
            RCULock lock;
            RadixElement e = src.root.load();
            e.incrementRefCount();
            root = e;
            m_node_count.store(src.nodeCount(), std::memory_order_relaxed);
        }

        // Make sure we the writes in the tree are behind us so
        // this copy won't mutate behind our back.
        RCULock::synchronize();
    }

    /**
     * Explicit contract for copying a stable source tree. The caller must
     * own/pin the source and guarantee that no source mutation is in flight.
     * Published immutable sources satisfy this intrinsically. A mutable
     * source also qualifies while its exclusive writer lock is held through
     * root sharing; later writes then follow the normal CoW path. Merely
     * accessing a mutable tree through const is insufficient.
     *
     * Unlike the generic copy, no grace period is needed to wait for writers
     * that entered an unshared source node before its root was shared. There
     * cannot be such a writer for an immutable published source. Mutating the
     * resulting tree still follows the normal copy-on-write path.
     */
    struct ImmutableSnapshotTag {};

    RadixTree(const RadixTree &src, ImmutableSnapshotTag) noexcept : RadixTree() {
        RCULock lock;
        RadixElement e = src.root.load();
        e.incrementRefCount();
        root = e;
        m_node_count.store(src.nodeCount(), std::memory_order_relaxed);
    }

    /**
     * Pin an O(1) Copy-on-Write snapshot of this tree without a global RCU
     * synchronize() barrier. The caller must exclude all writers to this tree
     * for the duration of the call, as ImmutableSnapshotTag describes: pinning
     * while a writer is active can tear the snapshot.
     */
    RadixTree pinSnapshot() const noexcept {
        return RadixTree(*this, ImmutableSnapshotTag{});
    }

    RadixTree &operator=(const RadixTree &rhs) {
        {
            RCULock lock;
            RadixElement e = rhs.root.load();
            e.incrementRefCount();
            root.load().decrementRefCount();
            root = e;
            m_node_count.store(rhs.nodeCount(), std::memory_order_relaxed);
        }

        // Make sure we the writes in the tree are behind us so
        // this copy won't mutate behind our back.
        RCULock::synchronize();

        return *this;
    }

    /**
     * Move semantic.
     */
    RadixTree(RadixTree &&src) : RadixTree() { *this = std::move(src); }
    RadixTree &operator=(RadixTree &&rhs) {
        {
            RCULock lock;
            RadixElement e = rhs.root.load();
            rhs.root = root.load();
            root = e;
            m_node_count.store(
                rhs.m_node_count.exchange(
                    m_node_count.load(std::memory_order_relaxed),
                    std::memory_order_relaxed),
                std::memory_order_relaxed);
        }

        return *this;
    }

    /** Number of interior nodes reachable from this tree. */
    size_t nodeCount() const noexcept {
        return m_node_count.load(std::memory_order_relaxed);
    }

    static constexpr size_t NodeBytes() noexcept { return sizeof(RadixNode); }

    /** Bytes held by interior nodes. Leaves are their owner's to count. */
    size_t nodeMemoryUsage() const noexcept {
        return nodeCount() * NodeBytes();
    }

    /**
     * Insert a value into the tree.
     * Returns true if the value was inserted, false if it was already present.
     */
    bool insert(const RCUPtr<T> &value) { return insert(getId(*value), value); }

    /**
     * Insert a value into the tree, or replace an existing leaf with the same
     * key using Copy-on-Write.
     * Returns true if a new key was inserted, false if an existing key was
     * replaced.
     */
    bool insertOrAssign(const RCUPtr<T> &value) {
        return insertOrAssign(getId(*value), value);
    }

    /**
     * Get the value corresponding to a key.
     * Returns the value if found, nullptr if not.
     */
    RCUPtr<T> get(const KeyType &key) {
        RCULock lock;
        return getWithinReadSection(key);
    }

    /** Lookup while the caller already owns an RCU read section. This is
     * useful when joining two pinned immutable trees during traversal; RCU
     * read sections themselves must not be nested.
     */
    RCUPtr<T> getWithinReadSection(const KeyType &key) {
        assert(RCULock::isLocked());
        uint32_t level = TOP_LEVEL;
        RadixElement e = root.load();

        // Find a leaf.
        while (e.isNode()) {
            e = e.getNode()->get(level--, key)->load();
        }

        T *leaf = e.getLeaf();
        if (leaf == nullptr || getId(*leaf) != key) {
            // We failed to find the proper element.
            return RCUPtr<T>();
        }

        // The leaf is non-null and the keys match. We have our guy.
        return RCUPtr<T>::copy(leaf);
    }

    RCUPtr<const T> get(const KeyType &key) const {
        T const *ptr = const_cast<RadixTree *>(this)->get(key).release();
        return RCUPtr<const T>::acquire(ptr);
    }

    RCUPtr<const T> getWithinReadSection(const KeyType &key) const {
        T const *ptr =
            const_cast<RadixTree *>(this)->getWithinReadSection(key).release();
        return RCUPtr<const T>::acquire(ptr);
    }

    template <typename Callable> bool forEachLeaf(Callable &&func) const {
        RCULock lock;
        return forEachLeaf(root.load(), func);
    }

    /**
     * Visit all leaves with key >= lower_bound_key in ascending radix order,
     * pruning subtrees strictly below lower_bound_key in O(depth).
     */
    template <typename Callable>
    bool forEachFrom(const KeyType &lower_bound_key, Callable &&func) const {
        RCULock lock;
        return forEachFrom(root.load(), TOP_LEVEL, lower_bound_key, true, func);
    }

    /**
     * Descend prefix_nibbles 4-bit levels matching prefix_key and visit only
     * leaves in that prefix subtree in ascending radix order.
     */
    template <typename Callable>
    bool forEachPrefix(const KeyType &prefix_key, size_t prefix_nibbles,
                       Callable &&func) const {
        RCULock lock;
        constexpr size_t TOTAL_NIBBLES = TOP_LEVEL + 1;
        if (prefix_nibbles > TOTAL_NIBBLES) {
            prefix_nibbles = TOTAL_NIBBLES;
        }
        RadixElement e = root.load();
        uint32_t level = TOP_LEVEL;
        for (size_t consumed = 0; consumed < prefix_nibbles;
             ++consumed, --level) {
            if (e.isLeaf()) {
                T *leaf = e.getLeaf();
                if (leaf == nullptr) {
                    return true;
                }
                const KeyType &leafKey = getId(*leaf);
                for (size_t i = 0; i < prefix_nibbles; ++i) {
                    const uint32_t chk = TOP_LEVEL - static_cast<uint32_t>(i);
                    if (childIndex(chk, leafKey) !=
                        childIndex(chk, prefix_key)) {
                        return true;
                    }
                }
                return func(RCUPtr<T>::copy(leaf));
            }
            e = e.getNode()->get(level, prefix_key)->load();
        }
        return forEachLeaf(e, func);
    }

#define SEEK_LEAF_LOOP()                                                       \
    RadixElement e = eptr->load();                                             \
                                                                               \
    /* Walk down the tree until we find a leaf for our node. */                \
    do {                                                                       \
        while (e.isNode()) {                                                   \
        Node:                                                                  \
            auto nptr = e.getNode();                                           \
            if (!nptr->isShared()) {                                           \
                eptr = nptr->get(level--, key);                                \
                e = eptr->load();                                              \
                continue;                                                      \
            }                                                                  \
                                                                               \
            auto copy = std::make_unique<RadixNode>(*nptr);                    \
            if (!eptr->compare_exchange_strong(e, RadixElement(copy.get()))) { \
                /* We failed to insert our subtree, just try again. */         \
                continue;                                                      \
            }                                                                  \
                                                                               \
            /* We have a subtree, resume normal operations from there. */      \
            e.decrementRefCount();                                             \
            eptr = copy->get(level--, key);                                    \
            e = eptr->load();                                                  \
            copy.release();                                                    \
        }                                                                      \
    } while (0)

    /**
     * Remove an element from the tree.
     * Returns the removed element, or nullptr if there isn't one.
     */
    RCUPtr<T> remove(const KeyType &key) {
        uint32_t level = TOP_LEVEL;

        RCULock lock;
        std::atomic<RadixElement> *eptr = &root;

        SEEK_LEAF_LOOP();

        T *leaf = e.getLeaf();
        if (leaf == nullptr || getId(*leaf) != key) {
            // We failed to find the proper element.
            return RCUPtr<T>();
        }

        // We have the proper element, try to delete it.
        if (eptr->compare_exchange_strong(e, RadixElement())) {
            return RCUPtr<T>::acquire(leaf);
        }

        // The element was replaced, either by a subtree or another element.
        if (e.isNode()) {
            goto Node;
        }

        // The element in the slot is not the one we are looking for.
        return RCUPtr<T>();
    }

private:
    KeyType getId(const T &value) const { return Adapter::getId(value); }

    static size_t childIndex(uint32_t level, const KeyType &key) {
        if constexpr (BITS == 4 && requires { key.GetNibble(level); }) {
            return key.GetNibble(level);
        } else {
            return size_t((key >> uint32_t(level * BITS)) & MASK);
        }
    }

    static bool keyAtLeast(const KeyType &a, const KeyType &b) {
        if constexpr (std::is_integral_v<KeyType>) {
            using U = std::make_unsigned_t<KeyType>;
            return static_cast<U>(a) >= static_cast<U>(b);
        } else if constexpr (requires { a < b; }) {
            return !(a < b);
        } else {
            for (uint32_t lvl = TOP_LEVEL;; --lvl) {
                const size_t na = childIndex(lvl, a);
                const size_t nb = childIndex(lvl, b);
                if (na != nb) {
                    return na > nb;
                }
                if (lvl == 0) {
                    return true;
                }
            }
        }
    }

    bool insert(const KeyType &key, RCUPtr<T> value) {
        uint32_t level = TOP_LEVEL;

        RCULock lock;
        std::atomic<RadixElement> *eptr = &root;

        while (true) {
            SEEK_LEAF_LOOP();

            // If the slot is empty, try to insert right there.
            if (e.getLeaf() == nullptr) {
                if (eptr->compare_exchange_strong(e,
                                                  RadixElement(value.get()))) {
                    value.release();
                    return true;
                }

                // CAS failed, we may have a node in there now.
                if (e.isNode()) {
                    goto Node;
                }
            }

            // The element was already in the tree.
            const KeyType &leafKey = getId(*e.getLeaf());
            if (key == leafKey) {
                return false;
            }

            // There is an element there, but it isn't a subtree. We need to
            // convert it into a subtree and resume insertion into that subtree.
            auto newChild = std::make_unique<RadixNode>(level, leafKey, e);
            if (eptr->compare_exchange_strong(e,
                                              RadixElement(newChild.get()))) {
                // We have a subtree, resume normal operations from there.
                newChild.release();
                m_node_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                // We failed to insert our subtree, clean it before it is freed.
                newChild->get(level, leafKey)->store(RadixElement());
            }
        }
    }

    bool insertOrAssign(const KeyType &key, RCUPtr<T> value) {
        uint32_t level = TOP_LEVEL;

        RCULock lock;
        std::atomic<RadixElement> *eptr = &root;

        while (true) {
            SEEK_LEAF_LOOP();

            // If the slot is empty, try to insert right there.
            if (e.getLeaf() == nullptr) {
                if (eptr->compare_exchange_strong(e,
                                                  RadixElement(value.get()))) {
                    value.release();
                    return true;
                }

                // CAS failed, we may have a node in there now.
                if (e.isNode()) {
                    goto Node;
                }
            }

            // Replace existing leaf with matching key via CoW.
            T *oldLeaf = e.getLeaf();
            const KeyType &leafKey = getId(*oldLeaf);
            if (key == leafKey) {
                if (oldLeaf == value.get()) {
                    return false;
                }
                if (eptr->compare_exchange_strong(e,
                                                  RadixElement(value.get()))) {
                    value.release();
                    RCUPtr<T>::acquire(oldLeaf);
                    return false;
                }
                if (e.isNode()) {
                    goto Node;
                }
                continue;
            }

            // There is an element there, but it isn't a subtree. We need to
            // convert it into a subtree and resume insertion into that subtree.
            auto newChild = std::make_unique<RadixNode>(level, leafKey, e);
            if (eptr->compare_exchange_strong(e,
                                              RadixElement(newChild.get()))) {
                newChild.release();
                m_node_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                newChild->get(level, leafKey)->store(RadixElement());
            }
        }
    }

#undef SEEK_LEAF_LOOP

    template <typename Callable>
    bool forEachLeaf(RadixElement e, Callable &&func) const {
        if (e.isLeaf()) {
            T *leaf = e.getLeaf();
            if (leaf != nullptr) {
                return func(RCUPtr<T>::copy(leaf));
            }

            return true;
        }

        return e.getNode()->forEachChild(
            [&](const std::atomic<RadixElement> *pElement) {
                return forEachLeaf(pElement->load(), func);
            });
    }

    template <typename Callable>
    bool forEachFrom(RadixElement e, uint32_t level,
                     const KeyType &lower_bound_key, bool tight,
                     Callable &&func) const {
        if (!tight) {
            return forEachLeaf(e, func);
        }
        if (e.isLeaf()) {
            T *leaf = e.getLeaf();
            if (leaf != nullptr && keyAtLeast(getId(*leaf), lower_bound_key)) {
                return func(RCUPtr<T>::copy(leaf));
            }
            return true;
        }
        const RadixNode *node = e.getNode();
        const size_t min_idx = childIndex(level, lower_bound_key);
        const RadixElement tight_child = node->getChild(min_idx)->load();
        if (level == 0) {
            if (!forEachFrom(tight_child, 0, lower_bound_key, true, func)) {
                return false;
            }
        } else {
            if (!forEachFrom(tight_child, level - 1, lower_bound_key, true,
                             func)) {
                return false;
            }
        }
        for (size_t i = min_idx + 1; i < CHILD_PER_LEVEL; ++i) {
            if (!forEachLeaf(node->getChild(i)->load(), func)) {
                return false;
            }
        }
        return true;
    }

    struct RadixElement {
    private:
        union {
            RadixNode *node;
            T *leaf;
            uintptr_t raw;
        };

        static const uintptr_t DISCRIMINANT = 0x01;
        bool getDiscriminant() const { return (raw & DISCRIMINANT) != 0; }

    public:
        explicit RadixElement() noexcept : raw(DISCRIMINANT) {}
        explicit RadixElement(RadixNode *nodeIn) noexcept : node(nodeIn) {}
        explicit RadixElement(T *leafIn) noexcept : leaf(leafIn) {
            raw |= DISCRIMINANT;
        }

        /**
         * RadixElement is designed to be a dumb wrapper. This allows any
         * container to release what is held by the RadixElement.
         */
        void incrementRefCount() {
            if (isNode()) {
                RCUPtr<RadixNode>::copy(getNode()).release();
            } else {
                RCUPtr<T>::copy(getLeaf()).release();
            }
        }

        void decrementRefCount() {
            if (isNode()) {
                RadixNode *ptr = getNode();
                RCUPtr<RadixNode>::acquire(ptr);
            } else {
                T *ptr = getLeaf();
                RCUPtr<T>::acquire(ptr);
            }
        }

        /**
         * Node features.
         */
        bool isNode() const { return !getDiscriminant(); }

        RadixNode *getNode() {
            assert(isNode());
            return node;
        }

        const RadixNode *getNode() const {
            assert(isNode());
            return node;
        }

        /**
         * Leaf features.
         */
        bool isLeaf() const { return getDiscriminant(); }

        T *getLeaf() {
            assert(isLeaf());
            return reinterpret_cast<T *>(raw & ~DISCRIMINANT);
        }

        const T *getLeaf() const {
            assert(isLeaf());
            return const_cast<RadixElement *>(this)->getLeaf();
        }
    };

    struct RadixNode {
        IMPLEMENT_RCU_REFCOUNT(uint64_t);

    private:
        union {
            std::array<std::atomic<RadixElement>, CHILD_PER_LEVEL> children;
            std::array<RadixElement, CHILD_PER_LEVEL>
                non_atomic_children_DO_NOT_USE;
        };

    public:
        // Nodes can outlive the tree that created them and be reclaimed on a
        // reader thread. The allocator must therefore be stateless/equal and
        // permit allocation and deallocation on different threads.
        static void *operator new(std::size_t size) {
            assert(size == sizeof(RadixNode));
            // Instantiate the rebound allocator only in the function body,
            // where RadixNode is complete (slabs need its size/alignment).
            using Allocator = typename std::allocator_traits<
                NodeAllocator>::template rebind_alloc<RadixNode>;
            static_assert(
                std::allocator_traits<Allocator>::is_always_equal::value);
            Allocator allocator;
            return std::allocator_traits<Allocator>::allocate(allocator, 1);
        }
        static void operator delete(void *ptr) noexcept {
            using Allocator = typename std::allocator_traits<
                NodeAllocator>::template rebind_alloc<RadixNode>;
            Allocator allocator;
            std::allocator_traits<Allocator>::deallocate(
                allocator, static_cast<RadixNode *>(ptr), 1);
        }

        RadixNode(uint32_t level, const KeyType &key, RadixElement e)
            : non_atomic_children_DO_NOT_USE() {
            get(level, key)->store(e);
        }

        ~RadixNode() {
            for (RadixElement e : non_atomic_children_DO_NOT_USE) {
                e.decrementRefCount();
            }
        }

        RadixNode(const RadixNode &rhs) : non_atomic_children_DO_NOT_USE() {
            for (size_t i = 0; i < CHILD_PER_LEVEL; i++) {
                auto e = rhs.children[i].load();
                e.incrementRefCount();
                non_atomic_children_DO_NOT_USE[i] = e;
            }
        }

        RadixNode &operator=(const RadixNode &) = delete;

        std::atomic<RadixElement> *get(uint32_t level, const KeyType &key) {
            return &children[childIndex(level, key)];
        }

        const std::atomic<RadixElement> *get(uint32_t level,
                                             const KeyType &key) const {
            return &children[childIndex(level, key)];
        }

        const std::atomic<RadixElement> *getChild(size_t index) const {
            return &children[index];
        }

        bool isShared() const { return refcount > 0; }

        template <typename Callable> bool forEachChild(Callable &&func) const {
            for (size_t i = 0; i < CHILD_PER_LEVEL; i++) {
                if (!func(&children[i])) {
                    return false;
                }
            }
            return true;
        }
    };

    // Make sure the alignment works for T and RadixElement.
    static_assert(alignof(T) > 1, "T's alignment must be 2 or more.");
    static_assert(alignof(RadixNode) > 1,
                  "RadixNode alignment must be 2 or more.");
};

#endif // BITCOIN_RADIX_H
