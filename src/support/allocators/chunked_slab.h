// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_ALLOCATORS_CHUNKED_SLAB_H
#define BITCOIN_SUPPORT_ALLOCATORS_CHUNKED_SLAB_H

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

/**
 * TigerBeetle-style chunked slab arena with an O(1) intrusive freelist for
 * fixed-size node allocations (such as boost::multi_index_container and
 * std::map / indirectmap tree and hash-index nodes in CTxMemPool).
 *
 * Instead of calling ::operator new for every individual node (which scatters
 * tree/hash nodes across disjoint heap pages under mempool churn), SlabArena
 * carves contiguous chunks of `SlotsPerChunk` slots and recycles freed slots
 * through an in-place LIFO intrusive freelist.
 */
class SlabArena final {
public:
    struct FreeNode {
        FreeNode *next;
    };
    static_assert(std::is_trivially_destructible_v<FreeNode>);

private:
    std::size_t m_slot_size{0};
    std::size_t m_slot_align{0};
    std::size_t m_chunk_bytes{0};
    std::size_t m_live_slots{0};
    FreeNode *m_free_head{nullptr};
    std::byte *m_bump_ptr{nullptr};
    std::byte *m_bump_end{nullptr};
    std::vector<std::byte *> m_chunks{};

    void AllocateChunk() {
        m_chunks.reserve(m_chunks.size() + 1);
        auto *raw = static_cast<std::byte *>(
            ::operator new(m_chunk_bytes, std::align_val_t{m_slot_align}));
        m_chunks.push_back(raw);
        m_bump_ptr = raw;
        m_bump_end = raw + m_chunk_bytes;
    }

public:
    constexpr SlabArena() noexcept = default;

    SlabArena(std::size_t slot_size, std::size_t slot_align,
              std::size_t slots_per_chunk) noexcept
        : m_slot_size(slot_size), m_slot_align(slot_align),
          m_chunk_bytes(slot_size * slots_per_chunk) {
        assert(m_slot_size >= sizeof(void *));
        assert(m_slot_align >= alignof(FreeNode));
        assert((m_slot_align & (m_slot_align - 1)) == 0);
        assert(m_slot_size % m_slot_align == 0);
        assert(m_chunk_bytes >= m_slot_size);
    }

    SlabArena(const SlabArena &) = delete;
    SlabArena &operator=(const SlabArena &) = delete;
    SlabArena(SlabArena &&) = delete;
    SlabArena &operator=(SlabArena &&) = delete;

    ~SlabArena() {
        for (std::byte *chunk : m_chunks) {
            ::operator delete(chunk, m_chunk_bytes,
                              std::align_val_t{m_slot_align});
        }
    }

    void Init(std::size_t slot_size, std::size_t slot_align,
              std::size_t slots_per_chunk) noexcept {
        assert(m_slot_size == 0 && m_chunks.empty());
        m_slot_size = slot_size;
        m_slot_align = slot_align;
        m_chunk_bytes = slot_size * slots_per_chunk;
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_slot_size != 0;
    }

    [[nodiscard]] bool Matches(std::size_t slot_size,
                               std::size_t slot_align) const noexcept {
        return m_slot_size == slot_size && m_slot_align == slot_align;
    }

    template <std::size_t SlotSize, std::size_t SlotAlign>
    [[nodiscard]] void *AllocateSlot() {
        static_assert(SlotSize >= sizeof(void *),
                      "SlotSize must be able to hold a freelist pointer");
        assert(m_slot_size == SlotSize && m_slot_align == SlotAlign);
        if (m_free_head != nullptr) {
            ++m_live_slots;
            FreeNode *node = m_free_head;
            m_free_head = node->next;
            return node;
        }
        if (m_bump_ptr == m_bump_end) {
            AllocateChunk();
        }
        ++m_live_slots;
        std::byte *slot = m_bump_ptr;
        m_bump_ptr += SlotSize;
        return slot;
    }

    void DeallocateSlot(void *p) noexcept {
        assert(p != nullptr);
        assert(m_live_slots > 0);
        --m_live_slots;
        m_free_head = ::new (p) FreeNode{m_free_head};
    }

    [[nodiscard]] std::size_t AdditionalChunkBytes(std::size_t slots) const noexcept {
        const std::size_t slots_per_chunk = m_chunk_bytes / m_slot_size;
        const std::size_t available = m_chunks.size() * slots_per_chunk - m_live_slots;
        return slots <= available ? 0 :
            ((slots - available + slots_per_chunk - 1) / slots_per_chunk) * m_chunk_bytes;
    }

    // Explicit clear-boundary sweep; allocation and free remain O(1). The
    // container's sentinel can pin one chunk without pinning all peak chunks.
    void ReleaseUnusedChunks() noexcept {
        if (m_chunks.empty()) return;
        if (m_live_slots == 0) {
            for (std::byte *chunk : m_chunks) {
                ::operator delete(chunk, m_chunk_bytes,
                                  std::align_val_t{m_slot_align});
            }
            m_chunks.clear();
            m_free_head = nullptr;
            m_bump_ptr = m_bump_end = nullptr;
            return;
        }
        if (m_chunks.size() == 1) return;
        // Allocate bookkeeping before changing the freelist. Allocation
        // failure merely retains memory; clear() must not start throwing.
        try {
            struct ChunkState {
                std::byte *base;
                std::size_t free_slots;
            };
            std::vector<ChunkState> chunks;
            chunks.reserve(m_chunks.size());
            for (std::byte *base : m_chunks) {
                const auto end = reinterpret_cast<std::uintptr_t>(base) + m_chunk_bytes;
                const std::size_t unissued = end == reinterpret_cast<std::uintptr_t>(m_bump_end)
                    ? static_cast<std::size_t>(m_bump_end - m_bump_ptr) / m_slot_size : 0;
                chunks.push_back({base, unissued});
            }
            std::sort(chunks.begin(), chunks.end(), [](const auto &a, const auto &b) {
                return reinterpret_cast<std::uintptr_t>(a.base) <
                       reinterpret_cast<std::uintptr_t>(b.base);
            });
            auto owner = [&](const void *ptr) -> ChunkState & {
                const auto address = reinterpret_cast<std::uintptr_t>(ptr);
                auto it = std::upper_bound(chunks.begin(), chunks.end(), address,
                    [](std::uintptr_t value, const ChunkState &chunk) {
                        return value < reinterpret_cast<std::uintptr_t>(chunk.base);
                    });
                assert(it != chunks.begin());
                --it;
                assert(address < reinterpret_cast<std::uintptr_t>(it->base) + m_chunk_bytes);
                return *it;
            };
            for (FreeNode *node = m_free_head; node; node = node->next) {
                ++owner(node).free_slots;
            }
            const std::size_t slots_per_chunk = m_chunk_bytes / m_slot_size;
            FreeNode **link = &m_free_head;
            while (*link) {
                FreeNode *node = *link;
                if (owner(node).free_slots == slots_per_chunk) *link = node->next;
                else link = &node->next;
            }
            m_chunks.clear();
            for (const auto &chunk : chunks) {
                if (chunk.free_slots == slots_per_chunk) {
                    if (chunk.base + m_chunk_bytes == m_bump_end) {
                        m_bump_ptr = m_bump_end = nullptr;
                    }
                    ::operator delete(chunk.base, m_chunk_bytes,
                                      std::align_val_t{m_slot_align});
                } else {
                    m_chunks.push_back(chunk.base);
                }
            }
        } catch (const std::bad_alloc &) {
            // Before mutation, the bookkeeping allocation is the only throw.
        }
    }

    [[nodiscard]] std::size_t NumAllocatedChunks() const noexcept {
        return m_chunks.size();
    }

    [[nodiscard]] std::size_t ChunkSizeBytes() const noexcept {
        return m_chunk_bytes;
    }

    [[nodiscard]] std::size_t SlotSizeBytes() const noexcept {
        return m_slot_size;
    }

    [[nodiscard]] std::size_t FreeListCount() const noexcept {
        std::size_t count = 0;
        for (const FreeNode *cur = m_free_head; cur != nullptr;
             cur = cur->next) {
            ++count;
        }
        return count;
    }
};

/**
 * Shared resource backing a family of rebound ChunkedSlabAllocator instances.
 *
 * Node-based containers (boost::multi_index_container, std::map) rebind their
 * value_type allocator to internal node type(s). Sharing a ChunkedSlabResource
 * across rebinds ensures that on-the-fly rebinding and stored node allocators
 * always resolve to the same SlabArena for a given (SlotSize, SlotAlign).
 */
template <std::size_t SlotsPerChunk = 16384> class ChunkedSlabResource final {
    static_assert(SlotsPerChunk > 0, "SlotsPerChunk must be positive");

    std::size_t m_array_bytes{0};
    std::size_t m_largest_rebound_slot{0};
    SlabArena m_primary_arena{};
    std::vector<std::unique_ptr<SlabArena>> m_overflow_arenas{};

public:
    ChunkedSlabResource() noexcept = default;
    ChunkedSlabResource(const ChunkedSlabResource &) = delete;
    ChunkedSlabResource &operator=(const ChunkedSlabResource &) = delete;

    [[nodiscard]] SlabArena *GetOrCreateArena(std::size_t slot_size,
                                              std::size_t slot_align) {
        if (!m_primary_arena.IsInitialized()) {
            m_primary_arena.Init(slot_size, slot_align, SlotsPerChunk);
            return &m_primary_arena;
        }
        if (m_primary_arena.Matches(slot_size, slot_align)) {
            return &m_primary_arena;
        }
        for (const auto &arena : m_overflow_arenas) {
            if (arena->Matches(slot_size, slot_align)) {
                return arena.get();
            }
        }
        m_overflow_arenas.push_back(
            std::make_unique<SlabArena>(slot_size, slot_align, SlotsPerChunk));
        return m_overflow_arenas.back().get();
    }

    [[nodiscard]] std::size_t NumAllocatedChunks() const noexcept {
        std::size_t total = m_primary_arena.NumAllocatedChunks();
        for (const auto &arena : m_overflow_arenas) {
            total += arena->NumAllocatedChunks();
        }
        return total;
    }

    // Rebinding to a container's implementation-node allocator reveals its
    // size even before its first allocation (notably an empty std::map).
    void ObserveReboundSlot(std::size_t size) noexcept {
        m_largest_rebound_slot = std::max(m_largest_rebound_slot, size);
    }
    [[nodiscard]] std::size_t AdditionalChunkBytes(std::size_t slots) const noexcept {
        if (!m_primary_arena.IsInitialized()) {
            return ((slots + SlotsPerChunk - 1) / SlotsPerChunk) *
                   SlotsPerChunk * m_largest_rebound_slot;
        }
        std::size_t bytes = m_primary_arena.AdditionalChunkBytes(slots);
        // Charging each node class is conservative for resources shared by
        // several rebound containers; it never counts an unused slot as free
        // in another class.
        for (const auto &arena : m_overflow_arenas) {
            bytes += arena->AdditionalChunkBytes(slots);
        }
        return bytes;
    }

    void AccountArrayAllocation(std::size_t bytes) noexcept {
        m_array_bytes += bytes;
    }
    void AccountArrayDeallocation(std::size_t bytes) noexcept {
        assert(m_array_bytes >= bytes);
        m_array_bytes -= bytes;
    }
    [[nodiscard]] std::size_t TotalAllocatedBytes() const noexcept {
        return TotalAllocatedChunkBytes() + m_array_bytes;
    }
    void ReleaseUnusedChunks() noexcept {
        m_primary_arena.ReleaseUnusedChunks();
        for (const auto &arena : m_overflow_arenas) {
            arena->ReleaseUnusedChunks();
        }
    }

    [[nodiscard]] std::size_t TotalAllocatedChunkBytes() const noexcept {
        std::size_t total = m_primary_arena.NumAllocatedChunks() *
                            m_primary_arena.ChunkSizeBytes();
        for (const auto &arena : m_overflow_arenas) {
            total += arena->NumAllocatedChunks() * arena->ChunkSizeBytes();
        }
        return total;
    }
};

/**
 * STL- and Boost.MultiIndex-compatible stateful allocator backed by
 * ChunkedSlabResource.
 *
 * - Single-element allocations (`n == 1`, used for all tree/hash index nodes)
 *   are served in O(1) from the slab arena's intrusive freelist or contiguous
 *   bump chunk.
 * - Multi-element allocations (`n > 1`, such as contiguous bucket pointer
 *   arrays in `boost::multi_index::hashed_unique`) fall back directly to
 *   aligned `::operator new` / `::operator delete`.
 */
template <typename T, std::size_t SlotsPerChunk = 16384>
class ChunkedSlabAllocator {
    static_assert(SlotsPerChunk > 0, "SlotsPerChunk must be positive");

    static constexpr std::size_t SlotAlign() noexcept {
        return std::max(alignof(T), alignof(SlabArena::FreeNode));
    }

    static constexpr std::size_t SlotSize() noexcept {
        constexpr std::size_t align =
            std::max(alignof(T), alignof(SlabArena::FreeNode));
        constexpr std::size_t raw =
            std::max(sizeof(T), sizeof(SlabArena::FreeNode));
        constexpr std::size_t size = ((raw + align - 1) / align) * align;
        static_assert(size >= sizeof(void *),
                      "SlotSize must be at least sizeof(void*)");
        static_assert((align & (align - 1)) == 0,
                      "SlotAlign must be a power of two");
        return size;
    }

    std::shared_ptr<ChunkedSlabResource<SlotsPerChunk>> m_resource;
    mutable SlabArena *m_arena{nullptr};

    template <typename U, std::size_t S> friend class ChunkedSlabAllocator;

    SlabArena *EnsureArena() const {
        if (m_arena == nullptr) {
            m_arena = m_resource->GetOrCreateArena(SlotSize(), SlotAlign());
        }
        return m_arena;
    }

public:
    using value_type = T;
    using pointer = T *;
    using const_pointer = const T *;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::false_type;

    template <typename U> struct rebind {
        using other = ChunkedSlabAllocator<U, SlotsPerChunk>;
    };

    ChunkedSlabAllocator()
        : m_resource(std::make_shared<ChunkedSlabResource<SlotsPerChunk>>()),
          m_arena(nullptr) {
        m_resource->ObserveReboundSlot(SlotSize());
    }

    ChunkedSlabAllocator(const ChunkedSlabAllocator &other) noexcept = default;
    ChunkedSlabAllocator &
    operator=(const ChunkedSlabAllocator &other) noexcept = default;

    ChunkedSlabAllocator(ChunkedSlabAllocator &&other) noexcept = default;
    ChunkedSlabAllocator &
    operator=(ChunkedSlabAllocator &&other) noexcept = default;

    template <typename U>
    ChunkedSlabAllocator(
        const ChunkedSlabAllocator<U, SlotsPerChunk> &other) noexcept
        : m_resource(other.m_resource), m_arena(nullptr) {
        m_resource->ObserveReboundSlot(SlotSize());
    }

    [[nodiscard]] T *allocate(std::size_t n) {
        if (n == 1) {
            return static_cast<T *>(
                EnsureArena()
                    ->template AllocateSlot<SlotSize(), SlotAlign()>());
        }
        T *result = static_cast<T *>(
            ::operator new(n * sizeof(T), std::align_val_t{alignof(T)}));
        m_resource->AccountArrayAllocation(n * sizeof(T));
        return result;
    }

    void deallocate(T *p, std::size_t n) noexcept {
        if (p == nullptr) {
            return;
        }
        if (n == 1) {
            EnsureArena()->DeallocateSlot(p);
            return;
        }
        ::operator delete(p, n * sizeof(T), std::align_val_t{alignof(T)});
        m_resource->AccountArrayDeallocation(n * sizeof(T));
    }

    [[nodiscard]] ChunkedSlabResource<SlotsPerChunk> *resource() const noexcept {
        return m_resource.get();
    }

    [[nodiscard]] SlabArena *arena() const { return EnsureArena(); }
};

template <typename T1, typename T2, std::size_t SlotsPerChunk>
bool operator==(const ChunkedSlabAllocator<T1, SlotsPerChunk> &a,
                const ChunkedSlabAllocator<T2, SlotsPerChunk> &b) noexcept {
    return a.resource() == b.resource();
}

template <typename T1, typename T2, std::size_t SlotsPerChunk>
bool operator!=(const ChunkedSlabAllocator<T1, SlotsPerChunk> &a,
                const ChunkedSlabAllocator<T2, SlotsPerChunk> &b) noexcept {
    return !(a == b);
}

#endif // BITCOIN_SUPPORT_ALLOCATORS_CHUNKED_SLAB_H
