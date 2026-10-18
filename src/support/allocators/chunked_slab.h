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
#include <mutex>
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

/**
 * Process-wide, mutex-guarded slab arena for one (SlotSize, SlotAlign) class.
 *
 * Threads reach the pool only in batches, through the per-thread magazines of
 * GlobalConcurrentSlabAllocator, so the mutex is taken once per
 * MAGAZINE_BATCH allocations or deallocations rather than once per call.
 *
 * The pool is constructed on first use in static storage and intentionally
 * never destroyed: objects released during static destruction (for example a
 * global CTransactionRef) can still return their slot safely.
 */
template <std::size_t SlotSize, std::size_t SlotAlign,
          std::size_t SlotsPerChunk>
class ConcurrentSlabPool final {
    std::mutex m_mutex;
    SlabArena m_arena{SlotSize, SlotAlign, SlotsPerChunk};
    //! Slots handed out to threads (in use or cached in a magazine).
    std::size_t m_outstanding{0};

    ConcurrentSlabPool() = default;

public:
    ConcurrentSlabPool(const ConcurrentSlabPool &) = delete;
    ConcurrentSlabPool &operator=(const ConcurrentSlabPool &) = delete;

    static ConcurrentSlabPool &Get() {
        alignas(ConcurrentSlabPool) static std::byte
            storage[sizeof(ConcurrentSlabPool)];
        static ConcurrentSlabPool *const pool =
            ::new (static_cast<void *>(storage)) ConcurrentSlabPool();
        return *pool;
    }

    /**
     * Fill out[0..count) with free slots. Returns the number of slots
     * provided, which is less than count only if a chunk allocation failed
     * after at least one slot was obtained; throws std::bad_alloc otherwise.
     */
    std::size_t AllocateBatch(void **out, std::size_t count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::size_t i = 0;
        try {
            for (; i < count; ++i) {
                out[i] = m_arena.template AllocateSlot<SlotSize, SlotAlign>();
            }
        } catch (const std::bad_alloc &) {
            if (i == 0) {
                throw;
            }
        }
        m_outstanding += i;
        return i;
    }

    void DeallocateBatch(void *const *in, std::size_t count) noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (std::size_t i = 0; i < count; ++i) {
            m_arena.DeallocateSlot(in[i]);
        }
        m_outstanding -= count;
    }

    [[nodiscard]] std::size_t NumAllocatedChunks() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_arena.NumAllocatedChunks();
    }

    [[nodiscard]] std::size_t OutstandingSlots() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_outstanding;
    }
};

/**
 * Stateless, thread-safe allocator for single objects of type T, backed by a
 * process-wide ConcurrentSlabPool (one per slot size/alignment class).
 *
 * Each thread keeps a magazine of up to MAGAZINE_SIZE free slots. The fast
 * path of allocate(1) / deallocate(p, 1) only touches that thread-local
 * magazine: no locks and no atomics. A thread refills or flushes
 * MAGAZINE_BATCH slots at a time under the pool mutex. Objects may be freed on
 * a different thread than the one that allocated them; the slot simply joins
 * the freeing thread's magazine.
 *
 * When a thread exits, its magazine is flushed back to the pool. Any slot
 * released on that thread afterwards (by later thread_local or static
 * destructors) bypasses the magazine and goes straight to the pool.
 *
 * Multi-object allocations (n != 1) use aligned ::operator new.
 * Like any slab, memory is reused for objects of the same class but never
 * returned to the system.
 */
template <typename T, std::size_t SlotsPerChunk = 16384>
class GlobalConcurrentSlabAllocator {
    static_assert(SlotsPerChunk > 0, "SlotsPerChunk must be positive");

    static constexpr std::size_t SlotAlign() noexcept {
        return std::max(alignof(T), alignof(SlabArena::FreeNode));
    }

    static constexpr std::size_t SlotSize() noexcept {
        constexpr std::size_t align = SlotAlign();
        constexpr std::size_t raw =
            std::max(sizeof(T), sizeof(SlabArena::FreeNode));
        return ((raw + align - 1) / align) * align;
    }

    using Pool = ConcurrentSlabPool<SlotSize(), SlotAlign(), SlotsPerChunk>;

    static constexpr std::size_t MAGAZINE_SIZE = 64;
    static constexpr std::size_t MAGAZINE_BATCH = MAGAZINE_SIZE / 2;

    enum class MagazineState : uint8_t { UNREGISTERED, LIVE, RETIRED };

    // Trivially destructible, so it stays usable during thread teardown.
    struct Magazine {
        void *slots[MAGAZINE_SIZE];
        uint32_t count;
        MagazineState state;
    };
    static_assert(std::is_trivially_destructible_v<Magazine>);

    static Magazine &LocalMagazine() noexcept {
        static thread_local constinit Magazine magazine{};
        return magazine;
    }

    struct MagazineRetirer {
        ~MagazineRetirer() {
            Magazine &mag = LocalMagazine();
            if (mag.count > 0) {
                Pool::Get().DeallocateBatch(mag.slots, mag.count);
                mag.count = 0;
            }
            mag.state = MagazineState::RETIRED;
        }
    };

    static void RegisterThread(Magazine &mag) {
        static thread_local MagazineRetirer retirer;
        (void)retirer;
        mag.state = MagazineState::LIVE;
    }

    static void *AllocateSlow(Magazine &mag) {
        if (mag.state == MagazineState::UNREGISTERED) {
            RegisterThread(mag);
        }
        if (mag.state == MagazineState::RETIRED) {
            void *slot;
            Pool::Get().AllocateBatch(&slot, 1);
            return slot;
        }
        mag.count = static_cast<uint32_t>(
            Pool::Get().AllocateBatch(mag.slots, MAGAZINE_BATCH));
        return mag.slots[--mag.count];
    }

    static void DeallocateSlow(Magazine &mag, void *p) noexcept {
        if (mag.state == MagazineState::UNREGISTERED) {
            RegisterThread(mag);
        }
        if (mag.state == MagazineState::RETIRED) {
            Pool::Get().DeallocateBatch(&p, 1);
            return;
        }
        if (mag.count == MAGAZINE_SIZE) {
            Pool::Get().DeallocateBatch(mag.slots + MAGAZINE_BATCH,
                                        MAGAZINE_SIZE - MAGAZINE_BATCH);
            mag.count = MAGAZINE_BATCH;
        }
        mag.slots[mag.count++] = p;
    }

public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using is_always_equal = std::true_type;

    template <typename U> struct rebind {
        using other = GlobalConcurrentSlabAllocator<U, SlotsPerChunk>;
    };

    constexpr GlobalConcurrentSlabAllocator() noexcept = default;
    template <typename U>
    constexpr GlobalConcurrentSlabAllocator(
        const GlobalConcurrentSlabAllocator<U, SlotsPerChunk> &) noexcept {}

    [[nodiscard]] T *allocate(std::size_t n) {
        if (n != 1) {
            return static_cast<T *>(
                ::operator new(n * sizeof(T), std::align_val_t{alignof(T)}));
        }
        Magazine &mag = LocalMagazine();
        if (mag.state == MagazineState::LIVE && mag.count > 0) {
            return static_cast<T *>(mag.slots[--mag.count]);
        }
        return static_cast<T *>(AllocateSlow(mag));
    }

    void deallocate(T *p, std::size_t n) noexcept {
        if (p == nullptr) {
            return;
        }
        if (n != 1) {
            ::operator delete(p, n * sizeof(T), std::align_val_t{alignof(T)});
            return;
        }
        Magazine &mag = LocalMagazine();
        if (mag.state == MagazineState::LIVE && mag.count < MAGAZINE_SIZE) {
            mag.slots[mag.count++] = p;
            return;
        }
        DeallocateSlow(mag, p);
    }

    /** Chunks carved by the pool backing T's slot class. */
    [[nodiscard]] static std::size_t NumAllocatedChunks() {
        return Pool::Get().NumAllocatedChunks();
    }

    /**
     * Slots currently in use or cached in live thread magazines for T's slot
     * class. Excludes slots that exited threads have flushed back.
     */
    [[nodiscard]] static std::size_t OutstandingSlots() {
        return Pool::Get().OutstandingSlots();
    }
};

template <typename T1, typename T2, std::size_t SlotsPerChunk>
constexpr bool
operator==(const GlobalConcurrentSlabAllocator<T1, SlotsPerChunk> &,
           const GlobalConcurrentSlabAllocator<T2, SlotsPerChunk> &) noexcept {
    return true;
}

template <typename T1, typename T2, std::size_t SlotsPerChunk>
constexpr bool
operator!=(const GlobalConcurrentSlabAllocator<T1, SlotsPerChunk> &,
           const GlobalConcurrentSlabAllocator<T2, SlotsPerChunk> &) noexcept {
    return false;
}

#endif // BITCOIN_SUPPORT_ALLOCATORS_CHUNKED_SLAB_H
