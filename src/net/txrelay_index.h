// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_TXRELAY_INDEX_H
#define BITCOIN_NET_TXRELAY_INDEX_H

#include <primitives/blockhash.h>
#include <primitives/txid.h>
#include <radix.h>
#include <support/allocators/chunked_slab.h>
#include <sync.h>
#include <uint256.h>
#include <uint256radixkey.h>
#include <util/hasher.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * Nucleation relay: short transaction ids and the index that maps them back.
 *
 * Short-id announcements (invshort) and continuous reconciliation share one
 * 64-bit short id per transaction per epoch. An epoch is the chain tip the
 * ids were computed against; its SipHash key is the per-epoch key of set
 * reconciliation (lotus::v2::DeriveEpochSipHashKey(tip hash, tip height)),
 * applied as in the Merklix handler (ComputeMerklixShortId). A new block
 * starts a new epoch (new key); the previous epoch stays indexed so that
 * peers still on it can be understood across the boundary.
 */
namespace txrelay {

/** Capability flags exchanged in sendinvshort */
enum Feature : uint64_t {
    TXRELAY_INVSHORT = 1 << 0,
    TXRELAY_RECON = 1 << 1,
    //! Complete immutable full-mempool scope5 framing (not legacy windows).
    TXRELAY_FULL_MEMPOOL = 1 << 3,
    // Accept sealedheader block announcements and unsolicited shorttx bodies.
    // This is separate from ordinary compact blocks and short-id requests.
    TXRELAY_HIGH_BANDWIDTH = 1 << 2,
};
/** Version of the sendinvshort message we send */
static constexpr uint32_t SENDINVSHORT_VERSION{1};

struct EpochKey {
    //! The chain tip (block hash) this epoch is keyed on
    uint256 epoch_id;
    uint64_t k0{0};
    uint64_t k1{0};

    friend bool operator==(const EpochKey &a, const EpochKey &b) {
        return a.epoch_id == b.epoch_id && a.k0 == b.k0 && a.k1 == b.k1;
    }
};

/** The epoch keyed on a chain tip */
EpochKey MakeEpochKey(const BlockHash &tip, uint64_t height);

/**
 * Short id of a transaction under an epoch key, truncated to `bits` bits
 * (64 in production; fewer only in tests, to force collisions). Never 0.
 */
uint64_t ComputeShortId(uint64_t k0, uint64_t k1, const TxId &txid,
                        unsigned bits = 64);

/**
 * The request-tracker key for a short id announced under an epoch:
 * the short id in the first 8 bytes and bytes 8..31 of the epoch id.
 * No transaction id can be expected to share 24 bytes with a block hash,
 * so these keys never collide with real transaction ids.
 */
uint256 ShortIdRequestKey(const uint256 &epoch_id, uint64_t short_id);
/** Recover the short id if `key` is a request key for `epoch_id` */
std::optional<uint64_t> ParseShortIdRequestKey(const uint256 &key,
                                               const uint256 &epoch_id);

/**
 * Index of the mempool's transactions by short id, for the current and the
 * previous epoch, plus the admission-time window used by reconciliation.
 * Thread safe.
 */
class TxRelayIndex {
public:
    using Clock = std::chrono::microseconds;

    explicit TxRelayIndex(unsigned shortid_bits = 64);

    unsigned ShortIdBits() const { return m_bits; }
    uint64_t ShortId(const EpochKey &key, const TxId &txid) const {
        return ComputeShortId(key.k0, key.k1, txid, m_bits);
    }

    using Snapshot = std::vector<std::pair<TxId, Clock>>;

    /**
     * Start a new epoch from a mempool snapshot obtained by `snapshot`.
     * The callback runs without the index lock, after mutation tracking starts.
     * Concurrent additions/removals are replayed before publication. If the
     * bounded mutation journal overflows, retain the old epoch and retry on
     * the next normal update; do not publish an incomplete index.
     * The current epoch becomes the previous one; an older one is dropped.
     * A no-op if `key` already is the current epoch.
     */
    void SetEpoch(const EpochKey &key,
                  const std::function<Snapshot()> &snapshot)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex, !m_rebuild_mutex);
    /** The current epoch, if any */
    std::optional<EpochKey> Current() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** The current and the previous epoch (those indexed) */
    std::vector<EpochKey> Epochs() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** The current or previous epoch named epoch_id, if indexed */
    std::optional<EpochKey> FindEpoch(const uint256 &epoch_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** A transaction entered the mempool (idempotent) */
    void Add(const TxId &txid, Clock time) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** A transaction left the mempool (the previous epoch keeps it) */
    void Remove(const TxId &txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    enum class Lookup { UNKNOWN_EPOCH, HAVE, MISSING };
    /**
     * Whether we have a transaction with this short id in this epoch;
     * `out` (if given) receives every transaction id under it.
     */
    Lookup Find(const uint256 &epoch_id, uint64_t short_id,
                std::vector<TxId> *out = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Transactions admitted at or after `since` (and before `until`), still
     * in the mempool
     */
    std::vector<TxId> AdmittedSince(Clock since,
                                    Clock until = Clock::max()) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Numerically ordered immutable candidate view. No transaction refs or
     * mempool lock are held by this index. Pinning retains a coherent index
     * membership view while callers check a separately pinned mempool view.
     */
    struct WindowEntry {
        const TxId txid;
        explicit WindowEntry(const TxId &id) : txid(id) {}
        static void *operator new(std::size_t) {
            return GlobalConcurrentSlabAllocator<WindowEntry, 1024>{}.allocate(
                1);
        }
        static void operator delete(void *p) noexcept {
            GlobalConcurrentSlabAllocator<WindowEntry, 1024>{}.deallocate(
                static_cast<WindowEntry *>(p), 1);
        }
        IMPLEMENT_RCU_REFCOUNT(uint32_t);
    };
    struct WindowEntryAdapter {
        // Return the numeric key by value. PassthroughAdapter returns auto&&,
        // which would dangle if forwarded from a temporary key conversion.
        Uint256RadixKey getId(const WindowEntry &entry) const {
            return entry.txid;
        }
    };
    using WindowTree =
        RadixTree<WindowEntry, WindowEntryAdapter,
                  GlobalConcurrentSlabAllocator<std::byte, 1024>>;
    /**
     * Pin the exact AdmittedSince set in numeric txid order. Monotonically
     * advancing windows update only newly eligible/expired occurrences;
     * queries do not rescan/sort the entire resident window. Nonmonotonic
     * queries rebuild, and out-of-order admissions use the legacy scan.
     */
    std::shared_ptr<const WindowTree> PinAdmittedSince(Clock since,
                                                       Clock until) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Forget window entries older than `before` */
    void PruneWindow(Clock before) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Number of times a short id already held a different transaction when
     * one was indexed (in any epoch)
     */
    uint64_t Collisions() const { return m_collisions.load(); }
    /** Transactions indexed in the current epoch */
    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Epoch {
        EpochKey key;
        std::unordered_map<uint64_t, std::vector<TxId>> by_short_id;
        std::unordered_map<TxId, uint64_t, SaltedTxIdHasher> short_id_of;
    };
    //! Index txid in epoch (which the caller owns or guards with m_mutex)
    void InsertUnlocked(Epoch &epoch, const TxId &txid) const;
    static void RemoveFromEpoch(Epoch &epoch, const TxId &txid);
    void RecordEpochChange(const TxId &txid, bool present)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    const Epoch *Get(const uint256 &epoch_id) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const unsigned m_bits;
    //! Only builders take this lock; never held by Add/Remove or snapshot
    //! callers.
    Mutex m_rebuild_mutex;
    mutable Mutex m_mutex;
    //! Bounded mutation count, independent of churn or rebuild duration.
    static constexpr size_t MAX_EPOCH_CHANGES{65'536};
    bool m_rebuilding GUARDED_BY(m_mutex){false};
    bool m_epoch_overflow GUARDED_BY(m_mutex){false};
    std::vector<std::pair<TxId, bool>> m_epoch_changes GUARDED_BY(m_mutex);
    std::unique_ptr<Epoch> m_current GUARDED_BY(m_mutex);
    std::unique_ptr<Epoch> m_previous GUARDED_BY(m_mutex);
    //! (admission time, txid), in admission order
    std::deque<std::pair<Clock, TxId>> m_window GUARDED_BY(m_mutex);
    // Numeric cursors survive deque growth; pruning advances its origin.
    uint64_t m_window_origin GUARDED_BY(m_mutex){0};
    size_t m_window_inversions GUARDED_BY(m_mutex){0};
    mutable bool m_query_valid GUARDED_BY(m_mutex){false};
    mutable Clock m_query_since GUARDED_BY(m_mutex){};
    mutable Clock m_query_until GUARDED_BY(m_mutex){};
    mutable uint64_t m_query_lower GUARDED_BY(m_mutex){0};
    mutable uint64_t m_query_upper GUARDED_BY(m_mutex){0};
    mutable std::unordered_map<TxId, size_t, SaltedTxIdHasher>
        m_query_counts GUARDED_BY(m_mutex);
    mutable WindowTree m_query_tree GUARDED_BY(m_mutex);
    void AddQueryOccurrence(const TxId &txid) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void RemoveQueryOccurrence(const TxId &txid) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    mutable std::atomic<uint64_t> m_collisions{0};
};

} // namespace txrelay

#endif // BITCOIN_NET_TXRELAY_INDEX_H
