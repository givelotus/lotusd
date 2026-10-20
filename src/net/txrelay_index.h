// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_TXRELAY_INDEX_H
#define BITCOIN_NET_TXRELAY_INDEX_H

#include <primitives/blockhash.h>
#include <primitives/txid.h>
#include <sync.h>
#include <uint256.h>
#include <util/hasher.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
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

    /**
     * Start a new epoch indexing `txs` (the mempool, with admission times).
     * The current epoch becomes the previous one; an older one is dropped.
     * A no-op if `key` already is the current epoch.
     */
    void SetEpoch(const EpochKey &key,
                  const std::vector<std::pair<TxId, Clock>> &txs)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
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
    void Insert(Epoch &epoch, const TxId &txid)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    const Epoch *Get(const uint256 &epoch_id) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const unsigned m_bits;
    mutable Mutex m_mutex;
    std::unique_ptr<Epoch> m_current GUARDED_BY(m_mutex);
    std::unique_ptr<Epoch> m_previous GUARDED_BY(m_mutex);
    //! (admission time, txid), in admission order
    std::deque<std::pair<Clock, TxId>> m_window GUARDED_BY(m_mutex);
    std::atomic<uint64_t> m_collisions{0};
};

} // namespace txrelay

#endif // BITCOIN_NET_TXRELAY_INDEX_H
