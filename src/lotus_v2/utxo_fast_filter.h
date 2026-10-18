// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_UTXO_FAST_FILTER_H
#define LOTUS_V2_UTXO_FAST_FILTER_H

#include "sparse_state.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_set>
#include <vector>

namespace lotus::v2 {

/** A 64-shard compact fingerprint hint for UTXO and mempool lookup.
 * Bloom negatives avoid shard lookup; fingerprint positives require the
 * authoritative outpoint/coin lookup. It does not certify coin availability
 * or authorize accepting/rejecting a transaction on its own.
 */
class UtxoFastFilter {
public:
    static constexpr size_t kNumShards = 64;
    static constexpr size_t kBloomWords = 32; // 2048 bits (256 bytes) per filter

    UtxoFastFilter();

    void ReservePerShard(size_t unspent_cap, size_t spent_cap);

    static uint64_t ComputeFingerprint(const uint8_t *txid32,
                                       uint32_t index) noexcept;
    static uint64_t ComputeFingerprint(const Outpoint &op) noexcept {
        return ComputeFingerprint(op.tx_id.data(), op.index);
    }

    static size_t ShardIndex(const uint8_t *txid32) noexcept {
        return static_cast<size_t>(txid32[0] & 0x3Fu);
    }
    static size_t ShardIndex(const Outpoint &op) noexcept {
        return ShardIndex(op.tx_id.data());
    }

    bool MarkSpentInMempool(const uint8_t *txid32, uint32_t index);
    bool MarkSpentInMempool(const Outpoint &op) {
        return MarkSpentInMempool(op.tx_id.data(), op.index);
    }

    bool UnmarkSpentInMempool(const uint8_t *txid32, uint32_t index);
    bool UnmarkSpentInMempool(const Outpoint &op) {
        return UnmarkSpentInMempool(op.tx_id.data(), op.index);
    }

    bool IsSpentInMempool(const uint8_t *txid32,
                          uint32_t index) const noexcept;
    bool IsSpentInMempool(const Outpoint &op) const noexcept {
        return IsSpentInMempool(op.tx_id.data(), op.index);
    }

    bool AddUnspent(const uint8_t *txid32, uint32_t index);
    bool AddUnspent(const Outpoint &op) {
        return AddUnspent(op.tx_id.data(), op.index);
    }

    bool RemoveUnspent(const uint8_t *txid32, uint32_t index);
    bool RemoveUnspent(const Outpoint &op) {
        return RemoveUnspent(op.tx_id.data(), op.index);
    }

    bool ContainsUnspent(const uint8_t *txid32,
                         uint32_t index) const noexcept;
    bool ContainsUnspent(const Outpoint &op) const noexcept {
        return ContainsUnspent(op.tx_id.data(), op.index);
    }

    /** Return a compact membership hint, not authoritative UTXO validity. */
    bool MayExistInChainOrMempool(const uint8_t *txid32,
                                  uint32_t index) const noexcept {
        return ContainsUnspent(txid32, index);
    }
    bool MayExistInChainOrMempool(const Outpoint &op) const noexcept {
        return ContainsUnspent(op.tx_id.data(), op.index);
    }

    void SetChainUhsAuthoritative(bool authoritative) noexcept {
        chain_uhs_authoritative_.store(authoritative,
                                       std::memory_order_release);
    }
    bool IsChainUhsAuthoritative() const noexcept {
        return chain_uhs_authoritative_.load(std::memory_order_acquire);
    }

    void ClearMempool();
    void ClearAll();

    size_t GetMempoolSpentCount() const noexcept;
    size_t MempoolSpentCount() const noexcept { return GetMempoolSpentCount(); }
    size_t GetUnspentCount() const noexcept;
    size_t UnspentCount() const noexcept { return GetUnspentCount(); }

private:
    friend struct UtxoFastFilterTestAccess;
    struct FlatFpSet {
        std::vector<uint64_t> slots;
        std::vector<size_t> references;
        size_t count{0};
        size_t tombstones{0};

        static constexpr uint64_t kEmpty = 0ULL;
        static constexpr uint64_t kTombstone = 1ULL;

        FlatFpSet();
        void Clear();
        void Reserve(size_t min_entries);
        bool Insert(uint64_t fp);
        bool Erase(uint64_t fp);
        bool Contains(uint64_t fp) const noexcept;
        void Rehash(size_t new_cap);
    };

    struct SaltedOutpointHasher {
        size_t operator()(const Outpoint &op) const noexcept {
            return ComputeFingerprint(op);
        }
    };

    struct alignas(64) Shard {
        std::array<std::atomic<uint64_t>, kBloomWords> spent_bloom{};
        std::array<std::atomic<uint64_t>, kBloomWords> unspent_bloom{};
        std::atomic<size_t> spent_count{0};
        std::atomic<size_t> unspent_count{0};
        mutable std::mutex mutex;
        // Exact identities make repeated insertion idempotent while distinct
        // outpoints sharing a fingerprint keep separate references.
        std::unordered_set<Outpoint, SaltedOutpointHasher> spent_outpoints;
        std::unordered_set<Outpoint, SaltedOutpointHasher> unspent_outpoints;
        FlatFpSet spent_set;
        FlatFpSet unspent_set;

        Shard();
        void RebuildSpentBloomLocked() noexcept;
        void RebuildUnspentBloomLocked() noexcept;
    };

    std::array<Shard, kNumShards> shards_;
    std::atomic<bool> chain_uhs_authoritative_{false};
};

} // namespace lotus::v2

#endif // LOTUS_V2_UTXO_FAST_FILTER_H
