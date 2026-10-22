// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_MINHASH_H
#define LOTUS_V2_MINHASH_H

#include "commitment.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lotus::v2::minhash {

/**
 * Bottom-k MinHash over transaction identity pairs (TxId, TxHash).
 *
 * Set semantics: one element per Merklix leaf. Re-inserting an identical
 * pair is not a membership change; replacing a TxId's TxHash removes the old
 * element and inserts the new one. Element value: SipHash-2-4 with the fixed
 * protocol key below over TxId || TxHash. Values are deterministic and
 * comparable across nodes; they are NOT secret, so transaction creators can
 * grind low values. The sketch is a fetching/similarity hint only and never
 * authenticates membership or decides validity.
 */
inline constexpr size_t K = 64;
//! Candidate buffer capacity: all members with value <= threshold are kept.
inline constexpr size_t CANDIDATES = 4 * K;
inline constexpr uint64_t KEY0 = 0x6c6f7475732d6d68ULL; // "lotus-mh"
inline constexpr uint64_t KEY1 = 0x2d74786964763031ULL; // "-txidv01"

uint64_t Value(const Hash &tx_id, const Hash &tx_hash) noexcept;

/** Reference: K smallest values of a multiset, ascending. */
std::vector<uint64_t> Reference(std::vector<uint64_t> all);

/**
 * Jaccard estimate from two bottom-k sketches (ascending, <= K values each).
 * Uses the K smallest values of the union; returns 1 for two empty sets.
 */
double EstimateJaccard(std::span<const uint64_t> a, std::span<const uint64_t> b);
/** Estimated |B \ A| from J and the exact set sizes. Never negative. */
double EstimateOnlyInB(double jaccard, uint64_t size_a, uint64_t size_b);

/**
 * Incrementally maintained bottom-k sketch with deletion support.
 *
 * Invariant: when capped, buffer == every member value <= threshold (with
 * multiplicity), and |buffer| >= K unless a rebuild is pending. When not
 * capped, buffer == every member value. Insertion is O(CANDIDATES) worst case
 * (sorted small vector). Deletion of a sampled value is O(CANDIDATES); if the
 * capped buffer falls below K, the next minima cannot be recovered locally and
 * NeedsRebuild() becomes true. The owner then supplies all member values
 * (O(n)); at least CANDIDATES-K+1 sampled deletions separate two rebuilds.
 */
class Maintainer {
public:
    void Insert(uint64_t value);
    void Erase(uint64_t value);
    void Clear();
    bool NeedsRebuild() const noexcept { return m_needs_rebuild; }
    void Rebuild(std::vector<uint64_t> all_values);
    /** The current bottom-k (ascending). Requires !NeedsRebuild(). */
    std::vector<uint64_t> Export() const;
    size_t BufferSize() const noexcept { return m_buffer.size(); }
    bool Capped() const noexcept { return m_capped; }

private:
    void Shrink();
    std::vector<uint64_t> m_buffer; // ascending, with multiplicity
    uint64_t m_threshold{0};
    bool m_capped{false};
    bool m_needs_rebuild{false};
};

} // namespace lotus::v2::minhash

#endif // LOTUS_V2_MINHASH_H
