// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_SET_RECONCILIATION_H
#define LOTUS_V2_SET_RECONCILIATION_H

#include "header.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace lotus::v2 {

/**
 * Irreducible primitive polynomial for GF(2^64):
 *   P(x) = x^64 + x^4 + x^3 + x + 1  (low 64 bits = 0x1b)
 */
inline constexpr uint64_t kGF64Modulus = 0x1bULL;

/**
 * Derive per-epoch 128-bit SipHash-2-4 key (k0, k1) from prev_block_id,
 * epoch_number, and parent_overlay_id so peers cannot pre-mine short_id
 * collisions across epochs (Hole 1).
 */
std::pair<uint64_t, uint64_t>
DeriveEpochSipHashKey(const Hash &prev_block_id, uint64_t epoch_number,
                      const Hash &parent_overlay_id = Hash{}) noexcept;

/**
 * Compute keyed SipHash-2-4 64-bit short_id for a 256-bit transaction hash.
 * Maps 0 -> 1 so every valid transaction maps to a non-zero element of GF(2^64)^*.
 */
uint64_t ComputeShortTxId(uint64_t k0, uint64_t k1,
                          const Hash &tx_hash) noexcept;

// ============================================================================
// GF(2^64) Finite Field Arithmetic modulo x^64 + x^4 + x^3 + x + 1
// ============================================================================

inline constexpr uint64_t GF64Add(uint64_t a, uint64_t b) noexcept {
    return a ^ b;
}

uint64_t GF64Mul(uint64_t a, uint64_t b) noexcept;
uint64_t GF64Sqr(uint64_t a) noexcept;
uint64_t GF64Cube(uint64_t a) noexcept;
uint64_t GF64Pow5(uint64_t a) noexcept;
uint64_t GF64Inv(uint64_t a) noexcept;
uint64_t GF64Trace(uint64_t a) noexcept;

/**
 * Solve y^2 + y = c in GF(2^64).
 * Returns true and sets y_out if Tr(c) == 0; returns false if Tr(c) == 1.
 */
bool GF64SolveQuadratic(uint64_t c, uint64_t &y_out) noexcept;

// ============================================================================
// Degree-2 BCH Bucket Syndrome with s5 Checksum over GF(2^64)
// ============================================================================

enum class ReconcileStatus {
    Identical, // d = 0 differences
    Decoded,   // d = 1 or d = 2 differences recovered and s5-verified
    Overflow,  // d >= 3 differences in bucket (requires fallback/subdivision)
};

struct BucketSyndrome {
    uint64_t s1{0}; // XOR sum of x
    uint64_t s3{0}; // XOR sum of x^3
    uint64_t s5{0}; // XOR sum of x^5

    void Add(uint64_t short_id) noexcept {
        if (short_id == 0) {
            return;
        }
        s1 ^= short_id;
        s3 ^= GF64Cube(short_id);
        s5 ^= GF64Pow5(short_id);
    }

    void Remove(uint64_t short_id) noexcept {
        Add(short_id); // In GF(2^64), addition and subtraction are both XOR
    }

    BucketSyndrome SymmetricDifference(const BucketSyndrome &other) const noexcept {
        return BucketSyndrome{s1 ^ other.s1, s3 ^ other.s3, s5 ^ other.s5};
    }

    bool IsZero() const noexcept { return s1 == 0 && s3 == 0 && s5 == 0; }
};

struct BucketDecodeResult {
    ReconcileStatus status{ReconcileStatus::Identical};
    std::vector<uint64_t> roots; // Sorted ascending recovered short_ids
};

/**
 * Decode a symmetric-difference BucketSyndrome (delta_s1, delta_s3, delta_s5):
 *   - d = 0: status = Identical, roots = {}
 *   - d = 1: status = Decoded,   roots = {x1} (verified against delta_s5)
 *   - d = 2: status = Decoded,   roots = {x1, x2} (sorted, verified against delta_s5)
 *   - d >= 3: status = Overflow, roots = {}
 */
BucketDecodeResult DecodeBucketSyndrome(const BucketSyndrome &delta);

} // namespace lotus::v2

#endif // LOTUS_V2_SET_RECONCILIATION_H
