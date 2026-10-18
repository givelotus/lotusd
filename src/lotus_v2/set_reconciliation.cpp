// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "set_reconciliation.h"

#include "tagged_hash.h"

#include <array>
#include <cassert>
#include <cstring>

namespace lotus::v2 {

namespace {

constexpr uint64_t RotL64(uint64_t x, int b) noexcept {
    return (x << b) | (x >> (64 - b));
}

constexpr uint64_t ReadLE64(const uint8_t *p) noexcept {
    return uint64_t(p[0]) | (uint64_t(p[1]) << 8) | (uint64_t(p[2]) << 16) |
           (uint64_t(p[3]) << 24) | (uint64_t(p[4]) << 32) |
           (uint64_t(p[5]) << 40) | (uint64_t(p[6]) << 48) |
           (uint64_t(p[7]) << 56);
}

constexpr void SipRound(uint64_t &v0, uint64_t &v1, uint64_t &v2,
                        uint64_t &v3) noexcept {
    v0 += v1;
    v1 = RotL64(v1, 13);
    v1 ^= v0;
    v0 = RotL64(v0, 32);
    v2 += v3;
    v3 = RotL64(v3, 16);
    v3 ^= v2;
    v0 += v3;
    v3 = RotL64(v3, 21);
    v3 ^= v0;
    v2 += v1;
    v1 = RotL64(v1, 17);
    v1 ^= v2;
    v2 = RotL64(v2, 32);
}

} // namespace

std::pair<uint64_t, uint64_t>
DeriveEpochSipHashKey(const Hash &prev_block_id, uint64_t epoch_number,
                      const Hash &parent_overlay_id) noexcept {
    std::array<uint8_t, 72> payload{};
    std::memcpy(payload.data(), prev_block_id.data(), 32);
    for (unsigned i = 0; i < 8; ++i) {
        payload[32 + i] = static_cast<uint8_t>((epoch_number >> (8 * i)) & 0xff);
    }
    std::memcpy(payload.data() + 40, parent_overlay_id.data(), 32);
    const Hash digest = TaggedHash(HashDomain::Branch, payload);
    const uint64_t k0 = ReadLE64(digest.data());
    const uint64_t k1 = ReadLE64(digest.data() + 8);
    return {k0, k1};
}

uint64_t ComputeShortTxId(uint64_t k0, uint64_t k1,
                          const Hash &tx_hash) noexcept {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    for (size_t offset = 0; offset < 32; offset += 8) {
        const uint64_t m = ReadLE64(tx_hash.data() + offset);
        v3 ^= m;
        SipRound(v0, v1, v2, v3);
        SipRound(v0, v1, v2, v3);
        v0 ^= m;
    }

    const uint64_t b = 32ULL << 56;
    v3 ^= b;
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xffULL;
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);

    const uint64_t out = v0 ^ v1 ^ v2 ^ v3;
    return out != 0 ? out : 1ULL;
}

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define LOTUS_GF64_USE_ARM_PMULL 1
#elif defined(__x86_64__) && defined(__PCLMUL__)
#include <wmmintrin.h>
#define LOTUS_GF64_USE_X86_PCLMUL 1
#endif

uint64_t GF64Mul(uint64_t a, uint64_t b) noexcept {
#if defined(LOTUS_GF64_USE_ARM_PMULL)
    const poly128_t p = vmull_p64(static_cast<poly64_t>(a),
                                  static_cast<poly64_t>(b));
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint8_t bytes[16];
    std::memcpy(bytes, &p, 16);
    std::memcpy(&lo, bytes, 8);
    std::memcpy(&hi, bytes + 8, 8);
    // Reduce hi * x^64 modulo x^64 + x^4 + x^3 + x + 1 (0x1B).
    // Since hi < 2^64 and degree(0x1B) == 4, r1 = hi * 0x1B is at most 68 bits:
    // its low 64 bits (r1_lo) are degrees 0..63, and its high 4 bits (r1_hi)
    // are degrees 64..67 which are reduced a second time by multiplying by 0x1B.
    const poly128_t r1 = vmull_p64(static_cast<poly64_t>(hi),
                                   static_cast<poly64_t>(kGF64Modulus));
    uint64_t r1_lo = 0;
    uint64_t r1_hi = 0;
    uint8_t r1_bytes[16];
    std::memcpy(r1_bytes, &r1, 16);
    std::memcpy(&r1_lo, r1_bytes, 8);
    std::memcpy(&r1_hi, r1_bytes + 8, 8);
    const poly128_t r2 = vmull_p64(static_cast<poly64_t>(r1_hi),
                                   static_cast<poly64_t>(kGF64Modulus));
    uint64_t r2_lo = 0;
    std::memcpy(&r2_lo, &r2, 8);
    return lo ^ r1_lo ^ r2_lo;
#elif defined(LOTUS_GF64_USE_X86_PCLMUL)
    const __m128i va = _mm_cvtsi64_si128(static_cast<long long>(a));
    const __m128i vb = _mm_cvtsi64_si128(static_cast<long long>(b));
    const __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);
    const uint64_t lo = static_cast<uint64_t>(_mm_cvtsi128_si64(prod));
    const uint64_t hi =
        static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_srli_si128(prod, 8)));
    const __m128i vmod = _mm_cvtsi64_si128(static_cast<long long>(kGF64Modulus));
    const __m128i r1 = _mm_clmulepi64_si128(
        _mm_cvtsi64_si128(static_cast<long long>(hi)), vmod, 0x00);
    const uint64_t r1_lo = static_cast<uint64_t>(_mm_cvtsi128_si64(r1));
    const uint64_t r1_hi =
        static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_srli_si128(r1, 8)));
    const __m128i r2 = _mm_clmulepi64_si128(
        _mm_cvtsi64_si128(static_cast<long long>(r1_hi)), vmod, 0x00);
    return lo ^ r1_lo ^
           static_cast<uint64_t>(_mm_cvtsi128_si64(r2));
#else
    uint64_t res = 0;
    for (int i = 0; i < 64 && b != 0; ++i) {
        if (b & 1ULL) {
            res ^= a;
        }
        const bool hi = (a & (1ULL << 63)) != 0;
        a <<= 1;
        if (hi) {
            a ^= kGF64Modulus;
        }
        b >>= 1;
    }
    return res;
#endif
}

uint64_t GF64Sqr(uint64_t a) noexcept {
    return GF64Mul(a, a);
}

uint64_t GF64Cube(uint64_t a) noexcept {
    return GF64Mul(GF64Sqr(a), a);
}

uint64_t GF64Pow5(uint64_t a) noexcept {
    const uint64_t a2 = GF64Sqr(a);
    const uint64_t a4 = GF64Sqr(a2);
    return GF64Mul(a, a4);
}

uint64_t GF64Inv(uint64_t a) noexcept {
    if (a == 0) {
        return 0;
    }
    // a^(2^64 - 2) = product_{i=1}^{63} a^(2^i)
    uint64_t result = 1;
    uint64_t cur = a;
    for (int i = 1; i < 64; ++i) {
        cur = GF64Sqr(cur);
        result = GF64Mul(result, cur);
    }
    return result;
}

uint64_t GF64Trace(uint64_t a) noexcept {
    uint64_t tr = 0;
    uint64_t cur = a;
    for (int i = 0; i < 64; ++i) {
        tr ^= cur;
        cur = GF64Sqr(cur);
    }
    return tr & 1ULL;
}

bool GF64SolveQuadratic(uint64_t c, uint64_t &y_out) noexcept {
    if (c == 0) {
        y_out = 0;
        return true;
    }
    // Modulo P(x) = x^64 + x^4 + x^3 + x + 1, e_61 = 1 (coeff of x^3) and 61 is
    // odd, so by Newton's identities z = x^61 has absolute trace Tr(z) = 1.
    constexpr uint64_t z = 1ULL << 61;

    uint64_t y = 0;
    uint64_t z_pow = z;
    uint64_t c_pow = c;
    uint64_t S = c; // Running prefix sum: sum_{i=0}^{j-1} c^(2^i)

    for (int j = 1; j < 64; ++j) {
        z_pow = GF64Sqr(z_pow); // z^(2^j)
        y ^= GF64Mul(z_pow, S);
        c_pow = GF64Sqr(c_pow); // c^(2^j)
        S ^= c_pow;
    }

    // At j = 64, S == Tr(c). Solvable iff Tr(c) == 0.
    if (S != 0) {
        return false;
    }
    y_out = y;
    return true;
}

BucketDecodeResult DecodeBucketSyndrome(const BucketSyndrome &delta) {
    BucketDecodeResult res;
    if (delta.s1 == 0 && delta.s3 == 0 && delta.s5 == 0) {
        res.status = ReconcileStatus::Identical;
        return res;
    }
    if (delta.s1 == 0) {
        res.status = ReconcileStatus::Overflow;
        return res;
    }

    const uint64_t s1_cubed = GF64Cube(delta.s1);
    if (delta.s3 == s1_cubed) {
        // Degree 1: single element difference x1 = s1, verified against s5
        if (GF64Pow5(delta.s1) != delta.s5) {
            res.status = ReconcileStatus::Overflow;
            return res;
        }
        res.status = ReconcileStatus::Decoded;
        res.roots.push_back(delta.s1);
        return res;
    }

    // Degree 2 candidate:
    //   x1 + x2 = s1
    //   x1 * x2 = (s3 + s1^3) / s1
    // Depressed quadratic for y = x1 / s1:
    //   y^2 + y = c, where c = (s3 + s1^3) / s1^3
    const uint64_t num = delta.s3 ^ s1_cubed;
    const uint64_t c = GF64Mul(num, GF64Inv(s1_cubed));
    uint64_t y = 0;
    if (!GF64SolveQuadratic(c, y)) {
        res.status = ReconcileStatus::Overflow;
        return res;
    }

    uint64_t x1 = GF64Mul(delta.s1, y);
    uint64_t x2 = x1 ^ delta.s1;
    if ((GF64Pow5(x1) ^ GF64Pow5(x2)) != delta.s5) {
        res.status = ReconcileStatus::Overflow;
        return res;
    }


    if (x2 < x1) {
        std::swap(x1, x2);
    }
    res.status = ReconcileStatus::Decoded;
    res.roots.push_back(x1);
    res.roots.push_back(x2);
    return res;
}

} // namespace lotus::v2
