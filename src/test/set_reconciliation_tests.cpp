// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/set_reconciliation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(set_reconciliation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(gf64_field_axioms_and_inversion) {
    BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(0, 123456789ULL), 0ULL);
    BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(1, 123456789ULL), 123456789ULL);
    BOOST_CHECK_EQUAL(lotus::v2::GF64Inv(0), 0ULL);
    BOOST_CHECK_EQUAL(lotus::v2::GF64Inv(1), 1ULL);
    BOOST_CHECK_EQUAL(lotus::v2::GF64Trace(1ULL << 61), 1ULL);

    const std::vector<uint64_t> edge_vals = {
        1ULL, 2ULL, 3ULL, 0x1bULL, 1ULL << 61, 1ULL << 63,
        0xffffffffffffffffULL, 0xdeadbeefcafebabeULL};
    for (uint64_t a : edge_vals) {
        const uint64_t inv = lotus::v2::GF64Inv(a);
        BOOST_CHECK_NE(inv, 0ULL);
        BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(a, inv), 1ULL);
        BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(inv, a), 1ULL);
    }

    for (int i = 0; i < 200; ++i) {
        uint64_t a = m_rng.rand64();
        uint64_t b = m_rng.rand64();
        uint64_t c = m_rng.rand64();
        if (a == 0) {
            a = 1;
        }

        // Commutativity and distributivity
        BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(a, b), lotus::v2::GF64Mul(b, a));
        BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(a, b ^ c),
                          lotus::v2::GF64Mul(a, b) ^ lotus::v2::GF64Mul(a, c));

        // Frobenius endomorphism: (a + b)^2 = a^2 + b^2
        BOOST_CHECK_EQUAL(lotus::v2::GF64Sqr(a ^ b),
                          lotus::v2::GF64Sqr(a) ^ lotus::v2::GF64Sqr(b));

        // Multiplicative inverse: a * a^-1 = 1
        const uint64_t inv_a = lotus::v2::GF64Inv(a);
        BOOST_CHECK_EQUAL(lotus::v2::GF64Mul(a, inv_a), 1ULL);

        // Quadratic solver: for any y, c = y^2 + y has Tr(c) = 0 and solutions {y, y ^ 1}
        const uint64_t rhs = lotus::v2::GF64Sqr(a) ^ a;
        BOOST_CHECK_EQUAL(lotus::v2::GF64Trace(rhs), 0ULL);
        uint64_t root = 0;
        BOOST_REQUIRE(lotus::v2::GF64SolveQuadratic(rhs, root));
        BOOST_CHECK(root == a || root == (a ^ 1ULL));
    }
}

BOOST_AUTO_TEST_CASE(siphash_short_txid_and_bch_degree2_reconciliation) {
    lotus::v2::Hash prev_block{};
    prev_block[0] = 0x42;
    prev_block[31] = 0x99;

    const auto [k0, k1] = lotus::v2::DeriveEpochSipHashKey(prev_block, 7);
    const auto [k0_next, k1_next] =
        lotus::v2::DeriveEpochSipHashKey(prev_block, 8);
    BOOST_CHECK(k0 != k0_next || k1 != k1_next);

    lotus::v2::Hash parent_overlay{};
    parent_overlay[0] = 0xab;
    const auto [k0_parent, k1_parent] =
        lotus::v2::DeriveEpochSipHashKey(prev_block, 7, parent_overlay);
    BOOST_CHECK(k0 != k0_parent || k1 != k1_parent);

    // Build a common pool of 500 transactions shared by Peer A and Peer B
    lotus::v2::BucketSyndrome base_syndrome;
    std::vector<uint64_t> shared_ids;
    shared_ids.reserve(500);
    for (int i = 0; i < 500; ++i) {
        uint256 rand_tx = m_rng.rand256();
        lotus::v2::Hash h{};
        std::memcpy(h.data(), rand_tx.begin(), 32);
        const uint64_t sid = lotus::v2::ComputeShortTxId(k0, k1, h);
        BOOST_CHECK_NE(sid, 0ULL);
        shared_ids.push_back(sid);
        base_syndrome.Add(sid);
    }

    // 1. d = 0: identical sets reconcile with ReconcileStatus::Identical
    {
        const auto delta = base_syndrome.SymmetricDifference(base_syndrome);
        const auto decoded = lotus::v2::DecodeBucketSyndrome(delta);
        BOOST_CHECK(decoded.status == lotus::v2::ReconcileStatus::Identical);
        BOOST_CHECK(decoded.roots.empty());
    }

    // 2. d = 1: 200 random single-difference trials
    for (int trial = 0; trial < 200; ++trial) {
        uint256 extra_tx = m_rng.rand256();
        lotus::v2::Hash h{};
        std::memcpy(h.data(), extra_tx.begin(), 32);
        const uint64_t expected_sid = lotus::v2::ComputeShortTxId(k0, k1, h);

        lotus::v2::BucketSyndrome peer_a = base_syndrome;
        peer_a.Add(expected_sid);

        const auto delta = peer_a.SymmetricDifference(base_syndrome);
        const auto decoded = lotus::v2::DecodeBucketSyndrome(delta);
        BOOST_REQUIRE(decoded.status == lotus::v2::ReconcileStatus::Decoded);
        BOOST_REQUIRE_EQUAL(decoded.roots.size(), 1U);
        BOOST_CHECK_EQUAL(decoded.roots[0], expected_sid);

        // Removing the element restores identity
        peer_a.Remove(expected_sid);
        BOOST_CHECK(peer_a.SymmetricDifference(base_syndrome).IsZero());
    }

    // 3. d = 2: 200 random two-difference trials (including 1 on Peer A and 1 on Peer B)
    for (int trial = 0; trial < 200; ++trial) {
        lotus::v2::Hash h1{}, h2{};
        uint256 r1 = m_rng.rand256();
        uint256 r2 = m_rng.rand256();
        std::memcpy(h1.data(), r1.begin(), 32);
        std::memcpy(h2.data(), r2.begin(), 32);

        uint64_t sid1 = lotus::v2::ComputeShortTxId(k0, k1, h1);
        uint64_t sid2 = lotus::v2::ComputeShortTxId(k0, k1, h2);
        if (sid1 == sid2) {
            continue;
        }

        lotus::v2::BucketSyndrome peer_a = base_syndrome;
        lotus::v2::BucketSyndrome peer_b = base_syndrome;
        if (trial % 2 == 0) {
            // Both extra elements on Peer A
            peer_a.Add(sid1);
            peer_a.Add(sid2);
        } else {
            // One unique element on Peer A, one unique element on Peer B
            peer_a.Add(sid1);
            peer_b.Add(sid2);
        }

        const auto delta = peer_a.SymmetricDifference(peer_b);
        const auto decoded = lotus::v2::DecodeBucketSyndrome(delta);
        BOOST_REQUIRE(decoded.status == lotus::v2::ReconcileStatus::Decoded);
        BOOST_REQUIRE_EQUAL(decoded.roots.size(), 2U);

        if (sid2 < sid1) {
            std::swap(sid1, sid2);
        }
        BOOST_CHECK_EQUAL(decoded.roots[0], sid1);
        BOOST_CHECK_EQUAL(decoded.roots[1], sid2);
    }

    // Edge cases: GF64Inv(0), GF64SolveQuadratic(0), and s1 == 0 with s3 != 0
    BOOST_CHECK_EQUAL(lotus::v2::GF64Inv(0), 0ULL);
    uint64_t y_zero = 99;
    BOOST_CHECK(lotus::v2::GF64SolveQuadratic(0, y_zero));
    BOOST_CHECK_EQUAL(y_zero, 0ULL);

    lotus::v2::BucketSyndrome zero_s1_nonzero_s3;
    zero_s1_nonzero_s3.s1 = 0;
    zero_s1_nonzero_s3.s3 = 1;
    const auto overflow_res =
        lotus::v2::DecodeBucketSyndrome(zero_s1_nonzero_s3);
    BOOST_CHECK(overflow_res.status == lotus::v2::ReconcileStatus::Overflow);

    uint64_t y_unsolvable = 0;
    BOOST_CHECK(!lotus::v2::GF64SolveQuadratic(1ULL << 61, y_unsolvable));

    lotus::v2::BucketSyndrome unsolvable_quad;
    unsolvable_quad.s1 = 1ULL;
    unsolvable_quad.s3 = (1ULL << 61) ^ 1ULL;
    BOOST_CHECK(lotus::v2::DecodeBucketSyndrome(unsolvable_quad).status ==
                lotus::v2::ReconcileStatus::Overflow);

    // 4. d = 4 (3 missing + 1 extra, |delta_count| = 2):
    // Verify that even when Tr(c) == 0 (~50% of trials, where a degree-2 solver
    // without s5 would emit two bogus roots), the s5 = XOR(x_i^5) checksum
    // catches 100% of trials as ReconcileStatus::Overflow with zero false
    // positives!
    size_t tr_zero_trials = 0;
    for (int trial = 0; trial < 500; ++trial) {
        std::vector<uint64_t> four_sids;
        while (four_sids.size() < 4) {
            uint256 r = m_rng.rand256();
            lotus::v2::Hash h{};
            std::memcpy(h.data(), r.begin(), 32);
            const uint64_t sid = lotus::v2::ComputeShortTxId(k0, k1, h);
            if (std::find(four_sids.begin(), four_sids.end(), sid) ==
                four_sids.end()) {
                four_sids.push_back(sid);
            }
        }

        // Peer A has 3 missing txs {0, 1, 2}; Peer B has 1 extra tx {3}.
        lotus::v2::BucketSyndrome peer_a = base_syndrome;
        lotus::v2::BucketSyndrome peer_b = base_syndrome;
        peer_a.Add(four_sids[0]);
        peer_a.Add(four_sids[1]);
        peer_a.Add(four_sids[2]);
        peer_b.Add(four_sids[3]);

        const auto delta = peer_a.SymmetricDifference(peer_b);
        if (delta.s1 != 0) {
            const uint64_t s1_cubed = lotus::v2::GF64Cube(delta.s1);
            const uint64_t c = lotus::v2::GF64Mul(
                delta.s3 ^ s1_cubed, lotus::v2::GF64Inv(s1_cubed));
            uint64_t dummy_y = 0;
            if (lotus::v2::GF64SolveQuadratic(c, dummy_y)) {
                ++tr_zero_trials;
            }
        }

        const auto decoded = lotus::v2::DecodeBucketSyndrome(delta);
        BOOST_CHECK(decoded.status == lotus::v2::ReconcileStatus::Overflow);
        BOOST_CHECK(decoded.roots.empty());
    }
    // Ensure a substantial number of trials had Tr(c) == 0 and were caught
    // specifically by the s5 checksum.
    BOOST_CHECK_GT(tr_zero_trials, 150U);
}

BOOST_AUTO_TEST_SUITE_END()

