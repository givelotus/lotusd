// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/tagged_hash.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(lotus_tagged_hash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sha256_domain_vectors) {
    using lotus::v2::HashDomain;
    using lotus::v2::TaggedHash;
    // Fixed Layer-1 vectors computed independently as
    // SHA256(SHA256(tag) || SHA256(tag) || payload).
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::TxRoot, {})),
        "b06e48ea1f3e2ce6b209a217cb5572d3a78cb773b2d31076de24aeab303d7151");
    const std::array<uint8_t, 4> binary{0, 1, 2, 255};
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::HeaderWork, binary)),
        "dd6b3958760790b424b1bd8f947533d4f6aeefe3ffd2c153bab389e082a5f061");
    const std::array<uint8_t, 3> ascii{'a', 'b', 'c'};
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::Output, ascii)),
        "f07c920ef06384c8b145925f7cad2bd6d58a3f95e9c54b61ff29204268ed4238");
}

BOOST_AUTO_TEST_SUITE_END()
