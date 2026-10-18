// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/tagged_hash.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(lotus_tagged_hash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blake3_domain_vectors) {
    using lotus::v2::HashDomain;
    using lotus::v2::TaggedHash;
    // Native vectors computed independently as BLAKE3(tag || 0 || payload).
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::TxRoot, {})),
        "21cbe78b600233e5092e085b2b7aec6d947cbabcb861419be01b5af2b02a2a35");
    const std::array<uint8_t, 4> binary{0, 1, 2, 255};
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::HeaderWork, binary)),
        "9423458608de43aa8ae5e8bcaf906742e31aa53f810073aab7a84ae24ab0ef05");
    const std::array<uint8_t, 3> ascii{'a', 'b', 'c'};
    BOOST_CHECK_EQUAL(
        HexStr(TaggedHash(HashDomain::Output, ascii)),
        "ccb875549f9c067e7b107302a5e9712210f8eb726ac4a21d93e2d40c6bc646e8");
}

BOOST_AUTO_TEST_SUITE_END()
