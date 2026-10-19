// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_alp_parse_burn.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using alp::ParseError;

namespace {

const Bytes BURN_PREFIX = Cat({SLP2, {0}, {0x04}, B("BURN")});

} // namespace

BOOST_AUTO_TEST_SUITE(token_alp_parse_burn_tests)

BOOST_AUTO_TEST_CASE(test_parse_alp_burn_not_enough_bytes) {
    for (size_t size = 0; size <= 31; ++size) {
        BOOST_CHECK(alp_parse(Cat({BURN_PREFIX, Rep(0, size)})) ==
                    not_enough("token_id", 32, size));
    }
    for (size_t size = 0; size <= 5; ++size) {
        BOOST_CHECK(
            alp_parse(Cat({BURN_PREFIX, Rep(0x76, 32), Rep(0, size)})) ==
            not_enough("burn_amount", 6, size));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_burn_leftover) {
    // leftover bytes
    BOOST_CHECK(
        alp_parse(Cat({BURN_PREFIX, Rep(0x76, 32), Rep(0, 6), B("hello")})) ==
        AlpErr(ParseError::LeftoverBytes(B("hello"))));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_burn_valid) {
    BOOST_CHECK(
        alp_parse(Cat({BURN_PREFIX, Rep(0x76, 32), {1, 2, 3, 4, 5, 6}})) ==
        AlpSectionResult(ParsedData{
            AlpTestMeta(),
            ParsedTxType::MakeBurn(0x60504030201),
        }));
}

BOOST_AUTO_TEST_SUITE_END()
