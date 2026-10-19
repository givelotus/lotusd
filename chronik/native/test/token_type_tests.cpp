// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/src/token_type.rs tests.

#include <chronik/native/token/structs.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native::token;

BOOST_AUTO_TEST_SUITE(token_type_tests)

BOOST_AUTO_TEST_CASE(test_slp_token_type_to_u8) {
    BOOST_CHECK_EQUAL(SlpTokenType::Fungible().ToU8(), 1);
    BOOST_CHECK_EQUAL(SlpTokenType::MintVault().ToU8(), 2);
    BOOST_CHECK_EQUAL(SlpTokenType::Nft1Child().ToU8(), 0x41);
    BOOST_CHECK_EQUAL(SlpTokenType::Nft1Group().ToU8(), 0x81);
    BOOST_CHECK_EQUAL(SlpTokenType::Unknown(3).ToU8(), 3);
    BOOST_CHECK_EQUAL(SlpTokenType::Unknown(100).ToU8(), 100);
}

BOOST_AUTO_TEST_CASE(test_alp_token_type_to_u8) {
    BOOST_CHECK_EQUAL(AlpTokenType::Standard().ToU8(), 0);
    BOOST_CHECK_EQUAL(AlpTokenType::Unknown(1).ToU8(), 1);
    BOOST_CHECK_EQUAL(AlpTokenType::Unknown(3).ToU8(), 3);
    BOOST_CHECK_EQUAL(AlpTokenType::Unknown(100).ToU8(), 100);
}

// Additional: Display texts used by Chronik's wire output
BOOST_AUTO_TEST_CASE(test_token_type_display) {
    BOOST_CHECK_EQUAL(TokenType::Slp(SlpTokenType::Fungible()).ToString(),
                      "SLP FUNGIBLE (V1)");
    BOOST_CHECK_EQUAL(TokenType::Alp(AlpTokenType::Standard()).ToString(),
                      "ALP STANDARD (V0)");
    BOOST_CHECK_EQUAL(TokenType::Slp(SlpTokenType::Unknown(7)).ToString(),
                      "SLP UNKNOWN (7)");
}

BOOST_AUTO_TEST_SUITE_END()
