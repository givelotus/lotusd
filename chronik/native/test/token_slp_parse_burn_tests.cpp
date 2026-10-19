// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_slp_parse_burn.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using slp::ParseError;

BOOST_AUTO_TEST_SUITE(token_slp_parse_burn_tests)

BOOST_AUTO_TEST_CASE(test_parse_burn_invalid_pushes) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (size_t pushes = 0; pushes < 100; ++pushes) {
            if (pushes == 2) {
                continue;
            }
            // Invalid BURN, unexpected number of pushes
            slp_check_err(Cat({SlpPrefix(token_type, BURN),
                               // repeat 0x0101, which pushes 0x01
                               Rep(0x01, pushes * 2)}),
                          ParseError::UnexpectedNumPushes(5, 3 + pushes));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_burn_invalid_token_id) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (int size = 0; size <= 0xff; ++size) {
            if (size == 32) {
                continue;
            }
            slp_check_err(Cat({SlpPrefix(token_type, BURN),
                               {0x4c, uint8_t(size)},
                               Rep(0x33, size),
                               {0x4c, 0x00}}),
                          ParseError::InvalidFieldSize("token_id", {32}, size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_burn_invalid_amount_size) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (int size = 0; size <= 0xff; ++size) {
            if (size == 8) {
                continue;
            }
            slp_check_err(Cat({SlpPrefix(token_type, BURN),
                               {32},
                               Rep(0x22, 32),
                               {0x4c, uint8_t(size)},
                               Rep(0x01, size)}),
                          ParseError::InvalidFieldSize("token_burn_quantity",
                                                       {8}, size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_burn_valid_simple) {
    const TokenId token_id = TokenIdBe(0x22);
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()}) {
        const Atoms amount = 0x987654321abcdef2;
        BOOST_CHECK(slp_parse(slp::BurnOpreturn(token_id, token_type,
                                                amount)) ==
                    SlpOk(ParsedData{
                        TokenMeta{token_id, TokenType::Slp(token_type)},
                        ParsedTxType::MakeBurn(amount),
                    }));
    }
}

BOOST_AUTO_TEST_SUITE_END()
