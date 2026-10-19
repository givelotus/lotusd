// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_slp_parse_send.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using slp::ParseError;

BOOST_AUTO_TEST_SUITE(token_slp_parse_send_tests)

BOOST_AUTO_TEST_CASE(test_parse_send_invalid_pushes) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (size_t pushes = 0; pushes < 2; ++pushes) {
            // Invalid SEND Vault, too few pushes
            slp_check_err(Cat({SlpPrefix(token_type, SEND),
                               // repeat 0x0101, which pushes 0x01
                               Rep(0x01, pushes * 2)}),
                          ParseError::TooFewPushes(5, 3 + pushes));
        }

        for (size_t pushes = 21; pushes < 100; ++pushes) {
            // Invalid SEND Vault, too many pushes
            slp_check_err(Cat({SlpPrefix(token_type, SEND),
                               // repeat 0x0101, which pushes 0x01
                               Rep(0x01, pushes * 2)}),
                          ParseError::SuperfluousPushes(23, 3 + pushes));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_send_invalid_token_id) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (int size = 0; size <= 0xff; ++size) {
            if (size == 32) {
                continue;
            }
            slp_check_err(Cat({SlpPrefix(token_type, SEND),
                               {0x4c, uint8_t(size)},
                               Rep(0x33, size),
                               {0x4c, 0x00, 0x01, 0x00}}),
                          ParseError::InvalidFieldSize("token_id", {32}, size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_send_invalid_amount_size) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        // Test all possible SEND outputs with one amount having 2 bytes
        for (size_t num_outputs = 1; num_outputs <= 19; ++num_outputs) {
            const Bytes script_intro =
                Cat({SlpPrefix(token_type, SEND), {0x20}, Rep(0x22, 32)});
            for (size_t invalid_idx = 0; invalid_idx < num_outputs;
                 ++invalid_idx) {
                Bytes script = script_intro;
                for (size_t idx = 0; idx < num_outputs; ++idx) {
                    const Bytes part =
                        invalid_idx == idx
                            ? Bytes{0x02, 0x00, 0x00}
                            : Bytes{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00};
                    script.insert(script.end(), part.begin(), part.end());
                }
                slp_check_err(
                    script,
                    ParseError::InvalidFieldSize(
                        slp::TOKEN_OUTPUT_QUANTITY_FIELD_NAMES[invalid_idx],
                        {8}, 2));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_valid_send_simple) {
    const TokenId token_id = TokenIdBe(0x22);
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()}) {
        const std::vector<Atoms> amounts{0x987654321abcdef2,
                                         0xffffffffffffffff, 0xb17c01abc};
        BOOST_CHECK(slp_parse(slp::SendOpreturn(token_id, token_type,
                                                amounts)) ==
                    SlpOk(ParsedData{
                        TokenMeta{token_id, TokenType::Slp(token_type)},
                        ParsedTxType::MakeSend(amounts),
                    }));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_send_valid_complex) {
    // Valid SEND, test all valid number of amounts
    for (const auto &[type_byte, token_type] :
         std::vector<std::pair<uint8_t, SlpTokenType>>{
             {1, SlpTokenType::Fungible()},
             {2, SlpTokenType::MintVault()},
             {0x41, SlpTokenType::Nft1Child()},
             {0x81, SlpTokenType::Nft1Group()},
         }) {
        const Bytes script_intro =
            Cat({SlpPrefix(type_byte, SEND), {0x20}, Rep(0x22, 32)});
        for (size_t num_amounts = 1; num_amounts <= 19; ++num_amounts) {
            Bytes script = script_intro;
            std::vector<Atoms> amounts;
            for (size_t idx = 0; idx < num_amounts; ++idx) {
                const Atoms amount = idx;
                script.push_back(0x08);
                const Bytes be = BeBytes(amount);
                script.insert(script.end(), be.begin(), be.end());
                amounts.push_back(amount);
            }
            BOOST_CHECK(slp_parse(script) ==
                        SlpOk(ParsedData{
                            TokenMeta{TokenIdBe(0x22),
                                      TokenType::Slp(token_type)},
                            ParsedTxType::MakeSend(amounts),
                        }));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
