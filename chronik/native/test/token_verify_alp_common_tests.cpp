// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_common.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const AlpTokenType Standard = AlpTokenType::Standard();
const std::optional<TokenOutput> NONE;

TokenMeta meta(const TokenId &token_id) {
    return meta_alp(token_id);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_alp_common_tests)

BOOST_AUTO_TEST_CASE(test_verify_empp_parse_error) {
    check_token_tx(verify<1>(Script(B("\x6a\x50\0")), {}),
                   TokenTx{
                       .entries = {},
                       .outputs = {NONE, NONE},
                       .failed_parsings = {FailedParsing{
                           std::nullopt,
                           B("\x6a\x50\0"),
                           ColorParseError{empp::ParseError::Make(
                               empp::ParseError::Kind::EmptyPushdata, OP_0)},
                       }},
                   });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_parse_error) {
    check_token_tx(
        verify<1>(Script(B("\x6a\x50\x04" "SLP\0")), {}),
        TokenTx{
            .entries = {},
            .outputs = {NONE, NONE},
            .failed_parsings = {FailedParsing{
                0,
                B("SLP\0"),
                ColorParseError{alp::ParseError::InvalidSlpLokadId()},
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_color_error) {
    check_token_tx(
        verify<1>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID2, Standard, {}),
                      alp_mint(TOKEN_ID2, {}, 0),
                  }),
                  {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .failed_colorings = {FailedColoring{
                    1,
                    parse_alp(alp_mint(TOKEN_ID2, {}, 0)),
                    ColorError::DuplicateTokenId(0, TOKEN_ID2),
                }},
            }},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_more_than_32767_inputs_invalid) {
    // More than 32767 inputs disallowed in ALP
    const std::vector<std::optional<SpentToken>> spent_tokens(
        alp_consts::MAX_TX_INPUTS + 1,
        spent_atoms(meta(TOKEN_ID2), 0xffff'ffff'ffff));
    check_token_tx(
        verify<1>(alp::SectionsOpreturn({alp::SendSection(
                      TOKEN_ID2, Standard, {0xffff'ffff'ffff})}),
                  spent_tokens),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .is_invalid = true,
                .actual_burn_atoms = uint128(32768) * 0xffff'ffff'ffff,
                .burn_error = BurnError::TooManyTxInputs(32768),
            }},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_32767_inputs_valid) {
    // 32767 inputs allowed in ALP
    const std::vector<std::optional<SpentToken>> spent_tokens(
        alp_consts::MAX_TX_INPUTS,
        spent_atoms(meta(TOKEN_ID2), 0xffff'ffff'ffff));
    check_token_tx(
        verify<1>(alp::SectionsOpreturn({alp::SendSection(
                      TOKEN_ID2, Standard, {0xffff'ffff'ffff})}),
                  spent_tokens),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .actual_burn_atoms = uint128(32766) * 0xffff'ffff'ffff,
            }},
            .outputs = {NONE, token_atoms<0>(0xffff'ffff'ffff)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
