// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_common.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;
const Atoms U64_MAX = std::numeric_limits<uint64_t>::max();

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_common_tests)

BOOST_AUTO_TEST_CASE(test_verify_slp_parse_error) {
    check_token_tx(
        verify<1>(Script(B("\x6a\x04" "SLP2")), {}),
        TokenTx{
            .entries = {},
            .outputs = {NONE, NONE},
            .failed_parsings = {FailedParsing{
                std::nullopt,
                B("\x6a\x04" "SLP2"),
                ColorParseError{slp::ParseError::Make(
                    slp::ParseError::Kind::InvalidAlpLokadId)},
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_slp_more_than_32767_inputs) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        // More than 32767 inputs allowed in SLP
        const std::vector<std::optional<SpentToken>> spent_tokens(
            alp_consts::MAX_TX_INPUTS + 1,
            spent_atoms(meta_slp(TOKEN_ID2, token_type), U64_MAX));
        check_token_tx(
            verify<1>(slp::SendOpreturn(TOKEN_ID2, token_type, {U64_MAX}),
                      spent_tokens),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta_slp(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                    .actual_burn_atoms = uint128(32767) * U64_MAX,
                }},
                .outputs = {NONE, token_atoms<0>(U64_MAX)},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_slp_colored_out_of_range) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(
                slp::SendOpreturn(TOKEN_ID2, token_type, {100, 200, 300}),
                {spent_atoms(meta_slp(TOKEN_ID2, token_type), 600)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta_slp(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                    .actual_burn_atoms = 500,
                    .has_colored_out_of_range = true,
                }},
                .outputs = {NONE, token_atoms<0>(100)},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_SUITE_END()
