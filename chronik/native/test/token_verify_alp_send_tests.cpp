// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_send.rs.

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

Script SendScript(const TokenId &token_id, std::vector<Atoms> atoms) {
    return alp::SectionsOpreturn({alp::SendSection(token_id, Standard, atoms)});
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_alp_send_tests)

BOOST_AUTO_TEST_CASE(test_verify_alp_send_no_inputs) {
    check_token_tx(
        verify<2>(SendScript(TOKEN_ID2, {80, 20}), {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .is_invalid = true,
                .burn_error = BurnError::InsufficientInputSum(100, 0),
            }},
            .outputs = {NONE, NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_insufficient_inputs) {
    check_token_tx(
        verify<2>(SendScript(TOKEN_ID2, {80, 20}),
                  {spent_atoms(meta(TOKEN_ID2), 90)}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .is_invalid = true,
                .actual_burn_atoms = 90,
                .burn_error = BurnError::InsufficientInputSum(100, 90),
            }},
            .outputs = {NONE, NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_wrong_token_id) {
    check_token_tx(
        verify<2>(SendScript(TOKEN_ID2, {80, 20}),
                  {spent_atoms(meta(TOKEN_ID3), 100)}),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::SEND,
                        .is_invalid = true,
                        .burn_error = BurnError::InsufficientInputSum(100, 0),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = std::nullopt,
                        .is_invalid = true,
                        .actual_burn_atoms = 100,
                    },
                },
            .outputs = {NONE, NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_success_simple) {
    check_token_tx(
        verify<2>(SendScript(TOKEN_ID2, {80, 20}),
                  {spent_atoms(meta(TOKEN_ID2), 100)}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
            }},
            .outputs = {NONE, token_atoms<0>(80), token_atoms<0>(20)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_success_no_tokens) {
    check_token_tx(verify<2>(SendScript(TOKEN_ID2, {0, 0}), {}),
                   TokenTx{
                       .entries = {TokenTxEntry{
                           .meta = meta(TOKEN_ID2),
                           .tx_type = TxType::SEND,
                       }},
                       .outputs = {NONE, NONE, NONE},
                       .failed_parsings = {},
                   });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_success_big) {
    check_token_tx(
        verify<5>(
            alp::SectionsOpreturn({
                alp::SendSection(TOKEN_ID2, Standard, {80, 0, 20}),
                alp::SendSection(TOKEN_ID3, Standard, {0, 8000, 0, 2000}),
                alp::SendSection(TOKEN_ID4, Standard, {0, 0, 0, 0, 500}),
            }),
            {
                spent_atoms(meta(TOKEN_ID2), 150),
                spent_atoms(meta(TOKEN_ID3), 14000),
                spent_atoms(meta(TOKEN_ID5), 700),
            }),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::SEND,
                        .actual_burn_atoms = 50,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = TxType::SEND,
                        .actual_burn_atoms = 4000,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID4),
                        .tx_type = TxType::SEND,
                        .is_invalid = true,
                        .burn_error = BurnError::InsufficientInputSum(500, 0),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID5),
                        .is_invalid = true,
                        .actual_burn_atoms = 700,
                    },
                },
            .outputs =
                {
                    NONE,
                    token_atoms<0>(80),
                    token_atoms<1>(8000),
                    token_atoms<0>(20),
                    token_atoms<1>(2000),
                    NONE,
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
