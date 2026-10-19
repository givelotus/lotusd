// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_burn.rs.

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

BOOST_AUTO_TEST_SUITE(token_verify_alp_burn_tests)

BOOST_AUTO_TEST_CASE(test_verify_alp_burn_standalone) {
    check_token_tx(
        verify<0>(alp::SectionsOpreturn(
                      {alp::BurnSection(TOKEN_ID2, Standard, 400)}),
                  {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::BURN,
                .intentional_burn_atoms = 400,
            }},
            .outputs = {NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_burn_with_send) {
    check_token_tx(
        verify<1>(alp::SectionsOpreturn({
                      alp::BurnSection(TOKEN_ID2, Standard, 400),
                      alp::SendSection(TOKEN_ID2, Standard, {200}),
                  }),
                  {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .is_invalid = true,
                .intentional_burn_atoms = 400,
                .burn_error = BurnError::InsufficientInputSum(200, 0),
            }},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_send_with_burn) {
    check_token_tx(
        verify<1>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID2, Standard, {200}),
                      alp::BurnSection(TOKEN_ID2, Standard, 400),
                  }),
                  {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .is_invalid = true,
                .intentional_burn_atoms = 400,
                .burn_error = BurnError::InsufficientInputSum(200, 0),
            }},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_burn_success) {
    check_token_tx(
        verify<2>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID2, Standard, {80, 20}),
                      alp::BurnSection(TOKEN_ID2, Standard, 400),
                  }),
                  {spent_atoms(meta(TOKEN_ID2), 500)}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::SEND,
                .intentional_burn_atoms = 400,
                .actual_burn_atoms = 400,
            }},
            .outputs = {NONE, token_atoms<0>(80), token_atoms<0>(20)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_burn_big) {
    check_token_tx(
        verify<4>(
            alp::SectionsOpreturn({
                alp::SendSection(TOKEN_ID2, Standard, {80, 20}),
                alp::BurnSection(TOKEN_ID2, Standard, 400),
                alp::SendSection(TOKEN_ID3, Standard, {0, 0, 5000, 1000}),
                alp::BurnSection(TOKEN_ID3, Standard, 1000),
                alp::BurnSection(TOKEN_ID4, Standard, 3000),
            }),
            {
                spent_atoms(meta(TOKEN_ID2), 500),
                spent_atoms(meta(TOKEN_ID3), 7000),
                spent_atoms(meta(TOKEN_ID4), 2000),
                spent_baton(meta(TOKEN_ID4)),
                spent_atoms(meta(TOKEN_ID5), 500),
            }),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::SEND,
                        .intentional_burn_atoms = 400,
                        .actual_burn_atoms = 400,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = TxType::SEND,
                        .intentional_burn_atoms = 1000,
                        .actual_burn_atoms = 1000,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID4),
                        .tx_type = TxType::BURN,
                        .is_invalid = true,
                        .intentional_burn_atoms = 3000,
                        .actual_burn_atoms = 2000,
                        .burns_mint_batons = true,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID5),
                        .is_invalid = true,
                        .actual_burn_atoms = 500,
                    },
                },
            .outputs =
                {
                    NONE,
                    token_atoms<0>(80),
                    token_atoms<0>(20),
                    token_atoms<1>(5000),
                    token_atoms<1>(1000),
                },
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
