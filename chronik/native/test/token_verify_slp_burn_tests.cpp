// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_burn.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_burn_tests)

BOOST_AUTO_TEST_CASE(test_verify_burn_wrong_token_id) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::BurnOpreturn(TOKEN_ID2, token_type, 10),
                      {spent_atoms(meta(TOKEN_ID3, token_type), 10)}),
            TokenTx{
                .entries =
                    {
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, token_type),
                            .tx_type = TxType::BURN,
                            .intentional_burn_atoms = 10,
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID3, token_type),
                            .is_invalid = true,
                            .actual_burn_atoms = 10,
                        },
                    },
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_burn_wrong_token_type) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        for (SlpTokenType wrong_token_type : ALL_SLP_TYPES) {
            if (token_type == wrong_token_type) {
                continue;
            }
            check_token_tx(
                verify<1>(slp::BurnOpreturn(TOKEN_ID2, wrong_token_type, 10),
                          {spent_atoms(meta(TOKEN_ID3, token_type), 10)}),
                TokenTx{
                    .entries =
                        {
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, wrong_token_type),
                                .tx_type = TxType::BURN,
                                .intentional_burn_atoms = 10,
                            },
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID3, token_type),
                                .is_invalid = true,
                                .actual_burn_atoms = 10,
                            },
                        },
                    .outputs = {NONE, NONE},
                    .failed_parsings = {},
                });
        }
    }
}

BOOST_AUTO_TEST_CASE(test_verify_burn_mint_baton) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::BurnOpreturn(TOKEN_ID2, token_type, 10),
                      {spent_baton(meta(TOKEN_ID2, token_type))}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::BURN,
                    .is_invalid = true,
                    .intentional_burn_atoms = 10,
                    .burns_mint_batons = true,
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_burn_wrong_amount) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::BurnOpreturn(TOKEN_ID2, token_type, 10),
                      {spent_atoms(meta(TOKEN_ID2, token_type), 9)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::BURN,
                    .intentional_burn_atoms = 10,
                    .actual_burn_atoms = 9,
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_burn_success) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::BurnOpreturn(TOKEN_ID2, token_type, 10),
                      {spent_atoms(meta(TOKEN_ID2, token_type), 10)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::BURN,
                    .intentional_burn_atoms = 10,
                    .actual_burn_atoms = 10,
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_SUITE_END()
