// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_mint.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;
const SlpTokenType MINT_TYPES[] = {SlpTokenType::Fungible(),
                                   SlpTokenType::Nft1Child(),
                                   SlpTokenType::Nft1Group()};

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_mint_tests)

BOOST_AUTO_TEST_CASE(test_verify_mint_no_inputs) {
    for (SlpTokenType token_type : MINT_TYPES) {
        check_token_tx(
            verify<1>(slp::MintOpreturn(TOKEN_ID2, token_type, std::nullopt,
                                        44),
                      {}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::MINT,
                    .is_invalid = true,
                    .burn_error = BurnError::MissingMintBaton(),
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_mint_no_mint_input) {
    for (SlpTokenType token_type : MINT_TYPES) {
        check_token_tx(
            verify<1>(slp::MintOpreturn(TOKEN_ID2, token_type, std::nullopt,
                                        44),
                      {spent_atoms(meta(TOKEN_ID2, token_type), 77)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::MINT,
                    .is_invalid = true,
                    .actual_burn_atoms = 77,
                    .burn_error = BurnError::MissingMintBaton(),
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_mint_wrong_mint_baton_token_id) {
    for (SlpTokenType token_type : MINT_TYPES) {
        check_token_tx(
            verify<1>(slp::MintOpreturn(TOKEN_ID2, token_type, std::nullopt,
                                        44),
                      {spent_baton(meta(TOKEN_ID3, token_type))}),
            TokenTx{
                .entries =
                    {
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, token_type),
                            .tx_type = TxType::MINT,
                            .is_invalid = true,
                            .burn_error = BurnError::MissingMintBaton(),
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID3, token_type),
                            .is_invalid = true,
                            .burns_mint_batons = true,
                        },
                    },
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_mint_wrong_mint_baton_token_type) {
    for (SlpTokenType out_token_type : MINT_TYPES) {
        for (SlpTokenType in_token_type : MINT_TYPES) {
            if (out_token_type == in_token_type) {
                continue;
            }
            check_token_tx(
                verify<1>(slp::MintOpreturn(TOKEN_ID2, out_token_type,
                                            std::nullopt, 44),
                          {spent_baton(meta(TOKEN_ID2, in_token_type))}),
                TokenTx{
                    .entries =
                        {
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, out_token_type),
                                .tx_type = TxType::MINT,
                                .is_invalid = true,
                                .burn_error = BurnError::MissingMintBaton(),
                            },
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, in_token_type),
                                .is_invalid = true,
                                .burns_mint_batons = true,
                            },
                        },
                    .outputs = {NONE, NONE},
                    .failed_parsings = {},
                });
        }
    }
}

BOOST_AUTO_TEST_CASE(test_verify_mint_success_simple) {
    for (SlpTokenType token_type : MINT_TYPES) {
        check_token_tx(
            verify<3>(slp::MintOpreturn(TOKEN_ID2, token_type, 3, 44),
                      {spent_baton(meta(TOKEN_ID2, token_type))}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::MINT,
                }},
                .outputs = {NONE, token_atoms<0>(44), NONE, token_baton<0>()},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_mint_success_with_burn) {
    for (SlpTokenType token_type : MINT_TYPES) {
        for (SlpTokenType wrong_token_type : MINT_TYPES) {
            if (token_type == wrong_token_type) {
                continue;
            }
            check_token_tx(
                verify<3>(slp::MintOpreturn(TOKEN_ID2, token_type, 3, 44),
                          {
                              spent_atoms(meta(TOKEN_ID2, token_type), 77),
                              spent_baton(meta(TOKEN_ID2, token_type)),
                              spent_baton(meta(TOKEN_ID2, wrong_token_type)),
                              spent_baton(meta(TOKEN_ID3, token_type)),
                              spent_baton(meta_alp(TOKEN_ID4)),
                          }),
                TokenTx{
                    .entries =
                        {
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, token_type),
                                .tx_type = TxType::MINT,
                                .actual_burn_atoms = 77,
                            },
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, wrong_token_type),
                                .is_invalid = true,
                                .burns_mint_batons = true,
                            },
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID3, token_type),
                                .is_invalid = true,
                                .burns_mint_batons = true,
                            },
                            TokenTxEntry{
                                .meta = meta_alp(TOKEN_ID4),
                                .is_invalid = true,
                                .burns_mint_batons = true,
                            },
                        },
                    .outputs = {NONE, token_atoms<0>(44), NONE,
                                token_baton<0>()},
                    .failed_parsings = {},
                });
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
