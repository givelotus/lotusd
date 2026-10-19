// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_send.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;
const SlpTokenType Fungible = SlpTokenType::Fungible();
const SlpTokenType Nft1Child = SlpTokenType::Nft1Child();
const SlpTokenType Nft1Group = SlpTokenType::Nft1Group();

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

/** (hi << 64) | lo, for Rust's u128 literals */
constexpr uint128 U128(uint64_t hi, uint64_t lo) {
    return (uint128(hi) << 64) | lo;
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_send_tests)

BOOST_AUTO_TEST_CASE(test_verify_send_no_inputs) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::SendOpreturn(TOKEN_ID2, token_type, {77}), {}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                    .is_invalid = true,
                    .burn_error = BurnError::InsufficientInputSum(77, 0),
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_not_enough_inputs) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::SendOpreturn(TOKEN_ID2, token_type, {7}),
                      {spent_atoms(meta(TOKEN_ID2, token_type), 5)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                    .is_invalid = true,
                    .actual_burn_atoms = 5,
                    .burn_error = BurnError::InsufficientInputSum(7, 5),
                }},
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_wrong_token_id) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<1>(slp::SendOpreturn(TOKEN_ID2, token_type, {7}),
                      {spent_atoms(meta(TOKEN_ID3, token_type), 7)}),
            TokenTx{
                .entries =
                    {
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, token_type),
                            .tx_type = TxType::SEND,
                            .is_invalid = true,
                            .burn_error = BurnError::InsufficientInputSum(7, 0),
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID3, token_type),
                            .is_invalid = true,
                            .actual_burn_atoms = 7,
                        },
                    },
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_wrong_token_type) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        for (SlpTokenType wrong_token_type : ALL_SLP_TYPES) {
            if (token_type == wrong_token_type) {
                continue;
            }
            check_token_tx(
                verify<1>(slp::SendOpreturn(TOKEN_ID2, wrong_token_type, {7}),
                          {spent_atoms(meta(TOKEN_ID2, token_type), 7)}),
                TokenTx{
                    .entries =
                        {
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, wrong_token_type),
                                .tx_type = TxType::SEND,
                                .is_invalid = true,
                                .burn_error =
                                    BurnError::InsufficientInputSum(7, 0),
                            },
                            TokenTxEntry{
                                .meta = meta(TOKEN_ID2, token_type),
                                .is_invalid = true,
                                .actual_burn_atoms = 7,
                            },
                        },
                    .outputs = {NONE, NONE},
                    .failed_parsings = {},
                });
        }
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_64bit_off_by_one) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<4>(slp::SendOpreturn(TOKEN_ID2, token_type,
                                        {1, 0xffff'ffff'ffff'0000,
                                         0xffff'ffff'ffff'0001, 2}),
                      {
                          spent_atoms(meta(TOKEN_ID2, token_type),
                                      0xffff'ffff'ffff'0000),
                          spent_atoms(meta(TOKEN_ID2, token_type),
                                      0xffff'ffff'ffff'0003),
                      }),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                    .is_invalid = true,
                    .actual_burn_atoms = U128(1, 0xffff'ffff'fffe'0003),
                    .burn_error = BurnError::InsufficientInputSum(
                        U128(1, 0xffff'ffff'fffe'0004),
                        U128(1, 0xffff'ffff'fffe'0003)),
                }},
                .outputs = {NONE, NONE, NONE, NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_success_null) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<2>(slp::SendOpreturn(TOKEN_ID2, token_type, {0, 0, 0}), {}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                }},
                .outputs = {NONE, NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_success_simple) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<4>(slp::SendOpreturn(TOKEN_ID2, token_type, {1, 2, 0, 4}),
                      {spent_atoms(meta(TOKEN_ID2, token_type), 7)}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                }},
                .outputs =
                    {
                        NONE,
                        token_atoms<0>(1),
                        token_atoms<0>(2),
                        NONE,
                        token_atoms<0>(4),
                    },
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_wrong_group_token_id) {
    // Different token ID causes us to ignore the group_token_id
    check_token_tx(
        verify<1>(slp::SendOpreturn(TOKEN_ID2, Nft1Child, {1}),
                  {spent_atoms_group(meta(TOKEN_ID3, Nft1Child), 1,
                                     meta(TOKEN_ID4, Nft1Group))}),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Nft1Child),
                        .tx_type = TxType::SEND,
                        .group_token_meta = std::nullopt,
                        .is_invalid = true,
                        .burn_error = BurnError::InsufficientInputSum(1, 0),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3, Nft1Child),
                        .tx_type = std::nullopt,
                        // group still carried over even when burned
                        .group_token_meta = meta(TOKEN_ID4, Nft1Group),
                        .is_invalid = true,
                        .actual_burn_atoms = 1,
                    },
                },
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
    // Different token type causes us to ignore the group_token_id too
    check_token_tx(
        verify<1>(slp::SendOpreturn(TOKEN_ID2, Fungible, {1}),
                  {spent_atoms_group(meta(TOKEN_ID2, Nft1Child), 1,
                                     meta(TOKEN_ID3, Nft1Group))}),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Fungible),
                        .tx_type = TxType::SEND,
                        .is_invalid = true,
                        .burn_error = BurnError::InsufficientInputSum(1, 0),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Nft1Child),
                        .group_token_meta = meta(TOKEN_ID3, Nft1Group),
                        .is_invalid = true,
                        .actual_burn_atoms = 1,
                    },
                },
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_send_success_group_token_id) {
    // Carry over group_token_id from the inputs if it matches
    check_token_tx(
        verify<4>(slp::SendOpreturn(TOKEN_ID2, Nft1Child, {1, 2, 0, 4}),
                  {spent_atoms_group(meta(TOKEN_ID2, Nft1Child), 7,
                                     meta(TOKEN_ID3, Nft1Group))}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2, Nft1Child),
                .tx_type = TxType::SEND,
                .group_token_meta = meta(TOKEN_ID3, Nft1Group),
            }},
            .outputs =
                {
                    NONE,
                    token_atoms<0>(1),
                    token_atoms<0>(2),
                    NONE,
                    token_atoms<0>(4),
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_send_success) {
    check_token_tx(
        verify<4>(slp::SendOpreturn(TOKEN_ID2, Nft1Child, {1, 2, 0, 4}),
                  {spent_atoms_group(meta(TOKEN_ID2, Nft1Child), 7,
                                     meta(TOKEN_ID3, Nft1Group))}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2, Nft1Child),
                .tx_type = TxType::SEND,
                .group_token_meta = meta(TOKEN_ID3, Nft1Group),
            }},
            .outputs =
                {
                    NONE,
                    token_atoms<0>(1),
                    token_atoms<0>(2),
                    NONE,
                    token_atoms<0>(4),
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_send_success_64bit) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<4>(slp::SendOpreturn(TOKEN_ID2, token_type,
                                        {1, 0xffff'ffff'ffff'0000,
                                         0xffff'ffff'ffff'0001, 2}),
                      {
                          spent_atoms(meta(TOKEN_ID2, token_type),
                                      0xffff'ffff'ffff'0000),
                          spent_atoms(meta(TOKEN_ID2, token_type),
                                      0xffff'ffff'ffff'0004),
                      }),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID2, token_type),
                    .tx_type = TxType::SEND,
                }},
                .outputs =
                    {
                        NONE,
                        token_atoms<0>(1),
                        token_atoms<0>(0xffff'ffff'ffff'0000),
                        token_atoms<0>(0xffff'ffff'ffff'0001),
                        token_atoms<0>(2),
                    },
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_send_success_big) {
    for (SlpTokenType token_type : ALL_SLP_TYPES) {
        check_token_tx(
            verify<3>(
                slp::SendOpreturn(
                    TOKEN_ID2, token_type,
                    {0xffff'ffff'ffff'0000, 0xffff'ffff'ffff'0002, 1}),
                {
                    spent_atoms(meta(TOKEN_ID2, token_type),
                                0xffff'ffff'ffff'0000),
                    spent_atoms(meta(TOKEN_ID2, token_type),
                                0xefff'ffff'ffff'0000),
                    spent_atoms(meta(TOKEN_ID2, token_type),
                                0x2fff'ffff'ffff'0000),
                    spent_atoms(meta(TOKEN_ID2, token_type), 10),
                    spent_atoms(meta(TOKEN_ID3, Nft1Child), 1),
                    spent_baton(meta(TOKEN_ID4, Fungible)),
                }),
            TokenTx{
                .entries =
                    {
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, token_type),
                            .tx_type = TxType::SEND,
                            .actual_burn_atoms = 0x1fff'ffff'ffff'0007,
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID3, Nft1Child),
                            .tx_type = std::nullopt,
                            .is_invalid = true,
                            .actual_burn_atoms = 1,
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID4, Fungible),
                            .tx_type = std::nullopt,
                            .is_invalid = true,
                            .burns_mint_batons = true,
                        },
                    },
                .outputs =
                    {
                        NONE,
                        token_atoms<0>(0xffff'ffff'ffff'0000),
                        token_atoms<0>(0xffff'ffff'ffff'0002),
                        token_atoms<0>(1),
                    },
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_SUITE_END()
