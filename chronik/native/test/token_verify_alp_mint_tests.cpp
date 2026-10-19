// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_mint.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;

TokenMeta meta(const TokenId &token_id) {
    return meta_alp(token_id);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_alp_mint_tests)

BOOST_AUTO_TEST_CASE(test_verify_alp_no_mint_baton) {
    check_token_tx(
        verify<2>(alp::SectionsOpreturn({alp_mint(TOKEN_ID2, {100}, 1)}), {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::MINT,
                .is_invalid = true,
                .burn_error = BurnError::MissingMintBaton(),
            }},
            .outputs = {NONE, NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_wrong_mint_baton_token_id) {
    check_token_tx(
        verify<2>(alp::SectionsOpreturn({alp_mint(TOKEN_ID2, {100}, 1)}),
                  {spent_baton(meta(TOKEN_ID3))}),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::MINT,
                        .is_invalid = true,
                        .burn_error = BurnError::MissingMintBaton(),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = std::nullopt,
                        .is_invalid = true,
                        .burns_mint_batons = true,
                    },
                },
            .outputs = {NONE, NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_success_simple) {
    check_token_tx(
        verify<2>(alp::SectionsOpreturn({alp_mint(TOKEN_ID2, {100}, 1)}),
                  {spent_baton(meta(TOKEN_ID2))}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2),
                .tx_type = TxType::MINT,
            }},
            .outputs = {NONE, token_atoms<0>(100), token_baton<0>()},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_success_big) {
    check_token_tx(
        verify<6>(alp::SectionsOpreturn({
                      alp_mint(TOKEN_ID2, {100, 0}, 1),
                      alp_mint(TOKEN_ID3, {0, 15, 0}, 1),
                      alp_mint(TOKEN_ID4, {0, 0, 0, 0, 2}, 1),
                  }),
                  {
                      spent_baton(meta(TOKEN_ID2)),
                      spent_baton(meta(TOKEN_ID3)),
                      spent_baton(meta(TOKEN_ID5)),
                  }),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::MINT,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = TxType::MINT,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID4),
                        .tx_type = TxType::MINT,
                        .is_invalid = true,
                        .burn_error = BurnError::MissingMintBaton(),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID5),
                        .tx_type = std::nullopt,
                        .is_invalid = true,
                        .burns_mint_batons = true,
                    },
                },
            .outputs =
                {
                    NONE,
                    token_atoms<0>(100),
                    token_atoms<1>(15),
                    token_baton<0>(),
                    token_baton<1>(),
                    NONE,
                    NONE,
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
