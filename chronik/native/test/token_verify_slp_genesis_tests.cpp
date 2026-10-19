// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_genesis.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;
const GenesisInfo &INFO = INFO_SLP;
const SlpTokenType Fungible = SlpTokenType::Fungible();
const SlpTokenType MintVault = SlpTokenType::MintVault();
const SlpTokenType Nft1Child = SlpTokenType::Nft1Child();
const SlpTokenType Nft1Group = SlpTokenType::Nft1Group();

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

TokenTxEntry MissingGroupEntry() {
    return TokenTxEntry{
        .meta = meta(TOKEN_ID1, Nft1Child),
        .tx_type = TxType::GENESIS,
        .genesis_info = INFO,
        .is_invalid = true,
        .burn_error = BurnError::MissingNft1Group(),
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_genesis_tests)

BOOST_AUTO_TEST_CASE(test_verify_genesis_missing_nft1_group) {
    // Missing NFT1 Group token
    check_token_tx(
        verify<1>(slp::GenesisOpreturn(INFO, Nft1Child, std::nullopt, 1), {}),
        TokenTx{
            .entries = {MissingGroupEntry()},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_wrong_nft1_group) {
    for (SlpTokenType in_token_type : {Fungible, MintVault, Nft1Child}) {
        check_token_tx(
            verify<1>(slp::GenesisOpreturn(INFO, Nft1Child, std::nullopt, 1),
                      {spent_atoms(meta(TOKEN_ID2, in_token_type), 1)}),
            TokenTx{
                .entries =
                    {
                        MissingGroupEntry(),
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, in_token_type),
                            .is_invalid = true,
                            .actual_burn_atoms = 1,
                        },
                    },
                .outputs = {NONE, NONE},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_wrong_nft1_group_input_position) {
    check_token_tx(
        verify<1>(slp::GenesisOpreturn(INFO, Nft1Child, std::nullopt, 1),
                  // NFT1 Group must be at idx 0, is at idx 1
                  {std::nullopt, spent_atoms(meta(TOKEN_ID2, Nft1Group), 1)}),
        TokenTx{
            .entries =
                {
                    MissingGroupEntry(),
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Nft1Group),
                        .is_invalid = true,
                        .actual_burn_atoms = 1,
                    },
                },
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_success_nft1_child) {
    check_token_tx(
        verify<1>(slp::GenesisOpreturn(INFO, Nft1Child, std::nullopt, 1),
                  {spent_atoms(meta(TOKEN_ID2, Nft1Group), 1)}),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID1, Nft1Child),
                        .tx_type = TxType::GENESIS,
                        .genesis_info = INFO,
                        .group_token_meta = meta(TOKEN_ID2, Nft1Group),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Nft1Group),
                    },
                },
            .outputs = {NONE, token_atoms<0>(1)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_success) {
    for (SlpTokenType out_token_type : {Fungible, Nft1Group}) {
        check_token_tx(
            verify<2>(slp::GenesisOpreturn(INFO, out_token_type, 2, 99), {}),
            TokenTx{
                .entries = {TokenTxEntry{
                    .meta = meta(TOKEN_ID1, out_token_type),
                    .tx_type = TxType::GENESIS,
                    .genesis_info = INFO,
                }},
                .outputs = {NONE, token_atoms<0>(99), token_baton<0>()},
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_success_with_burn) {
    for (SlpTokenType out_token_type : {Fungible, MintVault, Nft1Group}) {
        GenesisInfo genesis_info = INFO;
        if (out_token_type == MintVault) {
            ShaRmd160 scripthash;
            scripthash.fill(4);
            genesis_info.mint_vault_scripthash = scripthash;
        }

        check_token_tx(
            verify<3>(
                slp::GenesisOpreturn(genesis_info, out_token_type, 3, 55),
                {
                    spent_atoms(meta(TOKEN_ID2, Fungible), 77),
                    spent_atoms(meta_alp(TOKEN_ID3), 22),
                }),
            TokenTx{
                .entries =
                    {
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID1, out_token_type),
                            .tx_type = TxType::GENESIS,
                            .genesis_info = genesis_info,
                        },
                        TokenTxEntry{
                            .meta = meta(TOKEN_ID2, Fungible),
                            .is_invalid = true,
                            .actual_burn_atoms = 77,
                        },
                        TokenTxEntry{
                            .meta = meta_alp(TOKEN_ID3),
                            .is_invalid = true,
                            .actual_burn_atoms = 22,
                        },
                    },
                .outputs =
                    {
                        NONE,
                        token_atoms<0>(55),
                        NONE,
                        out_token_type != MintVault ? token_baton<0>() : NONE,
                    },
                .failed_parsings = {},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_verify_genesis_success_nft1_child_with_burn) {
    check_token_tx(
        verify<1>(slp::GenesisOpreturn(INFO, Nft1Child, std::nullopt, 1),
                  {
                      spent_atoms(meta(TOKEN_ID2, Nft1Group), 77),
                      spent_atoms(meta(TOKEN_ID2, Nft1Group), 44),
                      spent_atoms(meta_alp(TOKEN_ID3), 22),
                  }),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID1, Nft1Child),
                        .tx_type = TxType::GENESIS,
                        .genesis_info = INFO,
                        .group_token_meta = meta(TOKEN_ID2, Nft1Group),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, Nft1Group),
                        .is_invalid = true,
                        .actual_burn_atoms = 44,
                    },
                    TokenTxEntry{
                        .meta = meta_alp(TOKEN_ID3),
                        .is_invalid = true,
                        .actual_burn_atoms = 22,
                    },
                },
            .outputs = {NONE, token_atoms<0>(1)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
