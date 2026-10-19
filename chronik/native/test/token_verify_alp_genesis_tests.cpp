// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_genesis.rs.

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

BOOST_AUTO_TEST_SUITE(token_verify_alp_genesis_tests)

BOOST_AUTO_TEST_CASE(test_verify_alp_genesis) {
    GenesisInfo genesis_info;
    genesis_info.token_ticker = B("ALP");
    genesis_info.token_name = B("ALP Token");
    genesis_info.url = B("http::example.alp");
    genesis_info.data = B("ALP Data");
    genesis_info.auth_pubkey = B("ALP Pubkey");
    genesis_info.decimals = 4;
    check_token_tx(
        verify<5>(alp::SectionsOpreturn({alp::GenesisSection(
                      Standard, genesis_info,
                      ParsedMintData{{200, 0, 300}, 2})}),
                  {}),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID1),
                .tx_type = TxType::GENESIS,
                .genesis_info = genesis_info,
            }},
            .outputs =
                {
                    NONE,
                    token_atoms<0>(200),
                    NONE,
                    token_atoms<0>(300),
                    token_baton<0>(),
                    token_baton<0>(),
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_alp_genesis_with_burn) {
    check_token_tx(
        verify<5>(alp::SectionsOpreturn({alp::GenesisSection(
                      Standard, GenesisInfo::EmptyAlp(),
                      ParsedMintData{{200, 0, 300}, 2})}),
                  {
                      spent_atoms(meta(TOKEN_ID2), 100),
                      spent_atoms(meta(TOKEN_ID3), 2000),
                  }),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID1),
                        .tx_type = TxType::GENESIS,
                        .genesis_info = GenesisInfo::EmptyAlp(),
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .is_invalid = true,
                        .actual_burn_atoms = 100,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .is_invalid = true,
                        .actual_burn_atoms = 2000,
                    },
                },
            .outputs =
                {
                    NONE,
                    token_atoms<0>(200),
                    NONE,
                    token_atoms<0>(300),
                    token_baton<0>(),
                    token_baton<0>(),
                },
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
