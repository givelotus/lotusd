// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_alp_genesis.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const TokenId TOKEN_ID{TXID};
const AlpTokenType STD = AlpTokenType::Standard();
const GenesisInfo INFO = GenesisInfo::EmptyAlp();
const Atoms MAX = 0xffff'ffff'ffff;
const std::optional<TokenOutput> MINT_BATON = token_baton<0>();
const std::optional<TokenOutput> NONE;

template <size_t N> Tx make_tx(const Script &script) {
    return MakeTx(script, N, TXID);
}

ColoredTxSection GenesisSection() {
    return ColoredTxSection{meta_alp(TOKEN_ID), TxType::GENESIS, 0, false,
                            INFO};
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_alp_genesis_tests)

BOOST_AUTO_TEST_CASE(test_color_alp_genesis_must_be_first) {
    TOKEN_CHECK(
        ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
            alp::SendSection(TOKEN_ID2, STD, {}),
            alp::GenesisSection(STD, INFO, ParsedMintData{}),
        }))) ==
        ColoredTx{
            .sections = {ColoredTxSection{meta_alp(TOKEN_ID2), TxType::SEND,
                                          0, false, std::nullopt}},
            .outputs = {NONE},
            .failed_colorings = {FailedColoring{
                1,
                *alp::ParseSection(
                     TXID, alp::GenesisSection(STD, INFO, ParsedMintData{}))
                     .value(),
                ColorError::GenesisMustBeFirst(),
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_color_alp_genesis_too_few_outputs) {
    for (const ParsedMintData &mint_data : {
             ParsedMintData{{1, 2, 3, 4}, 0},
             ParsedMintData{{}, 4},
         }) {
        TOKEN_CHECK(
            ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                alp::GenesisSection(STD, GenesisInfo{}, mint_data),
            }))) ==
            ColoredTx{
                .outputs = {NONE},
                .failed_colorings = {FailedColoring{
                    0,
                    ParsedData{meta_alp(TOKEN_ID),
                               ParsedTxType::MakeGenesis(
                                   ParsedGenesis{INFO, mint_data})},
                    ColorError::TooFewOutputs(5, 1),
                }},
            });
    }
    // 0 amounts don't cause the coloring to fail even if there's no
    // associated output
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    alp::GenesisSection(STD, INFO,
                                        // 127 amounts
                                        ParsedMintData{
                                            std::vector<Atoms>(127, 0), 0}),
                }))) ==
                ColoredTx{
                    .sections = {GenesisSection()},
                    .outputs = {NONE},
                });
}

BOOST_AUTO_TEST_CASE(test_color_slpv2_genesis_success_simple) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    alp::GenesisSection(STD, INFO, ParsedMintData{}),
                }))) ==
                ColoredTx{
                    .sections = {GenesisSection()},
                    .outputs = {NONE},
                });
}

BOOST_AUTO_TEST_CASE(test_color_slpv2_genesis_success_big) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<9>(alp::SectionsOpreturn({
                    alp::GenesisSection(STD, INFO,
                                        ParsedMintData{{0, 7, MAX, 0}, 3}),
                }))) ==
                ColoredTx{
                    .sections = {GenesisSection()},
                    .outputs =
                        {
                            NONE,
                            NONE,
                            token_atoms<0>(7),
                            token_atoms<0>(MAX),
                            NONE,
                            MINT_BATON,
                            MINT_BATON,
                            MINT_BATON,
                            NONE,
                            NONE,
                        },
                });
}

BOOST_AUTO_TEST_SUITE_END()
