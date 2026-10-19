// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_alp_all_the_things.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const AlpTokenType Standard = AlpTokenType::Standard();
const Atoms MAX = 0xffff'ffff'ffff;

TokenMeta meta(const TokenId &token_id) {
    return meta_alp(token_id);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_alp_all_the_things_tests)

BOOST_AUTO_TEST_CASE(test_color_slpv2_all_the_things) {
    const TokenTx actual = verify<10>(
        alp::SectionsOpreturn({
            // success GENESIS
            alp::GenesisSection(Standard, GenesisInfo::EmptyAlp(),
                                ParsedMintData{{0, 7, 0, 0, 1}, 2}),
            // fail GENESIS: must be first
            alp::GenesisSection(Standard, GenesisInfo{}, ParsedMintData{}),
            // fail MINT: Too few outputs
            alp_mint(TOKEN_ID2, std::vector<Atoms>(7, 0), 99),
            // success BURN: token ID 2
            alp::BurnSection(TOKEN_ID2, Standard, 2),
            // success MINT: token ID 3
            alp_mint(TOKEN_ID3, {3, 0}, 1),
            // success MINT: token ID 2
            alp_mint(TOKEN_ID2, {0, 0, 0, 2, 0, 0, 0}, 1),
            // fail MINT: Duplicate token ID 2
            alp_mint(TOKEN_ID2, {}, 0),
            // fail BURN: Duplicate burn token ID 2
            alp::BurnSection(TOKEN_ID2, Standard, 2),
            // success SEND: token ID 4
            alp::SendSection(TOKEN_ID4, Standard,
                             {0, 0, 0, 0, 0, 0, 0, 0, 0, MAX, 0, 0, 0}),
            // fail MINT: Duplicate token ID 4
            alp_mint(TOKEN_ID4, {}, 0),
            // success UNKNOWN
            B("SLP2\x89"),
            // fail: Descending token type
            alp::BurnSection(TOKEN_ID2, Standard, 2),
            // Invalid usage of SLP\0
            B("SLP\0"),
            // success UNKNOWN
            B("SLP2\x9a"),
        }),
        {
            spent_baton(meta(TOKEN_ID3)),
            spent_baton(meta(TOKEN_ID2)),
            spent_atoms(meta(TOKEN_ID4), MAX - 2),
            spent_atoms(meta(TOKEN_ID4), 7),
        });
    check_token_tx(
        actual,
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID1),
                        .tx_type = TxType::GENESIS,
                        .genesis_info = GenesisInfo::EmptyAlp(),
                        .failed_colorings = {FailedColoring{
                            1,
                            parse_alp(alp::GenesisSection(
                                Standard, GenesisInfo{}, ParsedMintData{})),
                            ColorError::GenesisMustBeFirst(),
                        }},
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3),
                        .tx_type = TxType::MINT,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2),
                        .tx_type = TxType::MINT,
                        .intentional_burn_atoms = 2,
                        .failed_colorings =
                            {
                                FailedColoring{
                                    2,
                                    parse_alp(alp_mint(
                                        TOKEN_ID2, std::vector<Atoms>(7, 0),
                                        99)),
                                    ColorError::TooFewOutputs(107, 11),
                                },
                                FailedColoring{
                                    6,
                                    parse_alp(alp_mint(TOKEN_ID2, {}, 0)),
                                    ColorError::DuplicateTokenId(2, TOKEN_ID2),
                                },
                                FailedColoring{
                                    7,
                                    parse_alp(alp::BurnSection(TOKEN_ID2,
                                                               Standard, 2)),
                                    ColorError::DuplicateIntentionalBurnTokenId(
                                        0, 1, TOKEN_ID2),
                                },
                                FailedColoring{
                                    11,
                                    parse_alp(alp::BurnSection(TOKEN_ID2,
                                                               Standard, 2)),
                                    ColorError::DescendingTokenType(0x89, 0),
                                },
                            },
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID4),
                        .tx_type = TxType::SEND,
                        .actual_burn_atoms = 5,
                        .failed_colorings = {FailedColoring{
                            9,
                            parse_alp(alp_mint(TOKEN_ID4, {}, 0)),
                            ColorError::DuplicateTokenId(3, TOKEN_ID4),
                        }},
                    },
                    TokenTxEntry{
                        .meta = meta_alp_unknown(EMPTY_TOKEN_ID, 0x89),
                        .tx_type = TxType::UNKNOWN,
                    },
                    TokenTxEntry{
                        .meta = meta_alp_unknown(EMPTY_TOKEN_ID, 0x9a),
                        .tx_type = TxType::UNKNOWN,
                    },
                },
            .outputs =
                {
                    std::nullopt,
                    token_atoms<1>(3),
                    token_atoms<0>(7),
                    token_baton<1>(),
                    token_atoms<2>(2),
                    token_atoms<0>(1),
                    token_baton<0>(),
                    token_baton<0>(),
                    token_baton<2>(),
                    token_unknown<4>(0x89),
                    token_atoms<3>(MAX),
                },
            .failed_parsings = {FailedParsing{
                12,
                B("SLP\0"),
                ColorParseError{alp::ParseError::InvalidSlpLokadId()},
            }},
        });
}

BOOST_AUTO_TEST_SUITE_END()
