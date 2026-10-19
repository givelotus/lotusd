// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_alp_mint.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const Atoms MAX = 0xffff'ffff'ffff;
const std::optional<TokenOutput> NONE;

template <size_t N> Tx make_tx(const Script &script) {
    return MakeTx(script, N, TXID);
}

ParsedData parse(Bytes pushdata) {
    return *alp::ParseSection(TXID, std::move(pushdata)).value();
}

ColoredTxSection colored_mint_section(const TokenId &token_id) {
    return ColoredTxSection{meta_alp(token_id), TxType::MINT, 0, false,
                            std::nullopt};
}

ColoredTxSection colored_unknown_section(uint8_t token_type) {
    return ColoredTxSection{meta_alp_unknown(EMPTY_TOKEN_ID, token_type),
                            TxType::UNKNOWN, 0, false, std::nullopt};
}

Bytes make_mint(const TokenId &token_id, std::vector<Atoms> atoms_vec,
                size_t num_batons) {
    return alp_mint(token_id, std::move(atoms_vec), num_batons);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_alp_mint_tests)

BOOST_AUTO_TEST_CASE(test_color_alp_mint_duplicate_token_id) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    make_mint(TOKEN_ID2, {}, 0),
                    make_mint(TOKEN_ID2, {}, 0),
                }))) ==
                ColoredTx{
                    .sections = {colored_mint_section(TOKEN_ID2)},
                    .outputs = {NONE},
                    .failed_colorings = {FailedColoring{
                        1,
                        parse(make_mint(TOKEN_ID2, {}, 0)),
                        ColorError::DuplicateTokenId(0, TOKEN_ID2),
                    }},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_unknown_token_type) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<3>(alp::SectionsOpreturn({
                    // Valid mint
                    make_mint(TOKEN_ID2, {2}, 0),
                    // Valid unknown
                    B("SLP2\x77"),
                    // Invalid mint, descending token type
                    make_mint(TOKEN_ID3, {}, 0),
                    // Valid unknown
                    B("SLP2\x89"),
                    // Invalid unknown, descending token type
                    B("SLP2\x80"),
                }))) ==
                ColoredTx{
                    .sections =
                        {
                            colored_mint_section(TOKEN_ID2),
                            colored_unknown_section(0x77),
                            colored_unknown_section(0x89),
                        },
                    .outputs =
                        {
                            NONE,
                            token_atoms<0>(2),
                            token_unknown<1>(0x77),
                            token_unknown<1>(0x77),
                        },
                    .failed_colorings =
                        {
                            FailedColoring{
                                2,
                                parse(make_mint(TOKEN_ID3, {}, 0)),
                                ColorError::DescendingTokenType(0x77, 0),
                            },
                            FailedColoring{
                                4,
                                parse(B("SLP2\x80")),
                                ColorError::DescendingTokenType(0x89, 0x80),
                            },
                        },
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_too_few_outputs) {
    for (const Bytes &section : {
             make_mint(TOKEN_ID2, {123}, 0),
             make_mint(TOKEN_ID2, {}, 1),
         }) {
        TOKEN_CHECK(
            ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({section}))) ==
            ColoredTx{
                .outputs = {NONE},
                .failed_colorings = {FailedColoring{
                    0,
                    parse(section),
                    ColorError::TooFewOutputs(2, 1),
                }},
            });
    }
    // 0 amounts don't cause the coloring to fail even if there's no
    // associated output
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    make_mint(TOKEN_ID2, std::vector<Atoms>(127, 0), 0),
                }))) ==
                ColoredTx{
                    .sections = {colored_mint_section(TOKEN_ID2)},
                    .outputs = {NONE},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_overlapping_amount) {
    TOKEN_CHECK(
        ColoredTx::ColorTx(make_tx<3>(alp::SectionsOpreturn({
            make_mint(TOKEN_ID2, {0}, 1),
            make_mint(TOKEN_ID3, {0, 777, 1}, 0),
        }))) ==
        ColoredTx{
            .sections = {colored_mint_section(TOKEN_ID2)},
            .outputs = {NONE, NONE, token_baton<0>(), NONE},
            .failed_colorings = {FailedColoring{
                1,
                parse(make_mint(TOKEN_ID3, {0, 777, 1}, 0)),
                ColorError::OverlappingAtoms(
                    Token{meta_alp(TOKEN_ID2), TokenVariant::MintBaton()}, 2,
                    777),
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_overlapping_mint_baton) {
    TOKEN_CHECK(
        ColoredTx::ColorTx(make_tx<3>(alp::SectionsOpreturn({
            make_mint(TOKEN_ID2, {0, 0, 9}, 0),
            make_mint(TOKEN_ID3, {0}, 2),
        }))) ==
        ColoredTx{
            .sections = {colored_mint_section(TOKEN_ID2)},
            .outputs = {NONE, NONE, NONE, token_atoms<0>(9)},
            .failed_colorings = {FailedColoring{
                1,
                parse(make_mint(TOKEN_ID3, {0}, 2)),
                ColorError::OverlappingMintBaton(
                    Token{meta_alp(TOKEN_ID2), TokenVariant::MakeAtoms(9)}, 3),
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_simple) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<5>(alp::SectionsOpreturn({
                    make_mint(TOKEN_ID2, {2, 0, MAX}, 2),
                }))) ==
                ColoredTx{
                    .sections = {colored_mint_section(TOKEN_ID2)},
                    .outputs =
                        {
                            NONE,
                            token_atoms<0>(2),
                            NONE,
                            token_atoms<0>(MAX),
                            token_baton<0>(),
                            token_baton<0>(),
                        },
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_mint_complex) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<5>(alp::SectionsOpreturn({
                    make_mint(TOKEN_ID2, {0, 9, 0, 0, 0, 0, 0, 0}, 0),
                    make_mint(TOKEN_ID3, {7, 0}, 2),
                    make_mint(TOKEN_ID4, {0, 0, 0, 0}, 1),
                }))) ==
                ColoredTx{
                    .sections =
                        {
                            colored_mint_section(TOKEN_ID2),
                            colored_mint_section(TOKEN_ID3),
                            colored_mint_section(TOKEN_ID4),
                        },
                    .outputs =
                        {
                            NONE,
                            token_atoms<1>(7),
                            token_atoms<0>(9),
                            token_baton<1>(),
                            token_baton<1>(),
                            token_baton<2>(),
                        },
                });
}

BOOST_AUTO_TEST_SUITE_END()
