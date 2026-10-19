// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_alp_send.rs.

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

ColoredTxSection colored_send_section(const TokenId &token_id,
                                      uint128 required_input_sum) {
    return ColoredTxSection{meta_alp(token_id), TxType::SEND,
                            required_input_sum, false, std::nullopt};
}

Bytes make_send(const TokenId &token_id, std::vector<Atoms> atoms_vec) {
    return alp::SendSection(token_id, AlpTokenType::Standard(), atoms_vec);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_alp_send_tests)

BOOST_AUTO_TEST_CASE(test_color_alp_send_too_few_outputs) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<2>(alp::SectionsOpreturn({
                    make_send(TOKEN_ID2, {0, 0, 77}),
                    make_send(TOKEN_ID3, {0, 5, 0, 0, 0, 0}),
                }))) ==
                ColoredTx{
                    .sections = {colored_send_section(TOKEN_ID3, 5)},
                    .outputs = {NONE, NONE, token_atoms<0>(5)},
                    .failed_colorings = {FailedColoring{
                        0,
                        parse(make_send(TOKEN_ID2, {0, 0, 77})),
                        ColorError::TooFewOutputs(4, 3),
                    }},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_send_duplicate_token_id) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    make_send(TOKEN_ID2, {}),
                    make_send(TOKEN_ID2, {}),
                }))) ==
                ColoredTx{
                    .sections = {colored_send_section(TOKEN_ID2, 0)},
                    .outputs = {NONE},
                    .failed_colorings = {FailedColoring{
                        1,
                        parse(make_send(TOKEN_ID2, {})),
                        ColorError::DuplicateTokenId(0, TOKEN_ID2),
                    }},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_send_overlapping_amount) {
    TOKEN_CHECK(
        ColoredTx::ColorTx(make_tx<3>(alp::SectionsOpreturn({
            make_send(TOKEN_ID2, {0, 2, 0}),
            make_send(TOKEN_ID3, {3, 7, MAX}),
        }))) ==
        ColoredTx{
            .sections = {colored_send_section(TOKEN_ID2, 2)},
            .outputs = {NONE, NONE, token_atoms<0>(2), NONE},
            .failed_colorings = {FailedColoring{
                1,
                parse(make_send(TOKEN_ID3, {3, 7, MAX})),
                ColorError::OverlappingAtoms(
                    Token{meta_alp(TOKEN_ID2), TokenVariant::MakeAtoms(2)}, 2,
                    7),
            }},
        });
}

BOOST_AUTO_TEST_CASE(test_color_alp_send_success_simple) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<4>(alp::SectionsOpreturn({
                    make_send(TOKEN_ID2, {0, 2, 0, MAX}),
                }))) ==
                ColoredTx{
                    .sections = {colored_send_section(TOKEN_ID2,
                                                      uint128(MAX) + 2)},
                    .outputs = {NONE, NONE, token_atoms<0>(2), NONE,
                                token_atoms<0>(MAX)},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_send_success_complex) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<7>(alp::SectionsOpreturn({
                    make_send(TOKEN_ID2, {0, 2, 0, 0, 3}),
                    make_send(TOKEN_ID3, {0, 0, MAX}),
                    make_send(TOKEN_ID4, {1, 0, 0, 0, 0, 7}),
                }))) ==
                ColoredTx{
                    .sections =
                        {
                            colored_send_section(TOKEN_ID2, 5),
                            colored_send_section(TOKEN_ID3, MAX),
                            colored_send_section(TOKEN_ID4, 8),
                        },
                    .outputs =
                        {
                            NONE,
                            token_atoms<2>(1),
                            token_atoms<0>(2),
                            token_atoms<1>(MAX),
                            NONE,
                            token_atoms<0>(3),
                            token_atoms<2>(7),
                            NONE,
                        },
                });
}

BOOST_AUTO_TEST_SUITE_END()
