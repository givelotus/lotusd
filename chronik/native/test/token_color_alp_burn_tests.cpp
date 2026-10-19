// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_alp_burn.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const TxId BURN_TXID = MakeTxId(4);
const TokenId BURN_TOKEN_ID2{MakeTxId(5)};
const TokenId BURN_TOKEN_ID3{MakeTxId(6)};
const Atoms MAX = 0xffff'ffff'ffff;

template <size_t N> Tx make_tx(const Script &script) {
    return MakeTx(script, N, BURN_TXID);
}

ParsedData parse(Bytes pushdata) {
    return *alp::ParseSection(BURN_TXID, std::move(pushdata)).value();
}

Bytes make_burn(const TokenId &token_id, Atoms atoms) {
    return alp::BurnSection(token_id, AlpTokenType::Standard(), atoms);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_alp_burn_tests)

BOOST_AUTO_TEST_CASE(test_color_alp_burn_duplicate) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    make_burn(BURN_TOKEN_ID2, 3),
                    make_burn(BURN_TOKEN_ID2, 2),
                }))) ==
                ColoredTx{
                    .intentional_burns = {IntentionalBurn{
                        meta_alp(BURN_TOKEN_ID2), 3}},
                    .outputs = {std::nullopt},
                    .failed_colorings = {FailedColoring{
                        1,
                        parse(make_burn(BURN_TOKEN_ID2, 2)),
                        ColorError::DuplicateIntentionalBurnTokenId(
                            0, 1, BURN_TOKEN_ID2),
                    }},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_burn_success_simple) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(
                    alp::SectionsOpreturn({make_burn(BURN_TOKEN_ID2, 3)}))) ==
                ColoredTx{
                    .intentional_burns = {IntentionalBurn{
                        meta_alp(BURN_TOKEN_ID2), 3}},
                    .outputs = {std::nullopt},
                });
}

BOOST_AUTO_TEST_CASE(test_color_alp_burn_success_complex) {
    TOKEN_CHECK(ColoredTx::ColorTx(make_tx<0>(alp::SectionsOpreturn({
                    make_burn(BURN_TOKEN_ID2, 1),
                    make_burn(BURN_TOKEN_ID3, MAX),
                }))) ==
                ColoredTx{
                    .intentional_burns =
                        {
                            IntentionalBurn{meta_alp(BURN_TOKEN_ID2), 1},
                            IntentionalBurn{meta_alp(BURN_TOKEN_ID3), MAX},
                        },
                    .outputs = {std::nullopt},
                });
}

BOOST_AUTO_TEST_SUITE_END()
