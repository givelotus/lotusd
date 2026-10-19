// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_alp_all_the_things.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

// This test file uses its own token IDs (4..7).
const TxId T_TXID = MakeTxId(4);
const TokenId T_ID{T_TXID};
const TokenId T_ID2{MakeTxId(5)};
const TokenId T_ID3{MakeTxId(6)};
const TokenId T_ID4{MakeTxId(7)};
const Atoms MAX = 0xffff'ffff'ffff;
const AlpTokenType STD = AlpTokenType::Standard();
const std::optional<TokenOutput> NONE;

ParsedData parse(Bytes pushdata) {
    return *alp::ParseSection(T_TXID, std::move(pushdata)).value();
}

Bytes make_genesis(std::vector<Atoms> atoms_vec, size_t num_batons) {
    return alp::GenesisSection(STD, GenesisInfo{},
                               ParsedMintData{std::move(atoms_vec),
                                              num_batons});
}

Bytes make_mint(const TokenId &token_id, std::vector<Atoms> atoms_vec,
                size_t num_batons) {
    return alp_mint(token_id, std::move(atoms_vec), num_batons);
}

Bytes make_send(const TokenId &token_id, std::vector<Atoms> atoms_vec) {
    return alp::SendSection(token_id, STD, atoms_vec);
}

Bytes make_burn(const TokenId &token_id, Atoms atoms) {
    return alp::BurnSection(token_id, STD, atoms);
}

ColoredTxSection Section(TokenMeta meta, TxType tx_type,
                         uint128 required_input_sum = 0,
                         std::optional<GenesisInfo> genesis_info = {}) {
    return ColoredTxSection{meta, tx_type, required_input_sum, false,
                            std::move(genesis_info)};
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_alp_all_the_things_tests)

BOOST_AUTO_TEST_CASE(test_color_alp_all_the_things) {
    const Tx tx = MakeTx(
        alp::SectionsOpreturn({
            // success GENESIS
            make_genesis({0, 7, 0, 0, 1}, 2),
            // fail GENESIS: must be first
            make_genesis({}, 0),
            // fail MINT: Too few outputs
            make_mint(T_ID2, std::vector<Atoms>(7, 0), 99),
            // fail MINT: Overlapping atoms
            make_mint(T_ID2, {0, MAX}, 0),
            // fail MINT: Overlapping batons
            make_mint(T_ID2, {0}, 1),
            // success BURN: token ID 2
            make_burn(T_ID2, 2),
            // success MINT: token ID 3
            make_mint(T_ID3, {3, 0}, 1),
            // success MINT: token ID 2
            make_mint(T_ID2, {0, 0, 0, 2, 0, 0, 0}, 1),
            // fail MINT: Duplicate token ID 2
            make_mint(T_ID2, {}, 0),
            // fail BURN: Duplicate burn token ID 2
            make_burn(T_ID2, 7),
            // fail SEND: Too few outputs
            make_send(T_ID4, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
            // success SEND: token ID 4
            make_send(T_ID4, {0, 0, 0, 0, 0, 0, 0, 0, 0, MAX, 0, 0, 0}),
            // fail MINT: Duplicate token ID 4
            make_mint(T_ID4, {}, 0),
            // success UNKNOWN
            B("SLP2\x89"),
            // fail: Descending token type
            make_burn(T_ID3, 1),
            // Invalid usage of SLP\0
            B("SLP\0"),
            // success UNKNOWN
            B("SLP2\x9a"),
        }),
        10, T_TXID);

    const ColoredTx expected{
        .sections =
            {
                Section(meta_alp(T_ID), TxType::GENESIS, 0,
                        GenesisInfo::EmptyAlp()),
                Section(meta_alp(T_ID3), TxType::MINT),
                Section(meta_alp(T_ID2), TxType::MINT),
                Section(meta_alp(T_ID4), TxType::SEND, MAX),
                Section(meta_alp_unknown(EMPTY_TOKEN_ID, 0x89),
                        TxType::UNKNOWN),
                Section(meta_alp_unknown(EMPTY_TOKEN_ID, 0x9a),
                        TxType::UNKNOWN),
            },
        .intentional_burns = {IntentionalBurn{meta_alp(T_ID2), 2}},
        .outputs =
            {
                NONE,
                // success MINT: token ID 3
                token_atoms<1>(3),
                // success GENESIS
                token_atoms<0>(7),
                // success MINT: token ID 3
                token_baton<1>(),
                // success MINT: token ID 2
                token_atoms<2>(2),
                // success GENESIS
                token_atoms<0>(1),
                // success GENESIS
                token_baton<0>(),
                // success GENESIS
                token_baton<0>(),
                // success MINT: token ID 2
                token_baton<2>(),
                // success UNKNOWN
                token_unknown<4>(0x89),
                // success SEND: token ID 4
                token_atoms<3>(MAX),
            },
        .failed_parsings = {FailedParsing{
            15,
            B("SLP\0"),
            ColorParseError{alp::ParseError::InvalidSlpLokadId()},
        }},
        .failed_colorings =
            {
                // fail GENESIS: must be first
                FailedColoring{1, parse(make_genesis({}, 0)),
                               ColorError::GenesisMustBeFirst()},
                // fail MINT: Too few outputs
                FailedColoring{
                    2, parse(make_mint(T_ID2, std::vector<Atoms>(7, 0), 99)),
                    ColorError::TooFewOutputs(107, 11)},
                // fail MINT: Overlapping atoms
                FailedColoring{
                    3, parse(make_mint(T_ID2, {0, MAX}, 0)),
                    ColorError::OverlappingAtoms(
                        Token{meta_alp(T_ID), TokenVariant::MakeAtoms(7)}, 2,
                        MAX)},
                // fail MINT: Overlapping batons
                FailedColoring{
                    4, parse(make_mint(T_ID2, {0}, 1)),
                    ColorError::OverlappingMintBaton(
                        Token{meta_alp(T_ID), TokenVariant::MakeAtoms(7)}, 2)},
                // fail MINT: Duplicate token ID 2
                FailedColoring{8, parse(make_mint(T_ID2, {}, 0)),
                               ColorError::DuplicateTokenId(2, T_ID2)},
                // fail BURN: Duplicate burn token ID 2
                FailedColoring{
                    9, parse(make_burn(T_ID2, 7)),
                    ColorError::DuplicateIntentionalBurnTokenId(0, 1, T_ID2)},
                // fail SEND: Overlapping amount
                FailedColoring{
                    10,
                    parse(make_send(T_ID4, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})),
                    ColorError::TooFewOutputs(12, 11)},
                // fail MINT: Duplicate token ID 4
                FailedColoring{12, parse(make_mint(T_ID4, {}, 0)),
                               ColorError::DuplicateTokenId(3, T_ID4)},
                // fail: Descending token type
                FailedColoring{14, parse(make_burn(T_ID3, 1)),
                               ColorError::DescendingTokenType(137, 0)},
            },
    };
    const auto actual = ColoredTx::ColorTx(tx);
    BOOST_REQUIRE(actual);
    BOOST_CHECK(actual->sections == expected.sections);
    BOOST_CHECK(actual->intentional_burns == expected.intentional_burns);
    BOOST_CHECK(actual->outputs == expected.outputs);
    BOOST_CHECK(actual->failed_parsings == expected.failed_parsings);
    BOOST_CHECK(actual->failed_colorings == expected.failed_colorings);
    BOOST_CHECK(*actual == expected);
}

BOOST_AUTO_TEST_SUITE_END()
