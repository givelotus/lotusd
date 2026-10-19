// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_alp_parse_mint.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using alp::ParseError;

namespace {

const Bytes MINT_PREFIX = Cat({SLP2, {0}, {0x04}, B("MINT")});

AlpSectionResult MintOk(ParsedMintData mint_data) {
    return AlpSectionResult(ParsedData{
        AlpTestMeta(), ParsedTxType::MakeMint(std::move(mint_data))});
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_alp_parse_mint_tests)

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_not_enough_bytes) {
    for (size_t size = 0; size <= 31; ++size) {
        BOOST_CHECK(alp_parse(Cat({MINT_PREFIX, Rep(0, size)})) ==
                    not_enough("token_id", 32, size));
    }
    BOOST_CHECK(alp_parse(Cat({MINT_PREFIX, Rep(0x76, 32)})) ==
                not_enough("mint_amount", 1, 0));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_invalid_size) {
    // any size > 127 for num amounts and num batons is invalid
    const char *const fields[] = {"mint_amount", "num_batons"};
    for (size_t i : {0, 1}) {
        Bytes tail{0, 0};
        for (int invalid = 128; invalid <= 255; ++invalid) {
            tail[i] = uint8_t(invalid);
            BOOST_CHECK(
                alp_parse(Cat({MINT_PREFIX, Rep(0x76, 32), tail})) ==
                AlpErr(ParseError::SizeOutOfRange(fields[i], invalid)));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_simple) {
    BOOST_CHECK(alp_parse(Cat({MINT_PREFIX, Rep(0x76, 32), {0, 0}})) ==
                MintOk(ParsedMintData{}));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_leftover) {
    // leftover bytes
    BOOST_CHECK(
        alp_parse(Cat({MINT_PREFIX, Rep(0x76, 32), {0, 0}, B("hello")})) ==
        AlpErr(ParseError::LeftoverBytes(B("hello"))));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_valid_amounts) {
    for (size_t size = 0; size <= 127; ++size) {
        Bytes pushdata = Cat({MINT_PREFIX, Rep(0x76, 32)});
        pushdata.push_back(uint8_t(size));
        std::vector<Atoms> atoms_vec;
        for (size_t i = 0; i < size; ++i) {
            pushdata.push_back(uint8_t(i));
            pushdata.insert(pushdata.end(), 5, 0);
            atoms_vec.push_back(i);
        }
        pushdata.push_back(0);
        BOOST_CHECK(alp_parse(pushdata) ==
                    MintOk(ParsedMintData{atoms_vec, 0}));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_valid_num_batons) {
    for (size_t size = 0; size <= 127; ++size) {
        Bytes pushdata = Cat({MINT_PREFIX, Rep(0x76, 32), {0}});
        pushdata.push_back(uint8_t(size));
        BOOST_CHECK(alp_parse(pushdata) == MintOk(ParsedMintData{{}, size}));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_mint_valid_example) {
    BOOST_CHECK(
        alp_parse(Cat({MINT_PREFIX,
                       Rep(0x76, 32),
                       {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8},
                       {4}})) ==
        MintOk(ParsedMintData{
            {0x60504030201, 0x20100090807, 0x80706050403}, 4}));
}

BOOST_AUTO_TEST_SUITE_END()
