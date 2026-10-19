// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_alp_parse_genesis.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using alp::ParseError;

namespace {

const TxId GENESIS_TXID = MakeTxId(4);
const Bytes GENESIS_PREFIX = Cat({SLP2, {0}, {0x07}, B("GENESIS")});

AlpSectionResult Parse(const Bytes &tail) {
    return alp_parse(Cat({GENESIS_PREFIX, tail}), GENESIS_TXID);
}

AlpSectionResult GenesisOk(GenesisInfo info, ParsedMintData mint_data) {
    return AlpSectionResult(ParsedData{
        meta_alp(TokenId{GENESIS_TXID}),
        ParsedTxType::MakeGenesis(
            ParsedGenesis{std::move(info), std::move(mint_data)}),
    });
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_alp_parse_genesis_tests)

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_not_enough_bytes) {
    // missing token_ticker
    BOOST_CHECK(Parse({}) == not_enough("token_ticker", 1, 0));
    // token_ticker missing 99 bytes
    BOOST_CHECK(Parse({99}) == not_enough("token_ticker", 99, 0));
    // missing token_name
    BOOST_CHECK(Parse({0}) == not_enough("token_name", 1, 0));
    // token_name missing 99 bytes
    BOOST_CHECK(Parse({0, 99}) == not_enough("token_name", 99, 0));
    // missing url
    BOOST_CHECK(Parse({0, 0}) == not_enough("url", 1, 0));
    // url missing 99 bytes
    BOOST_CHECK(Parse({0, 0, 99}) == not_enough("url", 99, 0));
    // missing token data
    BOOST_CHECK(Parse({0, 0, 0}) == not_enough("data", 1, 0));
    // token data missing 99 bytes
    BOOST_CHECK(Parse({0, 0, 0, 99}) == not_enough("data", 99, 0));
    // missing auth_pubkey
    BOOST_CHECK(Parse({0, 0, 0, 0}) == not_enough("auth_pubkey", 1, 0));
    // auth_pubkey missing 99 bytes
    BOOST_CHECK(Parse({0, 0, 0, 0, 99}) == not_enough("auth_pubkey", 99, 0));
    // missing decimals
    BOOST_CHECK(Parse({0, 0, 0, 0, 0}) == not_enough("decimals", 1, 0));
    // missing num amounts
    BOOST_CHECK(Parse({0, 0, 0, 0, 0, 0}) == not_enough("mint_amount", 1, 0));
    // missing num batons
    BOOST_CHECK(Parse({0, 0, 0, 0, 0, 0, 0}) ==
                not_enough("num_batons", 1, 0));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_default) {
    // parsing default empty Genesis succeeded
    BOOST_CHECK(Parse({0, 0, 0, 0, 0, 0, 0, 0}) ==
                GenesisOk(GenesisInfo::EmptyAlp(), ParsedMintData{}));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_leftover_bytes) {
    // leftover bytes
    BOOST_CHECK(Parse(Cat({{0, 0, 0, 0, 0, 0, 0, 0}, B("hello")})) ==
                AlpErr(ParseError::LeftoverBytes(B("hello"))));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_invalid_sizes) {
    // any size > 127 for token_ticker, token_name, url, data, auth_pubkey,
    // decimals, num amounts and num batons is invalid
    const char *const fields[] = {
        "token_ticker", "token_name", "url",         "data",
        "auth_pubkey",  "decimals",   "mint_amount", "num_batons",
    };
    for (size_t i : {0, 1, 2, 3, 4, 6, 7}) {
        Bytes tail(8, 0);
        for (int invalid = 128; invalid <= 255; ++invalid) {
            tail[i] = uint8_t(invalid);
            BOOST_CHECK(Parse(tail) == AlpErr(ParseError::SizeOutOfRange(
                                           fields[i], invalid)));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_invalid_decimals) {
    // any decimals > 9 is invalid
    for (int invalid = 10; invalid <= 255; ++invalid) {
        BOOST_CHECK(Parse({0, 0, 0, 0, 0, uint8_t(invalid), 0, 0}) ==
                    AlpErr(ParseError::DecimalsOutOfRange(invalid)));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_valid_field_sizes) {
    // exhaustively test all allowed sizes for token_ticker, token_name, url,
    // data, auth_pubkey
    for (size_t i = 0; i < 5; ++i) {
        for (size_t size = 0; size <= 127; ++size) {
            Bytes tail = Rep(0, i);
            tail.push_back(uint8_t(size));
            const Bytes field = Rep(0x76, size);
            tail.insert(tail.end(), field.begin(), field.end());
            tail.insert(tail.end(), 4 - i, 0);
            tail.insert(tail.end(), 3, 0);
            GenesisInfo info = GenesisInfo::EmptyAlp();
            Bytes *fields[] = {&info.token_ticker, &info.token_name, &info.url,
                               &*info.data, &*info.auth_pubkey};
            *fields[i] = field;
            BOOST_CHECK(Parse(tail) == GenesisOk(info, ParsedMintData{}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_valid_amounts) {
    for (size_t size = 0; size <= 127; ++size) {
        Bytes tail{0, 0, 0, 0, 0, 0};
        tail.push_back(uint8_t(size));
        std::vector<Atoms> atoms_vec;
        for (size_t i = 0; i < size; ++i) {
            tail.push_back(uint8_t(i));
            tail.insert(tail.end(), 5, 0);
            atoms_vec.push_back(i);
        }
        tail.push_back(0);
        BOOST_CHECK(Parse(tail) == GenesisOk(GenesisInfo::EmptyAlp(),
                                             ParsedMintData{atoms_vec, 0}));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_valid_num_batons) {
    for (size_t size = 0; size <= 127; ++size) {
        Bytes tail{0, 0, 0, 0, 0, 0, 0};
        tail.push_back(uint8_t(size));
        BOOST_CHECK(Parse(tail) == GenesisOk(GenesisInfo::EmptyAlp(),
                                             ParsedMintData{{}, size}));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_genesis_valid_example) {
    GenesisInfo info;
    info.token_ticker = B("12");
    info.token_name = B("345");
    info.url = B("6789");
    info.data = B("abcde");
    info.auth_pubkey = B("fghijk");
    info.decimals = 7;
    BOOST_CHECK(
        Parse(Cat({B("\x02" "12"), B("\x03" "345"), B("\x04" "6789"),
                   B("\x05" "abcde"), B("\x06" "fghijk"),
                   {7},
                   {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8},
                   {4}})) ==
        GenesisOk(info, ParsedMintData{
                            {0x60504030201, 0x20100090807, 0x80706050403},
                            4}));
}

BOOST_AUTO_TEST_SUITE_END()
