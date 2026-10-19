// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_alp_parse_send.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using alp::ParseError;

namespace {

const Bytes SEND_PREFIX = Cat({SLP2, {0}, {0x04}, B("SEND")});

} // namespace

BOOST_AUTO_TEST_SUITE(token_alp_parse_send_tests)

BOOST_AUTO_TEST_CASE(test_parse_alp_send_not_enough_bytes) {
    for (size_t size = 0; size <= 31; ++size) {
        BOOST_CHECK(alp_parse(Cat({SEND_PREFIX, Rep(0, size)})) ==
                    not_enough("token_id", 32, size));
    }
    BOOST_CHECK(alp_parse(Cat({SEND_PREFIX, Rep(0x76, 32)})) ==
                not_enough("send_amount", 1, 0));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_send_invalid_size) {
    // any size > 127 for num amounts is invalid
    for (int invalid = 128; invalid <= 255; ++invalid) {
        BOOST_CHECK(
            alp_parse(Cat({SEND_PREFIX, Rep(0x76, 32), {uint8_t(invalid)}})) ==
            AlpErr(ParseError::SizeOutOfRange("send_amount", invalid)));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_alp_send_valid_minimal) {
    BOOST_CHECK(alp_parse(Cat({SEND_PREFIX, Rep(0x76, 32), {0}})) ==
                AlpSectionResult(ParsedData{
                    AlpTestMeta(),
                    ParsedTxType::MakeSend({}),
                }));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_send_leftover) {
    // leftover bytes
    BOOST_CHECK(
        alp_parse(Cat({SEND_PREFIX, Rep(0x76, 32), {0}, B("hello")})) ==
        AlpErr(ParseError::LeftoverBytes(B("hello"))));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_send_valid_amounts) {
    for (size_t size = 0; size <= 127; ++size) {
        Bytes pushdata = Cat({SEND_PREFIX, Rep(0x76, 32)});
        pushdata.push_back(uint8_t(size));
        std::vector<Atoms> amounts;
        for (size_t i = 0; i < size; ++i) {
            pushdata.push_back(uint8_t(i));
            pushdata.insert(pushdata.end(), 5, 0);
            amounts.push_back(i);
        }
        BOOST_CHECK(alp_parse(pushdata) ==
                    AlpSectionResult(ParsedData{
                        AlpTestMeta(),
                        ParsedTxType::MakeSend(amounts),
                    }));
    }
}

BOOST_AUTO_TEST_SUITE_END()
