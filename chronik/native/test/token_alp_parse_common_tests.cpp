// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_alp_parse_common.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using alp::ParseError;

namespace {

const TxId COMMON_TXID = MakeTxId(4);

AlpSectionResult Parse(Bytes data) {
    return alp_parse(std::move(data), COMMON_TXID);
}

void CheckShouldIgnore(const Bytes &pushdata, const ParseError &err) {
    BOOST_CHECK(Parse(pushdata) == AlpErr(err));
    BOOST_CHECK(alp::ParseSection(COMMON_TXID, pushdata) ==
                AlpParseResult{std::optional<ParsedData>{}});
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_alp_parse_common_tests)

BOOST_AUTO_TEST_CASE(test_parse_alp_intro) {
    CheckShouldIgnore({}, ParseError::MissingLokadId({}));
    CheckShouldIgnore({1, 2, 3}, ParseError::MissingLokadId({1, 2, 3}));
    CheckShouldIgnore({1, 2, 3, 4}, ParseError::InvalidLokadId({1, 2, 3, 4}));
    BOOST_CHECK(Parse(SLP2) == not_enough("token_type", 1, 0));
    BOOST_CHECK(Parse(Cat({SLP2, {99}})) ==
                AlpSectionResult(ParsedData{
                    meta_alp_unknown(TokenId{EMPTY_TXID}, 99),
                    ParsedTxType::MakeUnknown(),
                }));
    BOOST_CHECK(Parse(Cat({SLP2, {0}})) == not_enough("tx_type", 1, 0));
    BOOST_CHECK(Parse(Cat({SLP2, {0}, {99}})) == not_enough("tx_type", 99, 0));
    BOOST_CHECK(Parse(Cat({SLP2, {0}, {0}})) ==
                AlpErr(ParseError::UnknownTxType({})));
    BOOST_CHECK(Parse(Cat({SLP2, {0}, {7}, B("INVALID")})) ==
                AlpErr(ParseError::UnknownTxType(B("INVALID"))));
}

BOOST_AUTO_TEST_CASE(test_parse_alp_slp_mixup) {
    BOOST_CHECK(Parse({'S', 'L', 'P', 0}) ==
                AlpErr(ParseError::InvalidSlpLokadId()));
    BOOST_CHECK(Parse({'S', 'L', 'P', 0, 1}) ==
                AlpErr(ParseError::InvalidSlpLokadId()));
    BOOST_CHECK(Parse({'S', 'L', 'P', 0, 1, 1}) ==
                AlpErr(ParseError::InvalidSlpLokadId()));
}

BOOST_AUTO_TEST_SUITE_END()
