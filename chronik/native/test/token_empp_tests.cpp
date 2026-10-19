// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/src/empp/parse.rs tests.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using empp::EmppData;
using empp::ParseError;
using Kind = empp::ParseError::Kind;

namespace {

using EmppResult = Result<std::optional<EmppData>, ParseError>;

const EmppResult OK_NONE{std::optional<EmppData>{}};

void CheckParseErr(const Bytes &bytecode, const ParseError &expected_err,
                   bool should_ignore) {
    auto actual = empp::ParseWithIgnoredErr(bytecode);
    BOOST_REQUIRE_MESSAGE(!actual.ok(), "Test expected parse to fail");
    BOOST_CHECK(actual.error() == expected_err);
    auto parsed = empp::Parse(bytecode);
    const bool ignored = parsed.ok() && !parsed.value();
    BOOST_CHECK_EQUAL(ignored, should_ignore);
}

uint8_t N(Opcode op) {
    return op.number();
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_empp_tests)

BOOST_AUTO_TEST_CASE(test_empp_ignored) {
    BOOST_CHECK(empp::Parse(Script().bytecode()) == OK_NONE);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_PUSHDATA1)}) == OK_NONE);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN)}) == OK_NONE);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_PUSHDATA1)}) == OK_NONE);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_0)}) == OK_NONE);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_0), N(OP_RESERVED)}) ==
                OK_NONE);
    BOOST_CHECK(empp::Parse(Script::P2pk(Bytes(33, 0)).bytecode()) == OK_NONE);
    BOOST_CHECK(empp::Parse(Script::P2pkh({}).bytecode()) == OK_NONE);
    BOOST_CHECK(empp::Parse(Script::P2sh({}).bytecode()) == OK_NONE);
}

BOOST_AUTO_TEST_CASE(test_empp) {
    CheckParseErr({}, ParseError::Make(Kind::EmptyScript), true);
    CheckParseErr({N(OP_CHECKSIG)},
                  ParseError::Make(Kind::MissingOpReturn, OP_CHECKSIG), true);
    CheckParseErr({N(OP_RETURN)}, ParseError::Make(Kind::EmptyOpReturn), true);
    CheckParseErr({N(OP_RETURN), N(OP_CHECKSIG)},
                  ParseError::Make(Kind::MissingOpReserved, OP_CHECKSIG),
                  true);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_RESERVED)}) ==
                EmppResult{std::optional<EmppData>{EmppData{}}});
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_0)},
                  ParseError::Make(Kind::EmptyPushdata, OP_0), false);
    for (Opcode opcode : {OP_1NEGATE, OP_1, OP_2, OP_16}) {
        CheckParseErr({N(OP_RETURN), N(OP_RESERVED), opcode.number()},
                      ParseError::Make(Kind::InvalidPushOpcode, opcode),
                      false);
    }
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_CHECKSIG)},
                  ParseError::Make(Kind::InvalidNonPushOpcode, OP_CHECKSIG),
                  false);
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_PUSHDATA1), 0},
                  ParseError::Make(Kind::EmptyPushdata, OP_PUSHDATA1), false);
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_PUSHDATA2), 0, 0},
                  ParseError::Make(Kind::EmptyPushdata, OP_PUSHDATA2), false);
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_PUSHDATA4), 0, 0, 0, 0},
                  ParseError::Make(Kind::EmptyPushdata, OP_PUSHDATA4), false);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_RESERVED), 1, 77}) ==
                EmppResult{std::optional<EmppData>{EmppData{{77}}}});
    const EmppData two_pushes{{77}, {88, 99}};
    BOOST_CHECK(
        empp::Parse(Bytes{N(OP_RETURN), N(OP_RESERVED), 1, 77, 2, 88, 99}) ==
        EmppResult{std::optional<EmppData>{two_pushes}});
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), 1, 77, 2, 88, 99, 0},
                  ParseError::Make(Kind::EmptyPushdata, OP_0), false);
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_RESERVED),
                                  N(OP_PUSHDATA1), 1, 77}) ==
                EmppResult{std::optional<EmppData>{EmppData{{77}}}});
    BOOST_CHECK(empp::Parse(Bytes{N(OP_RETURN), N(OP_RESERVED),
                                  N(OP_PUSHDATA2), 1, 0, 77}) ==
                EmppResult{std::optional<EmppData>{EmppData{{77}}}});
    CheckParseErr({N(OP_RETURN), N(OP_RESERVED), N(OP_PUSHDATA4)},
                  ParseError::FromDataError(DataError::InvalidLength(4, 0)),
                  false);
}

BOOST_AUTO_TEST_SUITE_END()
