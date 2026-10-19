// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_slp_parse_common.rs and
// test_slp_parse_unknown.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using slp::ParseError;
using Kind = slp::ParseError::Kind;

namespace {

const Bytes SLP_PREFIX{0x6a, 0x04, 'S', 'L', 'P', 0x00};

} // namespace

BOOST_AUTO_TEST_SUITE(token_slp_parse_common_tests)

BOOST_AUTO_TEST_CASE(test_parse_not_opreturn) {
    // No outputs -> no parsed SLP data
    BOOST_CHECK(slp::ParseTx(Tx{}) ==
                SlpParseResult{std::optional<ParsedData>{}});

    // Empty script
    slp_check_script({}, ParseError::Make(Kind::EmptyScript), true);

    // Missing OP_RETURN opcode
    slp_check_script({0xac}, ParseError::MissingOpReturn(OP_CHECKSIG), true);
    slp_check_script({0x01}, ParseError::MissingOpReturn(Opcode{1}), true);
    slp_check_script({0x4c}, ParseError::MissingOpReturn(OP_PUSHDATA1), true);

    slp_check_script(Script::P2pk(Bytes(33, 0)).bytecode(),
                     ParseError::MissingOpReturn(Opcode{33}), true);
    slp_check_script(Script::P2pkh({}).bytecode(),
                     ParseError::MissingOpReturn(OP_DUP), true);
    slp_check_script(Script::P2sh({}).bytecode(),
                     ParseError::MissingOpReturn(OP_HASH160), true);
}

BOOST_AUTO_TEST_CASE(test_parse_slp_lokad_id) {
    // Missing LOKAD ID
    slp_check_script({0x6a}, ParseError::Make(Kind::MissingLokadId), true);

    // Invalid LOKAD ID opcode
    slp_check_script({0x6a, 0xac},
                     ParseError::InvalidLokadIdOpcode(OP_CHECKSIG), true);

    // Invalidly encoded LOKAD ID opcode also results in the same error
    slp_check_script({0x6a, 0x01},
                     ParseError::InvalidLokadIdOpcode(Opcode{1}), true);
    slp_check_script({0x6a, 0x4c},
                     ParseError::InvalidLokadIdOpcode(OP_PUSHDATA1), true);

    // Wrong LOKAD ID
    slp_check_script({0x6a, 0x01, 0x00}, ParseError::WrongLokadId({0x00}),
                     true);
    slp_check_script({0x6a, 0x01, 0x22, 0x01, 0x00},
                     ParseError::WrongLokadId({0x22}), true);
    slp_check_script({0x6a, 0x03, 'S', 'L', 'P'},
                     ParseError::WrongLokadId(B("SLP")), true);
    slp_check_script({0x6a, 0x04, 'S', 'L', 'P', 0x99},
                     ParseError::WrongLokadId(B("SLP\x99")), true);

    // Valid Lokad ID (using OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4)
    slp_check_script(
        {
            0x6a,                         // OP_RETURN
            0x04, 'S', 'L', 'P', 0x00,    // "SLP\0"
            0x4c, 0x00, 0x01, 0x00,       // token type (empty) & tx type
        },
        ParseError::InvalidTokenType({}), false);
    slp_check_script(
        {
            0x6a,                            // OP_RETURN
            0x4c, 0x04, 'S', 'L', 'P', 0x00, // OP_PUSHDATA1 "SLP\0"
            0x4c, 0x00, 0x01, 0x00, // token type (empty) & tx type
        },
        ParseError::InvalidTokenType({}), false);
    slp_check_script(
        {
            0x6a,                                  // OP_RETURN
            0x4d, 0x04, 0x00, 'S', 'L', 'P', 0x00, // OP_PUSHDATA2
            0x4c, 0x00, 0x01, 0x00, // token type (empty) & tx type
        },
        ParseError::InvalidTokenType({}), false);
    slp_check_script(
        {
            0x6a, // OP_RETURN
            // OP_PUSHDATA4 "SLP\0"
            0x4e, 0x04, 0x00, 0x00, 0x00, 'S', 'L', 'P', 0x00,
            // token type (empty) & tx type
            0x4c, 0x00, 0x01, 0x00,
        },
        ParseError::InvalidTokenType({}), false);

    // After OP_RETURN "SLP\0", all invalidly encoded opcodes are a DataError
    slp_check_script({0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01},
                     ParseError::FromDataError(DataError::InvalidLength(1, 0)),
                     false);
    slp_check_script({0x6a, 0x04, 'S', 'L', 'P', 0x00, OP_PUSHDATA4.number()},
                     ParseError::FromDataError(DataError::InvalidLength(4, 0)),
                     false);
}

BOOST_AUTO_TEST_CASE(test_parse_slp_alp_mixup) {
    // Used ALP ("SLP2") LOKAD ID, which we report separately and don't
    // ignore. Otherwise, someone forgetting the OP_RESERVED might get
    // confused.
    slp_check_script({0x6a, 0x04, 'S', 'L', 'P', '2'},
                     ParseError::Make(Kind::InvalidAlpLokadId), false);
    // Using it with additional bytes at the end also gets reported as ALP
    slp_check_script({0x6a, 0x05, 'S', 'L', 'P', '2', 0},
                     ParseError::Make(Kind::InvalidAlpLokadId), false);
    slp_check_script({0x6a, 0x06, 'S', 'L', 'P', '2', 0, 0},
                     ParseError::Make(Kind::InvalidAlpLokadId), false);
}

BOOST_AUTO_TEST_CASE(test_parse_slp_disallowed_push) {
    // Disallowed push
    std::vector<std::tuple<Bytes, Opcode, size_t>> scripts{
        {{0x00}, OP_0, 2},
        {{0x4f}, OP_1NEGATE, 2},
        {{0x4c, 0x00, 0x51}, OP_1, 3},
        {{0x4d, 0x00, 0x00, 0x52}, OP_2, 3},
        {{0x4e, 0x00, 0x00, 0x00, 0x00, 0x53}, OP_3, 3},
        {{0x01, 0x00, 0x54}, OP_4, 3},
        {{0x02, 0x00, 0x00, 0x55}, OP_5, 3},
        {{0x56}, OP_6, 2},
        {{0x57}, OP_7, 2},
        {{0x58}, OP_8, 2},
        {{0x59}, OP_9, 2},
        {{0x5a}, OP_10, 2},
        {{0x5b}, OP_11, 2},
        {{0x5c}, OP_12, 2},
        {{0x5d}, OP_13, 2},
        {{0x5e}, OP_14, 2},
        {{0x5f}, OP_15, 2},
        {{0x60}, OP_16, 2},
    };
    scripts.emplace_back(Cat({{0x4b}, Rep(0x00, 0x4b), {0x00}}), OP_0, 3);
    for (const auto &[script, opcode, op_idx] : scripts) {
        slp_check_script(Cat({SLP_PREFIX, script}),
                         ParseError::DisallowedPush(opcode, op_idx), false);
    }
}

BOOST_AUTO_TEST_CASE(test_parse_slp_non_pushop) {
    // Non-pushop
    for (int opcode = 0x61; opcode <= 0xff; ++opcode) {
        slp_check_script(Cat({SLP_PREFIX, {uint8_t(opcode)}}),
                         ParseError::NonPushOp(Opcode{uint8_t(opcode)}, 2),
                         false);
    }
}

BOOST_AUTO_TEST_CASE(test_parse_slp_too_few_pushes) {
    // Too few pushes
    const std::vector<Bytes> scripts{
        SLP_PREFIX,
        Cat({SLP_PREFIX, {0x01, 0x00}}),
    };
    for (size_t num_pushes = 0; num_pushes < scripts.size(); ++num_pushes) {
        slp_check_script(scripts[num_pushes],
                         ParseError::TooFewPushes(3, num_pushes + 1), false);
    }
}

BOOST_AUTO_TEST_CASE(test_parse_slp_invalid_token_type) {
    // Invalid token type, must be 1 or 2 bytes
    slp_check_script(Cat({SLP_PREFIX,
                          {
                              0x4c, 0x00, // 0 byte token type
                              0x01, 0x00, // tx type
                          }}),
                     ParseError::InvalidTokenType({}), false);
    slp_check_script(Cat({SLP_PREFIX,
                          {
                              0x02, 0x77, 0x77, // 3 byte token type
                              0x01, 0x00,       // tx type
                          }}),
                     ParseError::InvalidTokenType({0x77, 0x77}), false);
    slp_check_script(Cat({SLP_PREFIX,
                          {
                              0x03, 0x99, 0x99, 0x99, // 3 byte token type
                              0x01, 0x00,             // tx type
                          }}),
                     ParseError::InvalidTokenType({0x99, 0x99, 0x99}), false);
}

BOOST_AUTO_TEST_CASE(test_slp_parse_invalid_tx_type) {
    // test for all token types
    for (uint8_t typ : slp_consts::ALL_TOKEN_TYPES) {
        // Invalid tx type
        slp_check_script(Cat({SLP_PREFIX, {0x01, typ}, {0x07}, B("INVALID")}),
                         ParseError::InvalidTxType(B("INVALID")), false);
    }
}

// test_slp_parse_unknown.rs
BOOST_AUTO_TEST_CASE(test_slp_parse_unknown) {
    // Unknown token type (no error, but results in "Unknown" fields)
    std::vector<uint8_t> unknown_types{0};
    for (int t = 3; t < 0x41; ++t) { // 0x41 is NFT1 Child
        unknown_types.push_back(uint8_t(t));
    }
    for (int t = 0x42; t < 0x81; ++t) { // 0x81 is NFT1 Group
        unknown_types.push_back(uint8_t(t));
    }
    for (int t = 0x82; t <= 0xff; ++t) {
        unknown_types.push_back(uint8_t(t));
    }
    for (uint8_t typ : unknown_types) {
        BOOST_CHECK(
            slp_parse(Cat({SLP_PREFIX, {0x01, typ, 0x01, 0x00}})) ==
            SlpOk(ParsedData{
                TokenMeta{TokenId::FromBeBytes({}),
                          TokenType::Slp(SlpTokenType::Unknown(typ))},
                ParsedTxType::MakeUnknown(),
            }));
    }
}

BOOST_AUTO_TEST_SUITE_END()
