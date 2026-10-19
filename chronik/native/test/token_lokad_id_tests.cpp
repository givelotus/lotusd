// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/src/lokad_id.rs tests.

#include <chronik/native/token/lokad_id.h>
#include <chronik/native/token/parse.h>

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using chronik::native::script::Script;

namespace {

LokadId L(const char (&s)[5]) {
    return {uint8_t(s[0]), uint8_t(s[1]), uint8_t(s[2]), uint8_t(s[3])};
}

std::vector<LokadId> ParseEmpp(const Bytes &script) {
    auto parsed = empp::Parse(script);
    if (!parsed.ok() || !parsed.value()) {
        return {};
    }
    return EmppLokadIds(*parsed.value());
}

TxInput Input(Bytes script) {
    TxInput input;
    input.script = std::move(script);
    return input;
}

TxOutput Output(Bytes script) {
    TxOutput output;
    output.script = std::move(script);
    return output;
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_lokad_id_tests)

BOOST_AUTO_TEST_CASE(test_parse_lokad_id_opreturn) {
    auto parse = [](const Bytes &script) {
        return ParseOpreturnLokadId(script);
    };
    const std::optional<LokadId> none;
    const std::optional<LokadId> abcd = L("abcd");
    BOOST_CHECK(parse(Script().bytecode()) == none);
    BOOST_CHECK(parse(Script::P2pkh({}).bytecode()) == none);
    BOOST_CHECK(parse(Script::P2sh({}).bytecode()) == none);
    BOOST_CHECK(parse(B("\0")) == none);
    BOOST_CHECK(parse(B("\x04")) == none);
    BOOST_CHECK(parse(B("\x04" "abcd")) == none);
    BOOST_CHECK(parse(B("\x06" "abcdef")) == none);
    BOOST_CHECK(parse(B("\x6a")) == none);
    BOOST_CHECK(parse(B("\x6a\0")) == none);
    BOOST_CHECK(parse(B("\x6a\x01\x01")) == none);
    BOOST_CHECK(parse(B("\x6a\x04")) == none);
    BOOST_CHECK(parse(B("\x6a\x04" "abc")) == none);
    BOOST_CHECK(parse(B("\x6a\x04" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x4c\x04" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x4d\x04\0" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x4e\x04\0\0\0" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x04" "abcdef")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x04" "abcd" "\x04" "1234")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x4c\x04" "abcdef")) == abcd);
    BOOST_CHECK(parse(B("\x6a\x05" "abcde")) == none);
    BOOST_CHECK(parse(B("\x6a\x06" "abcdef")) == none);
}

BOOST_AUTO_TEST_CASE(test_parse_lokad_id_input) {
    auto parse = [](const Bytes &script) {
        return ParseInputScriptLokadId(script);
    };
    const std::optional<LokadId> none;
    const std::optional<LokadId> abcd = L("abcd");
    BOOST_CHECK(parse(B("")) == none);
    BOOST_CHECK(parse(B("\0")) == none);
    BOOST_CHECK(parse(B("\x04")) == none);
    BOOST_CHECK(parse(B("\x04" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x4c\x04" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x4d\x04\0" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x4e\x04\0\0\0" "abcd")) == abcd);
    BOOST_CHECK(parse(B("\x04" "abcdef")) == abcd);
    BOOST_CHECK(parse(B("\x04" "abcd" "\x04" "1234")) == abcd);
    BOOST_CHECK(parse(B("\x06" "abcdef")) == none);
    BOOST_CHECK(parse(B("\x6a\x04" "abcd")) == none);
}

BOOST_AUTO_TEST_CASE(test_parse_lokad_id_empp) {
    const std::vector<LokadId> empty;
    const std::vector<LokadId> abcd{L("abcd")};
    BOOST_CHECK(ParseEmpp(Script().bytecode()) == empty);
    BOOST_CHECK(ParseEmpp(Script::P2pkh({}).bytecode()) == empty);
    BOOST_CHECK(ParseEmpp(Script::P2sh({}).bytecode()) == empty);
    BOOST_CHECK(ParseEmpp(B("\0")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x04")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x04" "abcd")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x06" "abcdef")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\0")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x01\x01")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04" "abc")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04" "abcd")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x4c\x04" "abcd")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x4d\x04\0" "abcd")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x4e\x04\0\0\0" "abcd")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04" "abcdef")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04" "abcd" "\x04" "1234")) ==
                (std::vector<LokadId>{L("abcd"), L("1234")}));
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x4c\x04" "abcdef")) == empty);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x04" "abcd")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x05" "abcde")) == abcd);
    BOOST_CHECK(ParseEmpp(B("\x6a\x50\x06" "abcdef")) == abcd);
}

BOOST_AUTO_TEST_CASE(test_parse_tx_lokad_ids) {
    {
        Tx tx;
        tx.version = 1;
        tx.inputs = {
            Input(B("\x04" "abcd")),
            Input(B("\x4c\x04" "1234")),
            // ignored if first pushop is not 4 bytes
            Input(Cat({B("\x41"), Rep(0x41, 5), B("\x04" "xxxx")})),
        };
        tx.outputs = {
            Output(B("\x6a\x04" "6789" "\x04" "yyyy")),
            // Ignored: OP_RETURN must be first
            Output(B("\x6a\x04" "zzzz")),
        };
        BOOST_CHECK(ParseTxLokadIds(tx) ==
                    (std::vector<LokadId>{L("6789"), L("abcd"), L("1234")}));
    }
    {
        Tx tx;
        tx.version = 1;
        tx.inputs = {Input(B("\x4d\x04\0" "efgh"))};
        tx.outputs = {Output(B("\x6a\x50\x04" "6789" "\x04" "4321"))};
        BOOST_CHECK(ParseTxLokadIds(tx) ==
                    (std::vector<LokadId>{L("6789"), L("4321"), L("efgh")}));
    }
}

BOOST_AUTO_TEST_SUITE_END()
