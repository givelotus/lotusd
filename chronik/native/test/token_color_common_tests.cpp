// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_common.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const TxId COLOR_TXID = MakeTxId(4);

Tx MakeColorTx(const Script &script) {
    return MakeTx(script, 0, COLOR_TXID);
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_common_tests)

BOOST_AUTO_TEST_CASE(test_color_none) {
    TOKEN_CHECK(!ColoredTx::ColorTx(Tx{}));
    TOKEN_CHECK(!ColoredTx::ColorTx(MakeColorTx(Script())));
    TOKEN_CHECK(!ColoredTx::ColorTx(MakeColorTx(Script::P2pk(Bytes(33, 0)))));
    TOKEN_CHECK(!ColoredTx::ColorTx(MakeColorTx(Script::P2pkh({}))));
    TOKEN_CHECK(!ColoredTx::ColorTx(MakeColorTx(Script::P2sh({}))));
}

BOOST_AUTO_TEST_CASE(test_color_lokad_ids) {
    // Various ignored LOKAD IDs
    const std::vector<Bytes> lokad_ids{B(".xec"), B("\x6d\x01"), B("SLP3"),
                                       B("ALP\0")};

    // Test OP_RETURN <LOKAD ID> <other pushes>
    for (const Bytes &lokad_id : lokad_ids) {
        for (uint8_t n_pushes = 0; n_pushes < 10; ++n_pushes) {
            ScriptMut script;
            script.PutOpcodes({OP_RETURN});
            script.PutPushdata(lokad_id);
            for (uint8_t i = 0; i < n_pushes; ++i) {
                script.PutPushdata(Rep(i, i));
            }
            TOKEN_CHECK(!ColoredTx::ColorTx(MakeColorTx(script.Freeze())));
        }
    }

    // Test OP_RETURN OP_RESERVED [<LOKAD ID + other bytes>]*
    for (size_t n_pushdata = 0; n_pushdata < 10; ++n_pushdata) {
        std::vector<Bytes> sections;
        for (size_t idx = 0; idx < n_pushdata; ++idx) {
            sections.push_back(
                Cat({lokad_ids[idx % lokad_ids.size()], Rep(4, n_pushdata)}));
        }
        TOKEN_CHECK(
            !ColoredTx::ColorTx(MakeColorTx(alp::SectionsOpreturn(sections))));
    }
}

BOOST_AUTO_TEST_CASE(test_color_invalid_empp) {
    const Script script = alp::SectionsOpreturn({Bytes{}});
    TOKEN_CHECK(ColoredTx::ColorTx(MakeColorTx(script)) ==
                ColoredTx{
                    .outputs = {std::nullopt},
                    .failed_parsings = {FailedParsing{
                        std::nullopt,
                        script.bytecode(),
                        ColorParseError{empp::ParseError::Make(
                            empp::ParseError::Kind::EmptyPushdata, OP_0)},
                    }},
                });
}

BOOST_AUTO_TEST_SUITE_END()
