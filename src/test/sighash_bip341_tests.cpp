// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <core_io.h>
#include <hash.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/standard.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(sighash_bip341_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepare_spent_outputs) {
    LOCK(cs_main);
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_1));
    txFrom.vout[0].nValue = 1000 * SATOSHI;

    AddCoins(coins, CTransaction(txFrom), 0);

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_2));
    txTo.vout[0].nValue = 3000 * SATOSHI;

    PrecomputedTransactionData txdata =
        PrecomputedTransactionData::FromCoinsView(txTo, coins);
    BOOST_CHECK(txdata.m_spent_outputs == txFrom.vout);
}

BOOST_AUTO_TEST_CASE(precompute_bip341_hashes) {
    CMutableTransaction txFrom;
    txFrom.vout.resize(2);
    txFrom.vout[0] = CTxOut{1000 * SATOSHI, CScript() << OP_1};
    txFrom.vout[1] = CTxOut{2000 * SATOSHI, CScript() << OP_2};
    CMutableTransaction txTo;
    txTo.vin.resize(2);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vin[0].nSequence = 0xffff'fffe;
    txTo.vin[1].prevout = COutPoint(txFrom.GetId(), 1);
    txTo.vin[1].nSequence = 0xffff'ffff;
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey = CScript() << OP_3;
    txTo.vout[0].nValue = 3000 * SATOSHI;

    BOOST_CHECK_EQUAL(txFrom.GetId(),
                      uint256S("b691de70195fab2d9ca4f3600657439eb7892d9d593766e"
                               "3ed4d0e85da2c1c85"));

    PrecomputedTransactionData txdata(txTo, std::move(txFrom.vout));

    BOOST_CHECK_EQUAL(txdata.m_prevouts_single_hash,
                      uint256S("a7665bc0836a487c6c35b9745ce48d9a4d249336989451b"
                               "604f9b741c1b3ee50"));
    BOOST_CHECK_EQUAL(txdata.m_sequences_single_hash,
                      uint256S("01282d1aeed227f3c168067a934f754805702a15317106e"
                               "b2f76788b7f7fb381"));
    BOOST_CHECK_EQUAL(txdata.m_outputs_single_hash,
                      uint256S("01e2054d5e24f0163cb2862cca70d36ca9f2b1f1f3ee6bc"
                               "7e32118f150e5ebae"));

    BOOST_CHECK_EQUAL(txdata.hashPrevouts,
                      uint256S("4b665423628c1d0365c6bb55123f0132384b4c019f1cf3d"
                               "1ed1c34400b36f432"));
    BOOST_CHECK_EQUAL(txdata.hashPrevouts,
                      SHA256Uint256(txdata.m_prevouts_single_hash));

    BOOST_CHECK_EQUAL(txdata.hashSequence,
                      uint256S("b805fcb22768d3701b2fb60a55b5a5d7122bfdb2ba3d313"
                               "40c6e2bf17d425e98"));
    BOOST_CHECK_EQUAL(txdata.hashSequence,
                      SHA256Uint256(txdata.m_sequences_single_hash));

    BOOST_CHECK_EQUAL(txdata.hashOutputs,
                      uint256S("bbfa4eda7307e5de2aaeccb963beb427f51e9a3d4912ad2"
                               "ac9e1dc5f3407d4dc"));
    BOOST_CHECK_EQUAL(txdata.hashOutputs,
                      SHA256Uint256(txdata.m_outputs_single_hash));

    BOOST_CHECK_EQUAL(txdata.m_spent_amounts_single_hash,
                      uint256S("a6ad32a03e35d509baa268e437ea28289d6d07529c6efd8"
                               "f1f7ced8ef2aba365"));
    BOOST_CHECK_EQUAL(txdata.m_spent_scripts_single_hash,
                      uint256S("abf93a5b45ba5cda5b1eb8bf2272c060127d390a6e020ba"
                               "a5345b6977e89ea3c"));
}

static const std::vector<uint32_t> allflags{
    SCRIPT_VERIFY_NONE,
    STANDARD_SCRIPT_VERIFY_FLAGS,
};

void CheckCodesepPos(const CScript &script,
                     const uint32_t expected_codesep_pos) {
    for (uint32_t flags : allflags) {
        BaseSignatureChecker sigchecker;
        ScriptExecutionMetrics metrics = {};
        ScriptExecutionData execdata{CScript()};
        stacktype stack = {};
        bool r =
            EvalScript(stack, script, flags, sigchecker, metrics, execdata);
        BOOST_CHECK(r);
        BOOST_CHECK_EQUAL(execdata.m_codeseparator_pos, expected_codesep_pos);
        BOOST_CHECK_MESSAGE(execdata.m_codeseparator_pos ==
                                expected_codesep_pos,
                            "For script '" << ScriptToAsmStr(script) << "'");
    }
}

BOOST_AUTO_TEST_CASE(script_execution_data) {
    valtype data10(10);
    valtype data520(520);
    // Test unconditional cases
    CheckCodesepPos(CScript() << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data10 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data520 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data10 << OP_1, 0);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data520 << OP_1, 0);
    CheckCodesepPos(CScript() << data520 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data10 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data520 << OP_1 << OP_CODESEPARATOR, 2);
    CheckCodesepPos(CScript() << data520 << data10 << OP_1 << OP_CODESEPARATOR,
                    3);
    CheckCodesepPos(CScript() << data520 << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                              << OP_NOP << OP_CODESEPARATOR,
                    6);

    // Test conditional cases
    CheckCodesepPos(CScript() << 0 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 0 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 1 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript()
                        << 1 << 1 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    6);
    CheckCodesepPos(CScript()
                        << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ELSE
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF,
                    9);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_CODESEPARATOR
                              << OP_IF << OP_IF << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF,
                    10);
}

BOOST_AUTO_TEST_SUITE_END()
