// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <test/lcg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <core_io.h>

BOOST_FIXTURE_TEST_SUITE(op_loop_tests, BasicTestingSetup)

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;
std::array<uint32_t, 1> flagset{
    {STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MITRA}};

static void CheckSuccess(const CScript &script) {
    BaseSignatureChecker sigchecker;
    for (uint32_t flags : flagset) {
        ScriptError err = ScriptError::OK;
        stacktype stack{};
        bool r = EvalScript(stack, script, flags, sigchecker, &err);
        BOOST_CHECK_MESSAGE(r, "Expected OK but got "
                                   << ScriptErrorString(err) << " for '"
                                   << ScriptToAsmStr(script) << "'");
    }
}

static void CheckError(const CScript &script,
                       const ScriptError expected_error) {
    BaseSignatureChecker sigchecker;
    for (uint32_t flags : flagset) {
        ScriptError err = ScriptError::OK;
        stacktype stack{};
        bool r = EvalScript(stack, script, flags, sigchecker, &err);
        BOOST_CHECK_MESSAGE(
            !r, "Expected " << ScriptErrorString(expected_error) << " but got "
                            << ScriptErrorString(err) << " for '"
                            << ScriptToAsmStr(script) << "'");
        BOOST_CHECK_EQUAL(err, expected_error);
    }
}

BOOST_AUTO_TEST_CASE(simple_loops_test) {
    // do {} while(false);
    CheckSuccess(CScript() << OP_LOOP << OP_0 << OP_ENDLOOP << OP_1);
    // int i; for (i = 0; i < 10; ++i);
    CheckSuccess(CScript() << OP_0 << OP_LOOP << OP_1ADD << OP_DUP << OP_10
                           << OP_LESSTHAN << OP_ENDLOOP << OP_10
                           << OP_EQUALVERIFY);
    // int i; for (i = 0; i < 10; ++i) { int j; for (j = 0; j < 3; ++j); }
    CheckSuccess(CScript() << OP_0 << OP_LOOP << OP_1ADD << OP_0 << OP_LOOP
                           << OP_1ADD << OP_DUP << OP_3 << OP_LESSTHAN
                           << OP_ENDLOOP << OP_3 << OP_EQUALVERIFY << OP_DUP
                           << OP_10 << OP_LESSTHAN << OP_ENDLOOP << OP_10
                           << OP_EQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(loops_error_test) {
    CheckError(CScript() << OP_ENDLOOP, ScriptError::UNBALANCED_LOOP);
    CheckError(CScript() << OP_LOOP << OP_ENDLOOP,
               ScriptError::INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_SUITE_END()
