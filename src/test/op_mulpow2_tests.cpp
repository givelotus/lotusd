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

BOOST_FIXTURE_TEST_SUITE(op_mulpow2_tests, BasicTestingSetup)

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;
std::array<uint32_t, 2> flagset{{0, STANDARD_SCRIPT_VERIFY_FLAGS}};
std::vector<int64_t> interesting_numbers = {
    0,
    1,
    -1,
    2,
    -2,
    4,
    -4,
    10,
    -10,
    127,
    -127,
    256,
    -256,
    0x7fffffff,
    -0x7fffffff,
    0x100000000,
    -0x100000000,
    0x7fffffffff,
    -0x7fffffffff,
    0x10000000000,
    -0x10000000000,
    0x7fffffffffffff,
    -0x7fffffffffffff,
    0x100000000000000,
    -0x100000000000000,
    0x7fffffffffffffff,
    -0x7fffffffffffffff,
};

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

static bool Pow2(int64_t base, int64_t exponent, int64_t &result) {
    constexpr int64_t LIMIT = 0x4000'0000'0000'0000;
    result = base;
    if (base == 0) {
        return true;
    }
    if (exponent > 0) {
        for (int64_t i = 0; i < exponent; ++i) {
            if (result >= LIMIT || result <= -LIMIT) {
                return false;
            }
            result *= 2;
        }
    } else if (exponent < 0) {
        for (int64_t i = 0; i < -exponent; ++i) {
            result /= 2;
            if (result == 0) {
                return true;
            }
        }
    }
    return true;
}

static void CheckTestI64Shift(int64_t base, int32_t exponent) {
    int64_t result;
    if (Pow2(base, exponent, result)) {
        CheckSuccess(CScript()
                     << base << exponent << OP_MULPOW2 << result << OP_EQUAL);
    } else {
        CheckError(CScript() << base << exponent << OP_MULPOW2 << OP_1,
                   ScriptError::UNKNOWN);
    }
}

BOOST_AUTO_TEST_CASE(rng_shift_test) {
    MMIXLinearCongruentialGenerator lcg;
    for (int test = 0; test < 20; ++test) {
        uint64_t num = lcg.next();
        num <<= 32;
        num |= lcg.next();
        const int64_t base = int64_t(num);
        for (int64_t i = 0; i <= 63; ++i) {
            CheckTestI64Shift(base, i);
        }
    }
}

BOOST_AUTO_TEST_CASE(interesting_numbers_test) {
    for (int64_t base : interesting_numbers) {
        for (int64_t exponent : interesting_numbers) {
            CheckTestI64Shift(base, exponent);
        }
        for (int64_t exponent = 0; exponent <= 63; ++exponent) {
            CheckTestI64Shift(base, exponent);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
