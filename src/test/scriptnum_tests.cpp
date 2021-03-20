// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <test/lcg.h>
#include <test/util/setup_common.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(scriptnum_tests, BasicTestingSetup)

typedef boost::multiprecision::checked_int128_t i128_t;
typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

const i128_t MAX_SCRIPT_INT = 0x7fff'ffff'ffff'ffff;
const i128_t MIN_SCRIPT_INT = -0x7fff'ffff'ffff'ffff;
const static std::vector<uint32_t> flaglist({
    SCRIPT_VERIFY_NONE,
    STANDARD_SCRIPT_VERIFY_FLAGS,
    MANDATORY_SCRIPT_VERIFY_FLAGS,
});
const static std::vector<valtype> interesting_numbers({
    {}, // 0
    {1},
    {0x81}, // -1
    {2},
    {0x82}, // -2
    {4},
    {0x84}, // -4
    {10},
    {0x8a}, // -10
    {100},
    {0xe4}, // -100
    {127},
    {0xff},       // -127
    {0, 1},       // 256
    {0, 0x81},    // -256
    {0xe8, 0x03}, // 1000
    {0xe8, 0x83}, // -1000
    {0xb0, 0x13}, // 5040
    {0xb0, 0x93}, // -5040
    {0xff, 0x7f},
    {0xff, 0xff},
    {0x00, 0x00, 0x01},
    {0x00, 0x00, 0x81},
    {0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x81},
    {0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x81},
    {0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x81},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // invalid numbers
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81}, // vvvvvvvvvvvvvvv
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
});

static i128_t ToInt128(const valtype &vch) {
    if (vch.empty()) {
        return 0;
    }

    i128_t result = 0;
    for (size_t i = 0; i < vch.size(); ++i) {
        if (i == vch.size() - 1 && vch[i] & 0x80) {
            result |= i128_t(vch[i] & 0x7f) << (8 * i);
            return -result;
        }
        result |= i128_t(vch[i]) << (8 * i);
    }

    return result;
}

static valtype FromInt128(const i128_t &value) {
    if (value == 0) {
        return {};
    }

    valtype result;
    const bool neg = value < 0;
    i128_t absvalue = neg ? -value : value;

    while (absvalue) {
        result.push_back(uint8_t(absvalue & 0xff));
        absvalue >>= 8;
    }

    if (result.back() & 0x80) {
        result.push_back(neg ? 0x80 : 0);
    } else if (neg) {
        result.back() |= 0x80;
    }
    return result;
}

static bool IsInScriptBounds(const i128_t &num_int) {
    return num_int >= MIN_SCRIPT_INT && num_int <= MAX_SCRIPT_INT;
}

static bool AnyOverflows(const stacktype &stack) {
    for (const valtype &stackitem : stack) {
        if (stackitem.size() > CScriptNum::MAXIMUM_ELEMENT_SIZE) {
            return true;
        }
    }
    return false;
}

static void CheckErrorOrOverflow(const stacktype &original_stack,
                                 const opcodetype opcode,
                                 const ScriptError expected_error) {
    CScript script = CScript() << opcode;
    BaseSignatureChecker sigchecker;
    ScriptError err = ScriptError::OK;
    bool inputs_overflow = AnyOverflows(original_stack);
    for (uint32_t flags : flaglist) {
        stacktype stack{original_stack};
        bool r = EvalScript(stack, script, flags, sigchecker, &err);
        BOOST_CHECK(!r);
        if (inputs_overflow) {
            // Overflow
            BOOST_CHECK_EQUAL(err, ScriptError::UNKNOWN);
        } else {
            BOOST_CHECK_EQUAL(err, expected_error);
        }
    }
}

static void CheckPassOrOverflow(const stacktype &original_stack,
                                const opcodetype opcode,
                                const i128_t &expected_int) {
    CScript script = CScript() << opcode;
    BaseSignatureChecker sigchecker;
    ScriptError err = ScriptError::OK;
    bool inputs_overflow = AnyOverflows(original_stack);
    for (uint32_t flags : flaglist) {
        stacktype stack{original_stack};
        bool r = EvalScript(stack, script, flags, sigchecker, &err);
        if (inputs_overflow || !IsInScriptBounds(expected_int)) {
            // Overflow
            BOOST_CHECK(!r);
            BOOST_CHECK_EQUAL(err, ScriptError::UNKNOWN);
        } else {
            valtype result_script = FromInt128(expected_int);
            stacktype expected({result_script});
            BOOST_CHECK(r);
            BOOST_CHECK_EQUAL(err, ScriptError::OK);
            BOOST_CHECK(stack == expected);
        }
    }
}

static void CheckOperators(const valtype &a_i63, const valtype &b_i63) {
    i128_t a_i128 = ToInt128(a_i63);
    i128_t b_i128 = ToInt128(b_i63);
    CheckPassOrOverflow({a_i63}, OP_1ADD, a_i128 + 1);
    CheckPassOrOverflow({a_i63}, OP_1SUB, a_i128 - 1);
    CheckPassOrOverflow({a_i63}, OP_NEGATE, -a_i128);
    CheckPassOrOverflow({a_i63}, OP_ABS, boost::multiprecision::abs(a_i128));
    CheckPassOrOverflow({a_i63}, OP_NOT, !a_i128);
    CheckPassOrOverflow({a_i63}, OP_0NOTEQUAL, a_i128 != 0);
    CheckPassOrOverflow({a_i63, b_i63}, OP_ADD, a_i128 + b_i128);
    CheckPassOrOverflow({b_i63, a_i63}, OP_ADD, a_i128 + b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_SUB, a_i128 - b_i128);
    if (b_i128 != 0) {
        CheckPassOrOverflow({a_i63, b_i63}, OP_DIV, a_i128 / b_i128);
        CheckPassOrOverflow({a_i63, b_i63}, OP_MOD, a_i128 % b_i128);
    } else {
        CheckErrorOrOverflow({a_i63, b_i63}, OP_DIV, ScriptError::DIV_BY_ZERO);
        CheckErrorOrOverflow({a_i63, b_i63}, OP_MOD, ScriptError::MOD_BY_ZERO);
    }
    CheckPassOrOverflow({a_i63, b_i63}, OP_BOOLAND, a_i128 && b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_BOOLOR, a_i128 || b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_LESSTHAN, a_i128 < b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_GREATERTHAN, a_i128 > b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_LESSTHANOREQUAL, a_i128 <= b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_GREATERTHANOREQUAL,
                        a_i128 >= b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_MIN,
                        a_i128 < b_i128 ? a_i128 : b_i128);
    CheckPassOrOverflow({a_i63, b_i63}, OP_MAX,
                        a_i128 < b_i128 ? b_i128 : a_i128);
}

static void CheckTernary(const valtype &a_i63, const valtype &b_i63,
                         const valtype &c_i63) {
    i128_t a_i128 = ToInt128(a_i63);
    i128_t b_i128 = ToInt128(b_i63);
    i128_t c_i128 = ToInt128(c_i63);
    CheckPassOrOverflow({a_i63, b_i63, c_i63}, OP_WITHIN,
                        a_i128 >= b_i128 && a_i128 < c_i128);
    CheckPassOrOverflow({a_i63, c_i63, b_i63}, OP_WITHIN,
                        a_i128 >= c_i128 && a_i128 < b_i128);
    CheckPassOrOverflow({b_i63, c_i63, a_i63}, OP_WITHIN,
                        b_i128 >= c_i128 && b_i128 < a_i128);
    CheckPassOrOverflow({b_i63, a_i63, c_i63}, OP_WITHIN,
                        b_i128 >= a_i128 && b_i128 < c_i128);
    CheckPassOrOverflow({c_i63, a_i63, b_i63}, OP_WITHIN,
                        c_i128 >= a_i128 && c_i128 < b_i128);
    CheckPassOrOverflow({c_i63, b_i63, a_i63}, OP_WITHIN,
                        c_i128 >= b_i128 && c_i128 < a_i128);
}

BOOST_AUTO_TEST_CASE(num_arithmetic_test) {
    MMIXLinearCongruentialGenerator lcg;
    for (uint32_t test = 0; test < 2048; ++test) {
        uint32_t a_len = lcg.next() % 11; // generate numbers 0-10 bytes len
        uint32_t b_len = lcg.next() % 11;
        uint32_t c_len = lcg.next() % 11;
        valtype a_i63(a_len), b_i63(b_len), c_i63(c_len);
        for (uint32_t i = 0; i < a_len; ++i) {
            a_i63[i] = lcg.next() % 256;
        }
        for (uint32_t i = 0; i < b_len; ++i) {
            b_i63[i] = lcg.next() % 256;
        }
        for (uint32_t i = 0; i < c_len; ++i) {
            c_i63[i] = lcg.next() % 256;
        }
        CScriptNum::MinimallyEncode(a_i63);
        CScriptNum::MinimallyEncode(b_i63);
        CScriptNum::MinimallyEncode(c_i63);
        CheckOperators(a_i63, a_i63);
        CheckOperators(a_i63, b_i63);
        CheckOperators(b_i63, a_i63);
        CheckOperators(b_i63, b_i63);
        CheckTernary(a_i63, b_i63, c_i63);
        if (test < 256) {
            for (const valtype &interesting_num : interesting_numbers) {
                CheckOperators(a_i63, interesting_num);
                CheckOperators(interesting_num, a_i63);
                CheckOperators(b_i63, interesting_num);
                CheckOperators(interesting_num, b_i63);
            }
        }
    }
    for (const valtype &a_i63 : interesting_numbers) {
        CheckOperators(a_i63, a_i63);
        for (const valtype &b_i63 : interesting_numbers) {
            CheckOperators(a_i63, b_i63);
            for (const valtype &c_i63 : interesting_numbers) {
                CheckTernary(a_i63, b_i63, c_i63);
            }
        }
    }
}

static void CheckMinimalyEncode(std::vector<uint8_t> data,
                                const std::vector<uint8_t> &expected) {
    bool alreadyEncoded = CScriptNum::IsMinimallyEncoded(data, data.size());
    bool hasEncoded = CScriptNum::MinimallyEncode(data);
    BOOST_CHECK_EQUAL(hasEncoded, !alreadyEncoded);
    BOOST_CHECK(data == expected);
}

BOOST_AUTO_TEST_CASE(minimize_encoding_test) {
    CheckMinimalyEncode({}, {});

    // Check that positive and negative zeros encode to nothing.
    std::vector<uint8_t> zero, negZero;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++) {
        zero.push_back(0x00);
        CheckMinimalyEncode(zero, {});

        negZero.push_back(0x80);
        CheckMinimalyEncode(negZero, {});

        // prepare for next round.
        negZero[negZero.size() - 1] = 0x00;
    }

    // Keep one leading zero when sign bit is used.
    std::vector<uint8_t> n{0x80, 0x00}, negn{0x80, 0x80};
    std::vector<uint8_t> npadded = n, negnpadded = negn;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++) {
        CheckMinimalyEncode(npadded, n);
        npadded.push_back(0x00);

        CheckMinimalyEncode(negnpadded, negn);
        negnpadded[negnpadded.size() - 1] = 0x00;
        negnpadded.push_back(0x80);
    }

    // Mege leading byte when sign bit isn't used.
    std::vector<uint8_t> k{0x7f}, negk{0xff};
    std::vector<uint8_t> kpadded = k, negkpadded = negk;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++) {
        CheckMinimalyEncode(kpadded, k);
        kpadded.push_back(0x00);

        CheckMinimalyEncode(negkpadded, negk);
        negkpadded[negkpadded.size() - 1] &= 0x7f;
        negkpadded.push_back(0x80);
    }
}

BOOST_AUTO_TEST_SUITE_END()
