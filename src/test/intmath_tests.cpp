// Copyright (c) 2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <test/lcg.h>
#include <test/util/setup_common.h>
#include <util/intmath.h>
#include <script/intmath.h>

#include <cmath>

#include <boost/test/unit_test.hpp>
#include <boost/multiprecision/cpp_int.hpp>

BOOST_FIXTURE_TEST_SUITE(intmath_tests, BasicTestingSetup)

using i128_t = boost::multiprecision::checked_int128_t;

const i128_t MAX_SCRIPT_63_BIT_INT = 0x7fff'ffff'ffff'ffff;
const i128_t MIN_SCRIPT_63_BIT_INT = -0x7fff'ffff'ffff'ffff;

const static std::vector<int64_t> INTERESTING_63_BIT_NUMBERS({
    0,
    1,
    -1,
    2,
    -2,
    4,
    -4,
    10,
    -10,
    100,
    -100,
    127,
    -127,
    255,
    -255,
    256,
    -256,
    1000,
    -1000,
    5040,
    -5040,
    0x7fff,
    -0x7fff,
    0x1'0000,
    -0x1'0000,
    0x7f'ffff,
    -0x7f'ffff,
    0x100'0000,
    -0x100'0000,
    0x7fff'ffff,
    -0x7fff'ffff,
    0xffff'ffff,
    -0xffff'ffff,
    0x1'0000'0000,
    -0x1'0000'0000,
    0x7f'ffff'ffff,
    -0x7f'ffff'ffff,
    0xff'ffff'ffff,
    -0xff'ffff'ffff,
    0x100'0000'0000,
    -0x100'0000'0000,
    0x7fff'ffff'ffff,
    -0x7fff'ffff'ffff,
    0xffff'ffff'ffff,
    -0xffff'ffff'ffff,
    0x1'0000'0000'0000,
    -0x1'0000'0000'0000,
    0x7f'ffff'ffff'ffff,
    -0x7f'ffff'ffff'ffff,
    0xff'ffff'ffff'ffff,
    -0xff'ffff'ffff'ffff,
    0x100'0000'0000'0000,
    -0x100'0000'0000'0000,
    0x7fff'ffff'ffff'ffff,
    -0x7fff'ffff'ffff'ffff,
});

bool IsInScriptBounds(const i128_t &num_int) {
    return num_int >= MIN_SCRIPT_63_BIT_INT && num_int <= MAX_SCRIPT_63_BIT_INT;
}

void CheckArithmeticResult(std::string operation_str, bool expect_overflow,
                           bool had_overflow, int64_t result,
                           i128_t expected_result) {
    if (expect_overflow) {
        BOOST_CHECK_MESSAGE(had_overflow,
                            strprintf("%s didn't overflow", operation_str));
    } else {
        BOOST_CHECK_MESSAGE(!had_overflow,
                            strprintf("%s overflowed", operation_str));
        BOOST_CHECK_EQUAL(result, expected_result);
    }
}

void CheckArithmetic(const int64_t a_64, const int64_t b_64) {
    const i128_t a = a_64;
    const i128_t b = b_64;
    {
        bool expect_overflow = !IsInScriptBounds(a + b);
        // Test AddInt63OverflowEmulated
        int64_t result_emulated = uint64_t(1) + a_64 + b_64;
        bool had_overflow_emulated =
            AddInt63OverflowEmulated(a_64, b_64, result_emulated);
        CheckArithmeticResult(strprintf("%d + %d", a, b), expect_overflow,
                              had_overflow_emulated, result_emulated, a + b);
        // Test AddInt63Overflow
        int64_t result;
        bool had_overflow = AddInt63Overflow(a_64, b_64, result);
        CheckArithmeticResult(strprintf("%d + %d", a, b), expect_overflow,
                              had_overflow_emulated, result_emulated, a + b);
        if (!expect_overflow) {
            BOOST_CHECK_EQUAL(result, result_emulated);
        }
        BOOST_CHECK_EQUAL(had_overflow, had_overflow_emulated);
    }
    {
        bool expect_overflow = !IsInScriptBounds(a - b);
        // Test SubInt63OverflowEmulated
        int64_t result_emulated = uint64_t(1) + a_64 - b_64;
        bool had_overflow_emulated =
            SubInt63OverflowEmulated(a_64, b_64, result_emulated);
        CheckArithmeticResult(strprintf("%d - %d", a, b), expect_overflow,
                              had_overflow_emulated, result_emulated, a - b);
        // Test SubInt63Overflow
        int64_t result;
        bool had_overflow = SubInt63Overflow(a_64, b_64, result);
        CheckArithmeticResult(strprintf("%d - %d", a, b), expect_overflow,
                              had_overflow_emulated, result_emulated, a - b);
        if (!expect_overflow) {
            BOOST_CHECK_EQUAL(result, result_emulated);
        }
        BOOST_CHECK_EQUAL(had_overflow, had_overflow_emulated);
    }
}

/** Generate random number in [-2^63; 2^63]. */
int64_t GenInt63(MMIXLinearCongruentialGenerator &lcg) {
    while (true) {
        // Uniform number in [-2^63; 2^63].
        int64_t val = (int64_t(lcg.next()) << 32) | lcg.next();
        // Make bit-length uniformly distributed for better test coverage.
        val >>= (lcg.next() % 64);
        // Ensure value is in bounds.
        if (val != std::numeric_limits<int64_t>::min()) {
            return val;
        }
    }
}

BOOST_AUTO_TEST_CASE(check_arithmetic) {
    MMIXLinearCongruentialGenerator lcg;
    for (uint32_t test = 0; test < 2048; ++test) {
        int64_t a = GenInt63(lcg);
        int64_t b = GenInt63(lcg);
        CheckArithmetic(a, b);
        for (const int64_t &num : INTERESTING_63_BIT_NUMBERS) {
            CheckArithmetic(a, num);
            CheckArithmetic(num, b);
        }
    }
    for (const int64_t &a : INTERESTING_63_BIT_NUMBERS) {
        for (const int64_t &b : INTERESTING_63_BIT_NUMBERS) {
            CheckArithmetic(a, b);
        }
    }
}

BOOST_AUTO_TEST_CASE(log2fixedpoint_tests) {
    struct TestCase {
        uint32_t x;
        size_t prec;
        int32_t expect;
        double error;
    };
    std::vector<TestCase> test_cases = {
        {.x = 256, .prec = 1, .expect = 14, .error = 0.0},
        {.x = 512, .prec = 2, .expect = 28, .error = 0.0},
        {.x = 1024, .prec = 3, .expect = 56, .error = 0.0},
        {.x = 1, .prec = 1, .expect = -2, .error = 0.0},
        {.x = 2, .prec = 1, .expect = 0, .error = 0.0},
        {.x = 3, .prec = 1, .expect = 1, .error = 0.09},
        {.x = 4, .prec = 1, .expect = 2, .error = 0.0},
        {.x = 1, .prec = 2, .expect = -8, .error = 0.0},
        {.x = 2, .prec = 2, .expect = -4, .error = 0.0},
        {.x = 3, .prec = 2, .expect = -2, .error = 0.09},
        {.x = 4, .prec = 2, .expect = 0, .error = 0.0},
        {.x = 1, .prec = 3, .expect = -24, .error = 0.0},
        {.x = 2, .prec = 3, .expect = -16, .error = 0.0},
        {.x = 3, .prec = 3, .expect = -12, .error = 0.09},
        {.x = 4, .prec = 3, .expect = -8, .error = 0.0},
        {.x = 1'000, .prec = 8, .expect = 502, .error = 0.01},
        {.x = 10'000, .prec = 8, .expect = 1352, .error = 0.01},
        {.x = 100'000, .prec = 8, .expect = 2203, .error = 0.01},
        {.x = 1'000'000, .prec = 8, .expect = 3053, .error = 0.01},
        {.x = 10'000'000, .prec = 8, .expect = 3904, .error = 0.01},
        {.x = 100'000'000, .prec = 8, .expect = 4754, .error = 0.01},
        {.x = 1'000'000'000, .prec = 8, .expect = 5604, .error = 0.01},
        {.x = 0x7fff'ffff, .prec = 8, .expect = 5887, .error = 0.01},
        {.x = 0xffff'ffffU, .prec = 8, .expect = 6143, .error = 0.01},
        {.x = 1'000, .prec = 16, .expect = -395459, .error = 0.0001},
        {.x = 10'000, .prec = 16, .expect = -177753, .error = 0.0001},
        {.x = 100'000, .prec = 16, .expect = 39952, .error = 0.0001},
        {.x = 1'000'000, .prec = 16, .expect = 257658, .error = 0.0001},
        {.x = 10'000'000, .prec = 16, .expect = 475364, .error = 0.0001},
        {.x = 100'000'000, .prec = 16, .expect = 693070, .error = 0.0001},
        {.x = 1'000'000'000, .prec = 16, .expect = 910776, .error = 0.0001},
        {.x = 0x7fff'ffff, .prec = 16, .expect = 983039, .error = 0.0001},
        {.x = 0xffff'ffffU, .prec = 16, .expect = 1048575, .error = 0.0001},
    };
    for (auto &test_case : test_cases) {
        int32_t log = Log2FixedPoint(test_case.x, test_case.prec);
        double factor = 1U << test_case.prec;
        double actual = log / factor;
        double expected = log2(test_case.x / factor);
        BOOST_CHECK(abs(actual - expected) <= test_case.error);
        BOOST_CHECK_EQUAL(log, test_case.expect);
    }
}

BOOST_AUTO_TEST_SUITE_END()
