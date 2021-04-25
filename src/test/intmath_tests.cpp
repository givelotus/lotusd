#include <util/intmath.h>

#include <cmath>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

BOOST_FIXTURE_TEST_SUITE(intmath_tests, BasicTestingSetup)

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
