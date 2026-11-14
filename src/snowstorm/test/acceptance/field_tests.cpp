// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../oracle/field.h"
#include <snowstorm/gf64.h>
#include <array>
#include <limits>
#include <cerrno>
#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/types.h>
#include <sys/sysctl.h>
#elif defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

using namespace snowstorm_test;
namespace gf = snowstorm::gf64;
namespace oracle = snowstorm_oracle;
namespace {
struct HostCarrylessSupport {
    bool pmull{};
    bool pclmul{};
};
HostCarrylessSupport host_carryless_support() {
    // Deliberately independent of every production feature/dispatch function.
#if defined(__APPLE__) && defined(__aarch64__)
    int available = 0;
    std::size_t size = sizeof(available);
    const int result = sysctlbyname("hw.optional.arm.FEAT_PMULL", &available,
                                   &size, nullptr, 0);
    BOOST_REQUIRE_MESSAGE(result == 0, "PMULL capability sysctl failed: " << errno);
    BOOST_REQUIRE_EQUAL(size, sizeof(available));
    return {available != 0, false};
#elif defined(__linux__) && defined(__aarch64__)
    // Linux userspace ABI: AT_HWCAP/HWCAP_PMULL is the executable feature set.
    // https://kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html
    errno = 0;
    const auto hwcap = getauxval(AT_HWCAP);
    BOOST_REQUIRE_MESSAGE(errno == 0, "AT_HWCAP lookup failed: " << errno);
    return {(hwcap & HWCAP_PMULL) != 0, false};
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int registers[4]{};
    __cpuid(registers, 0);
    if (registers[0] < 1) return {};
    __cpuid(registers, 1);
    return {false, (registers[2] & (1 << 1)) != 0};
#elif defined(__x86_64__) || defined(__i386__)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return {};
    // CPUID.01H:ECX[1] is PCLMULQDQ. No AVX/XGETBV dependency for XMM form.
    return {false, (ecx & bit_PCLMUL) != 0};
#elif defined(__aarch64__) || defined(_M_ARM64)
    BOOST_FAIL("T1 requires an independent PMULL capability query on this OS");
    return {};
#else
    // Neither of the two specified hardware backends belongs to this ISA.
    return {};
#endif
}
} // namespace
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)

BOOST_AUTO_TEST_CASE(T1_field_million_pairs_and_inverses) {
    constexpr std::uint64_t seed = 0x7431000000000001ULL;
    constexpr std::size_t trials = 1'000'000;
    Rng rng(seed);
    BOOST_TEST_MESSAGE("T1 mul and inv seed=" << seed << " trials=" << trials);
    for (std::size_t i = 0; i < trials; ++i) {
        const auto a = rng.next();
        const auto b = rng.next();
        const auto expected = oracle::mul(a, b);
        BOOST_REQUIRE_EQUAL(gf::mul(a, b), expected);
        BOOST_REQUIRE_EQUAL(gf::mul_portable(a, b), expected);
        const auto x = rng.nonzero();
        const auto inverse = gf::inv(x);
        BOOST_REQUIRE(inverse.error == snowstorm::Error::ok);
        BOOST_REQUIRE_EQUAL(oracle::mul(inverse.value, x), 1U);
    }
    BOOST_REQUIRE(gf::inv(0).error == snowstorm::Error::zero_inverse);
}

BOOST_AUTO_TEST_CASE(T1_runtime_backend_conformance) {
    Rng rng(0x7431000000000002ULL);
    const auto host = host_carryless_support();
    BOOST_REQUIRE(gf::backend_available(gf::Backend::portable));
    BOOST_REQUIRE_EQUAL(gf::backend_available(gf::Backend::pmull), host.pmull);
    BOOST_REQUIRE_EQUAL(gf::backend_available(gf::Backend::pclmul), host.pclmul);
    const auto expected_backend = host.pmull ? gf::Backend::pmull :
                                  host.pclmul ? gf::Backend::pclmul : gf::Backend::portable;
    BOOST_REQUIRE(gf::backend() == expected_backend);
    BOOST_REQUIRE(gf::backend_available(gf::backend()));
    constexpr std::array backends{gf::Backend::portable, gf::Backend::pmull,
                                  gf::Backend::pclmul};
    for (const auto backend : backends) {
        if (!gf::backend_available(backend)) {
            std::uint64_t unchanged = 77;
            BOOST_REQUIRE(gf::mul_backend(backend, 2, 3, unchanged) ==
                          snowstorm::Error::invalid_argument);
            BOOST_REQUIRE_EQUAL(unchanged, 77U);
            continue;
        }
        for (std::size_t i = 0; i < 4096; ++i) {
            const auto a = rng.next();
            const auto b = rng.next();
            std::uint64_t actual = 0;
            BOOST_REQUIRE(gf::mul_backend(backend, a, b, actual) ==
                          snowstorm::Error::ok);
            BOOST_REQUIRE_EQUAL(actual, oracle::mul(a, b));
        }
    }
    // Polynomial hand checks: x^63*x=x^64=0x1b, and 3^2=5.
    BOOST_REQUIRE_EQUAL(gf::mul(std::uint64_t{1} << 63, 2), 0x1bU);
    BOOST_REQUIRE_EQUAL(gf::square(3), 5U);
}

BOOST_AUTO_TEST_CASE(T1_batch_inverse) {
    Rng rng(0x7431000000000003ULL);
    constexpr std::array<std::size_t, 9> sizes{1, 2, 3, 7, 16, 31, 64, 127, 257};
    for (const auto size : sizes) {
        std::vector<std::uint64_t> input(size), output(size), scratch(size);
        for (std::size_t trial = 0; trial < 128; ++trial) {
            std::generate(input.begin(), input.end(), [&] { return rng.nonzero(); });
            BOOST_REQUIRE(gf::batch_inv(input, output, scratch) == snowstorm::Error::ok);
            for (std::size_t i = 0; i < size; ++i) {
                BOOST_REQUIRE_EQUAL(output[i], gf::inv(input[i]).value);
                BOOST_REQUIRE_EQUAL(oracle::mul(output[i], input[i]), 1U);
            }
        }
        auto alias = input;
        BOOST_REQUIRE(gf::batch_inv(alias, alias, scratch) == snowstorm::Error::ok);
        BOOST_REQUIRE(alias == output);
        input[size / 2] = 0;
        const auto before = output;
        BOOST_REQUIRE(gf::batch_inv(input, output, scratch) == snowstorm::Error::zero_inverse);
        BOOST_REQUIRE(output == before);
        input[size / 2] = 1;
        BOOST_REQUIRE(gf::batch_inv(input, std::span(output).first(size - 1), scratch) ==
                      snowstorm::Error::capacity);
        BOOST_REQUIRE(output == before);
    }
    BOOST_REQUIRE(gf::batch_inv({}, {}, {}) == snowstorm::Error::ok);
}

BOOST_AUTO_TEST_CASE(T1_million_distinct_pair_solves) {
    constexpr std::uint64_t seed = 0x7431000000000004ULL;
    Rng rng(seed);
    for (std::size_t trial = 0; trial < 1'000'000; ++trial) {
        const auto a = rng.nonzero();
        auto b = rng.nonzero();
        while (b == a) b = rng.nonzero();
        const auto cube_a = oracle::mul(oracle::mul(a, a), a);
        const auto cube_b = oracle::mul(oracle::mul(b, b), b);
        const auto solved = gf::solve_pair(a ^ b, cube_a ^ cube_b);
        BOOST_REQUIRE(solved.solvable);
        BOOST_REQUIRE_EQUAL(solved.roots[0], std::min(a, b));
        BOOST_REQUIRE_EQUAL(solved.roots[1], std::max(a, b));
    }
}

BOOST_AUTO_TEST_CASE(T1_million_each_trace_class) {
    constexpr std::uint64_t theta = std::uint64_t{1} << 61;
    constexpr std::uint64_t seed = 0x7431000000000005ULL;
    Rng rng(seed);
    BOOST_REQUIRE_EQUAL(oracle::trace(theta), 1U);
    // y -> y^2+y is a two-to-one linear map onto the trace-zero subspace.
    // Uniform y therefore yields uniform trace-zero D. XOR with trace-one theta
    // is a bijection onto trace-one D: no production trace/solve classifies data.
    for (std::size_t trial = 0; trial < 1'000'000; ++trial) {
        const auto y = rng.next();
        const auto d0 = oracle::mul(y, y) ^ y;
        const auto d1 = d0 ^ theta;
        const auto yes = gf::solve(d0);
        const auto no = gf::solve(d1);
        BOOST_REQUIRE(yes.solvable);
        BOOST_REQUIRE(oracle::verifies_root(d0, yes.value));
        BOOST_REQUIRE(!no.solvable);
        BOOST_REQUIRE_EQUAL(gf::trace(d0), 0U);
        BOOST_REQUIRE_EQUAL(gf::trace(d1), 1U);
    }
    const auto zero = gf::solve(0);
    BOOST_REQUIRE(zero.solvable);
    BOOST_REQUIRE_EQUAL(zero.value, 0U);
    for (unsigned bit = 0; bit < 64; ++bit) {
        const auto basis = std::uint64_t{1} << bit;
        BOOST_REQUIRE_EQUAL(gf::trace(basis), oracle::trace(basis));
    }
}
BOOST_AUTO_TEST_SUITE_END()
