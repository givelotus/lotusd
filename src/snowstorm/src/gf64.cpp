// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/gf64.h>

#include "field_tables.h"

#include <algorithm>
#include <array>
#include <cstdint>

#if defined(__aarch64__)
#include <arm_neon.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <wmmintrin.h>
#endif

namespace snowstorm::gf64 {
namespace {
using detail::FIELD_BITS;
using detail::REDUCTION;
constexpr unsigned WINDOW_BITS = 4;
constexpr unsigned WINDOW_ENTRIES = 1U << WINDOW_BITS;
constexpr unsigned TOP_WINDOW = FIELD_BITS - WINDOW_BITS;

// x^64 = x^4+x^3+x+1. Fold high once, then its at most four overflow
// bits once more. These ordinary shifts/XORs reduce a carry-less product.
std::uint64_t reduce_product(std::uint64_t low, std::uint64_t high) noexcept {
    const auto overflow = (high >> (FIELD_BITS - 4)) ^
                          (high >> (FIELD_BITS - 3)) ^
                          (high >> (FIELD_BITS - 1));
    low ^= high ^ (high << 1) ^ (high << 3) ^ (high << 4);
    return low ^ overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
}

#if defined(__aarch64__)
__attribute__((target("aes")))
std::uint64_t mul_pmull(std::uint64_t a, std::uint64_t b) noexcept {
    const auto product = vmull_p64(a, b);
    const auto words = vreinterpretq_u64_p128(product);
    return reduce_product(vgetq_lane_u64(words, 0), vgetq_lane_u64(words, 1));
}
#elif defined(__x86_64__) || defined(__i386__)
__attribute__((target("pclmul,sse2")))
std::uint64_t mul_pclmul(std::uint64_t a, std::uint64_t b) noexcept {
    const auto left = _mm_set_epi64x(0, static_cast<long long>(a));
    const auto right = _mm_set_epi64x(0, static_cast<long long>(b));
    const auto product = _mm_clmulepi64_si128(left, right, 0);
    const auto low = static_cast<std::uint64_t>(_mm_cvtsi128_si64(product));
    const auto high = static_cast<std::uint64_t>(
        _mm_cvtsi128_si64(_mm_srli_si128(product, 8)));
    return reduce_product(low, high);
}
#endif

bool has_pmull() noexcept {
#if defined(__aarch64__) && defined(__APPLE__)
    int available = 0;
    std::size_t size = sizeof(available);
    return sysctlbyname("hw.optional.arm.FEAT_PMULL", &available, &size,
                       nullptr, 0) == 0 && size == sizeof(available) && available;
#elif defined(__aarch64__) && defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_PMULL) != 0;
#else
    return false;
#endif
}

bool has_pclmul() noexcept {
#if defined(__x86_64__) || defined(__i386__)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    return __get_cpuid(1, &eax, &ebx, &ecx, &edx) != 0 &&
           (ecx & bit_PCLMUL) != 0;
#else
    return false;
#endif
}

Backend detected_backend() noexcept {
    if (has_pmull()) return Backend::pmull;
    if (has_pclmul()) return Backend::pclmul;
    return Backend::portable;
}

using Multiply = std::uint64_t (*)(std::uint64_t, std::uint64_t) noexcept;
Multiply selected_multiply() noexcept {
#if defined(__aarch64__)
    if (backend() == Backend::pmull) return mul_pmull;
#elif defined(__x86_64__) || defined(__i386__)
    if (backend() == Backend::pclmul) return mul_pclmul;
#endif
    return mul_portable;
}

std::uint64_t repeated_square(std::uint64_t value, unsigned count) noexcept {
    for (unsigned i = 0; i < count; ++i) value = square(value);
    return value;
}

bool spans_overlap(std::span<const std::uint64_t> a,
                   std::span<const std::uint64_t> b) noexcept {
    if (a.empty() || b.empty()) return false;
    const auto left = reinterpret_cast<std::uintptr_t>(a.data());
    const auto right = reinterpret_cast<std::uintptr_t>(b.data());
    // Difference comparisons avoid end-pointer arithmetic overflow.
    if (left <= right) return right - left < a.size_bytes();
    return left - right < b.size_bytes();
}
} // namespace

Backend backend() noexcept {
    // Immutable CPU capability, not mutable protocol state or a test override.
    static const Backend selected = detected_backend();
    return selected;
}

bool backend_available(Backend candidate) noexcept {
    if (candidate == Backend::portable) return true;
    if (candidate == Backend::pmull) return has_pmull();
    if (candidate == Backend::pclmul) return has_pclmul();
    return false;
}

std::uint64_t mul(std::uint64_t a, std::uint64_t b) noexcept {
    static const Multiply multiply = selected_multiply();
    return multiply(a, b);
}

Error mul_backend(Backend candidate, std::uint64_t a, std::uint64_t b,
                  std::uint64_t &out) noexcept {
    if (!backend_available(candidate)) return Error::invalid_argument;
#if defined(__aarch64__)
    if (candidate == Backend::pmull) {
        out = mul_pmull(a, b);
        return Error::ok;
    }
#elif defined(__x86_64__) || defined(__i386__)
    if (candidate == Backend::pclmul) {
        out = mul_pclmul(a, b);
        return Error::ok;
    }
#endif
    out = mul_portable(a, b);
    return Error::ok;
}

std::uint64_t mul_portable(std::uint64_t a, std::uint64_t b) noexcept {
    std::array<std::uint64_t, WINDOW_ENTRIES> multiples{};
    for (unsigned bit = 1; bit < WINDOW_ENTRIES; bit <<= 1) {
        for (unsigned entry = 0; entry < bit; ++entry)
            multiples[entry | bit] = multiples[entry] ^ a;
        a = (a << 1) ^ ((a >> (FIELD_BITS - 1)) * REDUCTION);
    }
    std::uint64_t product = 0;
    for (unsigned remaining = FIELD_BITS; remaining != 0; remaining -= WINDOW_BITS) {
        const auto carry = product >> TOP_WINDOW;
        product = (product << WINDOW_BITS) ^ carry ^ (carry << 1) ^
                  (carry << 3) ^ (carry << 4);
        product ^= multiples[(b >> (remaining - WINDOW_BITS)) & (WINDOW_ENTRIES - 1)];
    }
    return product;
}

std::uint64_t square(std::uint64_t x) noexcept {
    return detail::apply_table(detail::SQUARE_TABLE, x);
}

InverseResult inv(std::uint64_t x) noexcept {
    if (x == 0) return {Error::zero_inverse, 0};
    // Itoh–Tsujii: beta_k=x^(2^k-1). Build k=1,2,4,8,16,32,
    // then concatenate 16,8,4,2,1 to reach beta_63 and square once.
    constexpr std::array<unsigned, 5> lengths{1, 2, 4, 8, 16};
    std::array<std::uint64_t, lengths.size() + 1> powers{};
    powers[0] = x;
    for (std::size_t i = 0; i < lengths.size(); ++i)
        powers[i + 1] = mul(repeated_square(powers[i], lengths[i]), powers[i]);
    auto result = powers.back();
    for (std::size_t i = lengths.size(); i != 0; --i)
        result = mul(repeated_square(result, lengths[i - 1]), powers[i - 1]);
    return {Error::ok, square(result)};
}

Error batch_inv(std::span<const std::uint64_t> input,
                std::span<std::uint64_t> output,
                std::span<std::uint64_t> scratch) noexcept {
    if (output.size() < input.size() || scratch.size() < input.size())
        return Error::capacity;
    if (input.empty()) return Error::ok;
    const auto destination = output.first(input.size());
    const auto workspace = scratch.first(input.size());
    if (spans_overlap(input, workspace) || spans_overlap(destination, workspace) ||
        (input.data() != destination.data() && spans_overlap(input, destination)))
        return Error::invalid_argument;
    if (std::find(input.begin(), input.end(), 0) != input.end())
        return Error::zero_inverse;
    std::uint64_t product = 1;
    for (std::size_t i = 0; i < input.size(); ++i) {
        workspace[i] = product;
        product = mul(product, input[i]);
    }
    auto inverse = inv(product).value;
    for (std::size_t i = input.size(); i != 0; --i) {
        const auto original = input[i - 1];
        destination[i - 1] = mul(inverse, workspace[i - 1]);
        inverse = mul(inverse, original);
    }
    return Error::ok;
}

std::uint8_t trace(std::uint64_t x) noexcept {
    // Newton sums for x^64+x^4+x^3+x+1: among the basis powers
    // x^0..x^63, only x^61 and x^63 have nonzero absolute trace.
    return static_cast<std::uint8_t>(
        ((x >> (FIELD_BITS - 3)) ^ (x >> (FIELD_BITS - 1))) & 1);
}

SolveResult solve(std::uint64_t d) noexcept {
    if (trace(d) != 0) return {false, 0};
    const auto root = detail::apply_table(detail::SOLVE_TABLE, d);
    if ((square(root) ^ root) != d) return {false, 0};
    return {true, root};
}

PairResult solve_pair(std::uint64_t s1, std::uint64_t s3) noexcept {
    if (s1 == 0) return {};
    const auto inverse_cube = inv(mul(square(s1), s1)).value;
    const auto solution = solve(1 ^ mul(s3, inverse_cube));
    if (!solution.solvable) return {};
    const auto first = mul(s1, solution.value);
    const auto second = first ^ s1;
    if (first == 0 || second == 0 || first == second) return {};
    return {true, {std::min(first, second), std::max(first, second)}};
}
} // namespace snowstorm::gf64
