// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/voting.h>
#include "log_factorial.h"
#include "params.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <numbers>
namespace snowstorm {
namespace {
constexpr long double STIRLING_LINEAR = 1.0L / 12;
constexpr long double STIRLING_CUBIC = 1.0L / 360;
constexpr long double STIRLING_QUINTIC = 1.0L / 1260;
constexpr double BETA_CEILING = 1.0 / 3;
constexpr double INF = std::numeric_limits<double>::infinity();
long double correction(long double n) noexcept {
    const auto inverse = 1 / n;
    const auto squared = inverse * inverse;
    return inverse * (STIRLING_LINEAR - squared * (STIRLING_CUBIC - squared * STIRLING_QUINTIC));
}
long double log_choose(std::uint64_t n, std::uint64_t k) noexcept {
    if (n < detail::LOG_FACTORIAL.size()) {
        return detail::LOG_FACTORIAL[n] - detail::LOG_FACTORIAL[k] - detail::LOG_FACTORIAL[n-k];
    }
    k = std::min(k, n-k);
    long double result = 0;
    // Public mathematical helpers have a uint64 domain. Bound all work even
    // outside the operational peer domain; short tails avoid lgamma cancellation.
    if (k <= params::MAX_PEERS) {
        for (std::uint64_t i = 1; i <= k; ++i)
            result += std::log2(static_cast<long double>(n-k+i) / i);
        return result;
    }
    const long double a = k, b = n-k, total = n;
    result = a * std::log1p(b/a) + b * std::log1p(a/b)
        + (std::log(total) - std::log(a) - std::log(b)
           - std::log(2 * std::numbers::pi_v<long double>)) / 2
        + correction(total) - correction(a) - correction(b);
    return result / std::numbers::ln2_v<long double>;
}
MathResult saturate(double current, double increment, double lower, double upper) noexcept {
    if (!std::isfinite(current) || std::isnan(increment) || current < lower || current > upper)
        return {Error::invalid_argument, 0};
    if (std::isinf(increment)) return {Error::ok, increment > 0 ? upper : lower};
    return {Error::ok, std::clamp(current + increment, lower, upper)};
}
}
Error voting_parameters(std::uint64_t population, double beta, double epsilon,
                        VotingParameters &out) noexcept {
    if (!std::isfinite(beta) || beta < 0 || beta >= BETA_CEILING ||
        !std::isfinite(epsilon) || epsilon <= 0 || epsilon >= 1)
        return Error::invalid_argument;
    VotingParameters result{};
    result.population = population;
    const auto null = std::floor((1.0L + beta) * population / 2);
    const auto alternative = std::ceil((1.0L - beta) * population);
    result.m0 = null >= population ? population : static_cast<std::uint64_t>(null);
    result.m1tx = alternative >= population ? population : static_cast<std::uint64_t>(alternative);
    result.b_root = static_cast<std::uint64_t>(std::ceil(std::log2(static_cast<double>(params::VOTING_HORIZON)) - std::log2(epsilon)));
    result.b_tx = (result.b_root + params::TX_THRESHOLD_DIVISOR - 1) / params::TX_THRESHOLD_DIVISOR;
    result.k = std::min(population, params::VOTING_SAMPLE);
    out = result;
    return Error::ok;
}
HypergeometricSupport hypergeometric_support(std::uint64_t n, std::uint64_t m,
                                             std::uint64_t k) noexcept {
    if (m > n || k > n) return {Error::invalid_argument, 0, 0};
    return {Error::ok, k > n-m ? k-(n-m) : 0, std::min(k,m)};
}
MathResult hypergeometric_log2(std::uint64_t y, std::uint64_t n,
                              std::uint64_t m, std::uint64_t k) noexcept {
    const auto support = hypergeometric_support(n,m,k);
    if (support.error != Error::ok) return {support.error,0};
    if (y < support.lower || y > support.upper) return {Error::ok,-INF};
    return {Error::ok, static_cast<double>(log_choose(m,y) + log_choose(n-m,k-y) - log_choose(n,k))};
}
MathResult hypergeometric_llr(std::uint64_t y, std::uint64_t n,
                             std::uint64_t m0, std::uint64_t m1,
                             std::uint64_t k) noexcept {
    if (y > k || k > n || m0 >= m1 || m1 > n) return {Error::invalid_argument,0};
    if (k == 0) return {Error::ok,0};
    const auto a = hypergeometric_support(n,m0,k), b = hypergeometric_support(n,m1,k);
    const bool null = y >= a.lower && y <= a.upper;
    const bool alternative = y >= b.lower && y <= b.upper;
    if (!null && !alternative) return {Error::ok, y > a.upper ? INF : -INF};
    if (!null) return {Error::ok,INF};
    if (!alternative) return {Error::ok,-INF};
    return {Error::ok, static_cast<double>(log_choose(m1,y) + log_choose(n-m1,k-y)
                                         - log_choose(m0,y) - log_choose(n-m0,k-y))};
}
MathResult update_root_confidence(double current, double increment, std::uint64_t bound) noexcept {
    return saturate(current,increment,0,static_cast<double>(bound));
}
MathResult update_tx_confidence(double current, double increment, std::uint64_t bound) noexcept {
    const auto ceiling = static_cast<double>(bound);
    return saturate(current,increment,-ceiling,ceiling);
}
Error estimate_m1(std::uint64_t n, std::uint64_t m0, std::uint64_t matches,
                   std::uint64_t sample, std::uint64_t &out) noexcept {
    if (m0 >= n || sample == 0 || sample > n || matches > sample) return Error::invalid_argument;
    const auto product = static_cast<unsigned __int128>(n) * matches;
    const auto estimate = static_cast<std::uint64_t>(product / sample + (product % sample != 0));
    out = std::clamp(estimate,m0+1,n);
    return Error::ok;
}
} // namespace snowstorm
