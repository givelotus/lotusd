// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
/** @defgroup snowstorm_voting_contract Snowstorm voting public contract
 * §8: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §8: derived thresholds and selected operational poll count for population D. */
struct VotingParameters {
    std::uint64_t population{};
    std::uint64_t m0{};
    std::uint64_t m1tx{};
    std::uint64_t b_root{};
    std::uint64_t b_tx{};
    std::uint64_t k{};
};
/** §8: typed mathematical result; infinities are IEEE infinities, never sentinels. */
struct MathResult {
    Error error{Error::ok};
    double value{};
};
/** §8: support interval for valid hypergeometric (N,M,K), inclusive endpoints. */
struct HypergeometricSupport {
    Error error{Error::ok};
    std::uint64_t lower{};
    std::uint64_t upper{};
};
/** §8: validated finite config; stable log2(25)-log2(epsilon), including subnormals. */
Error voting_parameters(std::uint64_t population, double beta_max,
                        double epsilon, VotingParameters &out) noexcept;
/** §8: exact integer support bounds; invalid domain is explicit error. */
HypergeometricSupport hypergeometric_support(std::uint64_t population,
                                             std::uint64_t successes,
                                             std::uint64_t draws) noexcept;
/** §8: logarithmic PMF; outside support is -infinity, invalid domain is error. */
MathResult hypergeometric_log2(std::uint64_t y, std::uint64_t population,
                              std::uint64_t successes, std::uint64_t draws) noexcept;
/** §8: monotone support-extended log ratio L(Y;D,M0,M1,K); K=0 gives0.
 * Both-zero high/low tails return +/-infinity explicitly; never NaN/finite proxy.
 */
MathResult hypergeometric_llr(std::uint64_t y, std::uint64_t population,
                             std::uint64_t m0, std::uint64_t m1,
                             std::uint64_t draws) noexcept;
/** §8: finite root saturation [0,Broot], explicit +/-infinity branches. */
MathResult update_root_confidence(double current, double increment,
                                  std::uint64_t b_root) noexcept;
/** §8: transaction saturation [-Btx,+Btx], explicit +/-infinity branches. */
MathResult update_tx_confidence(double current, double increment,
                                std::uint64_t b_tx) noexcept;
/** §8: prior completed-wave estimator; never consumes a current-wave vote. */
Error estimate_m1(std::uint64_t population, std::uint64_t m0,
                   std::uint64_t prior_matches, std::uint64_t prior_sample,
                   std::uint64_t &out) noexcept;
} // namespace snowstorm
/** @} */
