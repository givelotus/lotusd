// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/voting.h>
namespace snowstorm::detail {
/** Pure conservative preview; no wave, clock, transaction or session mutation.
 * transaction_ready is supplied by the caller: this helper chooses no policy
 * for current versus prospective transaction confidence. */
struct VotingPreview {
    Error error{Error::ok};
    double lower_llr{};
    double confidence{};
    bool eligible{};
};
/** Use the FULL selected sample K, counting every unanswered peer as a nonmatch.
 * Validate matches<=answered<=K<=D, ordered hypotheses (except the empty
 * D=M0=M1=K=0 population), positive threshold and finite C in [0,Broot].
 * A valid K=0 preview is neutral and never ends a nonexistent wave.
 * Eligibility means the conservative saturated root confidence reaches Broot
 * and transaction_ready is true; it is not an instruction to end a wave. */
VotingPreview preview_voting(std::uint64_t population, std::uint64_t m0,
    std::uint64_t m1, std::uint64_t sample, std::uint64_t answered,
    std::uint64_t matches, double current, std::uint64_t b_root,
    bool transaction_ready) noexcept;
} // namespace snowstorm::detail
