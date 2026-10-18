// Deterministic P04 candidate validation; no wall-clock eligibility policy.
#ifndef LOTUS_V2_HEADER_CONTEXT_H
#define LOTUS_V2_HEADER_CONTEXT_H
#include "header.h"
#include <optional>
#include <string>
#include <vector>
namespace lotus::v2 {
struct HeaderChainProfile {
    ChainId chain_id{};
    uint32_t version{};
    uint64_t genesis_time{};
    uint32_t genesis_bits{};
    Hash pow_limit{};
    int64_t half_life_seconds{};
    int64_t spacing_seconds{};
    // Exact manifest genesis. Zero permits synthetic module fixtures only;
    // daemon initialization must require a nonzero anchor before opening state.
    Hash genesis_id{};
};
// Authenticated history is newest first, includes parent, and contains exactly
// min(parent.height+1,11) headers. Caller authenticates its oldest entry
// against chain state; links within this window are checked here.
std::optional<uint64_t> ParentMedianTime(const HeaderChainProfile &profile,
                                         const Header &parent,
                                         const std::vector<Header> &history);
// Roots and size must be independently derived by the complete-block caller.
// Failure does not mutate any chain state. Future eligibility remains separate.
enum class HeaderCheckResult { Valid, Invalid, Inconclusive };
HeaderCheckResult
ValidateChildHeaderChecked(const HeaderChainProfile &, const Header &,
                           const std::vector<Header> &, const Header &,
                           const Hash &, const Hash &, uint64_t, std::string &);
bool ValidateChildHeader(const HeaderChainProfile &profile,
                         const Header &parent,
                         const std::vector<Header> &history,
                         const Header &child, const Hash &expected_tx_root,
                         const Hash &expected_state_root,
                         uint64_t expected_size, std::string &error);
} // namespace lotus::v2
#endif
