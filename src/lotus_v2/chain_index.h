// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CHAIN_INDEX_H
#define LOTUS_V2_CHAIN_INDEX_H
#include "header_context.h"
#include <array>
#include <span>
#include <vector>
namespace lotus::v2 {
// Positive targets and a uint64 height bound the cumulative sum by 2^319.
// Fixed little-endian u320; never reuse MonetaryState.prev_work as chainwork.
using ChainWork = std::array<uint8_t, 40>;
inline int CompareChainWork(const ChainWork &left, const ChainWork &right) {
    for (size_t i = left.size(); i-- > 0;)
        if (left[i] != right[i]) return left[i] < right[i] ? -1 : 1;
    return 0;
}
inline bool AddChainWork(const ChainWork &left, const ChainWork &right, ChainWork &out) {
    ChainWork result{}; unsigned carry{};
    for (size_t i = 0; i < result.size(); ++i) {
        const unsigned sum = unsigned(left[i]) + right[i] + carry;
        result[i] = uint8_t(sum); carry = sum >> 8;
    }
    if (carry) return false;
    out = result; return true;
}
inline bool HeaderWork(const Hash &positive_target, ChainWork &out) {
    bool positive{};
    std::array<uint8_t, 33> denominator{}, remainder{};
    for (size_t i = 0; i < positive_target.size(); ++i) {
        denominator[i] = positive_target[i]; positive |= positive_target[i] != 0;
    }
    if (!positive) return false;
    unsigned carry = 1;
    for (auto &byte : denominator) {
        const unsigned sum = unsigned(byte) + carry; byte = uint8_t(sum); carry = sum >> 8;
    }
    ChainWork quotient{};
    // Divide the 257-bit integer 2^256 by (target+1), without u256 wrap.
    for (int bit = 256; bit >= 0; --bit) {
        unsigned shift = bit == 256 ? 1 : 0;
        for (auto &byte : remainder) {
            const unsigned value = (unsigned(byte) << 1) | shift;
            byte = uint8_t(value); shift = value >> 8;
        }
        int comparison{};
        for (size_t i = remainder.size(); i-- > 0;)
            if (remainder[i] != denominator[i]) {
                comparison = remainder[i] < denominator[i] ? -1 : 1; break;
            }
        if (comparison < 0) continue;
        unsigned borrow{};
        for (size_t i = 0; i < remainder.size(); ++i) {
            const unsigned sub = unsigned(denominator[i]) + borrow;
            const unsigned old = remainder[i]; remainder[i] = uint8_t(old - sub);
            borrow = old < sub;
        }
        quotient[unsigned(bit) / 8] |= uint8_t(1 << (unsigned(bit) % 8));
    }
    out = quotient; return true;
}
enum class HeaderStage : uint8_t { HeaderChecked = 0, Connected = 1 };
struct IndexedHeader {
    Header header;
    ChainWork chain_work{};
    uint64_t max_ancestor_time{};
    HeaderStage stage{HeaderStage::HeaderChecked}; // Connected means ever connected.
};
struct ActiveChainIndex {
    Hash tip{};
    uint64_t height{};
    ChainWork chain_work{};
    uint64_t max_ancestor_time{};
};
struct ForkLimits {
    uint64_t max_disconnect{};
    uint64_t max_connect{};
    uint64_t max_reads{}; // Includes all underlying database Gets.
};
struct ForkPlan {
    Hash source{}, target{}, fork{};
    std::vector<Hash> disconnect; // Current tip down, excludes fork.
    std::vector<Hash> connect; // Fork child up to target.
};
enum class ChainIndexResult {
    Complete, Missing, NotHeavier, Deferred, CapacityRefused, StaleTip, StorageError, Excluded
};
class DiskStateStore;
struct DiskStateError;
// Caller serializes store access. Outputs change only on Complete. Quotas are
// operational and never classify a header as consensus-invalid. No mutation,
// body availability guarantee, best-chain activation or whole-reorg atomicity.
ChainIndexResult BuildActiveLocator(const DiskStateStore &, const Hash &expected_tip,
    size_t max_ids, std::vector<Hash> &out, DiskStateError &);
ChainIndexResult ReadActiveHeaders(const DiskStateStore &, const Hash &expected_tip,
    std::span<const Hash> locator, const Hash &stop, size_t max_locator,
    size_t max_headers, std::vector<Header> &out, DiskStateError &);
// Plans a strictly heavier header candidate, which still needs full block/state
// execution unless already connected. Exact ties retain the active tip. Future
// eligibility is explicit and checks the maximum timestamp of all ancestors.
ChainIndexResult PlanHeaderFork(const DiskStateStore &, const Hash &expected_tip,
    const Hash &target, const ForkLimits &, uint64_t now, uint64_t future_window,
    ForkPlan &out, DiskStateError &, bool allow_parked_source = false);
} // namespace lotus::v2
#endif
