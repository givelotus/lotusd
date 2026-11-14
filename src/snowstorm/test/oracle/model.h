// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#ifndef LOTUS_SNOWSTORM_TEST_ORACLE_MODEL_H
#define LOTUS_SNOWSTORM_TEST_ORACLE_MODEL_H

#include <cstdint>
#include <set>
#include <span>
#include <vector>

namespace snowstorm_oracle {

/** §4.1: oracle-owned value type; deliberately unrelated to production Cell. */
struct Cell {
    std::int32_t count{};
    std::uint64_t s1{};
    std::uint64_t s3{};
    std::uint64_t s5{};
    bool operator==(const Cell &) const = default;
};
/** §4.1: a nonzero item and its independently expected signed membership. */
struct SignedItem {
    std::uint64_t item{};
    int sign{};
    bool operator==(const SignedItem &) const = default;
};
using IdSet = std::set<std::uint64_t>;
/** §5: ID-level operation; sign zero denotes a body-only sequence event. */
struct Operation {
    std::uint64_t seq{};
    std::uint64_t item{};
    int sign{};
};

/** §4.1: direct field-power addition; false on invalid input/overflow, unchanged. */
bool add(Cell &cell, std::uint64_t item, int sign);
/** §4.1: exact count subtraction and XOR syndromes; throws on count overflow. */
Cell subtract(const Cell &received, const Cell &reference);
/** §4.1: independent full Zero/One/Two postcondition verification. */
bool verifies_decode(const Cell &source, std::uint64_t index,
                     std::span<const SignedItem> decoded,
                     const IdSet &reference);
/** §4.3: direct set encoding in [begin,end), with no incremental cache. */
std::vector<Cell> encode(const IdSet &items, std::uint64_t begin,
                         std::uint64_t end);
/** §4.3: direct signed-multiset encoding; useful for independent residuals. */
std::vector<Cell> encode_signed(std::span<const SignedItem> items,
                                std::uint64_t begin, std::uint64_t end);
/** §5: reconstructs a set by replaying operations from the initial state. */
IdSet snapshot(std::span<const Operation> log, std::uint64_t at_seq,
               const IdSet &initial = {});

} // namespace snowstorm_oracle
#endif
