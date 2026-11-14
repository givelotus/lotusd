// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>

/** @defgroup snowstorm_gf64_contract Snowstorm gf64 public contract
 * §2: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm::gf64 {
/** §2: selected runtime carry-less multiplication implementation. */
enum class Backend : std::uint8_t { portable, pmull, pclmul };
/** §2: typed inverse result; zero input has error=zero_inverse. */
struct InverseResult {
    Error error{Error::ok};
    std::uint64_t value{};
};
/** §2: trace-one inputs are unsolvable; successful roots are verified. */
struct SolveResult {
    bool solvable{};
    std::uint64_t value{};
};
/** §§2,4.1: distinct nonzero roots from S1/S3, ordered increasingly. */
struct PairResult {
    bool solvable{};
    std::array<std::uint64_t, 2> roots{};
};
/** §2: runtime-selected GF multiplication; no allocation. */
std::uint64_t mul(std::uint64_t a, std::uint64_t b) noexcept;
/** §2: portable 4-bit-window implementation for dispatch conformance. */
std::uint64_t mul_portable(std::uint64_t a, std::uint64_t b) noexcept;
/** §2: byte-table squaring. */
std::uint64_t square(std::uint64_t x) noexcept;
/** §2: Itoh–Tsujii inversion with explicit zero error. */
InverseResult inv(std::uint64_t x) noexcept;
/** §2: Montgomery batch inverse; output and scratch each need input.size().
 * Input/output may alias exactly; scratch must not overlap either. Undersized
 * spans return capacity; a zero input returns zero_inverse. Both leave output
 * unchanged. Empty input succeeds. No allocation.
 */
Error batch_inv(std::span<const std::uint64_t> input,
                std::span<std::uint64_t> output,
                std::span<std::uint64_t> scratch) noexcept;
/** §2: absolute field trace as zero or one. */
std::uint8_t trace(std::uint64_t x) noexcept;
/** §2: verified even-degree theta=x^61 solver; solve(0)={true,0}. */
SolveResult solve(std::uint64_t d) noexcept;
/** §§2,4.1: recover pair from nonzero S1 and S3, without S5 redundancy. */
PairResult solve_pair(std::uint64_t s1, std::uint64_t s3) noexcept;
/** §2: deterministic runtime CPU-selected backend, no mutable override. */
Backend backend() noexcept;
/** §2: query support before a direct backend conformance call. */
bool backend_available(Backend candidate) noexcept;
/** §2: available explicit backend product; unavailable returns invalid_argument. */
Error mul_backend(Backend candidate, std::uint64_t a, std::uint64_t b,
                  std::uint64_t &out) noexcept;
} // namespace snowstorm::gf64
/** @} */
