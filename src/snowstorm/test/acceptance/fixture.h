// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
#include <snowstorm/types.h>
#include "../oracle/model.h"
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

namespace snowstorm_test {
/** Test-only deterministic data generator; never passed into a node. */
class Rng {
public:
    explicit Rng(std::uint64_t seed);
    std::uint64_t next();
    std::uint64_t nonzero();
    std::uint64_t bounded(std::uint64_t exclusive);
private:
    std::mt19937_64 engine_;
};
using IdSet = snowstorm_oracle::IdSet;
/** Public cell boundary conversions; no protocol arithmetic here. */
snowstorm::Cell to_core(const snowstorm_oracle::Cell &cell);
snowstorm_oracle::Cell to_oracle(const snowstorm::Cell &cell);
void require_cell_equal(const snowstorm::Cell &actual,
                        const snowstorm_oracle::Cell &expected);
/** Membership callback refers only to the caller's explicit reference set. */
snowstorm::ReferenceView reference(const IdSet &ids);
std::vector<snowstorm_oracle::SignedItem> to_oracle(
    const snowstorm::DecodeResult &decoded);
/** Synthetic admitted body identities for the sans-IO host contract. */
class SyntheticBody final : public snowstorm::TxBody {
public:
    SyntheticBody(snowstorm::TxId txid, snowstorm::TxHash hash,
                  snowstorm::ShortId cached_id);
    snowstorm::TxId txid() const noexcept override;
    snowstorm::TxHash tx_hash() const noexcept override;
    snowstorm::ShortId short_id() const noexcept override;
private:
    snowstorm::TxId txid_;
    snowstorm::TxHash hash_;
    snowstorm::ShortId cached_id_;
};
snowstorm::TxHash make_hash(std::uint64_t seed);
snowstorm::TxHandle make_body(std::uint64_t seed,
                              snowstorm::ShortId cached_id = 0);
inline constexpr snowstorm::ShortIdKey collision_key{0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
inline constexpr snowstorm::ShortId collision_id = 0xf59bc9a6ce828e7bULL;
std::array<snowstorm::TxHandle, 2> collision_bodies();
std::vector<std::uint64_t> sorted_ids(const IdSet &ids);
} // namespace snowstorm_test
