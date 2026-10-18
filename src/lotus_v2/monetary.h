// Copyright (c) 2026 The Lotus developers
// Parameterized P05/P06/C16 arithmetic review model; not block validation.
#ifndef LOTUS_V2_MONETARY_H
#define LOTUS_V2_MONETARY_H

#include "ordinary_validation.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstdint>
#include <vector>

namespace lotus::v2 {

using MonetaryInteger = boost::multiprecision::cpp_int;

struct MonetaryProfile {
    uint32_t boot_shift;
    uint32_t tx_knee_shift;
    uint32_t ema_shift;
    uint64_t ema_min;
    uint32_t linear_shift;
    uint32_t quad_shift;
    uint64_t tail_min;
    uint64_t tail_max;
    uint64_t dust_limit;
    uint64_t min_fee_per_kb;
    uint64_t genesis_tail;
    Hash genesis_work;
};

struct MonetaryOrdinaryTx {
    MonetaryInteger native_inputs{}; // independently resolved u128 aggregate
    MonetaryInteger native_outputs{}; // all native outputs, including IS_BURN
    uint64_t serialized_bytes{};
    uint16_t token_outputs{}; // includes IS_BURN token outputs
    MonetaryInteger explicit_native_burn{}; // independently checked subset of outputs
};

struct MonetaryTransition {
    MonetaryState state{};
    uint64_t bootstrap_issued{};
    uint64_t subsidy{};
    MonetaryInteger total_fees{};
    MonetaryInteger token_burn{};
    MonetaryInteger burned_fees{};
    MonetaryInteger required_underclaim{};
    MonetaryInteger actual_underclaim{};
    MonetaryInteger spendable_supply_delta{}; // signed mathematical amount
    size_t expired_swept_count{};
    MonetaryInteger expired_burned_atoms{};
    MonetaryInteger cleaning_crew_bounty{};
    MonetaryInteger burned_total{};
};

inline constexpr uint64_t ABSOLUTE_TAIL_FORMULA_VERSION = 1;
uint64_t AbsoluteTail(const MonetaryProfile &, const MonetaryInteger &work);

// Throws std::invalid_argument for an invalid profile, state, range or rule.
// Genesis records the initial state without running an issuance step.
MonetaryState InitializeMonetaryGenesis(const MonetaryProfile &profile,
                                         const MonetaryState &initial,
                                         uint64_t coinbase_native_value);
MonetaryState DecodeMonetaryState(const std::vector<uint8_t> &wire);

uint64_t TransactionEffectiveCost(uint64_t linear_cost,
                                  const MonetaryProfile &profile);
MonetaryInteger BlockEffectiveCost(
    const MonetaryInteger &envelope_cost,
    const std::vector<uint64_t> &transaction_linear_costs,
    const MonetaryProfile &profile);
MonetaryInteger RequiredBlockBurn(const MonetaryInteger &block_cost,
                                  uint64_t ema, const MonetaryProfile &profile);

// This adapter derives output counts and explicit burn values from the native
// transaction. effects must come from a successful CheckOrdinaryCandidate;
// this function does not repeat authorization or UTXO resolution.
MonetaryOrdinaryTx AccountValidatedOrdinary(
    const Transaction &tx, const OrdinaryCandidateEffects &effects,
    const TxProfile &tx_profile, const MonetaryProfile &profile,
    const uint64_t *precomputed_wire_bytes = nullptr);

// Costs and frame byte counts are supplied by an independent block verifier.
// account_block_cost drives EMA; enforce_block_cost drives the burn floor.
MonetaryTransition AdvanceMonetary(const MonetaryProfile &profile,
    const MonetaryState &parent, const MonetaryInteger &work,
    const std::vector<MonetaryOrdinaryTx> &transactions,
    const MonetaryInteger &coinbase_native_outputs,
    const MonetaryInteger &coinbase_native_burn, uint64_t coinbase_bytes,
    uint64_t tx_frame_prefix_bytes, const MonetaryInteger &account_block_cost,
    const MonetaryInteger &enforce_block_cost,
    size_t expired_swept_count = 0,
    const MonetaryInteger &expired_burned_atoms = 0);

inline MonetaryTransition AdvanceMonetaryState(
    const MonetaryProfile &profile, const MonetaryState &parent,
    const MonetaryInteger &work,
    const std::vector<MonetaryOrdinaryTx> &transactions,
    const MonetaryInteger &coinbase_native_outputs,
    const MonetaryInteger &coinbase_native_burn, uint64_t coinbase_bytes,
    uint64_t tx_frame_prefix_bytes, const MonetaryInteger &account_block_cost,
    const MonetaryInteger &enforce_block_cost,
    size_t expired_swept_count = 0,
    const MonetaryInteger &expired_burned_atoms = 0) {
    return AdvanceMonetary(profile, parent, work, transactions,
                           coinbase_native_outputs, coinbase_native_burn,
                           coinbase_bytes, tx_frame_prefix_bytes,
                           account_block_cost, enforce_block_cost,
                           expired_swept_count, expired_burned_atoms);
}

} // namespace lotus::v2
#endif
