#include "monetary.h"

#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace lotus::v2;
using Int = MonetaryInteger;

namespace {
void Check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}
void Reject(const std::function<void()> &fn, const char *message) {
    try { fn(); } catch (const std::invalid_argument &) { return; }
    throw std::runtime_error(message);
}
const MonetaryProfile P{2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, Hash{9}};
MonetaryState State(uint64_t reserve, uint64_t tail, Int work, uint64_t ema) {
    Hash bytes{};
    for (auto &byte : bytes) {
        byte = static_cast<uint8_t>((work & 255).convert_to<unsigned>());
        work >>= 8;
    }
    return {reserve, tail, bytes, ema};
}
MonetaryTransition Step(const MonetaryState &parent,
                        const std::vector<MonetaryOrdinaryTx> &txs = {},
                        Int payout = 0, Int cb_burn = 0,
                        Int account = 4, Int enforce = 4, Int work = 9) {
    return AdvanceMonetary(P, parent, work, txs, payout, cb_burn,
                           1, 1, account, enforce);
}
void HandCalculated() {
    MonetaryState state = InitializeMonetaryGenesis(P, State(9, 200, 9, 4), 0);
    auto wire = EncodeMonetaryState(state);
    Check(wire[0] == 9 && wire[8] == 200 && wire[16] == 9 &&
          wire[48] == 4, "state wire positions");
    auto decoded = DecodeMonetaryState({wire.begin(), wire.end()});
    Check(decoded.bootstrap_reserve == 9 && decoded.tail_subsidy == 200 &&
          decoded.prev_work[0] == 9 && decoded.ema_block_cost == 4,
          "state wire roundtrip");
    Reject([&] { InitializeMonetaryGenesis(P, state, 1); }, "genesis issuance");
    Reject([&] { DecodeMonetaryState(std::vector<uint8_t>(55)); }, "short state");
    auto block1 = Step(state);
    Check(block1.bootstrap_issued == 2 && block1.subsidy == 202 &&
          block1.state.bootstrap_reserve == 7 && block1.state.tail_subsidy == 200,
          "height-one recurrence");
    uint64_t reserve = 9, issued = 0;
    while (reserve) {
        uint64_t b = std::max<uint64_t>(1, reserve >> 2);
        reserve -= b;
        issued += b;
    }
    Check(issued == 9, "telescoping reserve");
    Check(Step(State(0, 200, 9, 4)).bootstrap_issued == 0, "empty reserve");
    Check(Step(state, {}, 0, 0, 4, 4, 1).state.tail_subsidy == 66,
          "tail low rounding");
    Check(Step(state, {}, 0, 0, 4, 4, 18).state.tail_subsidy == 282,
          "tail isqrt rounding");
    Check(Step(state, {}, 0, 0, 4, 4, (Int(1) << 256) - 1)
              .state.tail_subsidy == 2000, "tail maximum clamp");
    Check(AbsoluteTail(P, 10) == 210 && AbsoluteTail(P, 9) == 200,
          "absolute rounding returns to anchor");
    auto upper = P; upper.tail_max = 300;
    Check(AbsoluteTail(upper, 36) == 300 && AbsoluteTail(upper, 9) == 200,
          "upper clipping recovery");
    auto lower = P; lower.tail_min = 180;
    Check(AbsoluteTail(lower, 1) == 180 && AbsoluteTail(lower, 9) == 200,
          "lower clipping recovery");
    auto wide = P; wide.genesis_tail = UINT64_MAX; wide.tail_max = UINT64_MAX;
    wide.genesis_work = Hash{1};
    Check(AbsoluteTail(wide, (Int(1) << 256) - 1) == UINT64_MAX,
          "wide numerator clamps before narrowing");
    auto zero = P; zero.genesis_work = {};
    Reject([&] { AbsoluteTail(zero, 9); }, "zero genesis anchor");
    zero = P; zero.genesis_tail = 0;
    Reject([&] { AbsoluteTail(zero, 9); }, "zero genesis tail");
    zero = P; zero.tail_min = 0;
    Reject([&] { AbsoluteTail(zero, 9); }, "zero tail lower bound");
    zero.genesis_tail = 0;
    Reject([&] { AbsoluteTail(zero, 9); }, "zero lower bound and anchor");
    auto smallest = P; smallest.tail_min = 1; smallest.genesis_tail = 1;
    smallest.genesis_work = Hash{1};
    Check(AbsoluteTail(smallest, 1) == 1, "positive minimum anchor accepted");
    Reject([&] { Step(State(9, 199, 9, 4)); }, "tampered cached tail");
    Reject([&] { InitializeMonetaryGenesis(P, State(9, 201, 9, 4), 0); },
           "initial anchor mismatch");
    auto saturated = Step(state, {}, 0, 0, 4, 4, (Int(1) << 256) - 1);
    auto returned = Step(saturated.state);
    Check(returned.subsidy == 2001 && returned.state.tail_subsidy == 200,
          "lag and return from saturation");
    Check(TransactionEffectiveCost(3, P) == 4 &&
          TransactionEffectiveCost(4, P) == 6 &&
          BlockEffectiveCost(5, {3, 4}, P) == 15 &&
          RequiredBlockBurn(8, 4, P) == 6, "P05 parabolic algebra");
    auto base = Step(State(9, 200, 9, 8), {}, 0, 0, 8, 8);
    auto strict = Step(State(9, 200, 9, 8), {}, 0, 0, 8, 64);
    Check(base.state.ema_block_cost == 8 && strict.state.ema_block_cost == 8 &&
          strict.required_underclaim > base.required_underclaim,
          "frozen accounting versus enforcement");
    MonetaryOrdinaryTx tx{100, 87, 10, 1, 2};
    auto result = Step(state, {tx}, 60);
    Check(result.subsidy == 202 && result.total_fees == 13 &&
          result.token_burn == 6 && result.burned_fees == 4 &&
          result.required_underclaim == 140 &&
          result.actual_underclaim == 145 &&
          result.spendable_supply_delta == 45, "odd fee and token burn once");
    auto explicit_coinbase = Step(state, {tx}, 60, 10);
    auto extra_underclaim = Step(state, {tx}, 50);
    Check(explicit_coinbase.spendable_supply_delta ==
          extra_underclaim.spendable_supply_delta &&
          explicit_coinbase.actual_underclaim == 145,
          "explicit burn versus underclaim");
    Reject([&] { Step(state, {tx}, 66); }, "coinbase overclaim");
    Reject([&] { Step(state, {tx}, 66, 66); },
           "explicit burn cannot fund mandatory underclaim");
    Reject([&] { Step(State(0, 2, 1, 0)); }, "insufficient entitlement");
    Reject([&] { Step(state, {}, 0, 0, 8, 7); },
           "enforcement below frozen accounting");
    Reject([&] { Step(state, {}, 0, 0, 4, 4, 0); }, "zero work");
    Reject([&] { Step(State(0, 200, 0, 0)); }, "zero previous work");
    Reject([&] { Step(State(0, 200, 1, std::numeric_limits<uint64_t>::max()),
                     {}, 0, 0, (Int(1) << 128) - 1, (Int(1) << 128) - 1); },
           "EMA overflow");
    Reject([&] { TransactionEffectiveCost(std::numeric_limits<uint64_t>::max(), P); },
           "transaction effective cost overflow");
    Reject([&] { BlockEffectiveCost((Int(1) << 128) - 1, {1}, P); },
           "block u128 sum overflow");
    auto two_max = Step(State(0, 66, 1, 0),
        {{2 * ((Int(1) << 64) - 1), 0, 1, 0, 0}});
    Check(two_max.total_fees == 2 * ((Int(1) << 64) - 1),
          "u128 fee aggregate above u64");
    Reject([&] { Step(State(0, 66, 1, 0),
        {{(Int(1) << 128) - 1, 0, 1, 0, 0},
         {(Int(1) << 128) - 1, 0, 1, 0, 0}}); },
        "aggregate fee overflow");
    Reject([&] { Step(state, {{10, 5, 1, 0, 6}}); },
           "ordinary explicit burn exceeds outputs");
    Reject([&] { Step(state, {{5, 10, 1, 0, 0}}); },
           "native inflation");
    MonetaryProfile wide_shift = P;
    wide_shift.boot_shift = 10000;
    wide_shift.ema_shift = 10000;
    wide_shift.tx_knee_shift = 10000;
    wide_shift.linear_shift = 10000;
    wide_shift.quad_shift = 10000;
    Check(TransactionEffectiveCost(1, wide_shift) == 1,
          "large profile shift");
    Check(Step(state).state.bootstrap_reserve == 7, "original profile intact");
}
void NativeTransactionAdapter() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    Transaction tx;
    Input spend;
    spend.prev_txid[0] = 1;
    spend.sequence = UINT32_MAX;
    spend.flags = 1;
    spend.witnesses = {BranchWitness{{0x51}, {}, {}}};
    tx.inputs.push_back(spend);
    Output burned;
    burned.flags = 2;
    burned.value = 17;
    burned.branches = {Hash32{}};
    tx.outputs.push_back(burned);
    OrdinaryCandidateEffects effects;
    effects.native_fee = 1000;
    auto accounted = AccountValidatedOrdinary(tx, effects, tx_profile, P);
    std::vector<uint8_t> wire;
    std::string error;
    Check(EncodeTransaction(tx, tx_profile, wire, error), "adapter fixture encode");
    Check(accounted.serialized_bytes == wire.size() &&
          accounted.native_inputs == 1017 && accounted.native_outputs == 17 &&
          accounted.token_outputs == 0 &&
          accounted.explicit_native_burn == 17,
          "native transaction adapter derives framing and burn outputs");
    effects.native_fee = wire.size() - 1;
    Reject([&] { AccountValidatedOrdinary(tx, effects, tx_profile, P); },
           "adapter byte fee floor");
    effects.native_fee = 1000;
    effects.token_output_burn_floor = 1;
    Reject([&] { AccountValidatedOrdinary(tx, effects, tx_profile, P); },
           "adapter token floor mismatch");
    tx.inputs[0].flags = 2;
    tx.inputs[0].witnesses.clear();
    effects.token_output_burn_floor = 0;
    Reject([&] { AccountValidatedOrdinary(tx, effects, tx_profile, P); },
           "adapter rejects coinbase");
}
void MixedTokenBurnAdapter() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    Transaction tx;
    Input spend;
    spend.prev_txid[0] = 1;
    spend.sequence = UINT32_MAX;
    spend.flags = 1;
    spend.witnesses = {BranchWitness{{0x4e}, {}, {}}};
    tx.inputs = {spend};
    Output native;
    native.flags = 2;
    native.value = 17;
    native.branches = {Hash32{}};
    Output token = native;
    token.flags = 3;
    token.value = 999999;
    token.token_id[0] = 3;
    tx.outputs = {native, token};
    OrdinaryCandidateEffects effects;
    effects.native_fee = 1000;
    effects.token_output_burn_floor = 2 * P.dust_limit;
    const auto record = AccountValidatedOrdinary(tx, effects, tx_profile, P);
    Check(record.native_inputs == 1017 && record.native_outputs == 17 &&
              record.explicit_native_burn == 17 && record.token_outputs == 1,
          "token amounts never enter native accounting");
    const auto state = State(9, 200, 9, 4);
    const auto result =
        AdvanceMonetary(P, state, 9, {record}, 0, 0, 0, 0, 0, 0);
    Check(result.spendable_supply_delta == -1017,
          "token burn does not destroy native token units");
}
void Vectors() {
    uint64_t r, t, w, e, work, fee, bytes, tokens, burn, payout, cb_burn;
    uint64_t cb_bytes, prefix, account, enforce;
    while (std::cin >> r >> t >> w >> e >> work >> fee >> bytes >> tokens >> burn
                    >> payout >> cb_burn >> cb_bytes >> prefix >> account >> enforce) {
        try {
            Check(tokens <= 65535, "vector token count");
            MonetaryOrdinaryTx tx{fee + 100, 100, bytes,
                                  static_cast<uint16_t>(tokens), burn};
            auto result = AdvanceMonetary(P, State(r, t, w, e), work,
                {tx}, payout, cb_burn, cb_bytes, prefix, account, enforce);
            std::cout << result.state.bootstrap_reserve << ' '
                      << result.state.tail_subsidy << ' '
                      << static_cast<unsigned>(result.state.prev_work[0]) << ' '
                      << result.state.ema_block_cost << ' '
                      << result.bootstrap_issued << ' ' << result.subsidy << ' '
                      << result.total_fees << ' ' << result.token_burn << ' '
                      << result.burned_fees << ' ' << result.required_underclaim
                      << ' ' << result.actual_underclaim << ' '
                      << result.spendable_supply_delta << '\n';
        } catch (const std::invalid_argument &) {
            std::cout << "ERR\n";
        }
    }
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--vectors") {
            Vectors();
            return EXIT_SUCCESS;
        }
        HandCalculated();
        NativeTransactionAdapter();
        MixedTokenBurnAdapter();
        std::cout << "monetary arithmetic checks passed\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
