// Copyright (c) 2026 The Lotus developers
#include "monetary.h"

#include <boost/multiprecision/integer.hpp>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace lotus::v2 {
namespace {
using Int = MonetaryInteger;
const Int U64 = (Int(1) << 64) - 1;
const Int U128 = (Int(1) << 128) - 1;
const Int U256 = (Int(1) << 256) - 1;
const Int U384 = (Int(1) << 384) - 1;

void Require(bool valid, const char *message) {
    if (!valid) throw std::invalid_argument(message);
}
void Range(const Int &value, const Int &maximum, const char *name) {
    Require(value >= 0 && value <= maximum, name);
}
uint64_t AsU64(const Int &value, const char *name) {
    Range(value, U64, name);
    return value.convert_to<uint64_t>();
}
Int WorkInteger(const Hash &work);
void ValidateProfile(const MonetaryProfile &p) {
    Require(WorkInteger(p.genesis_work) != 0, "zero genesis work anchor");
    Require(p.genesis_tail >= p.tail_min && p.genesis_tail <= p.tail_max, "genesis tail anchor bounds");
    Require(p.tail_min > 0 && p.tail_min <= p.tail_max, "tail bounds");
    Require(p.min_fee_per_kb == 1000, "P05 byte fee rate");
}
Int WorkInteger(const Hash &work) {
    Int value = 0;
    for (size_t i = work.size(); i > 0; --i) {
        value <<= 8;
        value += work[i - 1];
    }
    return value;
}
Hash WorkBytes(const Int &work) {
    Range(work, U256, "work width");
    Hash bytes{};
    Int value = work;
    for (auto &byte : bytes) {
        byte = static_cast<uint8_t>((value & 255).convert_to<unsigned>());
        value >>= 8;
    }
    return bytes;
}
void ValidateState(const MonetaryState &s) {
    Require(WorkInteger(s.prev_work) != 0, "zero previous work");
}
uint64_t ShiftU64(uint64_t value, uint32_t shift) {
    return shift >= 64 ? 0 : value >> shift;
}
uint64_t ByteFee(uint64_t bytes, const MonetaryProfile &p) {
    return AsU64((Int(bytes) * p.min_fee_per_kb + 999) / 1000,
                 "byte fee width");
}
Int Sum(const std::vector<Int> &values, const Int &maximum,
        const char *message) {
    Int sum = 0;
    for (const auto &value : values) {
        Range(value, maximum, message);
        sum += value;
        Range(sum, maximum, message);
    }
    return sum;
}
Int Isqrt(const Int &n) {
    if (n == 0) return 0;
    Int x = Int(1) << ((boost::multiprecision::msb(n) + 2) / 2);
    while (true) {
        Int next = (x + n / x) >> 1;
        if (next >= x) return x;
        x = std::move(next);
    }
}
} // namespace

uint64_t AbsoluteTail(const MonetaryProfile &profile, const MonetaryInteger &work) {
    ValidateProfile(profile);
    Range(work, U256, "work width");
    Require(work != 0, "zero work");
    Int numerator = Int(profile.genesis_tail) * profile.genesis_tail * work;
    Range(numerator, U384, "tail numerator width");
    Int raw = Isqrt(numerator / WorkInteger(profile.genesis_work));
    return AsU64(std::min(Int(profile.tail_max), std::max(Int(profile.tail_min), raw)), "tail width");
}

MonetaryState InitializeMonetaryGenesis(const MonetaryProfile &profile,
                                         const MonetaryState &initial,
                                         uint64_t coinbase_native_value) {
    ValidateProfile(profile);
    ValidateState(initial);
    Require(coinbase_native_value == 0, "genesis native issuance");
    Require(initial.tail_subsidy >= profile.tail_min &&
            initial.tail_subsidy <= profile.tail_max, "initial tail bounds");
    Require(initial.tail_subsidy == profile.genesis_tail && initial.prev_work == profile.genesis_work, "genesis anchor mismatch");
    return initial; // Genesis does not advance R, T, W or E.
}

uint64_t TransactionEffectiveCost(uint64_t linear_cost,
                                  const MonetaryProfile &profile) {
    ValidateProfile(profile);
    Int square = Int(linear_cost) * linear_cost;
    Range(square, U128, "transaction square width");
    return AsU64(Int(linear_cost) + (square >> profile.tx_knee_shift),
                 "transaction effective cost width");
}

MonetaryInteger BlockEffectiveCost(
    const MonetaryInteger &envelope_cost,
    const std::vector<uint64_t> &transaction_linear_costs,
    const MonetaryProfile &profile) {
    ValidateProfile(profile);
    Range(envelope_cost, U128, "envelope cost width");
    Int result = envelope_cost;
    for (uint64_t linear : transaction_linear_costs) {
        result += TransactionEffectiveCost(linear, profile);
        Range(result, U128, "block cost width");
    }
    return result;
}

MonetaryInteger RequiredBlockBurn(const MonetaryInteger &block_cost,
                                  uint64_t ema, const MonetaryProfile &profile) {
    ValidateProfile(profile);
    Range(block_cost, U128, "block cost width");
    return ((block_cost * std::max(ema, profile.ema_min)) >> profile.linear_shift) +
           ((block_cost * block_cost) >> profile.quad_shift);
}

MonetaryOrdinaryTx AccountValidatedOrdinary(
    const Transaction &tx, const OrdinaryCandidateEffects &effects,
    const TxProfile &tx_profile, const MonetaryProfile &profile,
    const uint64_t *precomputed_wire_bytes) {
    ValidateProfile(profile);
    uint64_t wire_size = 0;
    if (precomputed_wire_bytes != nullptr) {
        wire_size = *precomputed_wire_bytes;
    } else {
        std::vector<uint8_t> wire;
        std::string error;
        Require(EncodeTransaction(tx, tx_profile, wire, error),
                "ordinary framing");
        wire_size = static_cast<uint64_t>(wire.size());
    }
    Require(!tx.inputs.empty() && tx.inputs.front().flags != 2,
            "coinbase is not ordinary");
    uint32_t tokens = 0;
    Int explicit_burn = 0;
    Int total_outputs = 0;
    for (const Output &output : tx.outputs) {
        tokens += output.HasToken() ? 1 : 0;
        if (!output.HasToken()) {
            total_outputs += output.value;
            if (output.IsBurn()) explicit_burn += output.value;
        }
    }
    Range(total_outputs, U128, "native output sum width");
    Range(explicit_burn, U128, "explicit native burn width");
    Require(tokens <= 65535, "token output count");
    Int fee = effects.native_fee;
    Range(fee, U128, "native fee width");
    Int native_inputs = fee + total_outputs;
    Range(native_inputs, U128, "native input sum width");
    Int token_burn = Int(2) * profile.dust_limit * tokens;
    Range(token_burn, U128, "token burn width");
    Require(Int(effects.token_output_burn_floor) == token_burn,
            "ordinary token floor mismatch");
    Require(fee >= ByteFee(wire_size, profile) && fee >= token_burn,
            "ordinary fee floor");
    return {native_inputs, total_outputs, wire_size,
            static_cast<uint16_t>(tokens), explicit_burn};
}

MonetaryTransition AdvanceMonetary(const MonetaryProfile &profile,
    const MonetaryState &parent, const MonetaryInteger &work,
    const std::vector<MonetaryOrdinaryTx> &transactions,
    const MonetaryInteger &coinbase_native_outputs,
    const MonetaryInteger &coinbase_native_burn, uint64_t coinbase_bytes,
    uint64_t tx_frame_prefix_bytes, const MonetaryInteger &account_block_cost,
    const MonetaryInteger &enforce_block_cost) {
    ValidateProfile(profile);
    ValidateState(parent);
    Range(work, U256, "work width");
    Require(work != 0, "zero work");
    Range(account_block_cost, U128, "account block cost width");
    Range(enforce_block_cost, U128, "enforce block cost width");
    Require(enforce_block_cost >= account_block_cost, "enforcement below accounting");
    Require(parent.tail_subsidy >= profile.tail_min &&
            parent.tail_subsidy <= profile.tail_max, "parent tail bounds");
    const uint64_t paid_tail = AbsoluteTail(profile, WorkInteger(parent.prev_work));
    Require(parent.tail_subsidy == paid_tail, "parent cached tail mismatch");
    std::vector<Int> fees, token_burns, explicit_burns;
    fees.reserve(transactions.size());
    token_burns.reserve(transactions.size());
    explicit_burns.reserve(transactions.size() + 1);
    for (const auto &tx : transactions) {
        Range(tx.native_inputs, U128, "native input sum width");
        Range(tx.native_outputs, U128, "native output sum width");
        Range(tx.explicit_native_burn, U128, "explicit burn width");
        Require(tx.native_outputs <= tx.native_inputs,
                "native conservation");
        Require(tx.explicit_native_burn <= tx.native_outputs,
                "ordinary explicit burn exceeds outputs");
        Int tx_fee = tx.native_inputs - tx.native_outputs;
        Int token_burn = Int(2) * profile.dust_limit * tx.token_outputs;
        Range(token_burn, U128, "token burn width");
        Require(tx_fee >= ByteFee(tx.serialized_bytes, profile) &&
                tx_fee >= token_burn, "ordinary fee floor");
        fees.push_back(tx_fee);
        token_burns.push_back(token_burn);
        explicit_burns.push_back(tx.explicit_native_burn);
    }
    Int fee = Sum(fees, U128, "total fee width");
    Int token_burn = Sum(token_burns, U128, "total token burn width");
    Int remaining = fee - token_burn;
    Int burned_fees = remaining - remaining / 2;
    uint64_t bootstrap = parent.bootstrap_reserve == 0 ? 0 :
        std::max<uint64_t>(1, ShiftU64(parent.bootstrap_reserve, profile.boot_shift));
    uint64_t reserve = parent.bootstrap_reserve - bootstrap;
    uint64_t subsidy = AsU64(Int(bootstrap) + paid_tail, "subsidy width");
    Int entitlement = Int(subsidy) + remaining / 2;
    Range(entitlement, U128, "coinbase entitlement width");
    uint64_t overhead = AsU64(Int(134) + 4 + tx_frame_prefix_bytes, "overhead width");
    uint64_t charged_bytes = AsU64(Int(coinbase_bytes) + overhead, "coinbase charge bytes");
    Int k = ByteFee(charged_bytes, profile);
    Int floor = RequiredBlockBurn(enforce_block_cost, parent.ema_block_cost, profile);
    Int burn_shortfall = floor - burned_fees;
    Int required = std::max(k, std::max(Int(0), burn_shortfall));
    Require(required <= entitlement, "insufficient entitlement");
    Range(coinbase_native_outputs, U128, "coinbase outputs width");
    Range(coinbase_native_burn, U128, "coinbase burn width");
    Require(coinbase_native_burn <= coinbase_native_outputs,
            "coinbase explicit burn exceeds outputs");
    Require(coinbase_native_outputs <= entitlement - required, "coinbase overclaim");
    Int underclaim = entitlement - coinbase_native_outputs;
    uint64_t tail = AbsoluteTail(profile, work);
    uint64_t ema = AsU64(Int(parent.ema_block_cost) -
        ShiftU64(parent.ema_block_cost, profile.ema_shift) +
        (account_block_cost >> profile.ema_shift), "next EMA width");
    explicit_burns.insert(explicit_burns.begin(), coinbase_native_burn);
    Int explicit_burn = Sum(explicit_burns, U128, "total explicit burn width");
    Int delta = Int(subsidy) - token_burn - burned_fees - underclaim - explicit_burn;
    return {{reserve, tail, WorkBytes(work), ema}, bootstrap, subsidy, fee, token_burn,
            burned_fees, required, underclaim, delta};
}

} // namespace lotus::v2
