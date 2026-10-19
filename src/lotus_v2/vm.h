// Copyright (c) 2026 The Lotus developers
// Candidate P03 execution core. This is not a consensus validation entrypoint:
// callers still need authenticated witness context and P05 static accounting.
#ifndef LOTUS_V2_VM_H
#define LOTUS_V2_VM_H

#include "signing.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace lotus::v2 {
using VmBytes = std::vector<uint8_t>;
// Internal 16-bit opcode representation. A single wire byte b is 0x00bb; the
// EXT2 escape `ff xx` is 0xff00 | xx. 0x00ff itself is never an executable
// instruction: on the wire it always introduces a selector byte.
using VmOpcode = uint16_t;
constexpr uint8_t VM_EXT2_PREFIX = 0xff;
constexpr VmOpcode VmExt2(uint8_t selector) {
    return VmOpcode(0xff00 | selector);
}
constexpr bool IsVmExt2(VmOpcode op) { return op >= 0xff00; }
// P05's immutable per-item bound; caller profiles may only tighten it.
constexpr size_t VM_HARD_ELEMENT_BYTES = 8192;
constexpr size_t VM_MIN_NUMERIC_BYTES = 16;
constexpr size_t VM_MAX_NUMERIC_BYTES = 1024;
constexpr size_t VM_MAX_MUL_BYTES = 2048;

struct VmProfile {
    size_t max_script_bytes;
    size_t max_arguments;
    size_t max_element_bytes;
    size_t max_stack_items;
    size_t max_altstack_items;
    size_t max_vm_bytes;
    size_t max_ast_depth;
    size_t max_steps; // host-work guard; P05 cost is a separate obligation
};

// Candidate schedule is supplied explicitly. The coefficients must be
// nonnegative and monotonically bound the selected primitive's work; no
// mainnet schedule is selected here. All assigned bytes need positive base.
using VmCostUnits = __uint128_t;

enum class VmStatus {
    Success,
    AutomaticSuccess,
    Invalid,
    Unsupported,
    OperationalError
};
struct VmResult {
    VmStatus status = VmStatus::Invalid;
    std::string error;
    std::vector<VmBytes> final_stack;
    VmCostUnits executed_cost = 0;
};

class PreparedVmTransaction;

// Per-asset transaction totals. The zero key is the native asset; any other
// key is a token id. Spent coins count as inputs (mints contribute nothing);
// every output, including burns, counts as an output.
struct VmAssetTotals {
    __uint128_t inputs = 0;
    __uint128_t outputs = 0;
};
using VmAssetTotalsMap = std::map<Hash32, VmAssetTotals>;
bool AddVmAssetTotal(VmAssetTotalsMap &totals, const Output &output,
                     bool input, std::string &error);
bool ComputeVmAssetTotals(const Transaction &tx, const ResolvedCoins &resolved,
                          VmAssetTotalsMap &totals, std::string &error);

// Effects recorded by the successful invocations of one transaction (plan
// I-11). They are order-free: ENFORCEOUTPUT records `(output, claim)` and
// state authorizations without consuming a shared budget, so invocations
// can run in any order (or in parallel) and the result depends only on the
// set of recorded effects. One validation run of one transaction owns one
// accumulator; it is never stored in a PreparedVmTransaction, which is
// cached and reused across runs.
struct VmTransactionEffects {
    std::vector<std::pair<uint16_t, uint64_t>> claims;
    std::vector<uint16_t> state_authorized;
    bool Empty() const { return claims.empty() && state_authorized.empty(); }
    void Clear() {
        claims.clear();
        state_authorized.clear();
    }
    void Merge(const VmTransactionEffects &other) {
        claims.insert(claims.end(), other.claims.begin(), other.claims.end());
        state_authorized.insert(state_authorized.end(),
                                other.state_authorized.begin(),
                                other.state_authorized.end());
    }
};
// Per-transaction post-check, run after every invocation succeeded: the
// claims on each output j sum to at most outputs[j].value, and every
// HAS_STATE output was authorized by at least one invocation. Errors are
// "output-overclaimed" and "state-output-unauthorized".
bool FinalizeVmTransactionEffects(std::span<const Output> outputs,
                                  const VmTransactionEffects &effects,
                                  std::string &error);

struct VmExecutionContext {
    const Transaction &tx;
    const TxProfile &tx_profile;
    const ChainId &chain_id;
    const ResolvedCoins &resolved;
    size_t input_index;
    size_t witness_index;
    std::optional<PositiveDelta> positive_delta;
    const PreparedVmTransaction *prepared = nullptr;
    BatchSigCollector *batch_sigs = nullptr;
    // Committed only when the invocation succeeds; failures leave it
    // unchanged. Null means effect-producing opcodes are Unsupported.
    VmTransactionEffects *effects = nullptr;
};

struct VmOpcodeCost {
    uint64_t base = 0;
    uint64_t per_operand_byte = 0;
    uint64_t per_result_byte = 0;
    // ENFORCEOUTPUT (eb) only: charged once per transaction output scanned.
    uint64_t per_scanned_output = 0;
};
struct VmCostProfile {
    VmCostUnits max_invocation_cost = 0;
    uint64_t structural_byte_cost = 0;
    std::array<VmOpcodeCost, 256> opcode{};
    // Costs for two-byte `ff xx` opcodes, indexed by the selector byte. No
    // two-byte opcode is assigned yet, so every entry is currently unused.
    std::array<VmOpcodeCost, 256> ext_opcode{};
    // P05 field-size hints for db/dc/e6/e7. With an execution context, an
    // absent vector is the serialized authenticated field; a caller vector
    // may only be larger. Without a context, an absent vector uses
    // MAX_ELEMENT_BYTES.
    std::map<uint8_t, std::vector<size_t>> field_sizes;
};
// Same schedule checks used by charged execution; useful for rejecting a local
// configuration before opening chainstate. Does not execute a program.
bool ValidateVmCostProfile(const VmProfile &, const VmCostProfile &, std::string &);
// Owns an immutable transaction/coin/cost snapshot, prepared once before all
// invocations. Contexts must refer to this snapshot's exact objects; a cache
// from another transaction or mutable caller objects is never trusted.
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
enum class VmCryptoFault {
    None,
    Digest,
    P256Context,
    P256Verify,
    EdAllocation
};
void SetVmCryptoFault(VmCryptoFault);
struct VmPreparationCounts { size_t signing = 0; size_t field_sizes = 0; };
VmPreparationCounts VmPreparationWorkCounts();
#endif

class PreparedVmTransaction {
public:
    PreparedVmTransaction() = default;
    // Invocation contexts borrow these members and this object. Keep their
    // addresses stable for the complete lifetime of every borrowed context.
    PreparedVmTransaction(const PreparedVmTransaction &) = delete;
    PreparedVmTransaction &operator=(const PreparedVmTransaction &) = delete;
    PreparedVmTransaction(PreparedVmTransaction &&) = delete;
    PreparedVmTransaction &operator=(PreparedVmTransaction &&) = delete;
    SigningPreparationStatus
    PrepareChecked(const Transaction &, const TxProfile &, const ChainId &,
                   const ResolvedCoins &, const VmCostProfile &, std::string &,
                   const IdentityDigests *precomputed_identities = nullptr);
    bool Prepare(const Transaction &, const TxProfile &, const ChainId &,
                 const ResolvedCoins &, const VmCostProfile &, std::string &);
    // Borrowed contexts are valid until this object is prepared again or
    // destroyed; callers must finish all invocations before either event.
    VmExecutionContext Invocation(size_t input, size_t witness,
        std::optional<PositiveDelta> delta = std::nullopt,
        BatchSigCollector *batch_sigs = nullptr) const {
        return {tx_, profile_, chain_, coins_, input, witness, delta, this,
                batch_sigs};
    }
    const VmCostProfile &Cost() const { return cost_; }
    size_t MaxFieldBound(uint8_t op) const { return field_maxima_[op]; }
    bool TryGetFieldSizeAt(uint8_t op, size_t idx, size_t &out_size) const;
    size_t MaxFieldBound() const { return max_field_bound_; }
    size_t MintCount() const { return mint_count_; }
    const VmAssetTotalsMap &AssetTotals() const { return asset_totals_; }
    const PreparedSigningContext &Signing() const { return signing_; }
    bool Owns(const VmExecutionContext &context) const {
        return ready_ && &context.tx == &tx_ && &context.tx_profile == &profile_ &&
            &context.chain_id == &chain_ && &context.resolved == &coins_;
    }
private:
    Transaction tx_;
    TxProfile profile_{};
    ChainId chain_{};
    ResolvedCoins coins_;
    VmCostProfile cost_;
    PreparedSigningContext signing_;
    std::array<size_t, 256> field_maxima_{};
    size_t max_field_bound_ = 0;
    size_t mint_count_ = 0;
    VmAssetTotalsMap asset_totals_;
    bool ready_ = false;
};

struct VmChargedResult {
    VmResult invocation;
    VmCostUnits accounting_cost = 0;
    VmCostUnits enforcement_cost = 0;
    bool charged = false;
};

// `script` is exact revealed bytecode, `arguments` are already framed witness
// arguments. The caller must authenticate branch membership and enforce all
// transaction-wide bounds before invoking this standalone core.
VmResult EvaluateVm(std::span<const uint8_t> script,
                    const std::vector<VmBytes> &arguments,
                    const VmProfile &profile, uint16_t input_count = 0,
                    uint16_t output_count = 0,
                    BatchSigCollector *batch_sigs = nullptr);

// This overload authenticates the active script/arguments and selected-branch
// membership before OP_SUCCESS scanning. It still requires P05 cost gating and
// transaction-wide validation by the caller. It prepares a signing snapshot
// once per invocation, then reuses it for every SIGHASH/CHECKSIG opcode.
VmResult EvaluateVmWithContext(std::span<const uint8_t> script,
                               const std::vector<VmBytes> &arguments,
                               const VmProfile &profile,
                               const VmExecutionContext &context,
                               BatchSigCollector *batch_sigs = nullptr);

// The genesis accounting/enforcement views currently coincide. This entrypoint
// charges before executing ordinary bytecode and retains structural-only cost
// for a genesis OP_SUCCESS invocation. It does not charge transaction-wide
// resolution, hashing, state or monetary work (P05 L(tx) obligations).
VmChargedResult EvaluateVmCharged(std::span<const uint8_t> script,
                                  const std::vector<VmBytes> &arguments,
                                  const VmProfile &profile,
                                  const VmCostProfile &cost_profile,
                                  uint16_t input_count = 0,
                                  uint16_t output_count = 0,
                                  const VmExecutionContext *context = nullptr,
                                  BatchSigCollector *batch_sigs = nullptr);

} // namespace lotus::v2
#endif

