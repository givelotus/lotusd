// Copyright (c) 2026 The Lotus developers
// Non-consensus simulation evaluator for wallets, compilers and RPC.
//
// Simulation runs every invocation of a draft transaction (which may have no
// outputs and unsigned witnesses) through the consensus VM with three
// differences, all unreachable from the consensus entrypoints in vm.h:
//   - EMITLOG (0x6c) executes and records an event instead of rejecting at
//     scan time;
//   - an ENFORCEOUTPUT whose template finds no matching output (and does not
//     pin an output index) appends a draft output built from the template
//     and matches that;
//   - with SimSignatures::AssumeValid, a correctly framed nonempty signature
//     passes and is reported as a signing request.
// The per-transaction post-check is reported, not enforced. Nothing here
// changes consensus validation, and no simulation result enters a digest.
#ifndef LOTUS_V2_VM_SIMULATION_H
#define LOTUS_V2_VM_SIMULATION_H

#include "vm.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lotus::v2 {

// EMITLOG pops N(k) and then k items, k in 0..VM_EMITLOG_MAX_ITEMS.
inline constexpr size_t VM_EMITLOG_MAX_ITEMS = 64;

enum class SimSignatures { Verify, AssumeValid };

struct SimOptions {
    SimSignatures signatures = SimSignatures::Verify;
};

struct SimTransaction {
    Transaction tx;
    ResolvedCoins resolved;
    TxProfile tx_profile;
    ChainId chain_id{};
    VmProfile vm;
};

struct SimEvent {
    uint16_t input = 0;
    uint16_t witness = 0;
    // Index of the EMITLOG instruction in the decoded instruction list.
    uint32_t instruction = 0;
    // item_1..item_k; the topic is the last (top-of-stack) item.
    std::vector<VmBytes> items;
};

struct SimDraft {
    uint16_t output = 0;
    uint16_t input = 0;
    uint16_t witness = 0;
    VmBytes template_bytes;
    // Template-directed stack operands, in pop order.
    std::vector<VmBytes> popped;
    uint64_t claim = 0;
    // Slots holding a placeholder root the wallet must replace.
    std::vector<uint8_t> placeholder_slots;
    bool wallet_fill_required = false;
    // The most recent event of the same invocation whose topic is
    // "lotus.output.draft", if any (an index into SimulationResult::events).
    std::optional<size_t> draft_event;
};

struct SimSigningRequest {
    uint16_t input = 0;
    uint16_t witness = 0;
    // false: CHECKSIG/CHECKSIGVERIFY with `mode` the sighash mode. true:
    // CHECKDATASIG with `mode` the algorithm.
    bool data = false;
    uint8_t mode = 0;
    VmBytes key;
    // The message the signature must cover. For a transaction signature it
    // is provisional whenever drafts were appended.
    Hash message{};
};

struct SimInvocation {
    uint16_t input = 0;
    uint16_t witness = 0;
    VmStatus status = VmStatus::Invalid;
    std::string error;
    VmCostUnits executed_cost = 0;
    // The mint delta was unknown (no positive token delta yet) and 1 was
    // supplied instead.
    bool provisional_delta = false;
};

struct SimulationResult {
    // The draft transaction with every appended draft output.
    Transaction tx;
    std::vector<SimInvocation> invocations;
    std::vector<SimEvent> events;
    std::vector<SimDraft> drafts;
    std::vector<SimSigningRequest> signing_requests;
    // Deferred-check records of every successful invocation, in consensus
    // order.
    DeferredRecords effects;
    // The same records grouped by input, as the deferred checks see them.
    std::vector<DeferredRecords> input_effects;
    // TXID, SIGHASH, output introspection and counts observed by scripts
    // may differ from the final transaction's: drafts were appended or a
    // mint delta was supplied provisionally.
    bool provisional = false;
    bool post_check_ok = false;
    std::string post_check_error;
};

// Runs invocations input-ascending, then witness-ascending, as consensus
// does. Each invocation sees the drafts appended by earlier ones.
SimulationResult EvaluateVmSimulated(const SimTransaction &draft,
                                     const SimOptions &options);

namespace detail {
    // Callbacks from the VM in simulation mode. Only vm_simulation.cpp
    // implements them; consensus paths pass none.
    class VmSimulationHooks {
    public:
        virtual ~VmSimulationHooks() = default;
        virtual void EmitLog(uint32_t instruction,
                             std::vector<VmBytes> items) = 0;
        virtual bool AssumeSignatures() const = 0;
        virtual void SigningRequest(bool data, uint8_t mode,
                                    const VmBytes &key,
                                    const Hash &message) = 0;
        // Appends `output` to the transaction the context refers to and
        // returns its index.
        virtual size_t AppendDraft(Output output, VmBytes template_bytes,
                                   std::vector<VmBytes> popped,
                                   uint64_t claim,
                                   std::vector<uint8_t> placeholder_slots) = 0;
    };
    // One invocation in simulation mode, with no cost profile (unit
    // execution costs). The context's effects pointer must be set.
    VmResult EvaluateVmSimulationInvocation(
        std::span<const uint8_t> script, const std::vector<VmBytes> &arguments,
        const VmProfile &profile, const VmExecutionContext &context,
        VmSimulationHooks &hooks);
} // namespace detail

} // namespace lotus::v2

#endif
