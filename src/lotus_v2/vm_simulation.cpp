// Copyright (c) 2026 The Lotus developers
#include "vm_simulation.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace lotus::v2 {
namespace {
    constexpr std::string_view kDraftTopic = "lotus.output.draft";

    class Simulation final : public detail::VmSimulationHooks {
    public:
        Simulation(SimulationResult &result, const SimOptions &options)
            : result_(result), options_(options) {}
        void Begin(uint16_t input, uint16_t witness) {
            input_ = input;
            witness_ = witness;
            draft_event_.reset();
        }
        void EmitLog(uint32_t instruction,
                     std::vector<VmBytes> items) override {
            if (!items.empty() &&
                std::string_view(
                    reinterpret_cast<const char *>(items.back().data()),
                    items.back().size()) == kDraftTopic)
                draft_event_ = result_.events.size();
            result_.events.push_back(
                {input_, witness_, instruction, std::move(items)});
        }
        bool AssumeSignatures() const override {
            return options_.signatures == SimSignatures::AssumeValid;
        }
        void SigningRequest(bool data, uint8_t mode, const VmBytes &key,
                            const Hash &message) override {
            result_.signing_requests.push_back(
                {input_, witness_, data, mode, key, message});
        }
        size_t AppendDraft(Output output, VmBytes template_bytes,
                           std::vector<VmBytes> popped, uint64_t claim,
                           std::vector<uint8_t> placeholders) override {
            const size_t index = result_.tx.outputs.size();
            result_.tx.outputs.push_back(std::move(output));
            SimDraft draft;
            draft.output = uint16_t(index);
            draft.input = input_;
            draft.witness = witness_;
            draft.template_bytes = std::move(template_bytes);
            draft.popped = std::move(popped);
            draft.claim = claim;
            draft.wallet_fill_required = !placeholders.empty();
            draft.placeholder_slots = std::move(placeholders);
            draft.draft_event = draft_event_;
            result_.drafts.push_back(std::move(draft));
            return index;
        }

    private:
        SimulationResult &result_;
        const SimOptions &options_;
        uint16_t input_ = 0;
        uint16_t witness_ = 0;
        std::optional<size_t> draft_event_;
    };

    // The mint's positive delta over the current draft, if there is one.
    std::optional<PositiveDelta> MintDelta(const Transaction &tx,
                                           const ResolvedCoins &resolved,
                                           const Hash32 &token_id) {
        __uint128_t in = 0, out = 0;
        for (size_t i = 0; i < tx.inputs.size() && i < resolved.size(); ++i)
            if (resolved[i] && resolved[i]->HasToken() &&
                resolved[i]->token_id == token_id)
                in += resolved[i]->value;
        for (const auto &output : tx.outputs)
            if (output.HasToken() && output.token_id == token_id)
                out += output.value;
        if (out <= in) return std::nullopt;
        PositiveDelta delta{};
        const __uint128_t amount = out - in;
        for (size_t b = 0; b < delta.size(); ++b)
            delta[b] = uint8_t(amount >> (8 * b));
        return delta;
    }
} // namespace

SimulationResult EvaluateVmSimulated(const SimTransaction &draft,
                                     const SimOptions &options) {
    SimulationResult result;
    result.tx = draft.tx;
    Simulation hooks(result, options);
    for (size_t i = 0; i < result.tx.inputs.size(); ++i) {
        for (size_t j = 0; j < result.tx.inputs[i].witnesses.size(); ++j) {
            // Copy the witness: drafts appended during the invocation may
            // not reallocate the bytes being executed.
            const BranchWitness witness = result.tx.inputs[i].witnesses[j];
            SimInvocation invocation;
            invocation.input = uint16_t(i);
            invocation.witness = uint16_t(j);
            std::optional<PositiveDelta> delta;
            if (result.tx.inputs[i].flags == 3) {
                delta = MintDelta(result.tx, draft.resolved,
                                  result.tx.inputs[i].prev_txid);
                if (!delta) {
                    delta = PositiveDelta{};
                    (*delta)[0] = 1;
                    invocation.provisional_delta = true;
                }
            }
            // A failed invocation leaves no drafts or signing requests (its
            // events stay, for diagnosis), like its discarded effects.
            const size_t outputs_before = result.tx.outputs.size();
            const size_t drafts_before = result.drafts.size();
            const size_t requests_before = result.signing_requests.size();
            hooks.Begin(invocation.input, invocation.witness);
            VmExecutionContext context{result.tx,       draft.tx_profile,
                                       draft.chain_id,  draft.resolved,
                                       i,               j,
                                       delta};
            context.effects = &result.effects;
            const auto vm = detail::EvaluateVmSimulationInvocation(
                witness.script, witness.arguments, draft.vm, context, hooks);
            invocation.status = vm.status;
            invocation.error = vm.error;
            invocation.executed_cost = vm.executed_cost;
            if (vm.status != VmStatus::Success &&
                vm.status != VmStatus::AutomaticSuccess) {
                result.tx.outputs.resize(outputs_before);
                result.drafts.resize(drafts_before);
                result.signing_requests.resize(requests_before);
            }
            result.invocations.push_back(std::move(invocation));
        }
    }
    result.provisional =
        !result.drafts.empty() ||
        std::any_of(result.invocations.begin(), result.invocations.end(),
                    [](const SimInvocation &invocation) {
                        return invocation.provisional_delta;
                    });
    result.post_check_ok = FinalizeVmTransactionEffects(
        result.tx.outputs, result.effects, result.post_check_error);
    return result;
}

} // namespace lotus::v2
