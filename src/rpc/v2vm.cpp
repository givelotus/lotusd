// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// V2 VM introspection for compilers, wallets and indexers:
//   getv2vmprofile          the opcode allocation, VM limits and costs
//   testv2transaction       strict, non-mutating VM evaluation of a v7 tx
//   simulatev2transaction   the non-consensus simulation evaluator

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <core_io.h>
#include <lotus_v2/output.h>
#include <lotus_v2/output_template.h>
#include <lotus_v2/transaction.h>
#include <lotus_v2/vm.h>
#include <lotus_v2/vm_simulation.h>
#include <node/context.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <validation.h>

#include <univalue.h>

#include <string>
#include <vector>

using node::NodeContext;

namespace {

bool DefaultV2SimulationRpc() {
    return Params().GetChainType() == ChainType::REGTEST;
}

UniValue CostValue(lotus::v2::VmCostUnits cost) {
    if (cost <= std::numeric_limits<uint64_t>::max()) {
        return UniValue(uint64_t(cost));
    }
    return UniValue("overflow");
}

std::string StatusName(lotus::v2::VmStatus status) {
    switch (status) {
        case lotus::v2::VmStatus::Success:
            return "success";
        case lotus::v2::VmStatus::AutomaticSuccess:
            return "automatic-success";
        case lotus::v2::VmStatus::Invalid:
            return "invalid";
        case lotus::v2::VmStatus::Unsupported:
            return "unsupported";
        case lotus::v2::VmStatus::OperationalError:
            return "operational-error";
    }
    return "unknown";
}

UniValue BytesArray(const std::vector<lotus::v2::VmBytes> &items) {
    UniValue out(UniValue::VARR);
    for (const auto &item : items) {
        out.push_back(HexStr(item));
    }
    return out;
}

CMutableTransaction DecodeV7(const std::string &hex) {
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    if (mtx.nVersion != 7) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Not a V2 (version 7) transaction");
    }
    for (const auto &in : mtx.vin) {
        if (in.nFlags == 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "A coinbase runs no scripts");
        }
    }
    return mtx;
}

// The coin spent by each input, from the chain tip and mempool; mints have
// none.
lotus::v2::ResolvedCoins ResolveCoins(const NodeContext &node,
                                      const CMutableTransaction &mtx) {
    const CTxMemPool &mempool = EnsureMemPool(node);
    ChainstateManager &chainman = EnsureChainman(node);
    LOCK2(cs_main, mempool.cs);
    CCoinsViewCache &tip = chainman.ActiveChainstate().CoinsTip();
    CCoinsViewMemPool view(&tip, mempool);
    lotus::v2::ResolvedCoins resolved;
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        if (mtx.vin[i].nFlags == 3) {
            resolved.emplace_back(std::nullopt);
            continue;
        }
        const auto coin = view.GetCoin(mtx.vin[i].prevout);
        if (!coin || coin->IsSpent()) {
            throw JSONRPCError(RPC_VERIFY_ERROR,
                               strprintf("Input %u not found or already spent",
                                         i));
        }
        resolved.emplace_back(coin->GetTxOut().ToV2Output());
    }
    return resolved;
}

std::optional<lotus::v2::PositiveDelta>
MintDelta(const lotus::v2::Transaction &tx,
          const lotus::v2::ResolvedCoins &resolved, size_t input) {
    if (tx.inputs[input].flags != 3) {
        return std::nullopt;
    }
    lotus::v2::VmAssetTotalsMap totals;
    std::string error;
    if (!lotus::v2::ComputeVmAssetTotals(tx, resolved, totals, error)) {
        return std::nullopt;
    }
    const auto found = totals.find(tx.inputs[input].prev_txid);
    if (found == totals.end() || found->second.outputs <= found->second.inputs) {
        return std::nullopt;
    }
    const __uint128_t amount = found->second.outputs - found->second.inputs;
    lotus::v2::PositiveDelta delta{};
    for (size_t b = 0; b < delta.size(); ++b) {
        delta[b] = uint8_t(amount >> (8 * b));
    }
    return delta;
}

UniValue EffectsJson(const lotus::v2::DeferredRecords &effects) {
    UniValue claims(UniValue::VARR);
    for (const auto &record : lotus::v2::OutputClaimsOf(effects)) {
        UniValue claim(UniValue::VOBJ);
        claim.pushKV("output", record.matches.front());
        claim.pushKV("amount", record.amount);
        claims.push_back(claim);
    }
    UniValue authorized(UniValue::VARR);
    for (const auto &record : lotus::v2::StateAuthorizationsOf(effects)) {
        for (const auto output : record.outputs) {
            authorized.push_back(output);
        }
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("claims", claims);
    out.pushKV("state_authorized", authorized);
    return out;
}

UniValue PostCheckJson(const std::vector<lotus::v2::Output> &outputs,
                       std::span<const lotus::v2::DeferredRecords> per_input,
                       size_t input_count, bool &ok) {
    std::string error;
    ok = lotus::v2::RunDeferredChecks(
             lotus::v2::DeferredCheckRegistry::Consensus(),
             lotus::v2::DeferredTxView{outputs, input_count}, per_input,
             error) == lotus::v2::DeferredOutcome::Accepted;
    if (ok) {
        error.clear();
    }
    UniValue claimed(UniValue::VARR);
    std::vector<__uint128_t> sums(outputs.size());
    for (const auto &records : per_input) {
        for (const auto &claim : lotus::v2::OutputClaimsOf(records)) {
            if (claim.matches.front() < sums.size()) {
                sums[claim.matches.front()] += claim.amount;
            }
        }
    }
    for (size_t j = 0; j < outputs.size(); ++j) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("output", uint64_t(j));
        entry.pushKV("value", outputs[j].value);
        entry.pushKV("claimed", CostValue(sums[j]));
        entry.pushKV("unclaimed",
                     sums[j] <= outputs[j].value
                         ? UniValue(uint64_t(outputs[j].value - sums[j]))
                         : UniValue(0));
        claimed.push_back(entry);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("ok", ok);
    out.pushKV("error", error);
    out.pushKV("outputs", claimed);
    return out;
}

const RPCResult POST_CHECK_RESULT{
    RPCResult::Type::OBJ,
    "post_check",
    "The per-transaction ENFORCEOUTPUT/state post-check",
    {
        {RPCResult::Type::BOOL, "ok", "Whether it passes"},
        {RPCResult::Type::STR, "error", "The failure, or empty"},
        {RPCResult::Type::ARR,
         "outputs",
         "Claims per output",
         {{RPCResult::Type::OBJ,
           "",
           "",
           {{RPCResult::Type::NUM, "output", "Output index"},
            {RPCResult::Type::NUM, "value", "Output value"},
            {RPCResult::Type::NUM, "claimed", "Sum of claims"},
            {RPCResult::Type::NUM, "unclaimed",
             "value - claimed, or 0 when over-claimed"}}}}},
    }};

RPCHelpMan getv2vmprofile() {
    return RPCHelpMan{
        "getv2vmprofile",
        "Returns this node's V2 VM opcode allocation, limits and cost "
        "schedule. The digest identifies the target profile for compiled "
        "artifacts.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "registry_sha256",
                 "SHA-256 of the opcode registry snapshot (opcodes.json)"},
                {RPCResult::Type::ARR,
                 "opcodes",
                 "Every single-byte opcode",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::STR_HEX, "byte", "The byte"},
                    {RPCResult::Type::STR, "class",
                     "success, assigned, simulation-only or ext2-prefix"}}}}},
                {RPCResult::Type::ARR,
                 "ext2_assigned",
                 "Assigned two-byte ff xx selectors",
                 {{RPCResult::Type::STR_HEX, "", "Selector"}}},
                {RPCResult::Type::OBJ_DYN,
                 "vm_profile",
                 "VM limits",
                 {{RPCResult::Type::NUM, "limit", "Value"}}},
                {RPCResult::Type::OBJ,
                 "cost_profile",
                 "Cost schedule",
                 {{RPCResult::Type::NUM, "max_invocation_cost", ""},
                  {RPCResult::Type::NUM, "structural_byte_cost", ""},
                  {RPCResult::Type::ARR,
                   "opcodes",
                   "Costed single-byte opcodes",
                   {{RPCResult::Type::OBJ,
                     "",
                     "",
                     {{RPCResult::Type::STR_HEX, "byte", ""},
                      {RPCResult::Type::NUM, "base", ""},
                      {RPCResult::Type::NUM, "per_operand_byte", ""},
                      {RPCResult::Type::NUM, "per_result_byte", ""},
                      {RPCResult::Type::NUM, "per_scanned_output", ""}}}}}}},
                {RPCResult::Type::STR_HEX, "profile_digest",
                 "Commitment to vm_profile and cost_profile"},
                {RPCResult::Type::OBJ_DYN,
                 "limits",
                 "Transaction, loop and template limits",
                 {{RPCResult::Type::NUM, "limit", "Value"}}},
                {RPCResult::Type::BOOL, "simulation_rpc",
                 "Whether simulatev2transaction is enabled"},
            }},
        RPCExamples{HelpExampleCli("getv2vmprofile", "") +
                    HelpExampleRpc("getv2vmprofile", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const auto &vm = NodeV2VmProfile();
            const auto &cost = NodeV2VmCost();
            UniValue opcodes(UniValue::VARR);
            for (unsigned op = 0; op < 256; ++op) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("byte", strprintf("%02x", op));
                switch (lotus::v2::ClassifyVmOpcode(uint8_t(op))) {
                    case lotus::v2::VmOpcodeClass::Success:
                        entry.pushKV("class", "success");
                        break;
                    case lotus::v2::VmOpcodeClass::Assigned:
                        entry.pushKV("class", "assigned");
                        break;
                    case lotus::v2::VmOpcodeClass::SimulationOnly:
                        entry.pushKV("class", "simulation-only");
                        break;
                    case lotus::v2::VmOpcodeClass::Ext2Prefix:
                        entry.pushKV("class", "ext2-prefix");
                        break;
                }
                opcodes.push_back(entry);
            }
            UniValue ext2(UniValue::VARR);
            for (unsigned selector = 0; selector < 256; ++selector) {
                if (lotus::v2::IsVmExt2Assigned(uint8_t(selector))) {
                    ext2.push_back(strprintf("%02x", selector));
                }
            }
            UniValue vm_json(UniValue::VOBJ);
            vm_json.pushKV("max_script_bytes", uint64_t(vm.max_script_bytes));
            vm_json.pushKV("max_arguments", uint64_t(vm.max_arguments));
            vm_json.pushKV("max_element_bytes", uint64_t(vm.max_element_bytes));
            vm_json.pushKV("max_stack_items", uint64_t(vm.max_stack_items));
            vm_json.pushKV("max_altstack_items",
                           uint64_t(vm.max_altstack_items));
            vm_json.pushKV("max_vm_bytes", uint64_t(vm.max_vm_bytes));
            vm_json.pushKV("max_ast_depth", uint64_t(vm.max_ast_depth));
            vm_json.pushKV("max_steps", uint64_t(vm.max_steps));
            UniValue costed(UniValue::VARR);
            for (unsigned op = 0; op < 256; ++op) {
                const auto &c = cost.opcode[op];
                if (!c.base && !c.per_operand_byte && !c.per_result_byte &&
                    !c.per_scanned_output) {
                    continue;
                }
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("byte", strprintf("%02x", op));
                entry.pushKV("base", c.base);
                entry.pushKV("per_operand_byte", c.per_operand_byte);
                entry.pushKV("per_result_byte", c.per_result_byte);
                entry.pushKV("per_scanned_output", c.per_scanned_output);
                costed.push_back(entry);
            }
            UniValue cost_json(UniValue::VOBJ);
            cost_json.pushKV("max_invocation_cost",
                             CostValue(cost.max_invocation_cost));
            cost_json.pushKV("structural_byte_cost", cost.structural_byte_cost);
            cost_json.pushKV("opcodes", costed);
            const auto digest = lotus::v2::VmProfileDigest(vm, cost);
            UniValue limits(UniValue::VOBJ);
            limits.pushKV("max_inputs",
                          uint64_t(lotus::v2::DefaultTxProfile.max_inputs));
            limits.pushKV("max_outputs",
                          uint64_t(lotus::v2::DefaultTxProfile.max_outputs));
            limits.pushKV("max_enumerate", 256);
            limits.pushKV("max_statehash_items", 64);
            limits.pushKV("max_emitlog_items",
                          uint64_t(lotus::v2::VM_EMITLOG_MAX_ITEMS));
            limits.pushKV("max_output_branches",
                          uint64_t(lotus::v2::MAX_OUTPUT_BRANCHES));
            limits.pushKV("max_output_paths",
                          uint64_t(lotus::v2::MAX_OUTPUT_PATHS));
            limits.pushKV("max_output_bytes",
                          uint64_t(lotus::v2::MAX_OUTPUT_BYTES));
            UniValue result(UniValue::VOBJ);
            result.pushKV("registry_sha256",
                          lotus::v2::VM_OPCODE_REGISTRY_SHA256);
            result.pushKV("opcodes", opcodes);
            result.pushKV("ext2_assigned", ext2);
            result.pushKV("vm_profile", vm_json);
            result.pushKV("cost_profile", cost_json);
            result.pushKV("profile_digest", HexStr(digest));
            result.pushKV("limits", limits);
            result.pushKV("simulation_rpc",
                          gArgs.GetBoolArg("-v2simulationrpc",
                                           DefaultV2SimulationRpc()));
            return result;
        },
    };
}

RPCHelpMan testv2transaction() {
    return RPCHelpMan{
        "testv2transaction",
        "Evaluates every V2 VM invocation of a version 7 transaction against "
        "the current chain tip and mempool, without changing node state. "
        "This checks scripts, costs and the ENFORCEOUTPUT/state post-check "
        "only; fees, finality and mempool policy are not checked.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The serialized version 7 transaction"},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::BOOL, "valid",
                 "Every invocation succeeded and the post-check passed"},
                {RPCResult::Type::STR, "error",
                 "Preparation failure (witness membership or context), or "
                 "empty"},
                {RPCResult::Type::ARR,
                 "invocations",
                 "Input-ascending, then witness-ascending",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::NUM, "input", ""},
                    {RPCResult::Type::NUM, "witness", ""},
                    {RPCResult::Type::STR, "status", ""},
                    {RPCResult::Type::STR, "error", ""},
                    {RPCResult::Type::NUM, "accounting_cost",
                     "The static cost charged"},
                    {RPCResult::Type::NUM, "executed_cost",
                     "The cost of the executed path (informational)"},
                    {RPCResult::Type::OBJ,
                     "effects",
                     "ENFORCEOUTPUT claims and state authorizations",
                     {{RPCResult::Type::ELISION, "", ""}}}}}}},
                POST_CHECK_RESULT,
            }},
        RPCExamples{HelpExampleCli("testv2transaction", "\"hex\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const CMutableTransaction mtx =
                DecodeV7(request.params[0].get_str());
            const NodeContext &node = EnsureAnyNodeContext(request.context);
            const auto resolved = ResolveCoins(node, mtx);
            const lotus::v2::Transaction tx = mtx.ToV2Transaction();
            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", CTransaction(mtx).GetId().GetHex());
            lotus::v2::PreparedVmTransaction prepared;
            std::string error;
            if (prepared.PrepareChecked(tx, lotus::v2::DefaultTxProfile,
                                        GetActiveV2ChainId(), resolved,
                                        NodeV2VmCost(), error) !=
                lotus::v2::SigningPreparationStatus::Ready) {
                result.pushKV("valid", false);
                result.pushKV("error", error);
                result.pushKV("invocations", UniValue(UniValue::VARR));
                bool ok = false;
                result.pushKV("post_check",
                              PostCheckJson(tx.outputs, {}, tx.inputs.size(),
                                            ok));
                return result;
            }
            bool valid = true;
            // Records of the successful invocations, per input; the
            // deferred checks run over them sequentially, as in mempool
            // acceptance.
            std::vector<lotus::v2::DeferredRecords> per_input(
                tx.inputs.size());
            UniValue invocations(UniValue::VARR);
            for (size_t i = 0; i < tx.inputs.size(); ++i) {
                const auto delta = MintDelta(tx, resolved, i);
                for (size_t j = 0; j < tx.inputs[i].witnesses.size(); ++j) {
                    const auto &witness = tx.inputs[i].witnesses[j];
                    lotus::v2::DeferredRecords effects;
                    auto context = prepared.Invocation(i, j, delta, nullptr);
                    context.effects = &effects;
                    const auto vm = lotus::v2::EvaluateVmCharged(
                        witness.script, witness.arguments, NodeV2VmProfile(),
                        prepared.Cost(), uint16_t(tx.inputs.size()),
                        uint16_t(tx.outputs.size()), &context);
                    const bool ok =
                        (vm.invocation.status ==
                             lotus::v2::VmStatus::Success ||
                         vm.invocation.status ==
                             lotus::v2::VmStatus::AutomaticSuccess) &&
                        vm.charged;
                    valid &= ok;
                    per_input[i].Merge(effects);
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("input", uint64_t(i));
                    entry.pushKV("witness", uint64_t(j));
                    entry.pushKV("status", StatusName(vm.invocation.status));
                    entry.pushKV("error", vm.invocation.error);
                    entry.pushKV("accounting_cost",
                                 CostValue(vm.accounting_cost));
                    entry.pushKV("executed_cost",
                                 CostValue(vm.invocation.executed_cost));
                    entry.pushKV("effects", EffectsJson(effects));
                    invocations.push_back(entry);
                }
            }
            bool post_ok = false;
            UniValue post = PostCheckJson(tx.outputs, per_input,
                                          tx.inputs.size(), post_ok);
            result.pushKV("valid", valid && post_ok);
            result.pushKV("error", "");
            result.pushKV("invocations", invocations);
            result.pushKV("post_check", post);
            return result;
        },
    };
}

RPCHelpMan simulatev2transaction() {
    return RPCHelpMan{
        "simulatev2transaction",
        "Runs the non-consensus V2 simulation evaluator over a draft version "
        "7 transaction, which may lack outputs and signatures. EMITLOG "
        "events are recorded; an ENFORCEOUTPUT with no matching output "
        "appends a draft output built from its template. Requires "
        "-v2simulationrpc (default on regtest only).\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The serialized draft version 7 transaction"},
            {"options",
             RPCArg::Type::OBJ,
             RPCArg::Optional::OMITTED,
             "",
             {
                 {"assume_valid_signatures", RPCArg::Type::BOOL,
                  RPCArg::Default{false},
                  "Accept any correctly framed nonempty signature and report "
                  "a signing request"},
             }},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "hex",
                 "The draft with every appended output"},
                {RPCResult::Type::BOOL, "provisional",
                 "Drafts were appended or a mint delta was assumed, so "
                 "TXID, SIGHASH, output introspection and counts seen by "
                 "scripts may change"},
                {RPCResult::Type::ARR,
                 "invocations",
                 "",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::NUM, "input", ""},
                    {RPCResult::Type::NUM, "witness", ""},
                    {RPCResult::Type::STR, "status", ""},
                    {RPCResult::Type::STR, "error", ""},
                    {RPCResult::Type::NUM, "executed_cost",
                     "Unit execution cost"},
                    {RPCResult::Type::BOOL, "provisional_delta",
                     "The mint delta was unknown and 1 was used"}}}}},
                {RPCResult::Type::ARR,
                 "events",
                 "EMITLOG events",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::NUM, "input", ""},
                    {RPCResult::Type::NUM, "witness", ""},
                    {RPCResult::Type::NUM, "instruction",
                     "Instruction index"},
                    {RPCResult::Type::ARR,
                     "items",
                     "item_1..item_k",
                     {{RPCResult::Type::STR_HEX, "", ""}}},
                    {RPCResult::Type::STR_HEX, "topic",
                     "The last item, or empty"}}}}},
                {RPCResult::Type::ARR,
                 "drafts",
                 "Outputs appended by ENFORCEOUTPUT",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::NUM, "output", "Output index"},
                    {RPCResult::Type::NUM, "input", ""},
                    {RPCResult::Type::NUM, "witness", ""},
                    {RPCResult::Type::STR_HEX, "template", ""},
                    {RPCResult::Type::ARR,
                     "popped",
                     "Template operands in pop order",
                     {{RPCResult::Type::STR_HEX, "", ""}}},
                    {RPCResult::Type::NUM, "claim", ""},
                    {RPCResult::Type::ARR,
                     "placeholder_slots",
                     "Branch slots the wallet must fill",
                     {{RPCResult::Type::NUM, "", ""}}},
                    {RPCResult::Type::BOOL, "wallet_fill_required", ""},
                    {RPCResult::Type::NUM, "draft_event", /*optional=*/true,
                     "Index of the preceding lotus.output.draft event"}}}}},
                {RPCResult::Type::ARR,
                 "signing_requests",
                 "Signatures assumed valid",
                 {{RPCResult::Type::OBJ,
                   "",
                   "",
                   {{RPCResult::Type::NUM, "input", ""},
                    {RPCResult::Type::NUM, "witness", ""},
                    {RPCResult::Type::STR, "kind", "transaction or data"},
                    {RPCResult::Type::NUM, "mode",
                     "Sighash mode, or CHECKDATASIG algorithm"},
                    {RPCResult::Type::STR_HEX, "key", ""},
                    {RPCResult::Type::STR_HEX, "message",
                     "The message to sign"}}}}},
                {RPCResult::Type::OBJ,
                 "post_check",
                 "Reported, not enforced",
                 {{RPCResult::Type::ELISION, "", ""}}},
            }},
        RPCExamples{HelpExampleCli("simulatev2transaction", "\"hex\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            if (!gArgs.GetBoolArg("-v2simulationrpc",
                                  DefaultV2SimulationRpc())) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "simulatev2transaction is disabled (use "
                                   "-v2simulationrpc=1)");
            }
            const CMutableTransaction mtx =
                DecodeV7(request.params[0].get_str());
            lotus::v2::SimOptions options;
            if (!request.params[1].isNull()) {
                const UniValue &opts = request.params[1].get_obj();
                if (opts.exists("assume_valid_signatures") &&
                    opts["assume_valid_signatures"].get_bool()) {
                    options.signatures =
                        lotus::v2::SimSignatures::AssumeValid;
                }
            }
            const NodeContext &node = EnsureAnyNodeContext(request.context);
            lotus::v2::SimTransaction draft;
            draft.tx = mtx.ToV2Transaction();
            draft.resolved = ResolveCoins(node, mtx);
            draft.tx_profile = lotus::v2::DefaultTxProfile;
            draft.chain_id = GetActiveV2ChainId();
            draft.vm = NodeV2VmProfile();
            const auto sim = lotus::v2::EvaluateVmSimulated(draft, options);

            UniValue invocations(UniValue::VARR);
            for (const auto &invocation : sim.invocations) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("input", invocation.input);
                entry.pushKV("witness", invocation.witness);
                entry.pushKV("status", StatusName(invocation.status));
                entry.pushKV("error", invocation.error);
                entry.pushKV("executed_cost",
                             CostValue(invocation.executed_cost));
                entry.pushKV("provisional_delta",
                             invocation.provisional_delta);
                invocations.push_back(entry);
            }
            UniValue events(UniValue::VARR);
            for (const auto &event : sim.events) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("input", event.input);
                entry.pushKV("witness", event.witness);
                entry.pushKV("instruction", event.instruction);
                entry.pushKV("items", BytesArray(event.items));
                entry.pushKV("topic", event.items.empty()
                                          ? std::string{}
                                          : HexStr(event.items.back()));
                events.push_back(entry);
            }
            UniValue drafts(UniValue::VARR);
            for (const auto &d : sim.drafts) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("output", d.output);
                entry.pushKV("input", d.input);
                entry.pushKV("witness", d.witness);
                entry.pushKV("template", HexStr(d.template_bytes));
                entry.pushKV("popped", BytesArray(d.popped));
                entry.pushKV("claim", d.claim);
                UniValue slots(UniValue::VARR);
                for (const auto slot : d.placeholder_slots) {
                    slots.push_back(slot);
                }
                entry.pushKV("placeholder_slots", slots);
                entry.pushKV("wallet_fill_required", d.wallet_fill_required);
                if (d.draft_event) {
                    entry.pushKV("draft_event", uint64_t(*d.draft_event));
                }
                drafts.push_back(entry);
            }
            UniValue requests(UniValue::VARR);
            for (const auto &r : sim.signing_requests) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("input", r.input);
                entry.pushKV("witness", r.witness);
                entry.pushKV("kind", r.data ? "data" : "transaction");
                entry.pushKV("mode", r.mode);
                entry.pushKV("key", HexStr(r.key));
                entry.pushKV("message", HexStr(r.message));
                requests.push_back(entry);
            }
            bool post_ok = false;
            UniValue result(UniValue::VOBJ);
            result.pushKV(
                "hex",
                EncodeHexTx(CTransaction(
                    CMutableTransaction::FromV2Transaction(sim.tx))));
            result.pushKV("provisional", sim.provisional);
            result.pushKV("invocations", invocations);
            result.pushKV("events", events);
            result.pushKV("drafts", drafts);
            result.pushKV("signing_requests", requests);
            result.pushKV("post_check",
                          PostCheckJson(sim.tx.outputs, sim.input_effects,
                                        sim.tx.inputs.size(), post_ok));
            return result;
        },
    };
}

} // namespace

void RegisterV2VmRPCCommands(CRPCTable &t) {
    // clang-format off
    static const CRPCCommand commands[] = {
        //  category            actor (function)
        //  ------------------  ----------------------
        { "rawtransactions",    getv2vmprofile,          },
        { "rawtransactions",    testv2transaction,       },
        { "rawtransactions",    simulatev2transaction,   },
    };
    // clang-format on
    for (const auto &c : commands) {
        t.appendCommand(c.name, &c);
    }
}
