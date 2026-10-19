// Copyright (c) 2026 The Lotus developers
// Simulation evaluator (vm_simulation.h): EMITLOG events, constructive
// ENFORCEOUTPUT drafts, assumed signatures and the reported post-check.
#include "vm_simulation.h"

#include "commitment.h"
#include "tagged_hash.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
const TxProfile TX_PROFILE{32, 32, 8, 8192, 16, 8192, 64};
const VmProfile VM{4096, 16, 1024, 64, 16, 65536, 16, 100000};

VmBytes Hex(std::string hex) {
    hex.erase(std::remove(hex.begin(), hex.end(), ' '), hex.end());
    CHECK(hex.size() % 2 == 0);
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("hex");
    };
    VmBytes out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back((digit(hex[i]) << 4) | digit(hex[i + 1]));
    return out;
}
VmBytes Num(uint64_t n) {
    VmBytes out(16);
    for (size_t i = 0; i < 8; ++i) out[i] = uint8_t(n >> (8 * i));
    return out;
}
Hash Fill(uint8_t b) {
    Hash h;
    h.fill(b);
    return h;
}
void Push(VmBytes &script, const VmBytes &data) {
    if (data.empty()) {
        script.insert(script.end(), {0x4c, 0x00});
    } else if (data.size() <= 75) {
        script.push_back(uint8_t(data.size()));
    } else {
        CHECK(data.size() <= 255);
        script.insert(script.end(), {0x4c, uint8_t(data.size())});
    }
    script.insert(script.end(), data.begin(), data.end());
}
void Append(VmBytes &script, const VmBytes &tail) {
    script.insert(script.end(), tail.begin(), tail.end());
}
VmBytes Text(const std::string &text) { return VmBytes(text.begin(), text.end()); }

// OutputTemplate bytes (output_template.h) for the fields used here.
struct Tpl {
    uint8_t value_mode = 0, token_mode = 0, paths_mode = 0;
    bool burn = false, wildcard = false;
    uint64_t value = 0;
    uint8_t branch_count = 0;
    uint16_t mask = 0;
    uint8_t state_mode = 0, output_mode = 0;
    std::vector<Hash> branches;
    uint16_t output_index = 0;
};
VmBytes Encode(const Tpl &t) {
    VmBytes out{uint8_t(t.value_mode | t.token_mode << 2 | t.paths_mode << 4 |
                        uint8_t(t.burn) << 6 | uint8_t(t.wildcard) << 7)};
    auto le = [&](uint64_t v, size_t width) {
        for (size_t i = 0; i < width; ++i) out.push_back(uint8_t(v >> (8 * i)));
    };
    if (t.value_mode == 1 || t.value_mode == 2) le(t.value, 8);
    le(t.branch_count, 1);
    le(t.mask, 2);
    le(0, 2);
    le(t.state_mode, 1);
    le(t.output_mode, 1);
    if (t.output_mode == 1) le(t.output_index, 2);
    for (const auto &b : t.branches) out.insert(out.end(), b.begin(), b.end());
    return out;
}
// `[prefix] <template> <claim> ENFORCEOUTPUT DROP(j) [extra] TRUE`
VmBytes Enforce(const Tpl &t, uint64_t claim, const VmBytes &prefix = {},
                const VmBytes &extra = {}) {
    VmBytes script = prefix;
    Push(script, Encode(t));
    Push(script, Num(claim));
    script.insert(script.end(), {0xeb, 0x79});
    Append(script, extra);
    script.push_back(0x4e);
    return script;
}

// Draft with one spend input per script; each coin has a single branch.
SimTransaction Draft(const std::vector<VmBytes> &scripts,
                     uint64_t coin_value = 1000) {
    SimTransaction draft;
    draft.tx_profile = TX_PROFILE;
    draft.vm = VM;
    for (size_t i = 0; i < scripts.size(); ++i) {
        Input input;
        input.flags = 1;
        input.prev_txid = Fill(uint8_t(0x80 + i));
        input.sequence = UINT32_MAX;
        input.witnesses = {BranchWitness{scripts[i], {}, {}}};
        draft.tx.inputs.push_back(input);
        Output coin;
        coin.value = coin_value;
        coin.branches = {BranchLeaf(scripts[i])};
        coin.paths = {{0}};
        draft.resolved.push_back(coin);
    }
    return draft;
}
bool AllSucceeded(const SimulationResult &r, int line = __builtin_LINE()) {
    for (const auto &invocation : r.invocations)
        if (invocation.status != VmStatus::Success)
            throw std::runtime_error("line " + std::to_string(line) + ": invocation " +
                                     std::to_string(invocation.input) + ": " +
                                     invocation.error);
    return true;
}

void EmitLogIsSimulationOnly() {
    // "ab" N(1) EMITLOG TRUE.
    const VmBytes script = Hex("01ab 4e 6c 4e");
    CHECK(EvaluateVm(script, {}, VM).error == "EMITLOG is invalid on-chain");
    auto draft = Draft({script});
    VmExecutionContext context{draft.tx, draft.tx_profile, draft.chain_id,
                               draft.resolved, 0, 0, std::nullopt};
    CHECK(EvaluateVmWithContext(script, {}, VM, context).status ==
          VmStatus::Invalid);
    const auto r = EvaluateVmSimulated(draft, {});
    CHECK(AllSucceeded(r) && r.events.size() == 1);
    CHECK(r.events[0].input == 0 && r.events[0].instruction == 2 &&
          r.events[0].items == std::vector<VmBytes>{Hex("ab")});
    // k = 0 records an empty event; items are in push order, topic last.
    const auto zero = EvaluateVmSimulated(Draft({Hex("00 6c 4e")}), {});
    CHECK(AllSucceeded(zero) && zero.events[0].items.empty());
    const auto two = EvaluateVmSimulated(Draft({Hex("01aa 01bb 4f 6c 4e")}), {});
    CHECK(AllSucceeded(two) &&
          two.events[0].items == (std::vector<VmBytes>{Hex("aa"), Hex("bb")}));
    // Bounds: k in 0..64, with k items present.
    VmBytes over;
    Push(over, Num(65));
    over.insert(over.end(), {0x6c, 0x4e});
    CHECK(EvaluateVmSimulated(Draft({over}), {}).invocations[0].error ==
          "EMITLOG item count");
    CHECK(EvaluateVmSimulated(Draft({Hex("01aa 4f 6c 4e")}), {})
              .invocations[0]
              .error == "stack underflow");
    // A rejected invocation keeps its events but no other result.
    const auto failed = EvaluateVmSimulated(Draft({Hex("01ab 4e 6c 00")}), {});
    CHECK(failed.invocations[0].status == VmStatus::Invalid &&
          failed.events.size() == 1);
}

void ConstructiveEnforceOutput() {
    // A zero-output draft: OMIT value takes the claim; OMIT paths give the
    // single path over every slot.
    Tpl pinned;
    pinned.mask = 1;
    pinned.branches = {Fill(0xa0)};
    {
        const auto r = EvaluateVmSimulated(Draft({Enforce(pinned, 100)}), {});
        CHECK(AllSucceeded(r) && r.provisional && r.drafts.size() == 1);
        const Output &out = r.tx.outputs.at(0);
        CHECK(out.value == 100 && !out.HasToken() && !out.IsBurn() &&
              out.branches == std::vector<Hash32>{Fill(0xa0)} &&
              out.paths == (std::vector<std::vector<uint8_t>>{{0}}));
        CHECK(!r.drafts[0].wallet_fill_required &&
              r.drafts[0].template_bytes == Encode(pinned) &&
              r.drafts[0].claim == 100);
        CHECK(r.post_check_ok);
    }
    // Coalescing: a later identical template matches the earlier draft.
    // OMIT value then over-claims (100 + 100 > 100), which is reported.
    {
        const auto script = Enforce(pinned, 100);
        auto draft = Draft({script, script});
        const auto r = EvaluateVmSimulated(draft, {});
        CHECK(AllSucceeded(r) && r.drafts.size() == 1 &&
              r.tx.outputs.size() == 1 && lotus::v2::OutputClaimsOf(r.effects).size() == 2);
        CHECK(!r.post_check_ok && r.post_check_error == "output-overclaimed");
        Tpl min = pinned;
        min.value_mode = 2;
        min.value = 200;
        const auto merged =
            EvaluateVmSimulated(Draft({Enforce(min, 100), Enforce(min, 100)}), {});
        CHECK(AllSucceeded(merged) && merged.drafts.size() == 1 &&
              merged.tx.outputs[0].value == 200 && merged.post_check_ok);
    }
    // An existing matching output is used and no draft is appended.
    {
        auto draft = Draft({Enforce(pinned, 10)});
        Output existing;
        existing.value = 50;
        existing.branches = {Fill(0xa0)};
        existing.paths = {{0}};
        draft.tx.outputs = {existing};
        const auto r = EvaluateVmSimulated(draft, {});
        CHECK(AllSucceeded(r) && r.drafts.empty() && !r.provisional &&
              r.post_check_ok);
    }
    // Unpinned slots get distinct placeholders: H(sim/placeholder,
    // u16 output || u8 slot).
    {
        Tpl wide;
        wide.branch_count = 3;
        wide.mask = 2;
        wide.branches = {Fill(0xa1)};
        const auto r = EvaluateVmSimulated(Draft({Enforce(wide, 0)}), {});
        CHECK(AllSucceeded(r));
        const Output &out = r.tx.outputs.at(0);
        const std::array<uint8_t, 3> slot0{0, 0, 0}, slot2{0, 0, 2};
        CHECK(out.branches.size() == 3 && out.branches[1] == Fill(0xa1) &&
              out.branches[0] == TaggedHash(HashDomain::SimPlaceholder, slot0) &&
              out.branches[2] == TaggedHash(HashDomain::SimPlaceholder, slot2));
        CHECK(r.drafts[0].wallet_fill_required &&
              r.drafts[0].placeholder_slots == (std::vector<uint8_t>{0, 2}) &&
              out.paths == (std::vector<std::vector<uint8_t>>{{0, 1, 2}}));
    }
    // Burn drafts have no paths; EXACT value is taken from the template.
    {
        Tpl burn;
        burn.burn = true;
        burn.value_mode = 1;
        burn.value = 7;
        burn.mask = 1;
        burn.branches = {Fill(0xa2)};
        const auto r = EvaluateVmSimulated(Draft({Enforce(burn, 0)}), {});
        CHECK(AllSucceeded(r) && r.tx.outputs[0].IsBurn() &&
              r.tx.outputs[0].value == 7 && r.tx.outputs[0].paths.empty());
    }
    // INHERIT without wildcard copies the coin; FROM_STACK value and a
    // stack state root make a stateful continuation of this input's value.
    {
        Tpl vault;
        vault.value_mode = 3;
        vault.paths_mode = 2;
        vault.state_mode = 2;
        VmBytes prefix;
        Push(prefix, VmBytes(32, 0x5e)); // state root, popped last
        Append(prefix, Hex("d0 d6"));    // this input's coin value
        const auto script = Enforce(vault, 0, prefix);
        const auto r = EvaluateVmSimulated(Draft({script}, 1234), {});
        CHECK(AllSucceeded(r));
        const Output &out = r.tx.outputs.at(0);
        CHECK(out.value == 1234 && out.HasState() &&
              out.state_root == Fill(0x5e) &&
              out.branches == std::vector<Hash32>{BranchLeaf(script)} &&
              out.paths == (std::vector<std::vector<uint8_t>>{{0}}));
        CHECK(r.drafts[0].popped.size() == 2 && r.post_check_ok &&
              StateAuthorizationsOf(r.effects) == std::vector<StateAuthorization>{{{0}}});
    }
    // A pinned output index is never constructed.
    {
        Tpl at;
        at.output_mode = 1;
        const auto r = EvaluateVmSimulated(Draft({Enforce(at, 0)}), {});
        CHECK(r.invocations[0].error == "introspection index out of range" &&
              r.drafts.empty());
    }
    // A preceding "lotus.output.draft" event is linked to the draft.
    {
        VmBytes prefix;
        Push(prefix, Hex("01"));
        Push(prefix, Text("lotus.output.draft"));
        prefix.insert(prefix.end(), {0x4f, 0x6c});
        const auto r =
            EvaluateVmSimulated(Draft({Enforce(pinned, 1, prefix)}), {});
        CHECK(AllSucceeded(r) && r.drafts[0].draft_event == size_t(0));
    }
    // A failed invocation leaves no draft.
    {
        auto script = Enforce(pinned, 1);
        script.back() = 0x00; // FALSE
        const auto r = EvaluateVmSimulated(Draft({script}), {});
        CHECK(r.invocations[0].status == VmStatus::Invalid &&
              r.drafts.empty() && r.tx.outputs.empty() && r.effects.Empty() &&
              !r.provisional);
    }
}

void MintDraft() {
    // A mint whose own ENFORCEOUTPUT creates its token output: the delta is
    // unknown at the start, so 1 is supplied provisionally.
    Tpl self;
    self.token_mode = 3;
    self.value_mode = 1;
    self.value = 50;
    self.mask = 1;
    self.branches = {Fill(0xa3)};
    const auto mint_script = Enforce(self, 0, {}, Hex("79")); // drop delta
    auto draft = Draft({Hex("4e")});
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.prev_txid = BranchLeaf(mint_script);
    mint.witnesses = {BranchWitness{mint_script, {}, {}}};
    draft.tx.inputs.push_back(mint);
    draft.resolved.push_back(std::nullopt);
    const auto r = EvaluateVmSimulated(draft, {});
    CHECK(AllSucceeded(r) && r.invocations[1].provisional_delta &&
          r.provisional);
    CHECK(r.tx.outputs.size() == 1 && r.tx.outputs[0].HasToken() &&
          r.tx.outputs[0].token_id == mint.prev_txid &&
          r.tx.outputs[0].value == 50);
    // Re-simulating the completed draft finds the real delta.
    SimTransaction again = draft;
    again.tx = r.tx;
    const auto second = EvaluateVmSimulated(again, {});
    CHECK(AllSucceeded(second) && !second.invocations[1].provisional_delta &&
          second.drafts.empty() && !second.provisional);
}

void AssumedSignatures() {
    // x-only generator key; any 64-byte signature.
    const VmBytes key = Hex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    VmBytes script;
    Push(script, VmBytes(64, 0x11));
    Push(script, key);
    script.push_back(0xbc); // CHECKSIGVERIFY
    Push(script, VmBytes(64, 0x22));
    Push(script, VmBytes(32, 0x33)); // message
    Push(script, key);
    script.insert(script.end(), {0x00, 0xbd}); // CHECKDATASIG, BIP-340
    const auto draft = Draft({script});
    const auto verify = EvaluateVmSimulated(draft, {});
    CHECK(verify.invocations[0].error == "CHECKSIG NULLFAIL" &&
          verify.signing_requests.empty());
    SimOptions assume;
    assume.signatures = SimSignatures::AssumeValid;
    const auto r = EvaluateVmSimulated(draft, assume);
    CHECK(AllSucceeded(r) && r.signing_requests.size() == 2);
    CHECK(!r.signing_requests[0].data && r.signing_requests[0].mode == 0 &&
          r.signing_requests[0].key == key);
    CHECK(r.signing_requests[1].data && r.signing_requests[1].mode == 0 &&
          r.signing_requests[1].message == Fill(0x33));
    // Framing is still checked: a 63-byte signature is a wire error.
    VmBytes bad;
    Push(bad, VmBytes(63, 0x11));
    Push(bad, key);
    bad.insert(bad.end(), {0xbb});
    CHECK(EvaluateVmSimulated(Draft({bad}), assume).invocations[0].error ==
          "CHECKSIG wire encoding");
}
} // namespace

int main() {
    try {
        EmitLogIsSimulationOnly();
        ConstructiveEnforceOutput();
        MintDraft();
        AssumedSignatures();
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "Lotus V2 VM simulation vectors pass\n";
    return 0;
}
