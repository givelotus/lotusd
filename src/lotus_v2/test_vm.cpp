#include "vm.h"

#include "field_size.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
const VmProfile PROFILE{512, 8, 128, 16, 8, 256, 8, 100000};
VmBytes Hex(const std::string &hex) {
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
VmBytes Number(uint8_t n) {
    VmBytes out(16);
    out[0] = n;
    return out;
}
void Expect(const std::string &hex, VmStatus status,
            const std::vector<VmBytes> &args = {},
            const VmProfile &profile = PROFILE, uint16_t inputs = 0,
            uint16_t outputs = 0) {
    auto result = EvaluateVm(Hex(hex), args, profile, inputs, outputs);
    if (result.status != status)
        throw std::runtime_error(hex + ": " + result.error);
    if (status == VmStatus::Success)
        CHECK(result.final_stack == std::vector<VmBytes>{Number(1)});
}
void FramingAndSuccess() {
    Expect("66615e4c", VmStatus::AutomaticSuccess);
    Expect("614e635e64", VmStatus::AutomaticSuccess);
    Expect("5e4cfd", VmStatus::AutomaticSuccess);
    Expect("015e4e91", VmStatus::Invalid); // success byte is push payload
    for (const auto &bad : {"0244", "4cfd01005e", "4c015e5e", "4cfd", "4c4b",
                            "0064", "616a64", "676167646a", "6767676a6a6a"})
        Expect(bad, VmStatus::Invalid);
    Expect("bd", VmStatus::Invalid); // CHECKDATASIG underflows; not success
}
void ControlAndArithmetic() {
    for (const auto &valid :
         {"4d4e9e00a6", "00696a4e", "4e69614e6b646a4e", "677967794f6b6a666a4e",
          "4e7a91", "4c004c00914e91"})
        Expect(valid, VmStatus::Success, {}, PROFILE, 1);
    Expect("006179634e64", VmStatus::Success);
    Expect("00614e6b634e64", VmStatus::Success); // BREAK in skipped arm
    Expect("00696b6a4e", VmStatus::Success); // BREAK in zero-iteration loop
    Expect("4e614e6b634e64", VmStatus::Invalid); // executed outside loop
    Expect("00616b", VmStatus::Invalid); // still requires complete syntax
    Expect("006b6a", VmStatus::Invalid);
    Expect("61", VmStatus::Invalid, {Number(2)});
    Expect("4e6b", VmStatus::Invalid);
    VmBytes max(16, 255);
    max[15] = 127;
    Expect("98", VmStatus::Invalid, {max});
    Expect("4e4e", VmStatus::Invalid);
    VmProfile one_stack = PROFILE;
    one_stack.max_stack_items = 1;
    Expect("4e7a91", VmStatus::Invalid, {}, one_stack);
    VmProfile one_step = PROFILE;
    one_step.max_steps = 1;
    Expect("4e", VmStatus::Success, {}, one_step);
    Expect("4e4e91", VmStatus::OperationalError, {}, one_step);
}
void StackOpcodes() {
    auto check = [](std::initializer_list<uint8_t> initial, uint8_t op,
                    std::initializer_list<uint8_t> expected) {
        VmBytes script;
        for (uint8_t n : initial) script.push_back(0x4d + n);
        script.push_back(op);
        for (auto it = expected.end(); it != expected.begin();) {
            script.push_back(0x4d + *--it);
            script.push_back(0x92); // EQUALVERIFY consumes one result
        }
        script.push_back(0x4e);
        CHECK(EvaluateVm(script, {}, PROFILE).status == VmStatus::Success);
    };
    check({1, 2}, 0x72, {});
    check({1, 2}, 0x73, {1, 2, 1, 2});
    check({1, 2, 3}, 0x74, {1, 2, 3, 1, 2, 3});
    check({1, 2, 3, 4}, 0x75, {1, 2, 3, 4, 1, 2});
    check({1, 2, 3, 4, 5, 6}, 0x76, {3, 4, 5, 6, 1, 2});
    check({1, 2, 3, 4}, 0x77, {3, 4, 1, 2});
    check({1, 2}, 0x78, {1, 2, 2});
    check({1, 2}, 0x79, {1});
    check({1, 2}, 0x7a, {1, 2, 2});
    check({1, 2}, 0x7b, {2});
    check({1, 2}, 0x7c, {1, 2, 1});
    check({1, 2, 1}, 0x7d, {1, 2, 1});
    check({1, 2, 3, 2}, 0x7e, {2, 3, 1});
    check({1, 2, 3}, 0x7f, {2, 3, 1});
    check({1, 2}, 0x80, {2, 1});
    check({1, 2}, 0x81, {2, 1, 2});
    Expect("4e4d7d", VmStatus::Invalid); // negative PICK index
    Expect("4e4f7d", VmStatus::Invalid); // out-of-range PICK index
    Expect("4e4f7e", VmStatus::Invalid); // out-of-range ROLL index
}
void ByteOpcodes() {
    auto check = [](uint8_t opcode, const std::vector<VmBytes> &arguments,
                    const std::vector<VmBytes> &expected) {
        VmBytes script{opcode};
        for (auto it = expected.rbegin(); it != expected.rend(); ++it) {
            if (it->empty())
                script.insert(script.end(), {0x4c, 0x00});
            else {
                CHECK(it->size() <= 75);
                script.push_back(uint8_t(it->size()));
                script.insert(script.end(), it->begin(), it->end());
            }
            script.push_back(0x92);
        }
        script.push_back(0x4e);
        auto result = EvaluateVm(script, arguments, PROFILE);
        CHECK(result.status == VmStatus::Success);
    };
    check(0x89, {Hex("616263"), Number(1)}, {Hex("61"), Hex("6263")});
    check(0x89, {Hex("616263"), Number(0)}, {{}, Hex("616263")});
    check(0x89, {Hex("616263"), Number(3)}, {Hex("616263"), {}});
    CHECK(EvaluateVm(Hex("89"), {Hex("61"), Number(2)}, PROFILE).status ==
          VmStatus::Invalid);
    VmBytes negative128(16, 0xff);
    negative128[0] = 0x80;
    VmBytes negative32768(16, 0xff);
    negative32768[0] = 0;
    negative32768[1] = 0x80;
    check(0x8a, {Number(127), Number(1)}, {Hex("7f")});
    check(0x8a, {negative128, Number(1)}, {Hex("80")});
    check(0x8a, {Number(0), Number(0)}, {{}});
    CHECK(EvaluateVm(Hex("8a"), {Number(128), Number(1)}, PROFILE).status ==
          VmStatus::Invalid);
    check(0x8b, {Hex("80")}, {negative128});
    check(0x8b, {Hex("0080")}, {negative32768});
    check(0x8b, {{}}, {Number(0)});
    check(0x8b, {VmBytes(17, 0)}, {Number(0)});
    check(0x8b, {VmBytes(17, 1)}, {VmBytes(17, 1)});
    check(0x8d, {Hex("0055ff")}, {Hex("ffaa00")});
    check(0x8e, {Hex("f00f"), Hex("cc33")}, {Hex("c003")});
    check(0x8f, {Hex("f00f"), Hex("cc33")}, {Hex("fc3f")});
    check(0x90, {Hex("f00f"), Hex("cc33")}, {Hex("3c3c")});
    check(0x8e, {Hex("00"), Hex("0000")}, {Hex("0000")});
    check(0x8e, {Hex("ff"), Hex("55aa")}, {Hex("5500")});
    check(0x8f, {Hex("ff"), Hex("55aa")}, {Hex("ffaa")});
    check(0x90, {Hex("ff"), Hex("55aa")}, {Hex("aaaa")});
    check(0x93, {Hex("02"), Hex("01")}, {Hex("01"), Hex("02")});
    check(0x93, {Hex("0100"), Hex("01")}, {Hex("01"), Hex("0100")});
    check(0x94, {Hex("8101"), Number(1)}, {Hex("0203")});
    check(0x94, {Hex("8101"), VmBytes(16, 0xff)}, {Hex("c000")});
    check(0x94, {Hex("8101"), Number(16)}, {Hex("0000")});
    VmBytes minimum(16, 0);
    minimum.back() = 0x80;
    check(0x94, {Hex("8101"), minimum}, {Hex("0000")});
}
void NumericOpcodes() {
    using Signed = __int128_t;
    using Unsigned = __uint128_t;
    auto number = [](Signed value) {
        Unsigned bits = Unsigned(value);
        VmBytes encoded(16);
        for (auto &byte : encoded) {
            byte = uint8_t(bits);
            bits >>= 8;
        }
        return encoded;
    };
    auto check = [&](uint8_t opcode, const std::vector<VmBytes> &arguments,
                     Signed expected) {
        VmBytes script{opcode, 0x10};
        auto encoded = number(expected);
        script.insert(script.end(), encoded.begin(), encoded.end());
        script.insert(script.end(), {0x92, 0x4e});
        CHECK(EvaluateVm(script, arguments, PROFILE).status ==
              VmStatus::Success);
    };
    check(0xa1, {number(-7), number(3)}, -2);
    check(0xa2, {number(-7), number(3)}, -1);
    check(0xa1, {number(7), number(-3)}, -2);
    check(0xa2, {number(7), number(-3)}, 1);
    CHECK(EvaluateVm(Hex("a1"), {number(1), number(0)}, PROFILE).status ==
          VmStatus::Invalid);
    const Signed minimum = -Signed((Unsigned(1) << 127) - 1) - 1;
    CHECK(EvaluateVm(Hex("a2"), {number(minimum), number(-1)}, PROFILE)
              .status == VmStatus::Invalid);
    check(0xa3, {number(-7), number(-1)}, -3);
    check(0xa3, {number(3), number(4)}, 48);
    check(0xa3, {number(0), number(128)}, 0);
    check(0xa3, {number(1), number(-128)}, 0);
    CHECK(EvaluateVm(Hex("a3"), {number(1), number(128)}, PROFILE).status ==
          VmStatus::Invalid);
    check(0xa4, {number(1), number(0)}, 0);
    check(0xa5, {number(1), number(0)}, 1);
    CHECK(EvaluateVm(Hex("a4"), {number(2), number(1)}, PROFILE).status ==
          VmStatus::Invalid);
    check(0xad, {number(-5), number(2)}, -5);
    check(0xae, {number(-5), number(2)}, 2);
    check(0xaf, {number(4), number(3), number(5)}, 1);
    check(0xaf, {number(5), number(3), number(5)}, 0);
}
void MerkleProofBounds() {
    VmProfile wide = PROFILE;
    wide.max_element_bytes = VM_HARD_ELEMENT_BYTES;
    wide.max_vm_bytes = 9000;
    VmBytes leaf(32, 0x11);
    VmBytes key(32, 0xff);
    auto valid_sorted = EvaluateVm(Hex("c0794e"),
                                   {leaf, VmBytes(32 * 64, 0x22), Number(0)},
                                   wide);
    CHECK(valid_sorted.status == VmStatus::Success);
    auto excess_sorted = EvaluateVm(Hex("c0794e"),
                                    {leaf, VmBytes(32 * 65, 0x22), Number(0)},
                                    wide);
    CHECK(excess_sorted.status == VmStatus::Invalid &&
          excess_sorted.error == "Merkle proof framing");
    auto valid_indexed = EvaluateVm(
        Hex("c1794e"), {leaf, key, VmBytes(32 * 256, 0x22), Number(0)}, wide);
    CHECK(valid_indexed.status == VmStatus::Success);
    auto short_key = EvaluateVm(
        Hex("c1794e"), {leaf, Hex("ff"), VmBytes(32 * 9, 0x22), Number(0)},
        wide);
    CHECK(short_key.status == VmStatus::Invalid &&
          short_key.error == "Merkle proof framing");
    CHECK(EvaluateVm(Hex("c0794e"), {leaf, Hex("00"), Number(0)}, wide)
              .status == VmStatus::Invalid);
    CHECK(EvaluateVm(Hex("c0794e"), {leaf, {}, Number(4)}, wide)
              .status == VmStatus::Invalid);
    CHECK(EvaluateVm(Hex("c1794e"), {leaf, {}, {}, Number(0)}, wide)
              .status == VmStatus::Invalid);
}
void ContextFieldOpcodes() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    for (size_t i = 0; i < chain.size(); ++i) chain[i] = uint8_t(i);
    Transaction tx;
    tx.lock = (uint64_t(500) << 8) | 1;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x33);
    spend.prev_index = UINT32_MAX;
    spend.sequence = 5;
    spend.witnesses.push_back(BranchWitness{Hex("4e"), {}, {}});
    tx.inputs.push_back(spend);
    Output coin;
    coin.value = 2000;
    coin.branches = {BranchLeaf(spend.witnesses[0].script)};
    coin.paths = {{0}};
    ResolvedCoins resolved{coin};
    Output created = coin;
    created.value = 1000;
    created.branches[0].fill(0x44);
    tx.outputs.push_back(created);
    VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0, std::nullopt};
    auto run = [&](VmBytes script, std::vector<VmBytes> arguments = {}) {
        auto &witness = tx.inputs[0].witnesses[0];
        witness.script = std::move(script);
        witness.arguments = std::move(arguments);
        resolved[0]->branches[0] = BranchLeaf(witness.script);
        return EvaluateVmWithContext(witness.script, witness.arguments,
                                     PROFILE, ctx);
    };
    auto compare = [&](VmBytes prefix, const VmBytes &expected,
                       std::vector<VmBytes> arguments = {}) {
        CHECK(expected.size() <= 75);
        const bool retained_bytes = prefix.size() == 2 && prefix.back() == 0x8c;
        if (expected.empty())
            prefix.insert(prefix.end(), {0x4c, 0x00});
        else {
            prefix.push_back(uint8_t(expected.size()));
            prefix.insert(prefix.end(), expected.begin(), expected.end());
        }
        prefix.push_back(0x92);
        if (retained_bytes) prefix.push_back(0x79);
        prefix.push_back(0x4e);
        const uint8_t opcode = prefix.front();
        const auto result = run(std::move(prefix), std::move(arguments));
        if (result.status != VmStatus::Success)
            throw std::runtime_error("context opcode " +
                                     std::to_string(opcode) + ": " +
                                     result.error);
    };
    auto index = [](uint32_t value) {
        VmBytes encoded(16);
        for (size_t i = 0; i < 4; ++i)
            encoded[i] = uint8_t(value >> (8 * i));
        return encoded;
    };
    compare(Hex("c8"), Number(7));
    compare(Hex("cc"), index(500));
    compare(Hex("cd"), Number(1));
    compare(Hex("ce8c"), Number(32));
    compare(Hex("cf"), VmBytes(chain.begin(), chain.end()));
    compare(Hex("d2"), VmBytes(32, 0x33), {Number(0)});
    compare(Hex("d3"), index(UINT32_MAX), {Number(0)});
    compare(Hex("d4"), Number(5), {Number(0)});
    compare(Hex("d5"), Number(0), {Number(0)});
    compare(Hex("d6"), index(2000), {Number(0)});
    compare(Hex("d7"), VmBytes(32), {Number(0)});
    compare(Hex("d8"), Number(1), {Number(0)});
    compare(Hex("d98c"), Number(32), {Number(0), Number(0)});
    compare(Hex("da"), Number(1), {Number(0)});
    compare(Hex("db"), Hex("0100"), {Number(0), Number(0)});
    compare(Hex("dc8c"), Number(45), {Number(0)});
    compare(Hex("dd"), Number(0), {Number(0), VmBytes(32, 0x44)});
    compare(Hex("e0"), Number(0), {Number(0)});
    compare(Hex("e1"), index(1000), {Number(0)});
    compare(Hex("e2"), VmBytes(32), {Number(0)});
    compare(Hex("e3"), Number(1), {Number(0)});
    compare(Hex("e4"), VmBytes(32, 0x44), {Number(0), Number(0)});
    compare(Hex("e5"), Number(1), {Number(0)});
    compare(Hex("e6"), Hex("0100"), {Number(0), Number(0)});
    VmBytes output_bytes;
    std::string error;
    CHECK(EncodeOutput(tx.outputs[0], output_bytes, error));
    compare(Hex("e7"), output_bytes, {Number(0)});
    compare(Hex("e8"), Number(1), {Number(0), VmBytes(32, 0x44)});
    compare(Hex("e9"), Number(1), {Number(0), VmBytes(32, 0x44)});
    CHECK(run(Hex("e9794e"), {Number(0), Hex("00")}).error ==
          "exclusive root width");
    compare(Hex("f08c"), Number(22)); // bytecode includes this comparison
    compare(Hex("f1"), Number(1));
    compare(Hex("f28c"), Number(32));
    CHECK(run(Hex("f34e"), {Number(1), index(500)}).status ==
          VmStatus::Success);
    CHECK(run(Hex("f34e"), {Number(1), index(501)}).status ==
          VmStatus::Invalid);
    CHECK(run(Hex("f44e"), {Number(1), Number(5)}).status ==
          VmStatus::Success);
    CHECK(run(Hex("f44e"), {Number(1), Number(6)}).status ==
          VmStatus::Invalid);
    CHECK(run(Hex("d9"), {Number(0), index(UINT32_MAX)}).error ==
          "introspection index out of range");
    CHECK(run(Hex("e4"), {Number(0), index(UINT32_MAX)}).error ==
          "introspection index out of range");
    CHECK(run(Hex("db"), {Number(0), index(UINT32_MAX)}).error ==
          "introspection index out of range");
    CHECK(run(Hex("e6"), {Number(0), index(UINT32_MAX)}).error ==
          "introspection index out of range");
    VmBytes continuation = Hex("ea4e924e");
    tx.outputs[0].branches[0].fill(0x55);
    CHECK(run(continuation, {Number(0), VmBytes(32, 0x55)}).status ==
          VmStatus::Success);
    CHECK(run(continuation, {Number(0), VmBytes(32, 0x66)}).status ==
          VmStatus::Invalid);
    tx.outputs[0].flags = 2;
    tx.outputs[0].paths.clear();
    compare(Hex("ea"), Number(0), {Number(0), VmBytes(32, 0x55)});
    tx.outputs[0] = created;
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses.push_back(BranchWitness{Hex("794e"), {}, {}});
    mint.prev_txid = BranchLeaf(mint.witnesses[0].script);
    tx.inputs.push_back(mint);
    resolved.push_back(std::nullopt);
    CHECK(run(Hex("4ed8"), {}).error == "UTXO read at nonspend input");
    CHECK(run(Hex("4ed5"), {}).error == "path index at nonspend input");
    PositiveDelta delta{};
    delta[0] = 1;
    VmExecutionContext mint_ctx{tx, tx_profile, chain, resolved, 1, 0, delta};
    tx.inputs[1].witnesses[0].script = Hex("794ed8");
    tx.inputs[1].prev_txid = BranchLeaf(tx.inputs[1].witnesses[0].script);
    CHECK(EvaluateVmWithContext(tx.inputs[1].witnesses[0].script, {}, PROFILE,
                                mint_ctx)
              .error == "UTXO read at nonspend input");
    tx.inputs[1].witnesses[0].script = Hex("79ea4e");
    tx.inputs[1].witnesses[0].arguments = {Number(0), VmBytes(32, 0x44)};
    tx.inputs[1].prev_txid = BranchLeaf(tx.inputs[1].witnesses[0].script);
    const auto mint_continuation = EvaluateVmWithContext(
        tx.inputs[1].witnesses[0].script,
        {Number(0), VmBytes(32, 0x44)}, PROFILE, mint_ctx);
    if (mint_continuation.error != "continuation requires spend")
        throw std::runtime_error("mint continuation: " + mint_continuation.error);
}
void HashAndBounds() {
    Expect("03616263b820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff6"
           "1f20015ad91",
           VmStatus::Success); // SHA256('abc'), independently fixed
    Expect("03616263ba20"      // raw BLAKE3('abc')
           "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d8591",
           VmStatus::Success);
    Expect("0141be20", VmStatus::Invalid); // incomplete comparison push
    VmProfile tiny = PROFILE;
    tiny.max_script_bytes = 1;
    Expect("4e4e91", VmStatus::Invalid, {}, tiny);
    VmProfile small_element = PROFILE;
    small_element.max_element_bytes = 1;
    Expect("1000000000000000000000000000000000", VmStatus::Invalid, {},
           small_element);
    VmProfile tiny_bytes = PROFILE;
    tiny_bytes.max_vm_bytes = 16;
    Expect("4e4e91", VmStatus::Invalid, {}, tiny_bytes);
    Expect("5e", VmStatus::AutomaticSuccess, {}, tiny_bytes);
    VmProfile hard = PROFILE;
    hard.max_element_bytes = VM_HARD_ELEMENT_BYTES + 1;
    hard.max_vm_bytes = VM_HARD_ELEMENT_BYTES + 32;
    Expect("5e", VmStatus::OperationalError, {}, hard);
    hard.max_element_bytes = VM_HARD_ELEMENT_BYTES;
    hard.max_script_bytes = VM_HARD_ELEMENT_BYTES + 32;
    hard.max_stack_items = 2;
    Expect("794e", VmStatus::Success,
           {VmBytes(VM_HARD_ELEMENT_BYTES, 0x41)}, hard);
    Expect("794e", VmStatus::Invalid,
           {VmBytes(VM_HARD_ELEMENT_BYTES + 1, 0x41)}, hard);
}
VmCostProfile IllustrativeCost() {
    VmCostProfile schedule;
    schedule.max_invocation_cost = 10000000;
    schedule.structural_byte_cost = 1;
    for (auto &op : schedule.opcode)
        op = {1, 1, 1};
    return schedule;
}
void ChargedAccounting() {
    auto schedule = IllustrativeCost();
    auto charge = [&](const std::string &script,
                      const std::vector<VmBytes> &args = {},
                      uint16_t inputs = 0, uint16_t outputs = 0) {
        return EvaluateVmCharged(Hex(script), args, PROFILE, schedule, inputs,
                                 outputs);
    };
    auto hash = charge("03616263b8");
    CHECK(hash.charged && hash.accounting_cost == 45 &&
          hash.enforcement_cost == 45 &&
          hash.invocation.executed_cost == 45);
    auto underflow = charge("b8");
    CHECK(underflow.charged && underflow.accounting_cost == 1282);
    auto loop = charge("4e69796a4e");
    CHECK(loop.charged && loop.accounting_cost == 74 &&
          loop.invocation.status == VmStatus::Success &&
          loop.invocation.executed_cost == 74);
    auto loop_five = charge("5269796a4e");
    CHECK(loop_five.charged && loop_five.accounting_cost == 56 + 5 * 18 &&
          loop_five.invocation.status == VmStatus::Success &&
          loop_five.invocation.executed_cost == 56 + 5 * 18);
    auto loop_dynamic = charge("69796a4e", {Number(1)});
    CHECK(loop_dynamic.charged && loop_dynamic.accounting_cost == 4646 &&
          loop_dynamic.invocation.status == VmStatus::Success &&
          loop_dynamic.invocation.executed_cost == 56);
    auto loop_break = charge("5269794e6b6a4e");
    CHECK(loop_break.charged &&
          loop_break.invocation.status == VmStatus::Success &&
          loop_break.invocation.executed_cost > 0 &&
          loop_break.invocation.executed_cost < loop_break.accounting_cost);
    auto ignored_suffix = charge("5e4cfd");
    CHECK(ignored_suffix.charged && ignored_suffix.accounting_cost == 3 &&
          ignored_suffix.invocation.status == VmStatus::AutomaticSuccess &&
          ignored_suffix.invocation.executed_cost == 3);
    CHECK(!charge("4cfd5e").charged); // bad push before success
    auto skipped = charge("0061b8634e64");
    CHECK(skipped.charged && skipped.accounting_cost > 128 &&
          skipped.invocation.status == VmStatus::Success &&
          skipped.invocation.executed_cost > 0 &&
          skipped.invocation.executed_cost < skipped.accounting_cost);
    // Merkle folding adds a conservative selected hash charge for every
    // bounded proof step. An unknown selector takes the maximum step price.
    const VmBytes leaf(32), empty, two_steps(64);
    auto sorted_zero = charge("00c0794e", {leaf, empty});
    auto sorted_two = charge("00c0794e", {leaf, two_steps});
    auto sorted_sha = charge("4fc0794e", {leaf, two_steps});
    auto sorted_unknown = charge("c0794e", {leaf, two_steps, Number(0)});
    CHECK(sorted_zero.charged && sorted_two.charged && sorted_sha.charged &&
          sorted_unknown.charged);
    CHECK(sorted_two.accounting_cost - sorted_zero.accounting_cost ==
          64 + 2 * (1 + 96 + 32));
    CHECK(sorted_two.accounting_cost - sorted_sha.accounting_cost ==
          2 * (96 - 64));
    CHECK(sorted_two.accounting_cost - sorted_unknown.accounting_cost ==
          1 + 16 + 1); // omitted N(0) push and its structural byte
    schedule.max_invocation_cost = 44;
    CHECK(!charge("03616263b8").charged); // cap checked before execution
    schedule.max_invocation_cost = 2;
    CHECK(!charge("5e4cfd").charged);
    schedule.max_invocation_cost = 3;
    CHECK(charge("5e4cfd").charged);
    // A zero-bound body can exceed the invocation cap before multiplication;
    // only the complete charge is capped, while every u128 intermediate is
    // still checked. The same body with one input exceeds the cap.
    schedule = IllustrativeCost();
    schedule.max_invocation_cost = 24;
    auto zero_bound = charge("67794e796a4e", {}, 0);
    CHECK(zero_bound.charged && zero_bound.accounting_cost == 24 &&
          zero_bound.invocation.status == VmStatus::Success);
    auto one_bound = charge("67794e796a4e", {}, 1);
    CHECK(!one_bound.charged &&
          one_bound.invocation.status == VmStatus::Invalid);
    schedule.max_invocation_cost = 76;
    one_bound = charge("67794e796a4e", {}, 1);
    CHECK(one_bound.charged && one_bound.accounting_cost == 76 &&
          one_bound.invocation.status == VmStatus::Success);
    schedule = IllustrativeCost();
    schedule.opcode[0xbb].base = 0;
    CHECK(charge("5e").invocation.status == VmStatus::Unsupported);
    schedule = IllustrativeCost();
    schedule.max_invocation_cost = ~VmCostUnits(0);
    schedule.opcode[0xb8].per_operand_byte = UINT64_MAX;
    VmProfile huge = PROFILE;
    huge.max_element_bytes = SIZE_MAX;
    auto rejected_profile = EvaluateVmCharged(Hex("b8"), {}, huge, schedule);
    CHECK(!rejected_profile.charged &&
          rejected_profile.invocation.error == "invalid explicit VM profile");
}
void AuthenticatedPayment() {
    const auto wire =
        Hex("07000000000000000000000001000100"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "00000000ffffffff0100012220f9308a019258c31049344f85f89d5229b531c845"
            "836f99b08601f113bce036f9bb000140"
            "170c710899dd02f994fe139b507662b88c0701019174aafa87329af0b65a9c0b84"
            "9c421cd740417ddeb4c6f70f4c1f50609b58c00fe8e41f9955a1091d5754aa"
            "00e80300000000000001d0c0707d9e50c9c3aedc8409e2df04bb920a3d9f669e80"
            "a36d2f68ea1e3f0d2a010100");
    const auto coin_wire = Hex("00d00700000000000001d0c0707d9e50c9c3aedc8409e2d"
                               "f04bb920a3d9f669e80a36d2f68ea1e3f0d2a010100");
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    Transaction tx;
    Output coin;
    std::string error;
    CHECK(DecodeTransaction(wire, tx_profile, tx, error));
    CHECK(DecodeOutput(coin_wire, coin, error));
    ResolvedCoins resolved{coin};
    ChainId chain{};
    for (size_t i = 0; i < 32; ++i)
        chain[i] = uint8_t(i);
    VmExecutionContext context{tx, tx_profile, chain,       resolved,
                               0,  0,          std::nullopt};
    auto &witness = tx.inputs[0].witnesses[0];
    const auto original_args = witness.arguments;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    const auto charged_payment =
        EvaluateVmCharged(witness.script, witness.arguments, PROFILE,
                          IllustrativeCost(), 0, 0, &context);
    CHECK(charged_payment.charged &&
          charged_payment.invocation.status == VmStatus::Success &&
          charged_payment.accounting_cost == charged_payment.enforcement_cost);
    witness.arguments[0].push_back(1); // explicit partial signing mode
    const auto partial_charge =
        EvaluateVmCharged(witness.script, witness.arguments, PROFILE,
                          IllustrativeCost(), 0, 0, &context);
    CHECK(partial_charge.charged &&
          partial_charge.accounting_cost ==
              charged_payment.accounting_cost + 1 &&
          partial_charge.invocation.status == VmStatus::Invalid);
    witness.arguments = original_args;
    auto wrong_args = witness.arguments;
    wrong_args[0][0] ^= 1;
    CHECK(EvaluateVmWithContext(witness.script, wrong_args, PROFILE, context)
              .status == VmStatus::OperationalError);
    witness.arguments = wrong_args;
    const auto nullfail_res =
        EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                              context);
    CHECK(nullfail_res.status == VmStatus::Invalid &&
          nullfail_res.error == "CHECKSIG NULLFAIL");
    // Deferred BatchSigCollector collects the signature during VM execution
    // and rejects the corrupted signature in VerifyAll() / FirstFailingIndex().
    BatchSigCollector bad_batch;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context, &bad_batch)
              .status == VmStatus::Success);
    CHECK(bad_batch.Size() == 1 && !bad_batch.VerifyAll());
    CHECK(bad_batch.FirstFailingIndex() == std::optional<size_t>{0});
    witness.arguments = original_args;
    BatchSigCollector good_batch;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context, &good_batch)
              .status == VmStatus::Success);
    CHECK(good_batch.Size() == 1 && good_batch.VerifyAll());
    // Empty signature pushes false (Number(0)) without triggering NULLFAIL.
    const auto original_script = witness.script;
    witness.script =
        Hex("20f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bb9c");
    witness.arguments = {VmBytes{}};
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    // Non-empty invalid signature still triggers NULLFAIL even before OP_NOT.
    witness.arguments = wrong_args;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .error == "CHECKSIG NULLFAIL");
    // Empty signature on CHECKSIGVERIFY fails with CHECKSIGVERIFY false.
    witness.script =
        Hex("20f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bc4e");
    witness.arguments = {VmBytes{}};
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .error == "CHECKSIGVERIFY false");
    witness.script = original_script;
    witness.arguments = original_args;
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(Hex("5e"), witness.arguments, PROFILE, context)
              .status == VmStatus::OperationalError);
    witness.script = Hex("5e");
    witness.siblings.clear();
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::AutomaticSuccess);
    const auto charged_success =
        EvaluateVmCharged(witness.script, witness.arguments, PROFILE,
                          IllustrativeCost(), 0, 0, &context);
    CHECK(charged_success.charged && charged_success.accounting_cost == 1 &&
          charged_success.invocation.status == VmStatus::AutomaticSuccess);
    auto wrong_success_args = witness.arguments;
    wrong_success_args.push_back(Hex("00"));
    CHECK(!EvaluateVmCharged(witness.script, wrong_success_args, PROFILE,
                             IllustrativeCost(), 0, 0, &context)
               .charged);
    witness.script = Hex("00f2e8"); // output 0 requires this branch root
    witness.arguments.clear();
    const auto root = BranchLeaf(witness.script);
    resolved[0]->branches[0] = root;
    tx.outputs[0].branches[0] = root;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    tx.outputs[0].branches[0].front() ^= 1;
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Invalid);

    VmBytes sighash_script = Hex("00c28c10");
    const auto thirty_two = Number(32);
    sighash_script.insert(sighash_script.end(), thirty_two.begin(),
                          thirty_two.end());
    const auto finish = Hex("a68079");
    sighash_script.insert(sighash_script.end(), finish.begin(), finish.end());
    witness.script = sighash_script;
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    witness.script = Hex("00c200c291"); // two prepared messages, one snapshot
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    witness.script = Hex("cb0091"); // cached mint count for this invocation
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    witness.script = Hex("50c2"); // mode 03 rejects
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Invalid);

    witness.script = Hex("b820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb"
                         "410ff61f20015ad91");
    witness.arguments = {Hex("616263")};
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Success);
    witness.arguments = {Hex("616264")};
    CHECK(EvaluateVmWithContext(witness.script, witness.arguments, PROFILE,
                                context)
              .status == VmStatus::Invalid);

    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses.push_back(BranchWitness{Hex("5e"), {}, {}});
    mint.prev_txid = BranchLeaf(mint.witnesses[0].script);
    tx.inputs.push_back(mint);
    resolved.push_back(std::nullopt);
    PositiveDelta delta{};
    delta[0] = 1;
    VmExecutionContext mint_context{tx, tx_profile, chain, resolved,
                                    1,  0,          delta};
    CHECK(EvaluateVmWithContext(mint.witnesses[0].script, {}, PROFILE,
                                mint_context)
              .status == VmStatus::AutomaticSuccess);
    VmProfile underfunded = PROFILE;
    underfunded.max_vm_bytes = 15;
    CHECK(EvaluateVmWithContext(mint.witnesses[0].script, {}, underfunded,
                                mint_context)
              .status == VmStatus::Invalid);
}
void AuthenticatedFieldSizeHints() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x55);
    spend.sequence = UINT32_MAX;
    spend.witnesses.push_back(BranchWitness{Hex("00e775"), {}, {}});
    tx.inputs.push_back(spend);
    Output coin;
    coin.value = 2000;
    coin.branches = {BranchLeaf(spend.witnesses[0].script), Hash32{}};
    coin.branches[1].fill(0x66);
    coin.paths = {{0}};
    ResolvedCoins resolved{coin};
    Output created = coin;
    created.value = 1000;
    tx.outputs.push_back(created);
    VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0, std::nullopt};
    std::vector<uint8_t> encoded;
    std::string error;
    CHECK(EncodeOutput(created, encoded, error));
    const size_t output_bytes = encoded.size();
    CHECK(EncodeOutput(coin, encoded, error));
    const size_t coin_bytes = encoded.size();
    auto charge = [&](std::map<uint8_t, std::vector<size_t>> hints) {
        auto schedule = IllustrativeCost();
        schedule.field_sizes = std::move(hints);
        const auto &witness = tx.inputs[0].witnesses[0];
        return EvaluateVmCharged(witness.script, witness.arguments, PROFILE,
                                 schedule, 0, 0, &ctx);
    };
    auto rejected = [&](const VmChargedResult &result, const char *message) {
        return !result.charged &&
               result.invocation.status == VmStatus::OperationalError &&
               result.invocation.error == message;
    };
    std::map<uint8_t, std::vector<size_t>> derived;
    std::string derive_error;
    CHECK(DeriveFieldSizes(ctx, derived, derive_error));
    CHECK(derived[0xe7] == std::vector<size_t>{output_bytes});
    CHECK(derived[0xdc] == std::vector<size_t>{coin_bytes});
    CHECK(derived[0xe6] == std::vector<size_t>{2});
    CHECK(derived[0xdb] == std::vector<size_t>{2});
    CHECK(output_bytes < PROFILE.max_element_bytes);
    CHECK(output_bytes < VM_HARD_ELEMENT_BYTES);
    const auto none = charge({});
    const auto exact = charge({{0xe7, {output_bytes}}, {0xdc, {coin_bytes}},
                               {0xe6, {2}}, {0xdb, {2}}});
    const auto wider = charge({{0xe7, {output_bytes + 10}}});
    const auto context_free =
        EvaluateVmCharged(tx.inputs[0].witnesses[0].script, {}, PROFILE,
                          IllustrativeCost());
    CHECK(none.charged && exact.charged && wider.charged &&
          context_free.charged);
    // An absent hint charges the derived size, not the element maximum.
    CHECK(none.accounting_cost == exact.accounting_cost);
    CHECK(exact.accounting_cost < wider.accounting_cost);
    CHECK(wider.accounting_cost < context_free.accounting_cost);
    CHECK(charge({{0xe7, {}}}).accounting_cost == none.accounting_cost);
    const char *below = "field-size hint below authenticated field";
    CHECK(rejected(charge({{0xe7, {output_bytes - 1}}}), below));
    CHECK(rejected(charge({{0xdc, {coin_bytes - 1}}}), below));
    CHECK(rejected(charge({{0xe6, {1}}}), below));
    CHECK(rejected(charge({{0xdb, {1, 1}}}), below));
    CHECK(rejected(charge({{0xe7, {output_bytes, output_bytes}}}),
                   "field-size hint count"));
    // Canonical single-branch output is 45 bytes; its one path pushes 2.
    Output small;
    small.value = 1000;
    small.branches = {Hash32{}};
    small.branches[0].fill(0x44);
    small.paths = {{0}};
    tx.outputs[0] = small;
    auto &witness = tx.inputs[0].witnesses[0];
    witness.script = Hex("00e7");
    witness.arguments.clear();
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    std::vector<uint8_t> small_encoded;
    CHECK(EncodeOutput(small, small_encoded, error));
    CHECK(small_encoded.size() == 45);
    CHECK(PathSerializedSize(small.paths[0]) == 2);
    const auto record = charge({});
    const auto record_wide = charge({{0xe7, {60}}});
    CHECK(record.charged && record_wide.charged);
    CHECK(record.accounting_cost == 2 + 17 + (1 + 16 + 45));
    CHECK(record.accounting_cost < record_wide.accounting_cost);
    CHECK(rejected(charge({{0xe7, {44}}}), below));
    witness.script = Hex("00e6");
    witness.arguments = {VmBytes(16)};
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    const auto path = charge({});
    const auto path_wide = charge({{0xe6, {9}}});
    CHECK(path.charged && path_wide.charged);
    CHECK(path.accounting_cost == 2 + 17 + (1 + 16 + 16 + 2));
    CHECK(path.accounting_cost < path_wide.accounting_cost);
    CHECK(rejected(charge({{0xe6, {1}}}), below));
    // Slot 1 is a longer path. A constant index uses that slot, not the max.
    small.branches.push_back(Hash32{});
    small.branches[1].fill(0x22);
    small.paths = {{0}, {0, 1}};
    tx.outputs[0] = small;
    CHECK(DeriveFieldSizes(ctx, derived, derive_error));
    CHECK(derived[0xe6] == (std::vector<size_t>{2, 3}));
    const auto slot0 = charge({});
    witness.script = Hex("4ee6");
    resolved[0]->branches[0] = BranchLeaf(witness.script);
    const auto slot1 = charge({});
    CHECK(slot0.charged && slot1.charged);
    CHECK(slot0.accounting_cost == 2 + 17 + (1 + 16 + 16 + 2));
    CHECK(slot1.accounting_cost == 2 + 17 + (1 + 16 + 16 + 3));
    Transaction with_mint = tx;
    ResolvedCoins with_resolved = resolved;
    Input mint_input;
    mint_input.flags = 3;
    with_mint.inputs.push_back(mint_input);
    with_resolved.emplace_back(std::nullopt);
    VmExecutionContext mint_ctx{with_mint, tx_profile, chain, with_resolved,
                                0,         0,          std::nullopt};
    CHECK(DeriveFieldSizes(mint_ctx, derived, derive_error));
    CHECK(derived[0xdc].size() == 2);
    CHECK(derived[0xdc][0] == coin_bytes);
    CHECK(derived[0xdc][1] == 0);
    // Context-free charging keeps the earlier explicit-hint behavior.
    auto schedule = IllustrativeCost();
    schedule.field_sizes = {{0xe7, {1}}};
    CHECK(EvaluateVmCharged(Hex("00e775"), {}, PROFILE, schedule, 0, 1).charged);
    // A constant path slot uses that hint; a non-constant index uses the max.
    schedule.field_sizes = {{0xdb, {4, 50}}, {0xe6, {4, 50}}};
    const VmBytes wide(16, 0x11);
    const auto path0 =
        EvaluateVmCharged(Hex("00db"), {wide}, PROFILE, schedule);
    const auto path1 =
        EvaluateVmCharged(Hex("4edb"), {wide}, PROFILE, schedule);
    const auto path_any =
        EvaluateVmCharged(Hex("db"), {wide, wide}, PROFILE, schedule);
    const auto out0 =
        EvaluateVmCharged(Hex("00e6"), {wide}, PROFILE, schedule);
    CHECK(path0.charged && path1.charged && path_any.charged && out0.charged);
    CHECK(path0.accounting_cost == 2 + 17 + (1 + 16 + 16 + 4));
    CHECK(path1.accounting_cost == 2 + 17 + (1 + 16 + 16 + 50));
    CHECK(path_any.accounting_cost == 1 + (1 + 16 + 16 + 50));
    CHECK(out0.accounting_cost == path0.accounting_cost);
    CHECK(path0.accounting_cost < path_any.accounting_cost);
}
void PreparedTransactionOwnership() {
    const TxProfile tp{64, 64, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    ResolvedCoins coins;
    // Multiple invocations share exactly one whole-transaction preparation.
    for (size_t i = 0; i < 32; ++i) {
        Input input;
        input.flags = 1;
        input.prev_txid.fill(uint8_t(i + 1));
        input.sequence = UINT32_MAX;
        input.witnesses.push_back({Hex("4e"), {}, {}});
        tx.inputs.push_back(input);
        Output coin;
        coin.value = 1000;
        coin.branches = {BranchLeaf(Hex("4e"))};
        coin.paths = {{0}};
        coins.push_back(coin);
    }
    tx.outputs.push_back(*coins[0]);
    // A large unused authenticated field is legal with a tighter VM item
    // limit: only an opcode actually pushing it would exceed that limit.
    for (uint8_t i = 0; i < 4; ++i) {
        Hash branch{};
        branch.fill(uint8_t(0x90 + i));
        tx.outputs[0].branches.push_back(branch);
    }
    auto cost = IllustrativeCost();
    static_assert(!std::is_copy_constructible_v<PreparedVmTransaction>);
    static_assert(!std::is_copy_assignable_v<PreparedVmTransaction>);
    static_assert(!std::is_move_constructible_v<PreparedVmTransaction>);
    static_assert(!std::is_move_assignable_v<PreparedVmTransaction>);
    PreparedVmTransaction prepared;
    std::string error;
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
    const auto before = VmPreparationWorkCounts();
#endif
    CHECK(prepared.Prepare(tx, tp, chain, coins, cost, error));
    CHECK(prepared.MaxFieldBound(0xe7) > PROFILE.max_element_bytes);
    const auto original_context = VmExecutionContext{tx, tp, chain, coins, 0, 0, std::nullopt};
    const auto original = EvaluateVmCharged(Hex("4e"), {}, PROFILE, cost, 0, 0, &original_context);
    CHECK(original.invocation.status == VmStatus::Success);
    const auto *signing = &prepared.Signing();
    const auto *fields = &prepared.Cost();
    const auto first = prepared.Invocation(0, 0);
    const auto baseline = EvaluateVmCharged(Hex("4e"), {}, PROFILE, prepared.Cost(),
        0, 0, &first);
    // Destroy the caller's source objects. Evaluation must use the owned
    // immutable snapshot, including proof authentication and field bounds.
    tx.inputs.clear();
    tx.outputs.clear();
    coins.clear();
    cost.field_sizes = {{0xdc, {1}}};
    for (size_t i = 0; i < 32; ++i) {
        const auto context = prepared.Invocation(i, 0);
        CHECK(prepared.Owns(context));
        CHECK(&prepared.Signing() == signing && &prepared.Cost() == fields);
        const auto vm = EvaluateVmCharged(Hex("4e"), {}, PROFILE,
                                          prepared.Cost(), 0, 0, &context);
        CHECK(vm.invocation.status == VmStatus::Success && vm.charged);
        CHECK(vm.accounting_cost == baseline.accounting_cost);
    }
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
    const auto after = VmPreparationWorkCounts();
    CHECK(after.signing == before.signing + 2);
    CHECK(after.field_sizes == before.field_sizes + 2);
#endif
    // A cache pointer cannot authenticate caller-owned or foreign snapshot
    // references, even when the serialized bytes happen to be identical.
    const VmExecutionContext forged{tx, tp, chain, coins, 0, 0,
                                    std::nullopt, &prepared};
    const auto rejected = EvaluateVmCharged(Hex("4e"), {}, PROFILE,
                                           prepared.Cost(), 0, 0, &forged);
    CHECK(rejected.invocation.status == VmStatus::OperationalError);
    CHECK(rejected.invocation.error == "prepared transaction ownership mismatch");
}
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
void TypedCryptoFailures() {
    SetVmCryptoFault(VmCryptoFault::Digest);
    CHECK(EvaluateVm(Hex("b8794e"), {VmBytes{1}}, PROFILE).status ==
          VmStatus::OperationalError);
    // Valid P-256 generator, public fixture signature framing. Provider faults
    // are injected after operand validation; no secret key material is used.
    const auto p256 = Hex(
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    auto signature = VmBytes(64);
    signature[31] = 1;
    signature[63] = 1;
    SetVmCryptoFault(VmCryptoFault::P256Context);
    CHECK(EvaluateVm(Hex("bd794e"), {signature, VmBytes(32), p256, Number(1)},
                     PROFILE)
              .status == VmStatus::OperationalError);
    SetVmCryptoFault(VmCryptoFault::P256Verify);
    CHECK(EvaluateVm(Hex("bd794e"), {signature, VmBytes(32), p256, Number(1)},
                     PROFILE)
              .status == VmStatus::OperationalError);
    SetVmCryptoFault(VmCryptoFault::EdAllocation);
    CHECK(EvaluateVm(Hex("bd794e"),
                     {signature, VmBytes(32), VmBytes(32), Number(2)}, PROFILE)
              .status == VmStatus::OperationalError);
    SetVmCryptoFault(VmCryptoFault::None);
    // Under mandatory NULLFAIL, an empty signature pushes deterministic false
    // (demonstrated by NOT), whereas a non-empty wrong P-256 signature
    // immediately aborts with CHECKDATASIG NULLFAIL.
    CHECK(EvaluateVm(Hex("bd9c"), {VmBytes{}, VmBytes(32), p256, Number(1)},
                     PROFILE)
              .status == VmStatus::Success);
    const auto p256_nullfail = EvaluateVm(
        Hex("bd9c"), {signature, VmBytes(32), p256, Number(1)}, PROFILE);
    CHECK(p256_nullfail.status == VmStatus::Invalid &&
          p256_nullfail.error == "CHECKDATASIG NULLFAIL");
}
#endif
void BigIntAndZeroPadding() {
    VmProfile wide = PROFILE;
    wide.max_script_bytes = 8192;
    wide.max_element_bytes = 2048;
    wide.max_vm_bytes = 16384;
    wide.max_steps = 10000000;

    auto push_bytes = [](VmBytes &script, const VmBytes &data) {
        if (data.empty()) {
            script.push_back(0x4c);
            script.push_back(0);
        } else if (data.size() <= 75) {
            script.push_back(uint8_t(data.size()));
        } else if (data.size() < 0xfd) {
            script.push_back(0x4c);
            script.push_back(uint8_t(data.size()));
        } else {
            script.push_back(0x4c);
            script.push_back(0xfd);
            script.push_back(uint8_t(data.size() & 0xff));
            script.push_back(uint8_t((data.size() >> 8) & 0xff));
        }
        script.insert(script.end(), data.begin(), data.end());
    };
    auto check_wide = [&](uint8_t op, const std::vector<VmBytes> &args,
                          const std::vector<VmBytes> &expected) {
        VmBytes script{op};
        for (auto it = expected.rbegin(); it != expected.rend(); ++it) {
            push_bytes(script, *it);
            script.push_back(0x92);
        }
        script.push_back(0x4e);
        const auto res = EvaluateVm(script, args, wide);
        if (res.status != VmStatus::Success)
            throw std::runtime_error("BigIntAndZeroPadding failed op " +
                                     std::to_string(op) + ": " + res.error);
    };

    // SIMD bitwise & automatic zero-padding across 17B, 32B, 64B, 1024B
    for (size_t w : {size_t(17), size_t(31), size_t(32), size_t(64), size_t(1024)}) {
        VmBytes a(w, 0x5a), b(w / 2, 0xf0);
        VmBytes inv_a(w, uint8_t(~0x5a));
        check_wide(0x8d, {a}, {inv_a});
        VmBytes exp_and(w, 0), exp_or(w, 0x5a), exp_xor(w, 0x5a);
        for (size_t i = 0; i < b.size(); ++i) {
            exp_and[i] = a[i] & b[i];
            exp_or[i] = a[i] | b[i];
            exp_xor[i] = a[i] ^ b[i];
        }
        check_wide(0x8e, {a, b}, {exp_and});
        check_wide(0x8e, {b, a}, {exp_and});
        check_wide(0x8f, {a, b}, {exp_or});
        check_wide(0x8f, {b, a}, {exp_or});
        check_wide(0x90, {a, b}, {exp_xor});
        check_wide(0x90, {b, a}, {exp_xor});
    }

    // Mismatched-width unsigned fixed-width ops (ADDCARRY, SUBCARRY, MUL128_WIDE)
    check_wide(0xb0, {Hex("01"), Hex("0200"), Number(1)},
               {Number(4), Number(0)});
    check_wide(0xb1, {Hex("0500"), Hex("01"), Number(0)},
               {Number(4), Number(0)});
    check_wide(0xb2, {Hex("02"), Hex("0300")},
               {Number(0), Number(6)});

    // Multi-limb signed arithmetic across 32B, 64B, 256B, 512B, 1024B
    for (size_t w : {size_t(32), size_t(64), size_t(256), size_t(512), size_t(1024)}) {
        // a = 2^(8*(w-1)) (positive in w bytes), b = 3
        VmBytes a(w, 0);
        a[w - 2] = 1; // 2^(8*(w-2))
        VmBytes b = Number(3);
        VmBytes a_plus_1 = a;
        a_plus_1[0] = 1;
        check_wide(0x98, {a}, {a_plus_1});
        check_wide(0x99, {a_plus_1}, {a});
        VmBytes a_plus_b = a;
        a_plus_b[0] = 3;
        check_wide(0x9e, {a, b}, {a_plus_b});
        check_wide(0x9f, {a_plus_b, b}, {a});
        VmBytes prod(w, 0);
        prod[w - 2] = 3;
        check_wide(0xa0, {a, b}, {prod});
        check_wide(0xa1, {prod, b}, {a});
        VmBytes prod_plus_2 = prod;
        prod_plus_2[0] = 2;
        VmBytes rem2(w, 0);
        rem2[0] = 2;
        check_wide(0xa1, {prod_plus_2, b}, {a});
        check_wide(0xa2, {prod_plus_2, b}, {rem2});
        // Negative division & modulo (truncate toward zero)
        VmBytes neg_prod = prod_plus_2;
        check_wide(0x9a, {prod_plus_2}, { [&]() {
            VmBytes neg(w, 0xff);
            neg[0] = 0xfe;
            neg[w - 2] = uint8_t(~3);
            return neg;
        }() });
        // SQRT(2^(16*(w/2 - 1))) == 2^(8*(w/2 - 1))
        VmBytes sq(w, 0), root(w, 0);
        const size_t half = w / 2 - 1;
        sq[2 * half] = 1;
        root[half] = 1;
        check_wide(0xb4, {sq}, {root});
        // LOG(2^(8*(w-2))) == (8*(w-2)) << 64
        VmBytes expected_log(16, 0);
        uint64_t exp_val = uint64_t(8 * (w - 2));
        for (size_t i = 0; i < 8; ++i)
            expected_log[8 + i] = uint8_t((exp_val >> (8 * i)) & 0xff);
        check_wide(0xb3, {a}, {expected_log});
    }

    // 1024B * 1024B wide MUL producing 2048B product
    VmBytes max_pos_1024(1024, 0xff);
    max_pos_1024.back() = 0x7f;
    VmBytes two = Number(2);
    VmBytes dbl(1025, 0xff);
    dbl[0] = 0xfe;
    dbl[1023] = 0xff;
    dbl[1024] = 0x00;
    check_wide(0xa0, {max_pos_1024, two}, {dbl});

    // Reject 1025-byte numeric input to arithmetic
    CHECK(EvaluateVm(Hex("98"), {VmBytes(1025, 0)}, wide).status ==
          VmStatus::Invalid);
    CHECK(EvaluateVm(Hex("8b"), {VmBytes(1025, 0)}, wide).status ==
          VmStatus::Invalid);

    // LOG2_Q64 full-precision recurrence for e > 127 at half-ULP threshold:
    // floor(sqrt(2^255)) = 0xb504f333f9de6484597d89b3754abe9f, so
    // x_hi = 2 * floor(sqrt(2^255)) + 1 = 0x16a09e667f3bcc908b2fb1366ea957d3f (e=128)
    // has x_hi^2 > 2^256 (LOG = 0x808000000000000000), while x_lo = x_hi - 1
    // has x_lo^2 < 2^256 (LOG = 0x807fffffffffffffff).
    VmBytes x_hi = Hex("3f7d95ea6613fbb208c9bcf367e6096a01000000000000000000000000000000");
    VmBytes x_lo = Hex("3e7d95ea6613fbb208c9bcf367e6096a01000000000000000000000000000000");
    check_wide(0xb3, {x_hi}, {Hex("00000000000000808000000000000000")});
    check_wide(0xb3, {x_lo}, {Hex("ffffffffffffff7f8000000000000000")});

    // Quadratic static cost scaling for MUL / DIV / SQRT / LOG on >16B operands
    auto schedule = IllustrativeCost();
    const auto c16 = EvaluateVmCharged(Hex("a0794e"), {VmBytes(16, 1), VmBytes(16, 1)},
                                       wide, schedule);
    const auto c32 = EvaluateVmCharged(Hex("a0794e"), {VmBytes(32, 1), VmBytes(32, 1)},
                                       wide, schedule);
    const auto c64 = EvaluateVmCharged(Hex("a0794e"), {VmBytes(64, 1), VmBytes(64, 1)},
                                       wide, schedule);
    const auto c1024 = EvaluateVmCharged(Hex("a0794e"), {VmBytes(1024, 1), VmBytes(1024, 1)},
                                         wide, schedule);
    // Unknown state (pop on empty stack in untaken branch, then MUL) must charge >= Known 1024B
    const auto c_unk = EvaluateVmCharged(Hex("006179a0644e"), {}, wide, schedule);
    CHECK(c16.charged && c32.charged && c64.charged && c1024.charged && c_unk.charged);
    CHECK(c16.accounting_cost < c32.accounting_cost);
    CHECK(c32.accounting_cost < c64.accounting_cost);
    CHECK(c64.accounting_cost < c1024.accounting_cost);
    CHECK(c1024.accounting_cost <= c_unk.accounting_cost);
}
} // namespace
int main() {
    FramingAndSuccess();
    ControlAndArithmetic();
    StackOpcodes();
    ByteOpcodes();
    NumericOpcodes();
    BigIntAndZeroPadding();
    MerkleProofBounds();
    ContextFieldOpcodes();
    HashAndBounds();
    ChargedAccounting();
    AuthenticatedPayment();
    AuthenticatedFieldSizeHints();
    PreparedTransactionOwnership();
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
    TypedCryptoFailures();
#endif
    std::cout << "Lotus V2 VM core vectors pass\n";
}
