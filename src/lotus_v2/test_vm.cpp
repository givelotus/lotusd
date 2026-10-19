#include "vm.h"

#include "field_size.h"
#include "tagged_hash.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
const VmProfile PROFILE{512, 8, 128, 16, 8, 256, 8, 100000};
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
                            "0064", "616a64", "4e69610069646a", "0069006900696a6a6a"})
        Expect(bad, VmStatus::Invalid);
    Expect("bd", VmStatus::Invalid); // CHECKDATASIG underflows; not success
}
// EXT2 (`ff xx`) framing: every pair is OP_SUCCESS_EXT at genesis, a lone
// trailing prefix is malformed framing, and the selector is never a push.
void Ext2Framing() {
    for (const auto &success :
         {"ff00", "ff4c", "ffff", "ff4e", "4eff00", "0061ff0064", "66ff4c",
          "fe ff", "ff004cfd"}) {
        std::string hex(success);
        hex.erase(std::remove(hex.begin(), hex.end(), ' '), hex.end());
        Expect(hex, VmStatus::AutomaticSuccess);
    }
    for (unsigned selector = 0; selector < 256; ++selector) {
        VmBytes script{0xff, uint8_t(selector)};
        CHECK(EvaluateVm(script, {}, PROFILE).status ==
              VmStatus::AutomaticSuccess);
    }
    for (const auto &bad : {"ff", "4eff", "66ff", "0061ff"})
        Expect(bad, VmStatus::Invalid);
    CHECK(EvaluateVm(Hex("ff"), {}, PROFILE).error == "truncated EXT2");
    // A push payload byte ff is data, not an EXT2 prefix.
    Expect("01ff794e", VmStatus::Success);
    Expect("01ff", VmStatus::Invalid);
    // A malformed push before the prefix still rejects.
    Expect("4cfdff00", VmStatus::Invalid);
    // Structural charge only, like a single-byte success opcode.
    VmCostProfile schedule;
    schedule.max_invocation_cost = 1000;
    schedule.structural_byte_cost = 1;
    for (auto &op : schedule.opcode) op = {1, 1, 1};
    const auto charged =
        EvaluateVmCharged(Hex("ff4c00"), {}, PROFILE, schedule);
    CHECK(charged.charged && charged.accounting_cost == 3 &&
          charged.invocation.status == VmStatus::AutomaticSuccess);
    CHECK(VmExt2(0x12) == 0xff12 && IsVmExt2(VmExt2(0)) && !IsVmExt2(0xff));
}
// The P03 registry (docs/lotus-v2/tools/opcodes.json) leaves exactly these
// 31 single-byte OP_SUCCESS_N; check_opcode_coverage.py checks the registry
// itself against vm_test/opcode_coverage.json.
const std::vector<uint8_t> REGISTRY_SUCCESS_BYTES{
    0x5e, 0x5f, 0x67, 0x68, 0x6d, 0x6e, 0x6f, 0x82, 0x83, 0x84, 0x85,
    0x86, 0x87, 0x95, 0x96, 0x97, 0xb5, 0xb6, 0xb7, 0xc4, 0xc5, 0xc6,
    0xc7, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe};
void RegistryAllocation() {
    CHECK(REGISTRY_SUCCESS_BYTES.size() == 31);
    for (unsigned b = 0; b < 255; ++b) { // ff: see Ext2Framing
        const bool success =
            std::find(REGISTRY_SUCCESS_BYTES.begin(),
                      REGISTRY_SUCCESS_BYTES.end(),
                      b) != REGISTRY_SUCCESS_BYTES.end();
        // Suffix 4c would be a truncated push if the byte were assigned.
        const auto result = EvaluateVm(VmBytes{uint8_t(b), 0x4c}, {}, PROFILE);
        CHECK((result.status == VmStatus::AutomaticSuccess) == success);
    }
    // Retired fused loop headers are OP_SUCCESS_103/104.
    Expect("674c", VmStatus::AutomaticSuccess);
    Expect("68", VmStatus::AutomaticSuccess);
    Expect("4e69 67 6a", VmStatus::AutomaticSuccess);
    // EMITLOG rejects wherever the scan reaches it: alone, before a success
    // byte, in a skipped arm, after RETURN, inside a loop.
    for (const auto &bad : {"6c", "6cfe", "6cff00", "00616c644e", "666c",
                            "4e6c", "00696c6a4e", "0061 4e 63 6c 64 4e"}) {
        const auto result = EvaluateVm(Hex(bad), {}, PROFILE);
        CHECK(result.status == VmStatus::Invalid &&
              result.error == "EMITLOG is invalid on-chain");
    }
    Expect("fe6c", VmStatus::AutomaticSuccess); // success scanned first
    Expect("ff006c", VmStatus::AutomaticSuccess);
    Expect("016c794e", VmStatus::Success);     // push payload is data
    // Newly registered bytes are assigned: never success. Without an
    // authenticated context (or before their semantics land) they are
    // Unsupported; three index operands are supplied for the readers.
    // STATEHASH (c3) is context-free and covered by StateHashAndVerify.
    for (uint8_t b : {0xde, 0xdf, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf5, 0xf6})
        CHECK(EvaluateVm(VmBytes{b, 0x4e}, {Number(0), Number(0), Number(0)},
                         PROFILE)
                  .status == VmStatus::Unsupported);
    // Cost profiles need a base for every executable assigned byte, but not
    // for EMITLOG or the EXT2 prefix.
    VmCostProfile schedule;
    schedule.max_invocation_cost = 1000;
    schedule.structural_byte_cost = 1;
    for (auto &op : schedule.opcode) op = {1, 1, 1};
    schedule.opcode[0x6c] = {};
    schedule.opcode[0xff] = {};
    std::string error;
    CHECK(ValidateVmCostProfile(PROFILE, schedule, error));
    schedule.opcode[0xc3] = {};
    CHECK(!ValidateVmCostProfile(PROFILE, schedule, error) &&
          error == "missing assigned opcode cost");
}
void ControlAndArithmetic() {
    for (const auto &valid :
         {"4d4e9e00a6", "00696a4e", "4e69614e4e6b646a4e",
          "c96979c969794e4f6b6a666a4e",
          "4e7a91", "4c004c00914e91"})
        Expect(valid, VmStatus::Success, {}, PROFILE, 1);
    Expect("006179634e64", VmStatus::Success);
    Expect("00614e4e6b634e64", VmStatus::Success); // BREAK in skipped arm
    Expect("00696b6a4e", VmStatus::Success); // BREAK in zero-iteration loop
    Expect("4e614e4e6b634e64", VmStatus::Invalid); // executed outside loop
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
void StateAndActiveIndexOpcodes() {
    // UTXOFLAGS (de), UTXOSTATEROOT (ee), OUTPUTSTATEROOT (ef),
    // ACTIVEBRANCHINDEX (f5) and ACTIVEWITNESSINDEX (f6).
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x31);
    spend.sequence = UINT32_MAX;
    // Path 0 selects branches 0 and 2; the second witness runs branch 2.
    spend.witnesses = {BranchWitness{Hex("4e"), {}, {}},
                       BranchWitness{Hex("4e"), {}, {}}};
    tx.inputs.push_back(spend);
    Output coin;
    coin.value = 5000;
    coin.branches.resize(3);
    coin.branches[1].fill(0x77);
    coin.paths = {{0, 2}, {1}};
    ResolvedCoins resolved{coin};
    Output plain;
    plain.value = 1000;
    plain.branches = {Hash{}};
    plain.branches[0].fill(0x44);
    plain.paths = {{0}};
    Output stateful = plain;
    stateful.flags = 4;
    stateful.state_root.fill(0xab);
    tx.outputs = {plain, stateful};
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    tx.inputs.push_back(mint);
    resolved.push_back(std::nullopt);

    // Every witness must authenticate against its branch for the context.
    auto sync = [&] {
        resolved[0]->branches[0] = BranchLeaf(tx.inputs[0].witnesses[0].script);
        resolved[0]->branches[2] = BranchLeaf(tx.inputs[0].witnesses[1].script);
        tx.inputs[1].prev_txid = BranchLeaf(tx.inputs[1].witnesses[0].script);
    };
    auto run = [&](size_t input, size_t witness, VmBytes script,
                   std::vector<VmBytes> args) {
        auto &w = tx.inputs[input].witnesses[witness];
        w.script = script;
        w.arguments = args;
        sync();
        PositiveDelta delta{};
        delta[0] = 1;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, input,
                               witness, input == 1 ? std::optional(delta)
                                                   : std::nullopt};
        return EvaluateVmWithContext(w.script, w.arguments, PROFILE, ctx);
    };
    // Runs `op(args) expected EQUALVERIFY TRUE`.
    auto expect = [&](size_t input, size_t witness, uint8_t op,
                      std::vector<VmBytes> args, const VmBytes &expected) {
        VmBytes script;
        if (input == 1) script.push_back(0x79); // DROP the mint delta
        script.push_back(op);
        script.push_back(uint8_t(expected.size()));
        script.insert(script.end(), expected.begin(), expected.end());
        script.push_back(0x92); // EQUALVERIFY
        script.push_back(0x4e);
        const auto result = run(input, witness, script, args);
        if (result.status != VmStatus::Success)
            throw std::runtime_error("state opcode " + std::to_string(op) +
                                     ": " + result.error);
    };
    const VmBytes minus_one(16, 0xff);
    const VmBytes zeros(32, 0);
    const VmBytes root(32, 0xab);

    // A coin without HAS_STATE: flags 0, zero root.
    expect(0, 0, 0xde, {Number(0)}, Number(0));
    expect(0, 0, 0xee, {Number(0)}, zeros);
    // With HAS_STATE (and a token) the flags and root are visible.
    resolved[0]->flags = 5;
    resolved[0]->token_id.fill(0x09);
    resolved[0]->state_root.fill(0xab);
    expect(0, 0, 0xde, {Number(0)}, Number(5));
    expect(0, 0, 0xee, {Number(0)}, root);
    // Outputs: zeros without HAS_STATE, the root with it.
    expect(0, 0, 0xef, {Number(0)}, zeros);
    expect(0, 0, 0xef, {Number(1)}, root);
    expect(0, 0, 0xe0, {Number(1)}, Number(4)); // OUTPUTFLAGS shows 0x04
    // Active branch index is paths[path_index][witness_index].
    expect(0, 0, 0xf5, {}, Number(0));
    expect(0, 1, 0xf5, {}, Number(2));
    expect(0, 0, 0xf6, {}, Number(0));
    expect(0, 1, 0xf6, {}, Number(1));
    // Mint: no branch (-1), witness 0; UTXO reads at the mint fail.
    expect(1, 0, 0xf5, {}, minus_one);
    expect(1, 0, 0xf6, {}, Number(0));
    expect(0, 0, 0xf5, {}, Number(0));
    CHECK(run(0, 0, Hex("de4e"), {Number(1)}).error ==
          "UTXO read at nonspend input");
    CHECK(run(0, 0, Hex("ee4e"), {Number(1)}).error ==
          "UTXO read at nonspend input");
    CHECK(run(1, 0, Hex("de4e"), {Number(1)}).error ==
          "UTXO read at nonspend input");
    // Index bounds.
    CHECK(run(0, 0, Hex("de4e"), {Number(2)}).error ==
          "introspection index out of range");
    CHECK(run(0, 0, Hex("ee4e"), {Number(2)}).error ==
          "introspection index out of range");
    CHECK(run(0, 0, Hex("ef4e"), {Number(2)}).error ==
          "introspection index out of range");
    // Without an authenticated context: Unsupported.
    Expect("f5", VmStatus::Unsupported);
    Expect("f6", VmStatus::Unsupported);
    Expect("ef", VmStatus::Unsupported, {Number(0)});
    Expect("de", VmStatus::Unsupported, {Number(0)});
    // Static size pass: results are 16 (de/f5/f6) and 32 (ee/ef) bytes, so
    // the charged cost equals the measured cost.
    VmCostProfile cost;
    cost.max_invocation_cost = 1000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    for (const auto &[input, script, args] :
         std::vector<std::tuple<size_t, VmBytes, std::vector<VmBytes>>>{
             {0, Hex("de79ee79ef794e"), {Number(0), Number(0), Number(0)}},
             {0, Hex("f579f6794e"), {}},
             {1, Hex("79f579f6794e"), {}}}) {
        auto &w = tx.inputs[input].witnesses[0];
        w.script = script;
        w.arguments = args;
        sync();
        PositiveDelta delta{};
        delta[0] = 1;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, input, 0,
                               input == 1 ? std::optional(delta)
                                          : std::nullopt};
        const auto charged =
            EvaluateVmCharged(script, args, PROFILE, cost,
                              uint16_t(tx.inputs.size()),
                              uint16_t(tx.outputs.size()), &ctx);
        if (charged.invocation.status != VmStatus::Success)
            throw std::runtime_error("charged state opcodes: " +
                                     charged.invocation.error);
        // Exact abstract sizes: static accounting equals the executed cost.
        if (!charged.charged ||
            charged.accounting_cost != charged.invocation.executed_cost)
            throw std::runtime_error(
                "state opcode static cost " +
                std::to_string(uint64_t(charged.accounting_cost)) + " vs " +
                std::to_string(uint64_t(charged.invocation.executed_cost)));
    }
}
void TokenBalance() {
    // TXTOKENBALANCE (ec): Bytes32(asset) -> N(in) N(out). Zero = native.
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    chain[0] = 9;
    auto amount = [](uint64_t v) {
        VmBytes out(16);
        for (size_t i = 0; i < 8; ++i) out[i] = uint8_t(v >> (8 * i));
        return out;
    };
    Hash token_t{};
    token_t.fill(0x71);
    Transaction tx;
    Input native_spend;
    native_spend.flags = 1;
    native_spend.prev_txid.fill(0x21);
    native_spend.sequence = UINT32_MAX;
    native_spend.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    Input token_spend = native_spend;
    token_spend.prev_txid.fill(0x22);
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses = {BranchWitness{Hex("794e"), {}, {}}};
    mint.prev_txid = BranchLeaf(mint.witnesses[0].script);
    const Hash token_m = mint.prev_txid;
    tx.inputs = {native_spend, token_spend, mint};
    Output native_coin;
    native_coin.value = 5000;
    native_coin.branches = {BranchLeaf(Hex("4e"))};
    native_coin.paths = {{0}};
    Output token_coin = native_coin;
    token_coin.flags = 1;
    token_coin.token_id = token_t;
    token_coin.value = 30;
    ResolvedCoins resolved{native_coin, token_coin, std::nullopt};
    Output pay = native_coin;
    pay.value = 1000;
    Output token_out = token_coin;
    token_out.value = 20;
    Output token_burn = token_coin;
    token_burn.flags = 3;
    token_burn.value = 10;
    token_burn.paths.clear();
    Output minted = token_coin;
    minted.token_id = token_m;
    minted.value = 7;
    tx.outputs = {pay, token_out, token_burn, minted};

    // `asset ec <out> EQUALVERIFY <in> EQUALVERIFY TRUE`
    auto script_for = [&](const VmBytes &asset, uint64_t in, uint64_t out) {
        VmBytes script{uint8_t(asset.size())};
        script.insert(script.end(), asset.begin(), asset.end());
        script.push_back(0xec);
        for (const uint64_t v : {out, in}) {
            const VmBytes n = amount(v);
            script.push_back(16);
            script.insert(script.end(), n.begin(), n.end());
            script.push_back(0x92);
        }
        script.push_back(0x4e);
        return script;
    };
    PreparedVmTransaction prepared;
    VmCostProfile cost;
    cost.max_invocation_cost = 1000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    auto run = [&](const VmBytes &script, bool use_prepared) {
        tx.inputs[0].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(script);
        if (use_prepared) {
            std::string error;
            CHECK(prepared.Prepare(tx, tx_profile, chain, resolved, cost,
                                   error));
            const auto ctx = prepared.Invocation(0, 0);
            return EvaluateVmCharged(script, {}, PROFILE, prepared.Cost(),
                                     uint16_t(tx.inputs.size()),
                                     uint16_t(tx.outputs.size()), &ctx)
                .invocation;
        }
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0,
                               std::nullopt};
        return EvaluateVmWithContext(script, {}, PROFILE, ctx);
    };
    const VmBytes native(32, 0);
    const VmBytes t(token_t.begin(), token_t.end());
    const VmBytes m(token_m.begin(), token_m.end());
    const VmBytes absent(32, 0x5a);
    for (const bool use_prepared : {false, true}) {
        // Native: spent native coin in, every native output out.
        CHECK(run(script_for(native, 5000, 1000), use_prepared).status ==
              VmStatus::Success);
        // Token: burn outputs count toward the output total.
        CHECK(run(script_for(t, 30, 30), use_prepared).status ==
              VmStatus::Success);
        // Mint: no input side, so out - in is the minted delta.
        CHECK(run(script_for(m, 0, 7), use_prepared).status ==
              VmStatus::Success);
        // Absent asset: 0 0.
        CHECK(run(script_for(absent, 0, 0), use_prepared).status ==
              VmStatus::Success);
        CHECK(run(script_for(t, 30, 31), use_prepared).status ==
              VmStatus::Invalid);
        // Asset must be exactly 32 bytes.
        for (const size_t width : {size_t(31), size_t(33), size_t(0)}) {
            VmBytes script;
            if (width == 0)
                script = Hex("4c00");
            else {
                script.push_back(uint8_t(width));
                script.insert(script.end(), width, 0x71);
            }
            script.insert(script.end(), {0xec, 0x4e});
            const auto result = run(script, use_prepared);
            CHECK(result.status == VmStatus::Invalid &&
                  result.error == "token balance asset width");
        }
    }
    Expect("ec", VmStatus::Unsupported, {VmBytes(32)});
}
void InputWitnessArg() {
    // INPUTWITNESSARG (df): i w a -> bytes, for any input (plan I-12).
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x41);
    spend.sequence = UINT32_MAX;
    spend.witnesses = {BranchWitness{Hex("4e"), {}, {}},
                       BranchWitness{Hex("4e"), {}, {Hex("b1"), Hex("b2b2")}}};
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses = {BranchWitness{Hex("79794e"), {}, {Hex("aa")}}};
    mint.prev_txid = BranchLeaf(mint.witnesses[0].script);
    tx.inputs = {spend, mint};
    Output coin;
    coin.value = 900;
    coin.branches.resize(2);
    coin.paths = {{0, 1}};
    ResolvedCoins resolved{coin, std::nullopt};
    resolved[0]->branches[1] = BranchLeaf(spend.witnesses[1].script);
    Output pay;
    pay.value = 100;
    pay.branches = {Hash{}};
    pay.branches[0].fill(0x45);
    pay.paths = {{0}};
    Output minted = pay;
    minted.flags = 1;
    minted.token_id = mint.prev_txid;
    minted.value = 1;
    tx.outputs = {pay, minted};

    VmCostProfile cost;
    cost.max_invocation_cost = 1000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    PreparedVmTransaction prepared;
    // Witness 0 arguments are {X, i, w, a}; df reads input i witness w
    // argument a and compares it with `expected`, leaving X to drop.
    auto run = [&](uint8_t i, uint8_t w, uint8_t a, const VmBytes &expected,
                   bool use_prepared = false) {
        VmBytes script{0xdf, uint8_t(expected.size())};
        script.insert(script.end(), expected.begin(), expected.end());
        script.insert(script.end(), {0x92, 0x79, 0x4e});
        auto &witness = tx.inputs[0].witnesses[0];
        witness.script = script;
        witness.arguments = {Hex("c0ffee"), Number(i), Number(w), Number(a)};
        resolved[0]->branches[0] = BranchLeaf(script);
        if (use_prepared) {
            std::string error;
            CHECK(prepared.Prepare(tx, tx_profile, chain, resolved, cost,
                                   error));
            const auto ctx = prepared.Invocation(0, 0);
            return EvaluateVmCharged(script, witness.arguments, PROFILE,
                                     prepared.Cost(), 2, 2, &ctx);
        }
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0,
                               std::nullopt};
        return EvaluateVmCharged(script, witness.arguments, PROFILE, cost, 2,
                                 2, &ctx);
    };
    auto ok = [&](uint8_t i, uint8_t w, uint8_t a, const VmBytes &expected) {
        for (const bool use_prepared : {false, true}) {
            const auto result = run(i, w, a, expected, use_prepared);
            if (result.invocation.status != VmStatus::Success)
                throw std::runtime_error("INPUTWITNESSARG " +
                                         result.invocation.error);
        }
    };
    auto fails = [&](uint8_t i, uint8_t w, uint8_t a) {
        const auto result = run(i, w, a, Hex("00"));
        CHECK(result.invocation.status == VmStatus::Invalid);
        return result.invocation.error;
    };
    ok(0, 0, 0, Hex("c0ffee"));         // own invocation's first argument
    ok(0, 0, 3, Number(3));             // own top argument (a itself)
    ok(0, 1, 0, Hex("b1"));             // sibling witness of the same input
    ok(0, 1, 1, Hex("b2b2"));
    ok(1, 0, 0, Hex("aa"));             // another input's (mint) argument
    CHECK(fails(0, 0, 4) == "introspection index out of range");
    CHECK(fails(0, 2, 0) == "introspection index out of range");
    CHECK(fails(1, 1, 0) == "introspection index out of range"); // mint w==0
    CHECK(fails(2, 0, 0) == "introspection index out of range");
    CHECK(run(0, 0, 0, Hex("c0ffef")).invocation.status ==
          VmStatus::Invalid); // the value really is compared
    // The size pass bounds the result by the widest argument in the
    // prepared transaction (16 bytes), not the element cap.
    const auto loose = run(0, 0, 0, Hex("c0ffee"));
    const auto tight = run(0, 0, 0, Hex("c0ffee"), true);
    if (!loose.charged || !tight.charged ||
        // Charged once as df's result and once as EQUALVERIFY's operand.
        tight.accounting_cost + 2 * (PROFILE.max_element_bytes - 16) !=
            loose.accounting_cost)
        throw std::runtime_error(
            "INPUTWITNESSARG static bound " +
            std::to_string(uint64_t(tight.accounting_cost)) + " " +
            std::to_string(uint64_t(loose.accounting_cost)));
    CHECK(tight.invocation.executed_cost <= tight.accounting_cost);
    Expect("df", VmStatus::Unsupported, {Number(0), Number(0), Number(0)});
}
void StateHashAndVerify() {
    // STATEHASH (c3): item_1..item_k N(k) -> Hash32 under the
    // Lotus/v2/contractstate tag. Expected digests come from the Python
    // reference (test_framework.messages.lotus_v2_tagged_hash).
    const VmProfile wide{8192, 64, 8192, 256, 256, 1048576, 64, 100000};
    auto check = [&](const std::string &pushes, const std::string &digest) {
        const auto script = Hex(pushes + "c3 20" + digest + "92 4e");
        const auto result = EvaluateVm(script, {}, wide);
        if (result.status != VmStatus::Success)
            throw std::runtime_error("STATEHASH " + pushes + ": " + result.error);
    };
    check("00", "593ba2e63160ffe5a848e607a2c8d2bb2aef41e2956facd1b888178b0e170484");
    check("4c00 4e",
          "df8a9562ee5772b99d5cc7bcee85abd81aa0e78e8556676e9c622aca0369ac5b");
    check("01aa 10000102030405060708090a0b0c0d0e0f 4f",
          "6e84c64bbe536e5d14d89ee55c0c81fa8cf9ce41430b22e9dc7909d35ec3b77c");
    check("0101 4c00 020203 50",
          "43f4bb1049bc44deee1b79c758100b8e417d872cd35422143c10e92c356b66ef");
    std::string sixty_four;
    for (int i = 0; i < 64; ++i) sixty_four += "4c00";
    const std::string n64 = "10 40000000000000000000000000000000";
    check(sixty_four + n64,
          "894f918b4e09176295283b91e943d64d8aaa3cb2ea4736bc2abe7d50480522ce");
    // k outside 0..64, or more items than the stack holds, is an error.
    CHECK(EvaluateVm(Hex(sixty_four + "4c00 10 41000000000000000000000000000000 c3 4e"),
                     {}, wide)
              .error == "STATEHASH item count");
    CHECK(EvaluateVm(Hex("4d c3 4e"), {}, wide).error == "STATEHASH item count");
    CHECK(EvaluateVm(Hex("01aa 4f c3 4e"), {}, wide).error == "stack underflow");
    // The streamed digest equals the materialized tagged hash, including
    // multi-chunk items and three-byte CompactSize lengths.
    for (const size_t length : {size_t(0), size_t(300), size_t(2000)}) {
        std::vector<VmBytes> items{VmBytes(length, 0x5c), Hex("01")};
        VmBytes preimage{2};
        for (const auto &item : items) {
            if (item.size() < 253)
                preimage.push_back(uint8_t(item.size()));
            else
                preimage.insert(preimage.end(), {253, uint8_t(item.size()),
                                                 uint8_t(item.size() >> 8)});
            preimage.insert(preimage.end(), item.begin(), item.end());
        }
        CHECK(ContractStateHash(items) ==
              TaggedHash(HashDomain::ContractState, preimage));
        CHECK(ContractStateHash(items) !=
              TaggedHash(HashDomain::State, preimage)); // separate tag (I-13)
    }
    // Static cost: a literal count gives exact sizes, so accounting equals
    // the executed cost; a dynamic count is bounded by the 64-item worst case.
    VmCostProfile cost;
    cost.max_invocation_cost = 100000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    const auto exact = EvaluateVmCharged(
        Hex("01aa 10000102030405060708090a0b0c0d0e0f 4f c3 79 4e"), {}, wide,
        cost);
    CHECK(exact.invocation.status == VmStatus::Success && exact.charged &&
          exact.accounting_cost == exact.invocation.executed_cost);
    const auto dynamic = EvaluateVmCharged(Hex("c3 79 4e"),
                                           {Hex("aa"), Number(1)}, wide, cost);
    CHECK(dynamic.invocation.status == VmStatus::Success && dynamic.charged &&
          dynamic.accounting_cost > dynamic.invocation.executed_cost);

    // STATEVERIFY (ed): Hash32 ->, against the spent coin's state root.
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x51);
    spend.sequence = UINT32_MAX;
    spend.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    tx.inputs = {spend, mint};
    Output coin;
    coin.value = 700;
    coin.branches = {Hash{}};
    coin.paths = {{0}};
    coin.flags = 4;
    const std::vector<VmBytes> state_items{Hex("01"), Hex("0203")};
    coin.state_root = ContractStateHash(state_items);
    ResolvedCoins resolved{coin, std::nullopt};
    Output pay = coin;
    pay.flags = 0;
    pay.state_root = Hash{};
    pay.branches[0].fill(0x46);
    tx.outputs = {pay};
    auto run = [&](size_t input, const VmBytes &script) {
        tx.inputs[input].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(tx.inputs[0].witnesses[0].script);
        tx.inputs[1].prev_txid = BranchLeaf(tx.inputs[1].witnesses[0].script);
        PositiveDelta delta{};
        delta[0] = 1;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, input, 0,
                               input == 1 ? std::optional(delta)
                                          : std::nullopt};
        return EvaluateVmWithContext(script, {}, PROFILE, ctx);
    };
    VmBytes push_root{32};
    push_root.insert(push_root.end(), coin.state_root.begin(),
                     coin.state_root.end());
    auto with = [](VmBytes a, const std::string &tail) {
        const auto b = Hex(tail);
        a.insert(a.end(), b.begin(), b.end());
        return a;
    };
    CHECK(run(0, with(push_root, "ed 4e")).status == VmStatus::Success);
    // STATEHASH then STATEVERIFY: commit to the items behind the root.
    CHECK(run(0, Hex("0101 020203 4f c3 ed 4e")).status == VmStatus::Success);
    CHECK(run(0, Hex("0101 020204 4f c3 ed 4e")).error ==
          "STATEVERIFY mismatch");
    auto wrong = push_root;
    wrong.back() ^= 1;
    CHECK(run(0, with(wrong, "ed 4e")).error == "STATEVERIFY mismatch");
    CHECK(run(0, Hex("1f" + std::string(62, '0') + "ed 4e")).error ==
          "STATEVERIFY root width");
    CHECK(run(1, with(push_root, "ed 4e")).error ==
          "STATEVERIFY requires spend");
    resolved[0]->flags = 0;
    resolved[0]->state_root = Hash{};
    CHECK(run(0, with(push_root, "ed 4e")).error ==
          "STATEVERIFY coin lacks state");
    Expect("ed", VmStatus::Unsupported, {VmBytes(32)});
}
// Deferred records helpers: one claim / one authorization per record.
DeferredRecords ClaimRecords(
    std::initializer_list<std::pair<uint16_t, uint64_t>> claims) {
    DeferredRecords records;
    for (const auto &[j, amount] : claims)
        records.Add(kOutputClaimsKind, 0, OutputClaim{amount, {j}});
    return records;
}
DeferredRecords AuthorizeRecords(std::initializer_list<uint16_t> outputs) {
    DeferredRecords records;
    for (uint16_t j : outputs)
        records.Add(kStateAuthorizationKind, 0, StateAuthorization{{j}});
    return records;
}
// The consensus deferred checks over per-input records.
bool PostCheck(std::span<const Output> outputs,
               std::vector<DeferredRecords> per_input, std::string &error) {
    return RunDeferredChecks(DeferredCheckRegistry::Consensus(),
                             DeferredTxView{outputs, per_input.size()},
                             per_input, error) == DeferredOutcome::Accepted;
}
std::vector<OutputClaim> ClaimsOf(const DeferredRecords &records) {
    return OutputClaimsOf(records);
}
std::vector<uint16_t> AuthorizedOf(const DeferredRecords &records) {
    std::vector<uint16_t> out;
    for (const auto &record : StateAuthorizationsOf(records))
        out.insert(out.end(), record.outputs.begin(), record.outputs.end());
    return out;
}

void TransactionEffects() {
    // Order-free deferred records (plan I-11) and the consensus kinds.
    Output plain;
    plain.value = 100;
    plain.branches = {Hash{}};
    plain.branches[0].fill(0x61);
    plain.paths = {{0}};
    Output stateful = plain;
    stateful.flags = 4;
    stateful.state_root.fill(0x62);
    const std::vector<Output> outputs{plain, stateful};
    std::string error;
    CHECK(!PostCheck(outputs, {DeferredRecords{}}, error) &&
          error == "state-output-unauthorized");
    CHECK(PostCheck(outputs, {AuthorizeRecords({1})}, error));
    // Claims on one output sum across inputs, in any order.
    for (const bool ab : {true, false}) {
        auto a = ClaimRecords({{0, 60}});
        auto b = ClaimRecords({{0, 40}, {1, 100}});
        b.Merge(AuthorizeRecords({1}));
        std::vector<DeferredRecords> per_input;
        per_input.push_back(ab ? a : b);
        per_input.push_back(ab ? b : a);
        CHECK(PostCheck(outputs, per_input, error));
        per_input[0].Merge(ClaimRecords({{0, 1}}));
        CHECK(!PostCheck(outputs, per_input, error) &&
              error == "output-overclaimed");
    }
    // Claims cannot overflow the comparison.
    {
        auto huge = ClaimRecords({{0, UINT64_MAX}, {0, UINT64_MAX}});
        huge.Merge(AuthorizeRecords({1}));
        CHECK(!PostCheck(outputs, {huge}, error));
    }
    // Out-of-range indexes are rejected rather than ignored.
    CHECK(!PostCheck(outputs, {ClaimRecords({{2, 0}})}, error));
    CHECK(!PostCheck(outputs, {AuthorizeRecords({1, 2})}, error));

    // An invocation commits nothing on failure and nothing when no
    // record-producing opcode runs; the records live in the context, never
    // in the (reusable) prepared transaction.
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x63);
    spend.sequence = UINT32_MAX;
    spend.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    tx.inputs = {spend};
    tx.outputs = outputs;
    Output coin = plain;
    coin.value = 500;
    ResolvedCoins resolved{coin};
    const auto existing = ClaimRecords({{0, 5}});
    for (const auto &script : {Hex("4e"), Hex("4d")}) {
        tx.inputs[0].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(script);
        DeferredRecords accumulator = existing;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0,
                               std::nullopt};
        ctx.effects = &accumulator;
        EvaluateVmWithContext(script, {}, PROFILE, ctx);
        CHECK(ClaimsOf(accumulator) == ClaimsOf(existing) &&
              AuthorizedOf(accumulator).empty());
    }
}
struct TemplateSpec {
    uint8_t value_mode = 0, token_mode = 0, paths_mode = 0;
    bool burn = false, wildcard = false;
    uint64_t value = 0;
    Hash token{};
    uint8_t branch_count = 0;
    uint16_t mask = 0, stack_mask = 0;
    uint8_t state_mode = 0, output_mode = 0;
    Hash state_root{};
    uint16_t output_index = 0;
    std::vector<Hash> branches;
    std::vector<std::vector<uint8_t>> paths;
};
VmBytes EncodeTemplate(const TemplateSpec &t) {
    VmBytes out{uint8_t(t.value_mode | t.token_mode << 2 | t.paths_mode << 4 |
                        uint8_t(t.burn) << 6 | uint8_t(t.wildcard) << 7)};
    auto le = [&](uint64_t v, size_t width) {
        for (size_t i = 0; i < width; ++i) out.push_back(uint8_t(v >> (8 * i)));
    };
    if (t.value_mode == 1 || t.value_mode == 2) le(t.value, 8);
    if (t.token_mode == 2) out.insert(out.end(), t.token.begin(), t.token.end());
    le(t.branch_count, 1);
    le(t.mask, 2);
    le(t.stack_mask, 2);
    le(t.state_mode, 1);
    le(t.output_mode, 1);
    if (t.state_mode == 1)
        out.insert(out.end(), t.state_root.begin(), t.state_root.end());
    if (t.output_mode == 1) le(t.output_index, 2);
    for (const auto &b : t.branches) out.insert(out.end(), b.begin(), b.end());
    if (t.paths_mode == 1) {
        out.push_back(uint8_t(t.paths.size()));
        for (const auto &path : t.paths) {
            out.push_back(uint8_t(path.size()));
            out.insert(out.end(), path.begin(), path.end());
        }
    }
    return out;
}
void PushBytes(VmBytes &script, const VmBytes &data) {
    if (data.empty()) {
        script.insert(script.end(), {0x4c, 0x00}); // 0x00 is N(0)
    } else if (data.size() <= 75) {
        script.push_back(uint8_t(data.size()));
    } else {
        CHECK(data.size() <= 255);
        script.insert(script.end(), {0x4c, uint8_t(data.size())});
    }
    script.insert(script.end(), data.begin(), data.end());
}

void EnforceOutput() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    const VmProfile vm{4096, 16, 1024, 64, 16, 65536, 16, 100000};
    ChainId chain{};
    auto fill = [](uint8_t b) {
        Hash h;
        h.fill(b);
        return h;
    };
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x81);
    spend.sequence = UINT32_MAX;
    spend.witnesses = {BranchWitness{Hex("4e"), {}, {}}};
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.witnesses = {BranchWitness{Hex("79794e"), {}, {}}};
    tx.inputs = {spend, mint};
    Output coin;
    coin.value = 200;
    coin.branches = {Hash{}, fill(0xb1)};
    coin.paths = {{0}, {1}};
    ResolvedCoins resolved{coin, std::nullopt};
    const Hash state = fill(0x5e);
    Output o0;  // native 100, two branches
    o0.value = 100;
    o0.branches = {fill(0xa0), fill(0xa1)};
    o0.paths = {{0}, {1}};
    Output o1;  // continuation of the spent coin (synced per run)
    o1.value = 200;
    Output o2;  // minted token with state
    o2.flags = 5;
    o2.value = 5;
    o2.branches = {fill(0xa0)};
    o2.paths = {{0}};
    o2.state_root = state;
    Output o3;  // native burn
    o3.flags = 2;
    o3.value = 7;
    o3.branches = {fill(0xa2)};
    tx.outputs = {o0, o1, o2, o3};
    VmCostProfile cost;
    cost.max_invocation_cost = 100000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    cost.opcode[0xeb].per_scanned_output = 5;

    struct Run {
        VmChargedResult charged;
        DeferredRecords effects;
    };
    // Runs `script` as input `input` (0 spend, 1 mint) with fresh effects.
    auto run = [&](size_t input, const VmBytes &script,
                   std::vector<VmBytes> args = {}, bool sync = true) {
        tx.inputs[input].witnesses[0].script = script;
        tx.inputs[input].witnesses[0].arguments = args;
        resolved[0]->branches[0] = BranchLeaf(tx.inputs[0].witnesses[0].script);
        tx.inputs[1].prev_txid = BranchLeaf(tx.inputs[1].witnesses[0].script);
        tx.outputs[2].token_id = tx.inputs[1].prev_txid;
        if (sync) {
            tx.outputs[1].branches = resolved[0]->branches;
            tx.outputs[1].paths = resolved[0]->paths;
        }
        PositiveDelta delta{};
        delta[0] = 5;
        Run r;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, input, 0,
                               input == 1 ? std::optional(delta)
                                          : std::nullopt};
        ctx.effects = &r.effects;
        r.charged = EvaluateVmCharged(script, args, vm, cost, 2, 4, &ctx);
        return r;
    };
    // `<template> <claim> eb <j> EQUALVERIFY [drop delta] TRUE`
    auto script_for = [&](const TemplateSpec &t, uint64_t claim,
                          int expect_j, bool for_mint = false,
                          const VmBytes &prefix = {}) {
        VmBytes script = prefix;
        PushBytes(script, EncodeTemplate(t));
        VmBytes claim_n(16);
        for (size_t i = 0; i < 8; ++i) claim_n[i] = uint8_t(claim >> (8 * i));
        PushBytes(script, claim_n);
        script.push_back(0xeb);
        PushBytes(script, Number(uint8_t(expect_j)));
        script.push_back(0x92);
        if (for_mint) script.push_back(0x79);
        script.push_back(0x4e);
        return script;
    };
    auto expect_match = [&](const TemplateSpec &t, int j, size_t input = 0,
                            std::vector<VmBytes> args = {},
                            const VmBytes &prefix = {}) {
        const auto r = run(input, script_for(t, 0, j, input == 1, prefix), args);
        if (r.charged.invocation.status != VmStatus::Success)
            throw std::runtime_error("ENFORCEOUTPUT expected output " +
                                     std::to_string(j) + ": " +
                                     r.charged.invocation.error);
        const auto claims = ClaimsOf(r.effects);
        CHECK(claims.size() == 1 && claims[0].matches ==
                                        std::vector<uint16_t>{uint16_t(j)});
        return r;
    };
    auto expect_error = [&](const TemplateSpec &t, const std::string &error,
                            size_t input = 0, std::vector<VmBytes> args = {},
                            const VmBytes &prefix = {}) {
        const auto r = run(input, script_for(t, 0, 0, input == 1, prefix), args);
        if (r.charged.invocation.status != VmStatus::Invalid ||
            r.charged.invocation.error != error)
            throw std::runtime_error("ENFORCEOUTPUT expected '" + error +
                                     "', got: " + r.charged.invocation.error);
        CHECK(r.effects.Empty()); // staged effects are discarded on failure
    };
    const std::string none = "ENFORCEOUTPUT no matching output";

    // Value modes: OMIT, EXACT, MIN, FROM_STACK. The scan takes the first
    // non-burn, stateless match.
    TemplateSpec any;
    expect_match(any, 0);
    TemplateSpec exact;
    exact.value_mode = 1;
    exact.value = 200;
    expect_match(exact, 1);
    exact.value = 201;
    expect_error(exact, none);
    TemplateSpec min;
    min.value_mode = 2;
    min.value = 101;
    expect_match(min, 1);
    TemplateSpec from_stack;
    from_stack.value_mode = 3;
    expect_match(from_stack, 0, 0, {}, Hex("10 64000000000000000000000000000000"));
    // Burn: only burn outputs match burn templates.
    TemplateSpec burn;
    burn.burn = true;
    expect_match(burn, 3);
    burn.value_mode = 1;
    burn.value = 8;
    expect_error(burn, none);
    // Tokens: NATIVE, EXACT (zero = native), SELF from the mint invocation.
    TemplateSpec token;
    token.state_mode = 2; // o2 carries state
    token.token_mode = 2;
    auto state_push = [&] {
        VmBytes p;
        PushBytes(p, VmBytes(state.begin(), state.end()));
        return p;
    };
    token.token = BranchLeaf(Hex("4e")); // not the minted id
    expect_error(token, none, 0, {}, state_push());
    token.token_mode = 3; // SELF: the mint's own token id
    {
        const auto r = expect_match(token, 2, 1, {}, state_push());
        CHECK(AuthorizedOf(r.effects) == std::vector<uint16_t>{2});
    }
    TemplateSpec native = any;
    native.token_mode = 1;
    expect_match(native, 0);
    native.token_mode = 2; // EXACT with a zero id means native
    expect_match(native, 0);
    // Branch count and static/stack pins (stack roots pushed ascending).
    TemplateSpec pins;
    pins.branch_count = 2;
    pins.mask = 1;
    pins.branches = {fill(0xa0)};
    // o0's path {1} omits branch 0, so OMIT paths cannot pin it (below);
    // these pin cases state the paths explicitly.
    pins.paths_mode = 1;
    pins.paths = {{0}, {1}};
    expect_match(pins, 0);
    pins.branches = {fill(0xa2)};
    expect_error(pins, none);
    TemplateSpec stack_pins;
    stack_pins.branch_count = 2;
    stack_pins.stack_mask = 3;
    stack_pins.paths_mode = 1;
    stack_pins.paths = {{0}, {1}};
    VmBytes roots;
    PushBytes(roots, VmBytes(32, 0xa0)); // slot 0 (deeper)
    PushBytes(roots, VmBytes(32, 0xa1)); // slot 1 (top, popped first)
    expect_match(stack_pins, 0, 0, {}, roots);
    VmBytes swapped;
    PushBytes(swapped, VmBytes(32, 0xa1));
    PushBytes(swapped, VmBytes(32, 0xa0));
    expect_error(stack_pins, none, 0, {}, swapped);
    // Three stack roots and a stack value: pop order value, roots, state.
    {
        TemplateSpec three;
        three.value_mode = 3;
        three.stack_mask = 0b111;
        three.branch_count = 3;
        three.paths_mode = 1;
        three.paths = {{0}, {1}, {2}};
        tx.outputs[0].branches = {fill(0xa0), fill(0xa1), fill(0xa3)};
        tx.outputs[0].paths = {{0}, {1}, {2}};
        VmBytes prefix;
        PushBytes(prefix, VmBytes(32, 0xa0));
        PushBytes(prefix, VmBytes(32, 0xa1));
        PushBytes(prefix, VmBytes(32, 0xa3));
        PushBytes(prefix, Number(100));
        expect_match(three, 0, 0, {}, prefix);
        tx.outputs[0] = o0;
    }
    // OMIT paths requires every pinned root on every path: o0's path {1}
    // lacks branch 0, so pinning only slot 0 fails for o0.
    TemplateSpec omit_paths;
    omit_paths.mask = 1;
    omit_paths.branches = {fill(0xa0)};
    tx.outputs[0].paths = {{0, 1}};
    expect_match(omit_paths, 0);
    tx.outputs[0].paths = {{0}, {1}};
    expect_error(omit_paths, none);
    tx.outputs[0] = o0;
    // EXPLICIT paths.
    TemplateSpec explicit_paths;
    explicit_paths.paths_mode = 1;
    explicit_paths.paths = {{0}, {1}};
    expect_match(explicit_paths, 0);
    explicit_paths.paths = {{0, 1}};
    expect_error(explicit_paths, none);
    // INHERIT: same paths and branch count as the spent coin; unpinned
    // branches must also match unless the wildcard bit is set.
    TemplateSpec inherit;
    inherit.paths_mode = 2;
    expect_match(inherit, 1);
    {
        auto script = script_for(inherit, 0, 1);
        tx.inputs[0].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(script);
        tx.outputs[1].branches = resolved[0]->branches;
        tx.outputs[1].paths = resolved[0]->paths;
        tx.outputs[1].branches[1] = fill(0xc1); // changed unpinned branch
        CHECK(run(0, script, {}, false).charged.invocation.error == none);
        inherit.wildcard = true;
        // o0 has the coin's paths too, so a wildcard alone would select it;
        // pin output 1 (I-11: a script that needs an output pins it).
        inherit.output_mode = 1;
        inherit.output_index = 1;
        const auto wild = script_for(inherit, 0, 1);
        tx.inputs[0].witnesses[0].script = wild;
        resolved[0]->branches[0] = BranchLeaf(wild);
        tx.outputs[1].branches[0] = resolved[0]->branches[0];
        const auto wild_run = run(0, wild, {}, false);
        if (wild_run.charged.invocation.status != VmStatus::Success)
            throw std::runtime_error("wildcard: " +
                                     wild_run.charged.invocation.error);
        inherit.wildcard = false;
        inherit.output_mode = 0;
        // Unpinned, the wildcard selects the first output with the coin's
        // paths and branch count.
        TemplateSpec wild_first;
        wild_first.paths_mode = 2;
        wild_first.wildcard = true;
        expect_match(wild_first, 0);
    }
    expect_error(inherit, "template inherit in mint", 1);
    // State modes: NONE skips stateful outputs; TEMPLATE/STACK authorize.
    TemplateSpec stateful;
    stateful.state_mode = 1;
    stateful.state_root = state;
    {
        const auto r = expect_match(stateful, 2);
        CHECK(AuthorizedOf(r.effects) == std::vector<uint16_t>{2});
    }
    stateful.state_root = fill(0x5f);
    expect_error(stateful, none);
    TemplateSpec stack_state;
    stack_state.state_mode = 2;
    expect_match(stack_state, 2, 0, {}, state_push());
    expect_error(stack_state, "ENFORCEOUTPUT zero state", 0, {},
                 [&] { VmBytes p; PushBytes(p, VmBytes(32)); return p; }());
    // Output pinning: in the template or from the stack.
    TemplateSpec pinned = any;
    pinned.output_mode = 1;
    pinned.output_index = 1;
    expect_match(pinned, 1);
    pinned.output_index = 3; // a burn: no match
    expect_error(pinned, none);
    pinned.output_index = 4;
    expect_error(pinned, "introspection index out of range");
    TemplateSpec stack_pinned = any;
    stack_pinned.output_mode = 2;
    {
        VmBytes prefix;
        PushBytes(prefix, Number(1));
        expect_match(stack_pinned, 1, 0, {}, prefix);
    }
    // Malformed templates are script errors.
    auto raw_error = [&](const VmBytes &raw, const std::string &error) {
        VmBytes script;
        PushBytes(script, raw);
        PushBytes(script, Number(0));
        script.insert(script.end(), {0xeb, 0x79, 0x4e});
        const auto r = run(0, script);
        if (r.charged.invocation.error != error)
            throw std::runtime_error("template '" + error + "' got " +
                                     r.charged.invocation.error);
    };
    const VmBytes good = EncodeTemplate(any);
    for (size_t n = 0; n < good.size(); ++n)
        raw_error(VmBytes(good.begin(), good.begin() + n), "template truncated");
    auto trailing = good;
    trailing.push_back(0);
    raw_error(trailing, "template trailing bytes");
    TemplateSpec bad;
    bad.paths_mode = 3;
    raw_error(EncodeTemplate(bad), "template paths mode");
    bad = {};
    bad.state_mode = 3;
    raw_error(EncodeTemplate(bad), "template state mode");
    bad = {};
    bad.mask = 1;
    bad.stack_mask = 1;
    bad.branches = {fill(1)};
    raw_error(EncodeTemplate(bad), "template mask overlap");
    bad = {};
    bad.branch_count = 1;
    bad.mask = 2;
    bad.branches = {fill(1)};
    raw_error(EncodeTemplate(bad), "template mask beyond branch count");
    bad = {};
    bad.branch_count = 17;
    raw_error(EncodeTemplate(bad), "template branch count");
    bad = {};
    bad.state_mode = 1;
    raw_error(EncodeTemplate(bad), "template zero state root");
    bad = {};
    bad.burn = true;
    bad.paths_mode = 2;
    raw_error(EncodeTemplate(bad), "template burn inherits paths");
    bad.paths_mode = 1;
    bad.paths = {{0}};
    raw_error(EncodeTemplate(bad), "template burn with paths");
    // Claim range.
    {
        VmBytes script;
        PushBytes(script, good);
        VmBytes big(16, 0);
        big[8] = 1; // 2^64
        PushBytes(script, big);
        script.insert(script.end(), {0xeb, 0x79, 0x4e});
        CHECK(run(0, script).charged.invocation.error ==
              "ENFORCEOUTPUT claim range");
    }

    // Claims are recorded, not consumed (I-11): two identical templates
    // both select output 0, and the post-check judges the sum.
    {
        const auto first = run(0, script_for(any, 60, 0));
        CHECK(first.charged.invocation.status == VmStatus::Success);
        const auto second = run(0, script_for(any, 40, 0));
        std::vector<DeferredRecords> total{first.effects, second.effects};
        std::string error;
        CHECK(PostCheck(tx.outputs, total, error) == false &&
              error == "state-output-unauthorized"); // o2 still unauthorized
        total[1].Merge(AuthorizeRecords({2}));
        CHECK(PostCheck(tx.outputs, total, error));
        const auto third = run(0, script_for(any, 1, 0));
        total.push_back(third.effects); // 60 + 40 + 1 > 100
        CHECK(!PostCheck(tx.outputs, total, error) &&
              error == "output-overclaimed");
        // Pinning the second claim to output 1 (value 200) fixes it.
        pinned.output_index = 1;
        const auto moved = run(0, script_for(pinned, 101, 1));
        std::vector<DeferredRecords> pinned_total{first.effects, moved.effects};
        pinned_total[1].Merge(AuthorizeRecords({2}));
        CHECK(PostCheck(tx.outputs, pinned_total, error));
    }
    // A failing invocation commits nothing: `<enforce> FALSE`.
    {
        VmBytes script;
        PushBytes(script, good);
        PushBytes(script, Number(9));
        script.insert(script.end(), {0xeb, 0x79, 0x4d});
        const auto r = run(0, script);
        CHECK(r.charged.invocation.status == VmStatus::Invalid &&
              r.effects.Empty());
    }
    // I-10: any invocation may authorize state with a zero claim, so state
    // authorization alone is not authentication (documented weakness).
    {
        TemplateSpec forged;
        forged.state_mode = 1;
        forged.state_root = state;
        const auto r = run(0, script_for(forged, 0, 2));
        CHECK(r.charged.invocation.status == VmStatus::Success &&
              AuthorizedOf(r.effects) == std::vector<uint16_t>{2});
    }
    // Without a transaction-effects accumulator: Unsupported.
    {
        const auto script = script_for(any, 0, 0);
        tx.inputs[0].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(script);
        tx.outputs[1].branches = resolved[0]->branches;
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0,
                               std::nullopt};
        CHECK(EvaluateVmWithContext(script, {}, vm, ctx).status ==
              VmStatus::Unsupported);
    }
    // Static cost: a literal template gives an exact charge including the
    // per-output scan; a dynamic template is charged the worst case.
    {
        const auto r = run(0, script_for(any, 0, 0));
        CHECK(r.charged.charged &&
              r.charged.accounting_cost == r.charged.invocation.executed_cost);
        VmCostProfile no_scan = cost;
        no_scan.opcode[0xeb].per_scanned_output = 0;
        const auto script = script_for(any, 0, 0);
        VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0,
                               std::nullopt};
        DeferredRecords effects;
        ctx.effects = &effects;
        const auto cheaper = EvaluateVmCharged(script, {}, vm, no_scan, 2, 4, &ctx);
        CHECK(cheaper.accounting_cost + 5 * 4 == r.charged.accounting_cost);
        VmBytes dynamic = Hex("eb 79 4e");
        const auto d = run(0, dynamic, {good, Number(0)});
        CHECK(d.charged.invocation.status == VmStatus::Success &&
              d.charged.accounting_cost > d.charged.invocation.executed_cost);
    }
    // Example: a vault that may only be spent into an exact continuation
    // of itself carrying at least its own value
    // (`d0 d6` = UTXOVALUE(this input), FROM_STACK value, INHERIT paths).
    {
        TemplateSpec vault;
        vault.value_mode = 3;
        vault.paths_mode = 2;
        expect_match(vault, 1, 0, {}, Hex("d0 d6"));
        tx.outputs[1].value = 199;
        const auto script = script_for(vault, 0, 1, false, Hex("d0 d6"));
        tx.inputs[0].witnesses[0].script = script;
        resolved[0]->branches[0] = BranchLeaf(script);
        tx.outputs[1].branches = resolved[0]->branches;
        CHECK(run(0, script, {}, false).charged.invocation.error == none);
        tx.outputs[1].value = 200;
    }
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
    auto loop_break = charge("5269794e4e6b6a4e");
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
    schedule.max_invocation_cost = 10000000;
    const auto zero_cost = charge("0069794e796a4e").accounting_cost;
    const auto one_cost = charge("4e69794e796a4e").accounting_cost;
    // Old fused-header charges (24, 76) plus the bound push and ENUMERATE's
    // 16-byte operand.
    CHECK(zero_cost == 24 + 34 && one_cost == 76 + 34);
    schedule.max_invocation_cost = zero_cost;
    auto zero_bound = charge("0069794e796a4e");
    CHECK(zero_bound.charged && zero_bound.accounting_cost == zero_cost &&
          zero_bound.invocation.status == VmStatus::Success);
    auto one_bound = charge("4e69794e796a4e");
    CHECK(!one_bound.charged &&
          one_bound.invocation.status == VmStatus::Invalid);
    schedule.max_invocation_cost = one_cost;
    one_bound = charge("4e69794e796a4e");
    CHECK(one_bound.charged && one_bound.accounting_cost == one_cost &&
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
// `TXINPUTCOUNT|TXOUTPUTCOUNT ENUMERATE` is the only input/output loop. Its
// static bound is min(256, count), so it charges exactly what a literal bound
// of the same count charges (the old fused 67/68 charge plus the count push
// and ENUMERATE's operand).
void EnumerateIdiom() {
    auto schedule = IllustrativeCost();
    auto charge = [&](const std::string &script, uint16_t inputs,
                      uint16_t outputs = 0) {
        return EvaluateVmCharged(Hex(script), {}, PROFILE, schedule, inputs,
                                 outputs);
    };
    auto literal = [](unsigned n) {
        VmBytes push(16);
        push[0] = uint8_t(n);
        push[1] = uint8_t(n >> 8);
        std::string hex = "10";
        const char *digits = "0123456789abcdef";
        for (auto b : push) {
            hex.push_back(digits[b >> 4]);
            hex.push_back(digits[b & 15]);
        }
        return hex;
    };
    for (unsigned count : {0u, 1u, 2u, 255u, 256u}) {
        const auto idiom = charge("c969794e796a4e", uint16_t(count));
        CHECK(idiom.charged && idiom.invocation.status == VmStatus::Success);
        // A one-byte constant costs what TXINPUTCOUNT costs.
        if (count <= 16) {
            VmBytes script = Hex("69794e796a4e");
            script.insert(script.begin(), uint8_t(count ? 0x4d + count : 0));
            const auto constant =
                EvaluateVmCharged(script, {}, PROFILE, schedule, 0, 0);
            CHECK(constant.accounting_cost == idiom.accounting_cost);
        }
        // A 16-byte literal push differs only by its 16 extra script bytes.
        const auto pushed = charge(literal(count) + "69794e796a4e", 0);
        CHECK(pushed.accounting_cost == idiom.accounting_cost + 16);
        // Executed cost equals the static bound for this straight body.
        CHECK(idiom.invocation.executed_cost == idiom.accounting_cost);
    }
    CHECK(charge("c969794e796a4e", 1).accounting_cost == 76 + 34);
    // The static bound saturates at 256; at runtime 257 is out of range.
    const auto over = charge("c969794e796a4e", 257);
    CHECK(over.charged &&
          over.accounting_cost == charge("c969794e796a4e", 256).accounting_cost &&
          over.invocation.status == VmStatus::Invalid &&
          over.invocation.error == "loop bound");
    // Output idiom and nesting: both bounds come from the transaction.
    const auto nested = charge("c969ca69796a796a4e", 3, 4);
    const auto nested_constant = charge("5069 5169 796a796a4e", 0, 0);
    CHECK(nested.invocation.status == VmStatus::Success &&
          nested.accounting_cost == nested_constant.accounting_cost);
    // Only the instruction immediately before ENUMERATE counts.
    const auto separated = charge("c960 69794e796a4e", 1);
    CHECK(separated.accounting_cost > charge("c969794e796a4e", 256).accounting_cost);
    // Three nested loops never decode, whatever their bounds.
    Expect("c969c969c9696a6a6a4e", VmStatus::Invalid, {}, PROFILE, 1);
}
// BREAK pops Boolean(cond) and N(depth): N(1) exits `depth` loops, N(0)
// continues. The depth is checked even when the condition is false.
void ConditionalBreak() {
    // acc=0; 3 iterations of acc+=1, each followed by a BREAK.
    Expect("00 5069 7998 004e6b 6a 50a7 4e", VmStatus::Success);   // cond 0
    Expect("00 5069 7998 4e4e6b 6a 4ea7 4e", VmStatus::Success);   // cond 1
    Expect("00 5069 7998 4e4e6b 66 6a 4ea7 4e", VmStatus::Success); // rest skipped
    Expect("00 5069 7998 004e6b 66 6a 4e", VmStatus::Invalid);     // rest runs
    // Depth 2 leaves both loops; depth 2 with cond 0 runs all 4 bodies.
    Expect("00 4f69 79 4f69 7998 4e4f6b 6a6a 4ea7 4e", VmStatus::Success);
    Expect("00 4f69 79 4f69 7998 004f6b 6a6a 51a7 4e", VmStatus::Success);
    Expect("00 4f69 79 4f69 7998 4e4e6b 6a6a 4fa7 4e", VmStatus::Success);
    // A depth out of range errors even when cond is 0.
    for (const auto &bad : {"4e69 79 004f6b 6a 4e", "4e69 79 00006b 6a 4e",
                            "004e6b 4e", "4e4e6b 4e"}) {
        const auto result = EvaluateVm(Hex(bad), {}, PROFILE);
        CHECK(result.status == VmStatus::Invalid &&
              result.error == "BREAK depth");
    }
    // Non-Boolean conditions error; so does a missing operand.
    for (const auto &bad : {"4e69 79 4f4e6b 6a 4e", "4e69 79 4d4e6b 6a 4e"})
        CHECK(EvaluateVm(Hex(bad), {}, PROFILE).error ==
              "noncanonical Boolean");
    VmBytes long_true(17);
    long_true[0] = 1;
    CHECK(EvaluateVm(Hex("4e69 79 7a 4e6b 6a 794e"), {long_true}, PROFILE)
              .error == "noncanonical Boolean");
    CHECK(EvaluateVm(Hex("4e69 79 4e6b 6a 4e"), {}, PROFILE).error ==
          "stack underflow");
    // Skipped arms and zero-iteration loops never execute BREAK.
    Expect("00 61 4d4d6b 64 4e", VmStatus::Success);
    Expect("00 69 4d4d6b 6a 4e", VmStatus::Success);
    // The size pass continues after BREAK: with cond 0 the straight-line
    // body is charged exactly, including work after the BREAK.
    auto schedule = IllustrativeCost();
    const auto fall = EvaluateVmCharged(
        Hex("00 5069 7998 004e6b 03616263b879 6a 50a7 4e"), {}, PROFILE,
        schedule);
    CHECK(fall.charged && fall.invocation.status == VmStatus::Success &&
          fall.invocation.executed_cost == fall.accounting_cost);
    // A taken BREAK costs less than the static bound, never more.
    const auto taken = EvaluateVmCharged(
        Hex("00 5069 7998 4e4e6b 03616263b879 6a 4ea7 4e"), {}, PROFILE,
        schedule);
    CHECK(taken.charged && taken.invocation.status == VmStatus::Success &&
          taken.invocation.executed_cost < taken.accounting_cost);
    // Wide operands are charged at their size in both views.
    VmBytes wide_one(32);
    wide_one[0] = 1;
    const auto wide = EvaluateVmCharged(Hex("4e69 79 007c 6b 6a 794e"),
                                        {wide_one}, PROFILE, schedule);
    CHECK(wide.charged && wide.invocation.status == VmStatus::Success &&
          wide.invocation.executed_cost <= wide.accounting_cost);
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
    Ext2Framing();
    RegistryAllocation();
    ControlAndArithmetic();
    StackOpcodes();
    ByteOpcodes();
    NumericOpcodes();
    BigIntAndZeroPadding();
    MerkleProofBounds();
    ContextFieldOpcodes();
    StateAndActiveIndexOpcodes();
    TokenBalance();
    InputWitnessArg();
    StateHashAndVerify();
    TransactionEffects();
    EnforceOutput();
    HashAndBounds();
    ChargedAccounting();
    EnumerateIdiom();
    ConditionalBreak();
    AuthenticatedPayment();
    AuthenticatedFieldSizeHints();
    PreparedTransactionOwnership();
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
    TypedCryptoFailures();
#endif
    std::cout << "Lotus V2 VM core vectors pass\n";
}
