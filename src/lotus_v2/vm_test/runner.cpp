#include "vm.h"

#include "commitment.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lotus::v2;
namespace {
VmBytes Hex(const std::string &s) {
    if (s.size() % 2) throw std::runtime_error("odd hex");
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("invalid hex");
    };
    VmBytes bytes;
    for (size_t i = 0; i < s.size(); i += 2)
        bytes.push_back((digit(s[i]) << 4) | digit(s[i + 1]));
    return bytes;
}
std::string Decimal(VmCostUnits value) {
    if (!value) return "0";
    std::string digits;
    while (value) {
        digits.push_back(char('0' + value % 10));
        value /= 10;
    }
    std::reverse(digits.begin(), digits.end());
    return digits;
}
char Status(VmStatus status) {
    switch (status) {
        case VmStatus::Success:
            return 'S';
        case VmStatus::AutomaticSuccess:
            return 'A';
        case VmStatus::Invalid:
            return 'I';
        case VmStatus::Unsupported:
            return 'U';
        case VmStatus::OperationalError:
            return 'E';
    }
    return 'I';
}
// One spend and one 45-byte native output, path {0}. No caller field hints.
int ChargeDerived(const VmBytes &script, const std::vector<VmBytes> &args) {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    ChainId chain{};
    Transaction tx;
    Input spend;
    spend.flags = 1;
    spend.prev_txid.fill(0x11);
    spend.sequence = UINT32_MAX;
    spend.witnesses.push_back(BranchWitness{script, {}, args});
    tx.inputs.push_back(spend);
    Output coin;
    coin.value = 1000;
    coin.branches = {BranchLeaf(script)};
    coin.paths = {{0}};
    Output created = coin;
    created.branches[0].fill(0x44);
    tx.outputs.push_back(created);
    ResolvedCoins resolved{coin};
    VmExecutionContext ctx{tx, tx_profile, chain, resolved, 0, 0, std::nullopt};
    const VmProfile profile{512, 8, 8192, 16, 8, 16384, 8, 10000000};
    VmCostProfile cost;
    cost.max_invocation_cost = 10000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode)
        op = {1, 1, 1};
    const auto result =
        EvaluateVmCharged(script, args, profile, cost, 0, 0, &ctx);
    std::cout << Status(result.invocation.status) << ' '
              << (result.charged ? Decimal(result.accounting_cost) : "-")
              << '\n';
    return 0;
}
// Offline invocation protocol. Coins are exact Output frames in input order.
// Authentication here means commitment/membership authentication, not a chain
// state lookup: the harness must provide the independently resolved coin set.
int Context(int argc, char **argv) {
    if (argc < 7) return 2;
    const TxProfile tp{65535, 65535, 65535, 8192, 1024, 8192, 64};
    Transaction tx;
    std::string error;
    if (!DecodeTransaction(Hex(argv[2]), tp, tx, error)) return 2;
    const auto chain_bytes = Hex(argv[3]);
    if (chain_bytes.size() != 32 || size_t(argc - 6) != tx.inputs.size()) return 2;
    ChainId chain{};
    std::copy(chain_bytes.begin(), chain_bytes.end(), chain.begin());
    const size_t input = std::stoull(argv[4]), witness = std::stoull(argv[5]);
    if (input >= tx.inputs.size() || witness >= tx.inputs[input].witnesses.size()) return 2;
    ResolvedCoins coins;
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        if (std::string(argv[6 + i]) == "-") {
            if (tx.inputs[i].flags != 3) return 2;
            coins.push_back(std::nullopt);
        } else {
            if (tx.inputs[i].flags != 1) return 2;
            Output coin;
            if (!DecodeOutput(Hex(argv[6 + i]), coin, error) || coin.IsBurn()) return 2;
            coins.push_back(coin);
        }
    }
    std::optional<PositiveDelta> delta;
    if (tx.inputs[input].flags == 3) {
        const auto &token = tx.inputs[input].prev_txid;
        __uint128_t incoming = 0, outgoing = 0;
        for (const auto &coin : coins)
            if (coin && coin->HasToken() && coin->token_id == token) incoming += coin->value;
        for (const auto &output : tx.outputs)
            if (output.HasToken() && output.token_id == token) outgoing += output.value;
        if (outgoing <= incoming || outgoing - incoming > ((__uint128_t(1) << 127) - 1)) return 2;
        PositiveDelta bytes{};
        auto value = outgoing - incoming;
        for (auto &byte : bytes) { byte = uint8_t(value); value >>= 8; }
        delta = bytes;
    }
    const VmProfile profile{8192, 1024, 8192, 1024, 1024, 1048576, 16, 10000000};
    VmCostProfile cost;
    cost.max_invocation_cost = 1000000000;
    cost.structural_byte_cost = 1;
    for (auto &op : cost.opcode) op = {1, 1, 1};
    const auto &active = tx.inputs[input].witnesses[witness];
    VmExecutionContext ctx{tx, tp, chain, coins, input, witness, delta};
    const auto result = EvaluateVmCharged(active.script, active.arguments, profile, cost, 0, 0, &ctx);
    std::cout << Status(result.invocation.status) << ' '
              << (result.charged ? Decimal(result.accounting_cost) : "-") << ' '
              << (result.charged ? Decimal(result.enforcement_cost) : "-");
    constexpr char digits[] = "0123456789abcdef";
    for (const auto &item : result.invocation.final_stack) {
        std::cout << ' ';
        if (item.empty()) std::cout << '-';
        for (auto byte : item) std::cout << digits[byte >> 4] << digits[byte & 15];
    }
    std::cout << '\n';
    return 0;
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc >= 2 && std::string(argv[1]) == "--context") return Context(argc, argv);
    } catch (const std::exception &) { return 2; }
    if (argc >= 3 && std::string(argv[1]) == "--charge-derived") {
        std::vector<VmBytes> derived_args;
        for (int i = 3; i < argc; ++i)
            derived_args.push_back(Hex(argv[i]));
        return ChargeDerived(Hex(argv[2]), derived_args);
    }
    if (argc < 4) return 2;
    try {
        const std::string mode = argv[1];
        const bool charged = mode == "--charge" || mode == "--charge-fields" ||
                             mode == "--charge-bigint";
        const bool fields = mode == "--charge-fields";
        const bool bigint = mode == "--bigint" || mode == "--charge-bigint";
        const int offset = (charged || bigint) ? 1 : 0;
        if (argc < 4 + offset) return 2;
        const VmProfile profile =
            bigint ? VmProfile{8192, 16, 2048, 32, 16, 16384, 8, 10000000}
                   : VmProfile{512, 8,     fields ? 1024u : 128u,
                               16,  8,     fields ? 2048u : 256u,
                               8,   100000};
        const auto script = Hex(argv[1 + offset]);
        const auto inputs = std::stoul(argv[2 + offset]);
        const auto outputs = std::stoul(argv[3 + offset]);
        if (inputs > UINT16_MAX || outputs > UINT16_MAX) return 2;
        std::vector<VmBytes> args;
        for (int i = 4 + offset; i < argc; ++i)
            args.push_back(Hex(argv[i]));
        if (charged) {
            VmCostProfile cost;
            cost.max_invocation_cost = 10000000;
            cost.structural_byte_cost = 1;
            for (auto &op : cost.opcode)
                op = {1, 1, 1};
            if (fields) cost.field_sizes[0xe7] = {45, 812};
            const auto result =
                EvaluateVmCharged(script, args, profile, cost, uint16_t(inputs),
                                  uint16_t(outputs));
            std::cout << Status(result.invocation.status) << ' '
                      << (result.charged ? Decimal(result.accounting_cost)
                                         : "-")
                      << '\n';
            return 0;
        }
        const auto result = EvaluateVm(script, args, profile, uint16_t(inputs),
                                       uint16_t(outputs));
        std::cout << Status(result.status) << '\n';
        return 0;
    } catch (const std::exception &) {
        return 2;
    }
}
