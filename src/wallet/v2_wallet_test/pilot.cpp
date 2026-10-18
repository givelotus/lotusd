// Copyright (c) 2026 The Lotus developers
// Explicit offline integration test helper. No network or secret export API.
#include <algorithm>
#include <fstream>
#include <iostream>
#include <key.h>
#include <limits>
#include <lotus_v2/development_chain.h>
#include <lotus_v2/development_command.h>
#include <random.h>
#include <set>
#include <stdexcept>
#include <univalue.h>
#include <util/translation.h>
#include <wallet/v2_payment.h>

const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
namespace {
using namespace lotus::v2;
using namespace lotus::v2::wallet;
using V2Hash = lotus::v2::Hash;
void Require(bool condition, const std::string &why) {
    if (!condition) throw std::runtime_error(why);
}
void Keys(const UniValue &v, const std::set<std::string> &keys) {
    Require(v.isObject() && v.getKeys().size() == keys.size() &&
                std::set<std::string>(v.getKeys().begin(), v.getKeys().end()) ==
                    keys,
            "unknown, duplicate or missing helper field");
}
uint64_t Number(const UniValue &v, unsigned bits = 64) {
    Require(v.isStr() || v.isNum(), "unsigned integer required");
    const auto &s = v.getValStr();
    Require(!s.empty() && (s.size() == 1 || s.front() != '0'),
            "noncanonical unsigned integer");
    const uint64_t limit = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
    uint64_t out = 0;
    for (char c : s) {
        Require(c >= '0' && c <= '9' && out <= (limit - uint64_t(c - '0')) / 10,
                "unsigned integer range");
        out = out * 10 + (c - '0');
    }
    return out;
}
std::vector<uint8_t> Bytes(const UniValue &v, size_t maximum = 8192) {
    const auto &s = v.get_str();
    Require(s.size() % 2 == 0 && s.size() / 2 <= maximum, "hex width");
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("lowercase hex required");
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i < s.size(); i += 2)
        out.push_back((digit(s[i]) << 4) | digit(s[i + 1]));
    return out;
}
V2Hash HashValue(const UniValue &v) {
    const auto bytes = Bytes(v, 32);
    Require(bytes.size() == 32, "32-byte hash required");
    V2Hash result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}
template <typename T> std::string Hex(const T &bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 15];
    }
    return out;
}
SecureString Passphrase(const UniValue &request) {
    const fs::path path =
        fs::PathFromString(request["passphrase_file"].get_str());
    Require(path.is_absolute(),
            "explicit absolute ephemeral passphrase file required");
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    Require(bool(file) && file.tellg() > 0 && file.tellg() <= 4096,
            "invalid ephemeral passphrase file");
    const auto size = size_t(file.tellg());
    file.seekg(0);
    SecureString passphrase(size, '\0');
    Require(bool(file.read(passphrase.data(), size)),
            "passphrase file read failed");
    return passphrase; // Exact bytes, no newline trimming or secret logging.
}
Output Recipient(const UniValue &v) {
    Keys(v, {"flags", "value", "branches", "paths"});
    Output out;
    out.flags = Number(v["flags"], 8);
    out.value = Number(v["value"]);
    Require(v["branches"].isArray() && v["branches"].size() <= 16 &&
                v["paths"].isArray() && v["paths"].size() <= 16,
            "recipient policy bounds");
    for (const auto &branch : v["branches"].getValues())
        out.branches.push_back(HashValue(branch));
    for (const auto &path : v["paths"].getValues()) {
        Require(path.isArray() && path.size() <= 16, "recipient path bounds");
        std::vector<uint8_t> indexes;
        for (const auto &index : path.getValues())
            indexes.push_back(Number(index, 8));
        out.paths.push_back(std::move(indexes));
    }
    return out;
}
const char *Name(Result result) {
    switch (result) {
        case Result::Success:
            return "success";
        case Result::Invalid:
            return "invalid";
        case Result::Locked:
            return "locked";
        case Result::Stale:
            return "stale";
        case Result::InsufficientFunds:
            return "insufficient_funds";
        case Result::Inconclusive:
            return "inconclusive";
        case Result::StorageError:
            return "storage_error";
    }
    return "storage_error";
}
int Run(int argc, char **argv) {
    Require(argc == 5,
            "usage: lotus-v2-wallet-pilot MANIFEST CHAIN_HOME WALLET_HOME "
            "create|register|track|prepare|sign|reconcile|abandon|stale");
    std::string input;
    for (char c; std::cin.get(c);) {
        Require(input.size() < (1 << 20),
                "helper request exceeds local capacity");
        input += c;
    }
    UniValue request;
    Require(request.read(input), "helper JSON request required");
    const std::string command = argv[4];
    // Validate request shape before opening either explicitly supplied home.
    if (command == "create")
        Keys(request, {"passphrase_file"});
    else if (command == "register")
        Keys(request, {"script", "proof", "root"});
    else if (command == "track")
        Keys(request, {"prev_txid", "prev_index"});
    else if (command == "prepare")
        Keys(request, {"recipient", "fee"});
    else if (command == "sign")
        Keys(request, {"recipient", "fee", "passphrase_file"});
    else if (command == "reconcile")
        Keys(request, {});
    else if (command == "abandon")
        Keys(request, {"txid"});
    else if (command == "stale")
        Keys(request, {"recipient", "fee", "passphrase_file", "expected_tip"});
    else
        throw std::runtime_error("unknown wallet pilot command");
    DevelopmentManifest manifest;
    DiskStateStore store;
    std::string error;
    Require(OpenDevelopmentHome(argv[1], argv[2], manifest, store, error),
            error);
    ChainProfile profile{manifest.hp, manifest.op, manifest.mp, manifest.cp};
    std::unique_ptr<Wallet> wallet;
    UniValue answer(UniValue::VOBJ);
    Result result = Result::Success;
    if (command == "create") {
        Require(Wallet::Create(fs::PathFromString(argv[3]), profile.Binding(),
                               Passphrase(request), wallet, error),
                error);
        answer.pushKV("public_key", Hex(wallet->PublicKey()));
    } else {
        Require(Wallet::Open(fs::PathFromString(argv[3]), profile.Binding(),
                             wallet, error),
                error);
        if (command == "register") {
            auto script = Bytes(request["script"]);
            Require(request["proof"].isArray() && request["proof"].size() == 0,
                    "Payment proof must be empty");
            Require(BranchLeaf(script) == HashValue(request["root"]),
                    "Payment root mismatch");
            Require(wallet->RegisterPayment(script, {}, error), error);
            answer.pushKV("policy_root", Hex(BranchLeaf(script)));
        } else if (command == "track") {
            result = PaymentEngine::TrackFunding(
                *wallet, profile, store,
                {HashValue(request["prev_txid"]),
                 uint32_t(Number(request["prev_index"], 32))},
                error);
        } else if (command == "abandon") {
            Require(wallet->Abandon(HashValue(request["txid"]), error), error);
        } else if (command == "reconcile") {
            Reconciled state;
            result =
                PaymentEngine::Reconcile(*wallet, profile, store, state, error);
            if (result == Result::Success) {
                answer.pushKV("tip", Hex(state.chain.tip));
                answer.pushKV("height", state.chain.height);
                UniValue coins(UniValue::VARR);
                for (const auto &coin : state.coins) {
                    UniValue item(UniValue::VOBJ);
                    item.pushKV("prev_txid", Hex(coin.outpoint.tx_id));
                    item.pushKV("prev_index", coin.outpoint.index);
                    item.pushKV("present", coin.present);
                    item.pushKV("reserved", coin.reserved);
                    item.pushKV("mature", coin.mature);
                    item.pushKV("value", std::to_string(coin.value));
                    coins.push_back(item);
                }
                answer.pushKV("coins", coins);
            }
        } else {
            PaymentPlan plan;
            result = PaymentEngine::Prepare(
                *wallet, profile, store, Recipient(request["recipient"]),
                Number(request["fee"]), plan, error);
            if (result == Result::Success && command != "prepare") {
                Require(wallet->Unlock(Passphrase(request), error), error);
                if (command == "stale") {
                    Require(HashValue(request["expected_tip"]) ==
                                plan.Anchor().tip,
                            "stale-test expected tip mismatch");
                    Require(DisconnectDevelopmentTip(
                                plan.Anchor().tip, profile.header,
                                profile.ordinary, profile.monetary,
                                profile.costs, store, error),
                            error);
                    answer.pushKV("disconnected_tip", Hex(plan.Anchor().tip));
                    answer.pushKV("tip", Hex(store.Metadata().tip));
                }
                ExportedPayment payment;
                result = PaymentEngine::SignAndReserve(*wallet, profile, store,
                                                       plan, payment, error);
                if (result == Result::Success) {
                    answer.pushKV("wire", Hex(payment.wire));
                    answer.pushKV("txid", Hex(payment.txid));
                    answer.pushKV("txhash", Hex(payment.txhash));
                    answer.pushKV("digest", Hex(payment.digest));
                }
            }
        }
    }
    answer.pushKV("result", Name(result));
    if (!error.empty()) answer.pushKV("error", error);
    std::cout << answer.write() << '\n';
    // Match the offline daemon's separation of rejected/operational outcomes.
    return result == Result::Success        ? 0
           : result == Result::StorageError ? 4
                                            : 2;
}
} // namespace
int main(int argc, char **argv) {
    RandomInit();
    ECC_Start();
    try {
        const int result = Run(argc, argv);
        ECC_Stop();
        return result;
    } catch (const std::exception &error) {
        UniValue answer(UniValue::VOBJ);
        answer.pushKV("result", "setup_error");
        answer.pushKV("error", error.what());
        std::cout << answer.write() << '\n';
        ECC_Stop();
        return 1;
    }
}
