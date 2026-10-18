// Copyright (c) 2026 The Lotus developers
#include "development_command.h"
#include "development_chain.h"
#include <univalue.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
namespace lotus::v2 {
namespace {
void Require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
std::vector<uint8_t> ReadFile(const std::string &path, uint64_t cap) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    Require(bool(in), "cannot open input file");
    const auto length = in.tellg();
    Require(length >= 0 && uint64_t(length) <= cap && uint64_t(length) <= std::numeric_limits<size_t>::max(),
            "input exceeds local read capacity");
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    in.seekg(0); if (!bytes.empty()) in.read(reinterpret_cast<char *>(bytes.data()), bytes.size());
    Require(bool(in), "input file read failed"); return bytes;
}
VmCostUnits Number(const UniValue &v, unsigned bits = 64) {
    Require(v.isNum() || v.isStr(), "expected unsigned decimal integer");
    const auto &s = v.getValStr();
    Require(!s.empty() && (s.size() == 1 || s.front() != '0'), "noncanonical integer");
    const VmCostUnits maximum = bits == 128 ? ~VmCostUnits{0} : (VmCostUnits{1} << bits) - 1;
    VmCostUnits n = 0;
    for (char c : s) {
        Require(c >= '0' && c <= '9', "expected unsigned decimal integer");
        Require(n <= (maximum - (c - '0')) / 10, "integer out of range");
        n = n * 10 + (c - '0');
    }
    return n;
}
void Keys(const UniValue &v, const std::set<std::string> &expected) {
    Require(v.isObject(), "expected manifest object");
    const auto &keys = v.getKeys();
    Require(keys.size() == expected.size() && std::set<std::string>(keys.begin(), keys.end()) == expected,
            "unknown, duplicate or missing manifest field");
}
const UniValue &Array(const UniValue &v, size_t count) {
    Require(v.isArray() && v.size() == count, "manifest array length"); return v;
}
std::vector<uint8_t> Bytes(const UniValue &v) {
    const auto &s = v.get_str(); Require(s.size() % 2 == 0, "hex length");
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("expected lowercase hex");
    };
    std::vector<uint8_t> out; out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) out.push_back((digit(s[i]) << 4) | digit(s[i+1]));
    return out;
}
Hash HashValue(const UniValue &v) {
    const auto bytes = Bytes(v); Require(bytes.size() == 32, "expected 32-byte hash");
    Hash result; std::copy(bytes.begin(), bytes.end(), result.begin()); return result;
}
std::string Hex(const Hash &hash) {
    const char *digits = "0123456789abcdef"; std::string out;
    for (auto b : hash) { out += digits[b >> 4]; out += digits[b & 15]; } return out;
}
std::string Namespace(const std::string &directory, const std::string &identity) {
    namespace fs = std::filesystem;
    const fs::path root(directory), marker = root / "lotus-v2-development.identity";
    Require(!fs::is_symlink(root), "development directory cannot be a symlink");
    if (!fs::exists(root)) Require(fs::create_directories(root), "cannot create development directory");
    Require(fs::is_directory(root), "development data path is not a directory");
    auto check_entries = [&]() {
        for (const auto &entry : fs::directory_iterator(root)) {
            const auto name = entry.path().filename().string();
            Require(!entry.is_symlink() &&
                    (name == "lotus-v2-development.identity" || name == "chainstate-v2"),
                    "refusing unrelated or inherited data directory");
        }
    };
    if (fs::is_empty(root)) {
        // An exclusive directory prevents two initializers writing different
        // namespace markers. Interrupted initialization fails closed for review.
        const fs::path lock = root / ".initializing";
        Require(fs::create_directory(lock), "development namespace initialization busy");
        try {
            for (const auto &entry : fs::directory_iterator(root))
                Require(entry.path() == lock, "development directory changed during initialization");
            std::ofstream file(lock / "identity", std::ios::binary);
            file << identity; file.close(); Require(bool(file), "cannot write development identity");
            fs::rename(lock / "identity", marker); fs::remove(lock);
        } catch (...) { throw; } // Retain interrupted marker for explicit recovery.
    }
    check_entries();
    Require(fs::is_regular_file(marker), "development namespace marker required");
    const auto saved = ReadFile(marker.string(), 1024);
    Require(std::string(saved.begin(),saved.end()) == identity, "development namespace identity mismatch");
    return (root / "chainstate-v2").string();
}
DevelopmentManifest Load(const std::string &path) {
    const auto bytes = ReadFile(path, 8 << 20); // Local config limit, not consensus.
    UniValue v; Require(v.read(std::string(bytes.begin(), bytes.end())), "manifest JSON");
    Keys(v, {"schema", "tail_formula_version", "header", "transaction_limits", "vm_limits", "invocation_limits",
             "opcode_costs", "field_sizes", "monetary", "initial_monetary", "genesis",
             "coinbase_maturity", "dust_limit", "future_window", "block_read_limit", "outer_costs"});
    Require(Number(v["schema"]) == 2, "unsupported development manifest schema");
    Require(Number(v["tail_formula_version"]) == ABSOLUTE_TAIL_FORMULA_VERSION, "unsupported tail formula");
    const auto &h = v["header"];
    Keys(h, {"chain_id", "genesis_id", "version", "time", "bits", "pow_limit", "half_life", "spacing"});
    DevelopmentManifest m;
    m.hp.chain_id = HashValue(h["chain_id"]); m.hp.genesis_id = HashValue(h["genesis_id"]);
    m.hp.version = Number(h["version"],32); m.hp.genesis_time = Number(h["time"]);
    m.hp.genesis_bits = Number(h["bits"],32); m.hp.pow_limit = HashValue(h["pow_limit"]);
    m.hp.half_life_seconds = Number(h["half_life"],63); m.hp.spacing_seconds = Number(h["spacing"],63);
    const auto &t = Array(v["transaction_limits"],7);
    m.op.transaction = {size_t(Number(t[0], sizeof(size_t) * 8)),size_t(Number(t[1], sizeof(size_t) * 8)),size_t(Number(t[2], sizeof(size_t) * 8)),size_t(Number(t[3], sizeof(size_t) * 8)),
                        size_t(Number(t[4], sizeof(size_t) * 8)),size_t(Number(t[5], sizeof(size_t) * 8)),size_t(Number(t[6], sizeof(size_t) * 8))};
    const auto &vm = Array(v["vm_limits"],8);
    m.op.vm = {size_t(Number(vm[0], sizeof(size_t) * 8)),size_t(Number(vm[1], sizeof(size_t) * 8)),size_t(Number(vm[2], sizeof(size_t) * 8)),size_t(Number(vm[3], sizeof(size_t) * 8)),
               size_t(Number(vm[4], sizeof(size_t) * 8)),size_t(Number(vm[5], sizeof(size_t) * 8)),size_t(Number(vm[6], sizeof(size_t) * 8)),size_t(Number(vm[7], sizeof(size_t) * 8))};
    const auto &inv = Array(v["invocation_limits"],3);
    m.op.vm_cost.max_invocation_cost = Number(inv[0],128);
    m.op.max_total_invocation_cost = Number(inv[1],128);
    m.op.vm_cost.structural_byte_cost = Number(inv[2]);
    const auto &ops = Array(v["opcode_costs"],256);
    for (size_t i = 0; i < 256; ++i) {
        const auto &row = Array(ops[i],3);
        m.op.vm_cost.opcode[i] = {uint64_t(Number(row[0])),uint64_t(Number(row[1])),uint64_t(Number(row[2]))};
    }
    Require(v["field_sizes"].isArray(), "field sizes array");
    for (const auto &row : v["field_sizes"].getValues()) {
        Array(row,2); auto opcode = uint8_t(Number(row[0],8));
        Require(!m.op.vm_cost.field_sizes.count(opcode) && row[1].isArray(), "field size entry");
        auto &sizes = m.op.vm_cost.field_sizes[opcode];
        for (const auto &size : row[1].getValues()) sizes.push_back(size_t(Number(size, sizeof(size_t) * 8)));
    }
    const auto &p = Array(v["monetary"],12);
    m.mp = {uint32_t(Number(p[0],32)),uint32_t(Number(p[1],32)),uint32_t(Number(p[2],32)),uint64_t(Number(p[3])),
            uint32_t(Number(p[4],32)),uint32_t(Number(p[5],32)),uint64_t(Number(p[6])),uint64_t(Number(p[7])),
            uint64_t(Number(p[8])),uint64_t(Number(p[9])),uint64_t(Number(p[10])),HashValue(p[11])};
    const auto &cost = Array(v["outer_costs"],4);
    m.cp = {uint64_t(Number(cost[0])),uint64_t(Number(cost[1])),uint64_t(Number(cost[2])),uint64_t(Number(cost[3]))};
    m.initial = DecodeMonetaryState(Bytes(v["initial_monetary"])); m.genesis = Bytes(v["genesis"]);
    InitializeMonetaryGenesis(m.mp, m.initial, 0);
    m.op.coinbase_maturity = Number(v["coinbase_maturity"]); m.op.dust_limit = Number(v["dust_limit"]);
    m.future_window = Number(v["future_window"]); m.block_read_limit = Number(v["block_read_limit"]);
    Require(m.block_read_limit > 0, "zero local block read capacity");
    return m;
}
} // namespace
bool LoadDevelopmentManifest(const std::string &manifest_path,
    DevelopmentManifest &out, std::string &error) {
    try {
        auto candidate = Load(manifest_path);
        out = std::move(candidate); error.clear(); return true;
    } catch (const std::exception &e) { error = e.what(); return false; }
}
bool PrepareDevelopmentHomeDirectory(const DevelopmentManifest &m,
    const std::string &home, std::string &directory, std::string &error) {
    try {
        auto candidate = Namespace(home, "Lotus V2 development command 1\n" + Hex(m.hp.chain_id) + "\n" +
            Hex(m.hp.genesis_id) + "\n" + Hex(BlockValidationProfileDigest(m.hp,m.op,m.mp,m.cp)) + "\n");
        directory = std::move(candidate); error.clear(); return true;
    } catch (const std::exception &e) { error = e.what(); return false; }
}
bool OpenDevelopmentHome(const std::string &manifest_path, const std::string &home,
    DevelopmentManifest &out, DiskStateStore &store, std::string &error) {
    try {
        DevelopmentManifest m;
        if (!LoadDevelopmentManifest(manifest_path, m, error)) return false;
        std::string directory;
        if (!PrepareDevelopmentHomeDirectory(m, home, directory, error)) return false;
        DiskStateStore candidate;
        if (!OpenDevelopmentChain(directory,m.genesis,m.hp,m.op,m.mp,m.cp,m.initial,{},candidate,error))
            return false;
        out = std::move(m); store = std::move(candidate); error.clear(); return true;
    } catch (const std::exception &e) { error = e.what(); return false; }
}
int RunDevelopmentCommand(int argc, char *argv[]) {
    try {
        Require(argc == 5 || argc == 6,
                "usage: lotusd -lotusv2development MANIFEST DATADIR status|submit BLOCK|disconnect TIP");
        const std::string command = argv[4];
        Require((command == "status" && argc == 5) || ((command == "submit" || command == "disconnect") && argc == 6),
                "unknown development command or arguments");
        DevelopmentManifest m; DiskStateStore store; std::string error;
        if (!OpenDevelopmentHome(argv[2],argv[3],m,store,error))
            throw std::runtime_error(error);
        int result = 0; UniValue answer(UniValue::VOBJ);
        if (command == "submit") {
            const auto wire = ReadFile(argv[5],m.block_read_limit);
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            Require(now >= 0, "invalid local UTC clock"); StagedBlockTransition connected;
            const auto status = ConnectEligibleDiskBlock(wire,uint64_t(now),m.future_window,m.hp,m.op,m.mp,m.cp,store,connected,error);
            result = status == DiskBlockAdmission::Accepted ? 0 : status == DiskBlockAdmission::Invalid ? 2 : status == DiskBlockAdmission::Deferred ? 3 : 4;
            if (result == 0) {
                // Decimal strings preserve all bits for JSON consumers.
                UniValue charges(UniValue::VOBJ);
                charges.pushKV("invocation", MonetaryInteger(connected.invocation_cost).str());
                charges.pushKV("account", connected.account_cost.str());
                charges.pushKV("enforce", connected.enforce_cost.str());
                charges.pushKV("required_underclaim", connected.monetary.required_underclaim.str());
                charges.pushKV("actual_underclaim", connected.monetary.actual_underclaim.str());
                charges.pushKV("fees", connected.monetary.total_fees.str());
                charges.pushKV("subsidy", std::to_string(connected.monetary.subsidy));
                answer.pushKV("charges", charges);
            }
            answer.pushKV("accepted",result == 0);
            answer.pushKV("result",result == 0 ? "accepted" : result == 2 ? "invalid" : result == 3 ? "deferred" : status == DiskBlockAdmission::Inconclusive ? "inconclusive" : "storage_error");
        } else if (command == "disconnect") {
            if (!DisconnectDevelopmentTip(HashValue(UniValue(std::string(argv[5]))),m.hp,m.op,m.mp,m.cp,store,error)) result = 4;
            answer.pushKV("disconnected",result == 0);
        }
        if (store.IsOpen()) {
            const auto meta = store.Metadata(); Header tip;
            Require(ParseHeader(meta.header.data(),meta.header.size(),tip),"stored tip unavailable");
            answer.pushKV("tip",Hex(meta.tip)); answer.pushKV("height",tip.height);
            answer.pushKV("utxo_root",Hex(store.Root())); answer.pushKV("state_root",Hex(tip.state_root));
        } else {
            answer.pushKV("tip_known",false); answer.pushKV("reopen_required",true);
        }
        if (!error.empty()) answer.pushKV("error",error);
        std::cout << answer.write() << '\n'; return result;
    } catch (const std::exception &e) { std::cerr << "V2 development: " << e.what() << '\n'; return 1; }
}
} // namespace lotus::v2
