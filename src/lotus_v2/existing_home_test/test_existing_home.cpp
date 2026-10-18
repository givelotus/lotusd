// Copyright (c) 2026 The Lotus developers
#include "../dev_genesis.h"
#include "../development_chain.h"
#include "../disk_body.h"
#include "../header_admission.h"
#include "../signing.h"
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <map>
#include <fstream>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace lotus::v2;
namespace {
// Explicit easy-target genesis fixture; distinct from toy DevelopmentGenesis 200/9.
constexpr MonetaryProfile EasyGenesis{2,3,2,4,3,5,2,2000,3,1000,200,Hash{2}};
void Check(bool value, const std::string &why) {
    if (!value) throw std::runtime_error(why);
}
std::string FreshPath() {
    char pattern[] = "/private/tmp/lotus-v2-initializer-XXXXXX";
    Check(mkdtemp(pattern) != nullptr, "temporary path");
    std::filesystem::remove_all(pattern);
    return pattern;
}
struct Fixture {
    HeaderChainProfile hp;
    OrdinaryCandidateProfile op;
    MonetaryState money;
    BlockCostProfile costs{1, 1, 1, 1};
    Header header;
    Transaction cb;
    std::vector<uint8_t> wire;
    std::optional<Coin> coin;
    Hash root;
    explicit Fixture(bool burn) {
        hp.version = 2;
        hp.genesis_time = 1000;
        hp.genesis_bits = 0x207fffff;
        hp.pow_limit.fill(255);
        hp.half_life_seconds = 172800;
        hp.spacing_seconds = 120;
        op.transaction = {32, 32, 8, 512, 8, 8192, 64};
        op.vm = {512, 8, 8192, 32, 32, 65536, 16, 1000000};
        op.coinbase_maturity = 2;
        op.dust_limit = EasyGenesis.dust_limit;
        op.max_total_invocation_cost = 1000000;
        op.vm_cost.max_invocation_cost = 1000000;
        op.vm_cost.structural_byte_cost = 1;
        // Synthetic positive schedule, not a calibrated network cost profile.
        for (auto &opcode : op.vm_cost.opcode)
            opcode.base = 1;
        money.bootstrap_reserve = 9;
        money.tail_subsidy = 200;
        money.prev_work[0] = 2;
        money.ema_block_cost = 4;
        Input input;
        input.flags = 2;
        input.sequence = UINT32_MAX;
        cb.inputs = {input};
        Output output;
        output.flags = burn ? 2 : 0;
        output.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
        if (!burn) output.paths = {{0}};
        cb.outputs = {output};
        header.version = 2;
        header.time = 1000;
        header.bits = hp.genesis_bits;
        Rebuild();
    }
    void Rebuild() {
        std::string error;
        IdentityDigests ids;
        Check(ComputeIdentities(cb, op.transaction, hp.chain_id, ids, error),
              error);
        IncrementalUtxoSet tree;
        coin.reset();
        if (!cb.outputs[0].IsBurn()) {
            coin = Coin{{ids.txid, 0}, cb.outputs[0], 0, 0, true};
            Check(tree.Insert(*coin), "fixture coin");
        }
        root = tree.Root();
        header.state_root = StateRoot(hp.chain_id, 0, root, money);
        Check(CompleteTransactionRoot({cb}, op.transaction, hp.chain_id,
                                      header.tx_root, error),
              error);
        std::vector<uint8_t> transaction;
        Check(EncodeTransaction(cb, op.transaction, transaction, error), error);
        header.size = HEADER_SIZE + 4 + CompactSizeWidth(transaction.size()) +
                      transaction.size();
        MineAndEncode();
    }
    void MineAndEncode() {
        std::string error;
        Hash target, id;
        Check(DecodeTarget(header.bits, hp.pow_limit, target),
              "fixture target");
        header.nonce = 0;
        for (;; ++header.nonce) {
            Check(BlockId(hp.chain_id, header, id), "fixture block ID");
            if (MeetsTarget(id, target)) break;
        }
        hp.genesis_id = id;
        Check(EncodeBlockWire(header, {cb}, op.transaction, wire, error),
              error);
    }
    bool Open(const std::string &path, DiskStateStore &out,
              std::string &error) const {
        return OpenDevelopmentChain(path, wire, hp, op, EasyGenesis,
                                    costs, money, {}, out, error);
    }
};
using Rows = std::map<std::string, std::string>;
Rows ReadRows(const std::string &path) {
    Rows rows;
    std::string error;
    Check(RawDiskStateSnapshot(path, rows, &error), "raw snapshot: " + error);
    return rows;
}
void RawEdit(const std::string &path, const std::string &key,
             const std::optional<std::string> &value) {
    std::string error;
    Check(RawDiskStateAccess(path, std::nullopt, nullptr, {{key, value}}, &error),
          "raw edit: " + error);
}
DiskStateOptions Options(const Fixture &f) {
    DiskStateOptions options;
    options.existing_only = true;
    options.identity = f.hp.chain_id;
    options.profile_digest = BlockValidationProfileDigest(f.hp, f.op, EasyGenesis, f.costs);
    options.header_index = f.hp;
    return options;
}
bool OpenChain(const Fixture &f, const std::string &path, DiskStateOptions options,
               DiskStateStore &out, std::string &error) {
    return OpenDevelopmentChain(path, f.wire, f.hp, f.op, EasyGenesis,
                                f.costs, f.money, options, out, error);
}
void RefuseUnchanged(const Fixture &f, const std::string &path,
                     const DiskStateOptions &options) {
    const Rows before = ReadRows(path);
    DiskStateStore out;
    DiskStateError failure;
    DiskStateMetadata initial; initial.tip[0] = 42;
    const auto initial_before = initial;
    Check(!DiskStateStore::Open(path, options, {}, out, failure), "storage refusal");
    Check(!out.IsOpen() && !failure.message.empty(), "storage output unchanged");
    std::string error;
    Check(!OpenChain(f, path, options, out, error), "chain refusal");
    Check(!out.IsOpen() && !error.empty(), "chain output unchanged");
    // Even a supplied generic initial state cannot initialize existing-only.
    auto generic = options; generic.header_index.reset();
    Check(!DiskStateStore::Open(path, generic, initial, out, failure), "initial state refusal");
    Check(initial == initial_before && !out.IsOpen(), "initial argument unchanged");
    Check(ReadRows(path) == before, "logical database unchanged on refusal");
}
void Run() {
    Fixture f(false);
    auto options = Options(f);
    DiskStateError failure;
    std::string error;
    DiskStateStore out;
    const auto missing = FreshPath();
    Check(!DiskStateStore::Open(missing, options, {}, out, failure), "missing directory refused");
    Check(!OpenChain(f, missing, options, out, error), "missing chain refused");
    Check(!out.IsOpen() && !std::filesystem::exists(missing), "missing directory remains absent");
    const auto directory_only = FreshPath();
    std::filesystem::create_directory(directory_only);
    { std::ofstream marker(directory_only + "/marker"); marker << "preserve"; }
    Check(!OpenChain(f, directory_only, options, out, error), "directory without CURRENT refused");
    Check(std::distance(std::filesystem::directory_iterator(directory_only),
                        std::filesystem::directory_iterator{}) == 1,
          "refusal does not create engine files");
    std::ifstream marker(directory_only + "/marker");
    std::string contents; marker >> contents;
    Check(contents == "preserve", "existing directory contents preserved");
    std::filesystem::remove_all(directory_only);
    const auto empty = FreshPath();
    RawEdit(empty, "unused", std::nullopt);
    Check(std::filesystem::exists(empty + "/mdbx.dat"), "valid empty mdbx.dat");
    RefuseUnchanged(f, empty, options);
    std::filesystem::remove_all(empty);
    const auto uninitialized = FreshPath();
    auto create = options; create.existing_only = false;
    Check(DiskStateStore::Open(uninitialized, create, {}, out, failure), failure.message);
    out = {};
    RefuseUnchanged(f, uninitialized, options);
    // Default initialization retains its crash retry behavior.
    Check(OpenChain(f, uninitialized, create, out, error), error);
    const auto initialized_rows_tip = out.Metadata();
    out = {};
    const Rows before = ReadRows(uninitialized);
    Check(OpenChain(f, uninitialized, options, out, error), error);
    Check(out.Metadata() == initialized_rows_tip, "existing metadata preserved");
    DiskStateStore locked;
    Check(!DiskStateStore::Open(uninitialized, options, {}, locked, failure), "exclusive lock retained");
    Check(!locked.IsOpen(), "lock failure output unchanged");
    Check(!OpenChain(f, uninitialized, options, out, error) && out.Metadata() == initialized_rows_tip,
          "already-open output preserved");
    out = {};
    Check(ReadRows(uninitialized) == before, "valid open does not logically write");
    // Schema mismatch never migrates even with intact valid metadata.
    auto mismatch = options; mismatch.recovery = DiskRecoveryOptions{4096, 1 << 20};
    RefuseUnchanged(f, uninitialized, mismatch);
    RawEdit(uninitialized, "S", std::nullopt);
    RefuseUnchanged(f, uninitialized, options);
    std::filesystem::remove_all(uninitialized);
    const auto missing_schema = FreshPath();
    Check(OpenChain(f, missing_schema, create, out, error), error); out = {};
    RawEdit(missing_schema, "V", std::nullopt);
    RefuseUnchanged(f, missing_schema, options);
    std::filesystem::remove_all(missing_schema);
    // Existing-only is initialization policy, not recovery admission policy.
    const auto recovery = FreshPath();
    create.recovery = DiskRecoveryOptions{4096, 1 << 20};
    Check(OpenChain(f, recovery, create, out, error), error);
    DiskRecoveryUpdate update;
    update.expected_tip = out.Metadata().tip;
    update.expected_root = out.Root();
    update.next_tip = update.expected_tip;
    update.next_journal = std::vector<uint8_t>{1,2,3};
    Check(out.WriteRecoveryJournal(update, failure), failure.message);
    out = {};
    const Rows journal_before = ReadRows(recovery);
    create.existing_only = true;
    Check(OpenChain(f, recovery, create, out, error), error);
    std::optional<std::vector<uint8_t>> journal;
    Check(out.ReadRecoveryJournal(4096, journal, failure) && journal == update.next_journal,
          "pending recovery preserved for caller admission policy");
    out = {};
    Check(ReadRows(recovery) == journal_before, "pending recovery unchanged");
    std::filesystem::remove_all(recovery);
}
} // namespace
int main() {
    try { Run(); std::cout << "existing home checks passed\n"; return 0; }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
