// Copyright (c) 2026 The Lotus developers
#include "dev_genesis.h"
#include "development_chain.h"
#include "disk_body.h"
#include "header_admission.h"
#include "signing.h"
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
    auto pattern = (std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                    "lotus-v2-initializer-XXXXXX").string();
    Check(mkdtemp(pattern.data()) != nullptr, "temporary path");
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
ChainWork SmallWork(uint64_t value) {
    ChainWork work{};
    for (size_t i = 0; i < 8; ++i)
        work[i] = uint8_t(value >> (8 * i));
    return work;
}
void CheckActiveIndex(const DiskStateStore &store, const Hash &tip,
                      uint64_t height, uint64_t work, uint64_t max_time) {
    DiskStateError failure;
    std::optional<ActiveChainIndex> active;
    Check(store.ReadActiveIndex(active, failure) && active.has_value(),
          failure.message);
    Check(active->tip == tip && active->height == height &&
              active->chain_work == SmallWork(work) &&
              active->max_ancestor_time == max_time,
          "active index matches exact tip height work and ancestor time");
    std::optional<Hash> at_height;
    Check(store.ReadActiveId(height, at_height, failure) && at_height == tip,
          "active height ID matches tip");
    std::optional<IndexedHeader> indexed;
    Check(store.ReadIndexedHeader(tip, indexed, failure) && indexed.has_value(),
          failure.message);
    Check(indexed->header.height == height &&
              indexed->chain_work == SmallWork(work) &&
              indexed->max_ancestor_time == max_time &&
              indexed->stage == HeaderStage::Connected,
          "connected header index matches active index");
}
void CheckValid(bool burn) {
    Fixture f(burn);
    const auto path = FreshPath();
    DiskStateStore store;
    std::string error;
    Check(f.Open(path, store, error), error);
    const auto metadata = store.Metadata();
    CheckActiveIndex(store, f.hp.genesis_id, 0, 2, f.header.time);
    const auto money = EncodeMonetaryState(f.money);
    Check(metadata.tip == f.hp.genesis_id && store.Root() == f.root,
          "exact genesis ID/root");
    Check(metadata.monetary == std::vector<uint8_t>(money.begin(), money.end()),
          "genesis never advances monetary state");
    Check(metadata.header == std::vector<uint8_t>(f.wire.begin(),
                                                  f.wire.begin() + HEADER_SIZE),
          "exact persisted genesis header");
    std::vector<Header> history;
    std::vector<uint8_t> body;
    Check(ReadDiskChainContext(metadata, f.hp, history, body, error) &&
              history.size() == 1 && body == f.wire,
          "exact genesis history/body");
    auto check_coin = [&] {
        DiskStateError failure;
        std::optional<Coin> found;
        IdentityDigests ids;
        Check(ComputeIdentities(f.cb, f.op.transaction, f.hp.chain_id, ids,
                                error),
              error);
        Check(store.ReadCoin({ids.txid, 0}, found, failure), failure.message);
        Check(found.has_value() == !burn,
              "burn pruned; spendable zero retained");
        if (found)
            Check(found->output.value == 0 && found->creation_height == 0 &&
                      found->creation_parent_mtp == 0 && found->coinbase,
                  "genesis zero-coin context");
    };
    check_coin();
    Check(!f.Open(path, store, error) && store.Metadata() == metadata &&
              store.Root() == f.root,
          "already-open output rejected without mutation");
    store = DiskStateStore{};
    Check(f.Open(path, store, error), error);
    Check(store.Metadata() == metadata && store.Root() == f.root,
          "exact reopen");
    check_coin();
    // Reject another exact manifest without mutating existing storage or
    // output.
    store = DiskStateStore{};
    Fixture other = f;
    ++other.header.time;
    ++other.hp.genesis_time;
    other.Rebuild();
    DiskStateStore untouched;
    Check(!other.Open(path, untouched, error) && !untouched.IsOpen(),
          "different manifest rejected");
    Check(f.Open(path, store, error) && store.Metadata() == metadata &&
              store.Root() == f.root,
          "failed alternate open preserves existing state");
    store = DiskStateStore{};
    std::filesystem::remove_all(path);
}
void InvalidBeforeOpen() {
    for (unsigned mutation = 0; mutation < 7; ++mutation) {
        Fixture f(true);
        switch (mutation) {
            case 0:
                f.hp.genesis_id = {};
                break;
            case 1:
                f.header.state_root[0] ^= 1;
                break;
            case 2:
                f.money.prev_work[0] = 3;
                break;
            case 3:
                f.cb.inputs[0].prev_index = 1;
                f.Rebuild();
                break;
            case 4:
                f.cb.outputs[0].value = 1;
                f.Rebuild();
                break;
            case 5:
                f.wire.pop_back();
                break;
            case 6:
                f.header.tx_root[0] ^= 1;
                break;
        }
        if (mutation == 1 || mutation == 6) {
            f.MineAndEncode();
        }
        const auto path = FreshPath();
        DiskStateStore out;
        std::string error;
        Check(!f.Open(path, out, error),
              "invalid genesis accepted mutation " + std::to_string(mutation));
        const char *reasons[] = {"explicit genesis identity",
                                 "genesis state commitment",
                                 "initial monetary genesis work",
                                 "coinbase",
                                 "genesis native issuance",
                                 "block",
                                 "transaction root"};
        Check(error.find(reasons[mutation]) != std::string::npos,
              "unexpected rejection reason for mutation " +
                  std::to_string(mutation) + ": " + error);
        Check(!out.IsOpen() && !std::filesystem::exists(path),
              "invalid genesis created database path");
    }
}
void InvalidProfilesBeforeOpen() {
    for (unsigned mutation = 0; mutation < 13; ++mutation) {
        Fixture f(true);
        switch (mutation) {
            case 0:
                f.op.coinbase_maturity = 0;
                break;
            case 1:
                f.op.max_total_invocation_cost = 0;
                break;
            case 2:
                f.op.vm_cost.max_invocation_cost = 0;
                break;
            case 3:
                ++f.op.dust_limit;
                break;
            case 4:
                f.op.vm.max_script_bytes = 0;
                break;
            case 5:
                f.op.vm.max_element_bytes = 0;
                break;
            case 6:
                f.op.vm.max_element_bytes = VM_HARD_ELEMENT_BYTES + 1;
                break;
            case 7:
                f.op.vm.max_stack_items = 0;
                break;
            case 8:
                f.op.vm.max_altstack_items = 0;
                break;
            case 9:
                f.op.vm.max_vm_bytes = 0;
                break;
            case 10:
                f.op.vm.max_ast_depth = 0;
                break;
            case 11:
                f.op.vm.max_steps = 0;
                break;
            case 12:
                f.op.dust_limit = 0;
                break;
        }
        const auto path = FreshPath();
        DiskStateStore out;
        std::string error;
        Check(!f.Open(path, out, error),
              "invalid development profile accepted");
        const auto reason = mutation <= 2 || mutation == 12
                                ? "ordinary profile resource limits"
                            : mutation == 3 ? "dust mismatch"
                                            : "VM profile limits";
        Check(error.find(reason) != std::string::npos,
              "unexpected profile rejection: " + error);
        Check(!out.IsOpen() && !std::filesystem::exists(path),
              "invalid profile created database path");
    }
}
void InvalidCostProfilesBeforeOpen() {
    const char *reasons[] = {
        "invalid explicit cost profile", "missing assigned opcode cost",
        "invalid field-size opcode", "invalid field-size bound"};
    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        Fixture f(true);
        switch (mutation) {
            case 0:
                f.op.vm_cost.structural_byte_cost = 0;
                break;
            case 1:
                f.op.vm_cost.opcode[0x75].base = 0;
                break; // Assigned DROP.
            case 2:
                f.op.vm_cost.field_sizes[0x75] = {1};
                break;
            case 3:
                f.op.vm_cost.field_sizes[0xdb] = {f.op.vm.max_element_bytes +
                                                  1};
                break;
        }
        const auto path = FreshPath();
        DiskStateStore out;
        std::string error;
        Check(!f.Open(path, out, error), "invalid VM cost schedule accepted");
        Check(error == reasons[mutation],
              "unexpected VM cost preflight error: " + error);
        Check(!out.IsOpen() && !std::filesystem::exists(path),
              "invalid VM cost schedule created database path");
    }
}
void DevelopmentDisconnectChecks() {
    for (const bool corrupt_predecessor : {false, true}) {
        Fixture f(corrupt_predecessor);
        const auto path = FreshPath();
        std::string error;
        DiskStateStore store;
        DiskStateError failure;
        DiskStateMetadata genesis;
        if (!corrupt_predecessor) {
            Check(f.Open(path, store, error), error);
            genesis = store.Metadata();
            Check(!DisconnectDevelopmentTip(genesis.tip, f.hp, f.op,
                                            EasyGenesis, f.costs, store,
                                            error) &&
                      error == "cannot disconnect genesis" &&
                      store.Metadata() == genesis && store.Root() == f.root,
                  "genesis disconnect refusal preserves state");
        } else {
            // Deliberately corrupt local checkpoint metadata: the predecessor
            // retains its exact manifest header but has no retained body.
            // This raw backend fixture is not an accepted complete block.
            genesis.tip = f.hp.genesis_id;
            genesis.header.assign(f.wire.begin(), f.wire.begin() + HEADER_SIZE);
            const auto money = EncodeMonetaryState(f.money);
            genesis.monetary.assign(money.begin(), money.end());
            genesis.auxiliary = EncodeDiskChainContext({f.header}, {});
            DiskStateOptions options;
            options.identity = f.hp.chain_id;
            options.profile_digest = BlockValidationProfileDigest(
                f.hp, f.op, EasyGenesis, f.costs);
            options.header_index = f.hp;
            Check(DiskStateStore::Open(path, options, {}, store, failure),
                  failure.message);
            {
                DiskStateTransaction seed;
                Check(store.Begin(seed, failure) &&
                          seed.Commit(genesis, f.header, failure),
                      failure.message);
            }
        }
        // Synthetic locally stored checkpoint, not ConnectEligibleDiskBlock
        // acceptance. The body reuses genesis transactions to isolate undo.
        Header child = f.header;
        child.prev_id = genesis.tip;
        child.height = 1;
        child.time = f.header.time + 120;
        child.state_root = StateRoot(f.hp.chain_id, 1, f.root, f.money);
        Hash target, id;
        Check(DecodeTarget(child.bits, f.hp.pow_limit, target),
              "checkpoint target");
        child.nonce = 0;
        for (;; ++child.nonce) {
            Check(BlockId(f.hp.chain_id, child, id), "checkpoint ID");
            if (MeetsTarget(id, target)) break;
        }
        std::vector<uint8_t> body;
        Check(EncodeBlockWire(child, {f.cb}, f.op.transaction, body, error),
              error);
        DiskStateMetadata checkpoint;
        checkpoint.tip = id;
        checkpoint.header.assign(body.begin(), body.begin() + HEADER_SIZE);
        checkpoint.monetary = genesis.monetary;
        checkpoint.auxiliary = EncodeDiskChainContext({child, f.header}, body);
        {
            DiskStateTransaction tx;
            Check(store.Begin(tx, failure) &&
                      tx.Commit(checkpoint, child, failure),
                  failure.message);
        }
        CheckActiveIndex(store, id, 1, 4, child.time);
        auto wrong_tip = id;
        wrong_tip[0] ^= 1;
        Check(!DisconnectDevelopmentTip(wrong_tip, f.hp, f.op,
                                        EasyGenesis, f.costs, store,
                                        error) &&
                  error == "active tip changed" &&
                  store.Metadata() == checkpoint && store.Root() == f.root,
              "expected tip mismatch preserves child");
        auto wrong_profile = f.op;
        ++wrong_profile.vm.max_steps;
        Check(!DisconnectDevelopmentTip(id, f.hp, wrong_profile,
                                        EasyGenesis, f.costs, store,
                                        error) &&
                  error == "stored validator profile mismatch" &&
                  store.Metadata() == checkpoint && store.Root() == f.root,
              "profile mismatch preserves child");
        const auto disconnected = DisconnectDevelopmentTip(
            id, f.hp, f.op, EasyGenesis, f.costs, store, error);
        if (corrupt_predecessor) {
            Check(!disconnected && error == "stored tip body unavailable" &&
                      store.Metadata() == checkpoint && store.Root() == f.root,
                  "corrupt predecessor callback refuses publication: " + error);
            store = DiskStateStore{};
            Check(f.Open(path, store, error), error);
            Check(store.Metadata() == checkpoint && store.Root() == f.root,
                  "restart preserves child after rejected predecessor");
        } else {
            CheckActiveIndex(store, genesis.tip, 0, 2, f.header.time);
            std::optional<Hash> inactive_height;
            Check(store.ReadActiveId(1, inactive_height, failure) &&
                      !inactive_height,
                  "disconnect removes active height one");
            std::optional<IndexedHeader> retained_header;
            Check(store.ReadIndexedHeader(id, retained_header, failure) &&
                      retained_header &&
                      retained_header->stage == HeaderStage::Connected &&
                      retained_header->chain_work == SmallWork(4),
                  "disconnected header retains ever-connected work record");
            Check(disconnected && store.Metadata() == genesis &&
                      store.Root() == f.root,
                  "chain-aware checkpoint disconnect restores exact genesis");
            store = DiskStateStore{};
            Check(f.Open(path, store, error), error);
            Check(store.Metadata() == genesis && store.Root() == f.root,
                  "chain-aware disconnect survives reopen");
            CheckActiveIndex(store, genesis.tip, 0, 2, f.header.time);
            std::optional<Coin> coin;
            Check(store.ReadCoin(f.coin->outpoint, coin, failure) &&
                      coin.has_value(),
                  "genesis zero coin survives checkpoint undo and restart");
        }
        store = DiskStateStore{};
        std::filesystem::remove_all(path);
    }
}

void RetainedBodyChecks() {
    Fixture f(true);
    const auto path = FreshPath();
    DiskStateStore store;
    std::string error;
    DiskStateError failure;
    Check(f.Open(path, store, error), error);
    const auto genesis = store.Metadata();
    auto read = [&](const Hash &id, uint64_t cap, RetainedBodyStatus status,
                    const std::vector<uint8_t> &expected) {
        const auto before = store.Metadata();
        const auto root = store.Root();
        std::vector<uint8_t> output{7, 8, 9};
        Check(ReadRetainedBlockBody(id, cap, f.hp, f.op, EasyGenesis,
                                    f.costs, store, output, error) == status,
              "unexpected retained body status: " + error);
        Check(output == (status == RetainedBodyStatus::Available
                             ? expected
                             : std::vector<uint8_t>{7, 8, 9}),
              "retained body output publication");
        Check(store.Metadata() == before && store.Root() == root,
              "retained body read mutated state");
    };
    read(genesis.tip, f.wire.size(), RetainedBodyStatus::Available, f.wire);
    read(genesis.tip, f.wire.size() - 1, RetainedBodyStatus::CapacityRefused,
         {});
    Hash missing;
    missing.fill(0x43);
    read(missing, UINT64_MAX, RetainedBodyStatus::Missing, {});
    auto wrong_profile = f.op;
    ++wrong_profile.vm.max_steps;
    std::vector<uint8_t> untouched{1, 2};
    Check(ReadRetainedBlockBody(genesis.tip, UINT64_MAX, f.hp, wrong_profile,
                                EasyGenesis, f.costs, store, untouched,
                                error) == RetainedBodyStatus::StorageError &&
              untouched == std::vector<uint8_t>({1, 2}) &&
              store.Metadata() == genesis,
          "retained body profile mismatch is operational and preserves output");
    // A raw, explicitly synthetic locally stored checkpoint supplies a framed
    // coinbase and internally consistent commitments, without asserting that
    // a monetary transition or ConnectEligibleDiskBlock accepted it.
    Header child = f.header;
    child.height = 1;
    child.time += 120;
    child.prev_id = genesis.tip;
    child.state_root = StateRoot(f.hp.chain_id, 1, f.root, f.money);
    auto cb = f.cb;
    cb.inputs[0].prev_txid = genesis.tip;
    cb.inputs[0].prev_index = 1;
    Check(CompleteTransactionRoot({cb}, f.op.transaction, f.hp.chain_id,
                                  child.tx_root, error),
          error);
    Hash target, id;
    Check(DecodeTarget(child.bits, f.hp.pow_limit, target),
          "retained checkpoint target");
    child.nonce = 0;
    for (;; ++child.nonce) {
        Check(BlockId(f.hp.chain_id, child, id), "retained checkpoint ID");
        if (MeetsTarget(id, target)) break;
    }
    std::vector<uint8_t> body;
    Check(EncodeBlockWire(child, {cb}, f.op.transaction, body, error), error);
    DiskStateMetadata checkpoint;
    checkpoint.tip = id;
    checkpoint.header.assign(body.begin(), body.begin() + HEADER_SIZE);
    checkpoint.monetary = genesis.monetary;
    checkpoint.auxiliary = EncodeDiskChainContext({child, f.header}, body);
    {
        DiskStateTransaction tx;
        Check(store.Begin(tx, failure) && tx.Commit(checkpoint, child, failure),
              failure.message);
    }
    read(genesis.tip, UINT64_MAX, RetainedBodyStatus::Available, f.wire);
    read(id, body.size(), RetainedBodyStatus::Available, body);
    Check(store.Disconnect(id, failure), failure.message);
    read(id, UINT64_MAX, RetainedBodyStatus::Available, body);
    read(genesis.tip, UINT64_MAX, RetainedBodyStatus::Available, f.wire);
    store = DiskStateStore{};
    Check(f.Open(path, store, error), error);
    read(id, UINT64_MAX, RetainedBodyStatus::Available, body);
    store = DiskStateStore{};
    std::filesystem::remove_all(path);
}
void CorruptRetainedBodies() {
    for (unsigned mutation = 0; mutation < 5; ++mutation) {
        Fixture f(true);
        DiskStateMetadata corrupted;
        corrupted.tip = f.hp.genesis_id;
        corrupted.header.assign(f.wire.begin(), f.wire.begin() + HEADER_SIZE);
        auto money = f.money;
        if (mutation == 1) money.prev_work[0] = 3;
        if (mutation == 2) ++money.bootstrap_reserve;
        const auto money_bytes = EncodeMonetaryState(money);
        corrupted.monetary.assign(money_bytes.begin(), money_bytes.end());
        auto body = f.wire;
        if (mutation == 0)
            body[body.size() - 2] ^=
                1; // Branch digest: same canonical framing, wrong TxRoot.
        corrupted.auxiliary = EncodeDiskChainContext({f.header}, body);
        if (mutation == 3) corrupted.auxiliary.resize(5);
        if (mutation == 4) corrupted.header.pop_back();
        DiskStateOptions options;
        options.identity = f.hp.chain_id;
        options.profile_digest = BlockValidationProfileDigest(
            f.hp, f.op, EasyGenesis, f.costs);
        const auto path = FreshPath();
        DiskStateStore store;
        DiskStateError failure;
        Check(DiskStateStore::Open(path, options, corrupted, store, failure),
              failure.message);
        const auto root = store.Root();
        std::vector<uint8_t> out{17};
        std::string error;
        Check(ReadRetainedBlockBody(corrupted.tip,
                                    mutation >= 3 ? 0 : UINT64_MAX, f.hp, f.op,
                                    EasyGenesis, f.costs, store, out,
                                    error) == RetainedBodyStatus::StorageError,
              "corrupt retained body was served");
        const char *reason[] = {"transaction root", "monetary target work",
                                "state commitment", "history framing",
                                "header encoding"};
        Check(error.find(reason[mutation]) != std::string::npos,
              "wrong retained corruption rejection: " + error);
        Check(out == std::vector<uint8_t>{17} &&
                  store.Metadata() == corrupted && store.Root() == root,
              "corrupt retained read mutated output or storage");
        store = DiskStateStore{};
        std::filesystem::remove_all(path);
    }
}
void HeaderOnlyAdmissionChecks() {
    Fixture f(true);
    const auto path = FreshPath();
    DiskStateStore store;
    std::string error;
    DiskStateError failure;
    Check(f.Open(path, store, error), error);
    const auto genesis = store.Metadata();
    const auto root = store.Root();
    auto mine = [&](Header &h) {
        Hash target, id;
        Check(DecodeTarget(h.bits, f.hp.pow_limit, target),
              "header-only target");
        h.nonce = 0;
        for (;; ++h.nonce) {
            Check(BlockId(f.hp.chain_id, h, id), "header-only ID");
            if (MeetsTarget(id, target)) return id;
        }
    };
    Header child = f.header;
    child.prev_id = genesis.tip;
    child.height = 1;
    child.time += 120;
    // Header-only commitments deliberately have no validated body or state.
    child.tx_root.fill(0x31);
    child.state_root.fill(0x62);
    child.size = 777;
    const auto id = mine(child);
    auto admit = [&](const Header &h, HeaderAdmission status) {
        Check(AdmitDevelopmentHeader(h, f.hp, f.op, EasyGenesis, f.costs,
                                     store, error) == status,
              "unexpected header-only admission result: " + error);
        Check(store.Metadata() == genesis && store.Root() == root,
              "header-only admission mutated active state");
        CheckActiveIndex(store, genesis.tip, 0, 2, f.header.time);
    };
    admit(child, HeaderAdmission::Stored);
    std::optional<IndexedHeader> checked;
    Check(store.ReadIndexedHeader(id, checked, failure) && checked &&
              checked->stage == HeaderStage::HeaderChecked &&
              checked->chain_work == SmallWork(4) &&
              checked->max_ancestor_time == child.time &&
              checked->header.state_root == child.state_root,
          "header-only record stores untrusted commitments and checked work");
    std::optional<Hash> active_child;
    Check(store.ReadActiveId(1, active_child, failure) && !active_child,
          "header-only record is not active at height one");
    std::vector<uint8_t> body{19};
    Check(ReadRetainedBlockBody(id, UINT64_MAX, f.hp, f.op, EasyGenesis,
                                f.costs, store, body,
                                error) == RetainedBodyStatus::Missing &&
              body == std::vector<uint8_t>{19},
          "header-only admission does not imply retained body availability");
    admit(child, HeaderAdmission::Known);
    admit(f.header, HeaderAdmission::Known);
    for (unsigned mutation = 0; mutation < 7; ++mutation) {
        auto bad = child;
        switch (mutation) {
            case 0:
                bad.prev_id.fill(0x45);
                break;
            case 1:
                ++bad.height;
                break;
            case 2:
                bad.bits = 0x207ffffe;
                break;
            case 3:
                bad.time = f.header.time;
                break;
            case 4:
                bad = f.header;
                ++bad.time;
                break;
            case 5:
                bad.size = HEADER_SIZE + 3;
                break;
            case 6:
                bad.prev_id.fill(0x46);
                break;
        }
        auto bad_id = mine(bad);
        if (mutation == 6) {
            Hash target;
            Check(DecodeTarget(bad.bits, f.hp.pow_limit, target),
                  "bad-PoW target");
            do {
                ++bad.nonce;
                Check(BlockId(f.hp.chain_id, bad, bad_id), "bad-PoW ID");
            } while (MeetsTarget(bad_id, target));
        }
        admit(bad, mutation == 0 ? HeaderAdmission::MissingParent
                                 : HeaderAdmission::Invalid);
        std::optional<IndexedHeader> absent;
        Check(store.ReadIndexedHeader(bad_id, absent, failure) && !absent,
              "rejected header-only record was persisted");
    }
    auto wrong_profile = f.op;
    ++wrong_profile.vm.max_steps;
    Check(
        AdmitDevelopmentHeader(child, f.hp, wrong_profile, EasyGenesis,
                               f.costs, store,
                               error) == HeaderAdmission::StorageError &&
            store.Metadata() == genesis && store.Root() == root,
        "header-only profile mismatch is operational without active mutation");
    store = DiskStateStore{};
    Check(f.Open(path, store, error), error);
    CheckActiveIndex(store, genesis.tip, 0, 2, f.header.time);
    Check(store.ReadIndexedHeader(id, checked, failure) && checked &&
              checked->stage == HeaderStage::HeaderChecked,
          "header-only record survives reopen without active promotion");
    store = DiskStateStore{};
    std::filesystem::remove_all(path);
}
void AbsoluteProfileBinding() {
    Fixture f(true);
    const auto digest = BlockValidationProfileDigest(f.hp, f.op, EasyGenesis, f.costs);
    auto changed = EasyGenesis;
    ++changed.genesis_tail;
    Check(digest != BlockValidationProfileDigest(f.hp, f.op, changed, f.costs),
          "profile digest binds genesis tail anchor");
    changed = EasyGenesis;
    changed.genesis_work[0] = 3;
    Check(digest != BlockValidationProfileDigest(f.hp, f.op, changed, f.costs),
          "profile digest binds genesis work anchor");
    const auto path = FreshPath();
    std::string error;
    DiskStateStore store;
    Check(f.Open(path, store, error), error);
    const auto before = store.Metadata();
    store = DiskStateStore{};
    DiskStateStore rejected;
    Check(!OpenDevelopmentChain(path, f.wire, f.hp, f.op, changed,
          f.costs, f.money, {}, rejected, error) && !rejected.IsOpen(),
          "changed absolute anchor cannot reopen existing home");
    Check(f.Open(path, store, error) && store.Metadata() == before,
          "failed anchor migration preserves existing home");
    store = DiskStateStore{};
    std::filesystem::remove_all(path);
}
void GenericStoreIsNotMigrated() {
    Fixture f(true);
    const auto path = FreshPath();
    DiskStateOptions generic;
    generic.identity = f.hp.chain_id;
    generic.profile_digest =
        BlockValidationProfileDigest(f.hp, f.op, EasyGenesis, f.costs);
    DiskStateError failure;
    {
        DiskStateStore store;
        Check(DiskStateStore::Open(path, generic, {}, store, failure),
              failure.message);
    }
    DiskStateStore out;
    std::string error;
    Check(!f.Open(path, out, error) && !out.IsOpen(),
          "generic schema must not migrate implicitly");
    DiskStateStore unchanged;
    Check(DiskStateStore::Open(path, generic, {}, unchanged, failure),
          failure.message);
    Check(unchanged.Metadata() == DiskStateMetadata{} &&
              unchanged.Root() == EmptyUtxoRoot(),
          "failed indexed open leaves generic store unchanged");
    unchanged = DiskStateStore{};
    std::filesystem::remove_all(path);
}
void BlankRetry() {
    Fixture f(false);
    const auto path = FreshPath();
    DiskStateOptions options;
    options.identity = f.hp.chain_id;
    options.profile_digest =
        BlockValidationProfileDigest(f.hp, f.op, EasyGenesis, f.costs);
    options.header_index = f.hp;
    {
        DiskStateStore blank;
        DiskStateError failure;
        Check(DiskStateStore::Open(path, options, {}, blank, failure),
              failure.message);
        Check(blank.Metadata() == DiskStateMetadata{} &&
                  blank.Root() == EmptyUtxoRoot(),
              "blank bound pre-genesis store");
        DiskStateMetadata expected;
        expected.tip = f.hp.genesis_id;
        expected.header.assign(f.wire.begin(), f.wire.begin() + HEADER_SIZE);
        const auto money = EncodeMonetaryState(f.money);
        expected.monetary.assign(money.begin(), money.end());
        expected.auxiliary = EncodeDiskChainContext({f.header}, f.wire);
        {
            DiskStateTransaction missing_header;
            Check(blank.Begin(missing_header, failure) &&
                      missing_header.Insert(*f.coin, failure),
                  failure.message);
            Check(!missing_header.Commit(expected, failure),
                  "indexed mode rejects old commit overload without explicit "
                  "header");
        }
        Check(blank.Metadata() == DiskStateMetadata{} &&
                  blank.Root() == EmptyUtxoRoot(),
              "old indexed commit overload cannot publish coins or metadata");
    }
    DiskStateStore initialized;
    std::string error;
    Check(f.Open(path, initialized, error), error);
    Check(initialized.Metadata().tip == f.hp.genesis_id &&
              initialized.Root() == f.root,
          "crash-before-genesis retry");
    initialized = DiskStateStore{};
    std::filesystem::remove_all(path);
}
} // namespace
int main() {
    try {
        CheckValid(true);
        CheckValid(false);
        InvalidBeforeOpen();
        InvalidProfilesBeforeOpen();
        InvalidCostProfilesBeforeOpen();
        HeaderOnlyAdmissionChecks();
        AbsoluteProfileBinding();
        GenericStoreIsNotMigrated();
        BlankRetry();
        RetainedBodyChecks();
        CorruptRetainedBodies();
        DevelopmentDisconnectChecks();
        std::cout << "development chain initialization checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
