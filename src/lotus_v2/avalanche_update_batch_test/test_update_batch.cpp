// Copyright (c) 2026 The Lotus developers
#include "../development_runtime.h"
#include "../development_runtime_test/fixtures.h"
#include <helpers/memenv/memenv.h>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <iostream>
using namespace lotus::v2;
using namespace runtime_fixture;
namespace {
struct BatchHome {
    std::unique_ptr<leveldb::Env> env{leveldb::NewMemEnv(leveldb::Env::Default())};
    std::string path;
    DevelopmentRuntimeConfig config;
    DiskStateStore store;
    std::vector<Hash> ids;
    explicit BatchHome(uint64_t pending = 64 << 20, uint64_t reads = 100000) {
        char name[] = "/private/tmp/lotus-v2-avalanche-batch-XXXXXX";
        Check(mkdtemp(name) != nullptr, "temporary home");
        path = name;
        config.directory = path;
        config.genesis_wire = Bytes(genesis_wire);
        config.profiles = Profiles();
        config.initial_money = DecodeMonetaryState(Bytes(initial_money));
        config.storage.env = env.get();
        config.storage.avalanche = true;
        config.storage.max_pending_bytes = pending;
        config.storage.max_avalanche_reads = reads;
        config.storage.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
        config.storage.candidates = CandidateStoreOptions{4096, 4096, 128};
        config.bodies = {64, 1 << 20, 64 << 20, 64, 64 << 20, 64};
        config.initial_body_epoch = config.initial_context_generation = 1;
        std::string error;
        const auto &p = config.profiles;
        Check(OpenDevelopmentChain(path, config.genesis_wire, p.header, p.ordinary,
            p.monetary, p.cost, config.initial_money, config.storage, store, error), "open: " + error);
        ids.push_back(p.header.genesis_id);
    }
    ~BatchHome() { store = {}; std::filesystem::remove_all(path); }
    void Headers(size_t count) {
        // Mechanically valid HeaderChecked index corpus, not contextual body
        // acceptance or an alternative consensus profile. Apply Accepted uses
        // this existing public runtime boundary; no finality is asserted here.
        Header previous;
        Check(ParseHeader(config.genesis_wire.data(), HEADER_SIZE, previous), "genesis header");
        Hash target;
        Check(DecodeTarget(previous.bits, config.profiles.header.pow_limit, target), "target");
        DiskStateError error;
        for (size_t height = 1; height <= count; ++height) {
            Header next = previous;
            next.prev_id = ids.back(); next.height = height;
            next.time = previous.time + 120;
            next.nonce = 0;
            Hash id;
            while (true) {
                Check(BlockId(config.profiles.header.chain_id, next, id), "header id");
                if (MeetsTarget(id, target)) break;
                ++next.nonce;
            }
            Check(store.PutCheckedHeader(next, error), "index header: " + error.message);
            ids.push_back(id); previous = next;
        }
    }
    void ConnectedFixtures() {
        const auto &p = config.profiles;
        for (size_t i : {0, 1, 2, 3}) {
            StagedBlockTransition out;
            std::string error;
            Check(ConnectEligibleDiskBlock(Bytes(V(i).wire), UINT64_MAX, 0,
                p.header, p.ordinary, p.monetary, p.cost, store, out, error) == DiskBlockAdmission::Accepted,
                "connect fixture: " + error);
        }
    }
    std::unique_ptr<DevelopmentRuntime> Open() {
        store = {};
        std::unique_ptr<DevelopmentRuntime> runtime;
        std::string error;
        Check(DevelopmentRuntime::Open(config, runtime, error), "open runtime: " + error);
        return runtime;
    }
};
RuntimeBlockUpdate Update(DevelopmentRuntime &r, const Hash &id, RuntimeBlockStatus status) {
    const auto s = r.Snapshot();
    Check(bool(s.chain), "runtime authority");
    return {id, status, s.chain->stable_tip, s.context_generation};
}
RuntimeBlockObservation Observe(DevelopmentRuntime &r, const Hash &id) {
    RuntimeBlockObservation result; std::string error;
    Check(r.ObserveAvalancheBlock(id, result, error), "observe: " + error);
    return result;
}
void OverlappingBatch(bool historical_failure) {
    BatchHome home; home.Headers(2024); auto runtime = home.Open();
    std::vector<RuntimeBlockUpdate> updates;
    for (size_t i = 1001; i <= 2024; ++i)
        updates.push_back(Update(*runtime, home.ids[i], RuntimeBlockStatus::Accepted));
    Check(updates.size() == 1024 && DiskStateOptions{}.max_avalanche_reads == 100000 &&
        home.config.storage.max_avalanche_reads == 100000,
        "actual default read cap and native maximum poll element count");
    const auto before = runtime->Snapshot();
    std::string error;
    const bool applied = runtime->ApplyAvalancheUpdates(updates, error);
    const auto after = runtime->Snapshot();
    Check(!after.reopen_required && after.chain && before.chain &&
        after.chain->stable_tip == before.chain->stable_tip && after.chain->root == before.chain->root,
        "batch never establishes transaction acceptance or changes active state root");
    if (historical_failure) {
        Check(!applied && error == "Avalanche ancestry read capacity" &&
            after.chain->revision == before.chain->revision &&
            after.context_generation == before.context_generation, "historical atomic capacity refusal: " + error);
        std::cout << "REPRODUCED: 1024 distinct overlapping updates at height2024 exhaust default100000 reads before policy mutation\n";
        return;
    }
    Check(applied, "1024 overlapping updates: " + error);
    Check(after.chain->revision > before.chain->revision, "policy commit completed");
    const auto observed = Observe(*runtime, home.ids.back());
    Check(observed.known && !observed.parked && !observed.finalized && !observed.active,
        "Accepted does not fabricate finality or active-chain acceptance");
}
void OrderedFinalization(bool reject_last) {
    BatchHome home; home.ConnectedFixtures(); auto runtime = home.Open();
    const auto tip = H(V(3).id), ancestor = H(V(1).id);
    auto accepted = Update(*runtime, tip, RuntimeBlockStatus::Accepted);
    auto rejected = Update(*runtime, ancestor, RuntimeBlockStatus::Rejected);
    auto finalized = Update(*runtime, tip, RuntimeBlockStatus::Finalized);
    const auto before = runtime->Snapshot();
    std::vector<RuntimeBlockUpdate> updates{finalized};
    if (reject_last) { updates.push_back(accepted); updates.push_back(rejected); }
    else { updates.push_back(rejected); updates.push_back(accepted); }
    std::string error;
    const bool applied = runtime->ApplyAvalancheUpdates(updates, error);
    if (reject_last) {
        Check(!applied && error == "batch parks finalized ancestry", "ordered conflict refusal: " + error);
        Check(runtime->Snapshot().chain->revision == before.chain->revision,
            "conflicting finalized ancestry batch commits nothing");
        Check(!Observe(*runtime, tip).finalized && !Observe(*runtime, ancestor).parked, "no partial policies on conflict");
    } else {
        Check(applied, "later Accepted clears staged ancestor through cache hits: " + error);
        Check(Observe(*runtime, tip).finalized && !Observe(*runtime, ancestor).parked,
            "ordered clearing and finalization retained");
    }
}
void ResourceCaps() {
    BatchHome home(64 << 10); home.Headers(512); auto runtime = home.Open();
    const auto before = runtime->Snapshot(); std::string error;
    Check(!runtime->ApplyAvalancheUpdates({Update(*runtime, home.ids.back(), RuntimeBlockStatus::Accepted)}, error) &&
        error == "Avalanche header cache capacity", "cache payload cap refusal: " + error);
    Check(!runtime->Snapshot().reopen_required && runtime->Snapshot().chain->revision == before.chain->revision,
        "cache refusal has no policy writes or authority fault");
    Check(!Observe(*runtime, home.ids.back()).parked, "cache refusal has no park marker");
    BatchHome small(64 << 20, 20); small.Headers(16); auto bounded = small.Open();
    const auto initial = bounded->Snapshot();
    Check(!bounded->ApplyAvalancheUpdates({Update(*bounded, small.ids.back(), RuntimeBlockStatus::Accepted)}, error) &&
        error == "Avalanche ancestry read capacity", "unique reads still consume supplied budget: " + error);
    Check(!bounded->Snapshot().reopen_required && bounded->Snapshot().chain->revision == initial.chain->revision,
        "read refusal remains operational and atomic");
}
void MissingAndCorrupt() {
    BatchHome missing; missing.Headers(8); auto runtime = missing.Open();
    Hash unknown{}; unknown.fill(0xff);
    const auto before = runtime->Snapshot(); std::string error;
    Check(!runtime->ApplyAvalancheUpdates({Update(*runtime, missing.ids.back(), RuntimeBlockStatus::Rejected),
        Update(*runtime, unknown, RuntimeBlockStatus::Accepted)}, error) && error == "unknown Avalanche block",
        "missing header refusal: " + error);
    Check(!runtime->Snapshot().reopen_required && runtime->Snapshot().chain->revision == before.chain->revision &&
        !Observe(*runtime, missing.ids.back()).parked, "missing header doesn't fault or publish earlier park");
    BatchHome corrupt; corrupt.Headers(8); corrupt.store = {};
    const auto &id = corrupt.ids.back();
    std::string key(1, 'H'); key.append(reinterpret_cast<const char *>(id.data()), id.size());
    std::string raw_err;
    Check(RawDiskStateAccess(corrupt.path, std::nullopt, nullptr, {{key, std::string("corrupt")}}, &raw_err),
          "write malformed first-miss record: " + raw_err);
    auto faulted = corrupt.Open();
    Check(!faulted->ApplyAvalancheUpdates({Update(*faulted, id, RuntimeBlockStatus::Accepted)}, error),
        "corrupt header refusal");
    Check(faulted->Snapshot().reopen_required, "first cache miss preserves storage corruption authority revocation");
}
}
int main(int argc, char **argv) {
    try {
        const bool historical = argc == 2 && std::string(argv[1]) == "--expect-capacity-failure";
        OverlappingBatch(historical);
        if (historical) return 0;
        OrderedFinalization(false); OrderedFinalization(true);
        ResourceCaps(); MissingAndCorrupt();
        std::cout << "Avalanche overlapping batch, ordering, logical cache/read caps and corruption: PASS\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
