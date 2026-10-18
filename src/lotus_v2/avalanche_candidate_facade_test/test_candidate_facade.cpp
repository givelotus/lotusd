// Copyright (c) 2026 The Lotus developers
#include "../development_runtime.h"
#include "../development_runtime_test/fixtures.h"
#include <iostream>
#include <leveldb/env.h>
using namespace lotus::v2;
using namespace runtime_fixture;
namespace {
using Result = DevelopmentRuntimeResult;
constexpr CandidateQueryLimits query{16, 4096, 4096, 64 << 10};
DevelopmentRuntimeConfig Config(Home &h, bool avalanche = true) {
    DevelopmentRuntimeConfig c;
    c.directory = h.path; c.genesis_wire = Bytes(genesis_wire); c.profiles = h.p;
    c.initial_money = DecodeMonetaryState(Bytes(initial_money));
    c.storage.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
    c.storage.candidates = CandidateStoreOptions{64, 64, 8};
    c.storage.avalanche = avalanche;
    c.storage.env = h.env;
    c.bodies = {64, 1 << 20, 64 << 20, 64, 64 << 20, 64};
    c.initial_body_epoch = 1; c.initial_context_generation = 1;
    return c;
}
void Seed(Home &h) {
    h.store = {}; std::filesystem::remove_all(h.path);
    auto c = Config(h); std::string e;
    Check(OpenDevelopmentChain(h.path, c.genesis_wire, h.p.header, h.p.ordinary,
          h.p.monetary, h.p.cost, c.initial_money, c.storage, h.store, e), "seed: " + e);
    for (size_t n : {0, 1, 2, 3}) h.Connect(n);
    h.store = {};
}
std::unique_ptr<DevelopmentRuntime> Open(Home &h, bool avalanche = true) {
    std::unique_ptr<DevelopmentRuntime> r; std::string e;
    Check(DevelopmentRuntime::Open(Config(h, avalanche), r, e), "open: " + e);
    return r;
}
CandidatePage Sentinel() {
    CandidatePage p; p.view.revision = 777; p.complete = true;
    p.rows.push_back({H(V(0).id), {}});
    p.next = CandidateRankCursor{{}, H(V(0).id)}; p.used.reads = 777;
    return p;
}
void Unchanged(const CandidatePage &p) {
    Check(p.view.revision == 777 && p.complete && p.rows.size() == 1 &&
          p.rows[0].id == H(V(0).id) && p.next && p.next->id == H(V(0).id) &&
          p.used.reads == 777, "refusal preserves full output sentinel");
}
DevelopmentTickLimits TickLimits() {
    DevelopmentTickLimits l;
    l.selection.query = {64, 100000, 100000, 1 << 20};
    l.selection.fork = {8, 8, 10000}; l.selection.max_probe_calls = 128;
    l.selection.max_probe_bytes = 1 << 20; l.selection.max_missing_bodies = 8;
    l.selection.max_resident_bytes = 1 << 20; l.recovery = Limits();
    l.propagation = {64, 100000, 100000, 1 << 20}; return l;
}
std::vector<Hash> Scan(DevelopmentRuntime &r) {
    std::optional<CandidateRankCursor> cursor;
    std::vector<Hash> ids; std::string e;
    auto limits = query; limits.max_rows = 1;
    for (unsigned n = 0; n < 64; ++n) {
        CandidatePage page;
        Check(r.ReadAvalancheCandidates(cursor, limits, page, e) == Result::Progress,
              "bounded persisted page: " + e);
        Check(page.rows.size() <= 1 && page.used.rows <= 1 &&
              page.used.reads <= limits.max_reads &&
              page.used.iterator_steps <= limits.max_iterator_steps &&
              page.used.decoded_bytes <= limits.max_decoded_bytes,
              "reported query bounds");
        Check(page.view.stable_tip == r.Snapshot().chain->stable_tip &&
              page.view.revision == r.Snapshot().chain->revision,
              "page publishes authoritative snapshot");
        for (const auto &row : page.rows) {
            Check(std::find(ids.begin(), ids.end(), row.id) == ids.end(), "cursor excludes duplicates");
            ids.push_back(row.id);
        }
        if (page.complete) return ids;
        Check(page.next && page.next != cursor, "pagination makes progress");
        cursor = page.next;
    }
    throw std::runtime_error("scan did not complete");
}
void PersistedAndFenced() {
    Home h; Seed(h); auto r = Open(h); std::string e;
    for (size_t n : {4, 5, 6}) {
        HeaderAdmission a;
        Check(r->AdmitHeader(HeaderOf(V(n)), a, e) == Result::Progress &&
              a == HeaderAdmission::Stored, "admit fork: " + e);
    }
    const auto ids = Scan(*r);
    Check(ids.size() == 3, "persisted speculative fork inventory");
    r.reset(); r = Open(h);
    Check(Scan(*r) == ids, "reopen retains rank order and candidates without pool bodies");
    const auto before = r->Snapshot();
    for (unsigned dimension = 0; dimension < 4; ++dimension) {
        auto limits = query;
        if (dimension == 0) limits.max_rows = 0;
        if (dimension == 1) limits.max_reads = 0;
        if (dimension == 2) limits.max_iterator_steps = 0;
        if (dimension == 3) limits.max_decoded_bytes = 0;
        auto out = Sentinel();
        Check(r->ReadAvalancheCandidates({}, limits, out, e) == Result::CapacityRefused,
              "zero query budget has resource typing");
        Unchanged(out);
        Check(!r->Snapshot().reopen_required && r->Snapshot().chain &&
              r->Snapshot().chain->revision == before.chain->revision &&
              r->Snapshot().context_generation == before.context_generation,
              "resource refusal preserves authority and generation");
    }
    Check(Scan(*r) == ids, "resource refusal leaves reader usable");
    const auto snap = r->Snapshot();
    Check(r->ApplyAvalancheUpdates({{H(V(2).id), RuntimeBlockStatus::Rejected,
          snap.chain->stable_tip, snap.context_generation}}, e), "park active branch: " + e);
    auto tick = r->Tick(UINT64_MAX, 0, TickLimits());
    Check(tick.result == Result::Prepared, "prepare parked unwind: " + tick.diagnostic);
    auto out = Sentinel();
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::Recovering,
          "pending journal refuses page"); Unchanged(out);
    r.reset(); r = Open(h); out = Sentinel();
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::Recovering,
          "reopened journal still fences page"); Unchanged(out);
    bool receipt = false, settled = false;
    for (unsigned n = 0; n < 100; ++n) {
        tick = r->Tick(UINT64_MAX, 0, TickLimits());
        Check(!tick.snapshot.reopen_required, "recovery storage: " + tick.diagnostic);
        if (tick.snapshot.chain->pending_receipt) {
            receipt = true; out = Sentinel();
            Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::Recovering,
                  "pending receipt refuses page"); Unchanged(out);
        }
        if (!tick.snapshot.chain->pending_journal && !tick.snapshot.chain->pending_receipt &&
            !tick.snapshot.chain->pending_propagation) { settled = true; break; }
    }
    Check(receipt && settled, "recovery reaches receipt and settles");
    const auto parked = Scan(*r);
    for (size_t n : {2, 3})
        Check(std::find(parked.begin(), parked.end(), H(V(n).id)) != parked.end(),
              "disconnected parked candidate remains pollable");
    r.reset(); r = Open(h);
    Check(Scan(*r) == parked, "parked candidate ranks survive reopening");
    DevelopmentRuntime moved(std::move(*r)); out = Sentinel();
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::Closed,
          "moved owner refuses Closed"); Unchanged(out);
}
void Disabled() {
    Home h; h.store = {}; auto r = Open(h, false); std::string e;
    auto out = Sentinel();
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::InvalidConfiguration,
          "ordinary runtime refuses Avalanche candidate reads"); Unchanged(out);
    Check(!r->Snapshot().reopen_required && r->Snapshot().chain,
          "disabled policy does not poison storage");
}
class FaultEnv final : public leveldb::EnvWrapper {
public:
    bool fail{}, reenter{}, saw_busy{};
    DevelopmentRuntime *runtime{};
    FaultEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File final : public leveldb::WritableFile {
        FaultEnv &env;
        std::unique_ptr<leveldb::WritableFile> file;
    public:
        File(FaultEnv &e, leveldb::WritableFile *f) : env(e), file(f) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &s) override { return file->Append(s); }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Close() override { return file->Close(); }
        leveldb::Status Sync() override {
            auto status = file->Sync();
            if (env.reenter && env.runtime) {
                env.reenter = false;
                auto out = Sentinel(); std::string e;
                env.saw_busy = env.runtime->ReadAvalancheCandidates({}, query, out, e) == Result::Busy;
                Unchanged(out);
            }
            if (status.ok() && env.fail) {
                env.fail = false;
                return leveldb::Status::IOError("injected failure after durable sync");
            }
            return status;
        }
    };
    leveldb::Status NewWritableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewWritableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
    leveldb::Status NewAppendableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewAppendableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
};
void BusyAndReopenRequired() {
    FaultEnv env; Home h(32 << 20, Profiles(), true, &env); Seed(h);
    auto r = Open(h); env.runtime = r.get(); env.reenter = true; env.fail = true;
    auto snap = r->Snapshot(); std::string e;
    Check(!r->ApplyAvalancheUpdates({{H(V(2).id), RuntimeBlockStatus::Rejected,
          snap.chain->stable_tip, snap.context_generation}}, e), "ambiguous durable update refused");
    Check(env.saw_busy, "candidate reader refuses Busy during storage callback");
    auto out = Sentinel();
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::ReopenRequired,
          "ambiguous authority refuses ReopenRequired"); Unchanged(out);
    Check(!r->Snapshot().chain, "ambiguous authority stays revoked");
    Check(r->Tick(UINT64_MAX, 0, TickLimits()).result == Result::Reopened,
          "explicit tick reopens authoritative store");
    Check(r->ReadAvalancheCandidates({}, query, out, e) == Result::Progress,
          "successful reopen restores candidate reads");
    env.runtime = nullptr;
}
}
int main() {
    try { PersistedAndFenced(); Disabled(); BusyAndReopenRequired(); std::cout << "Avalanche candidate facade checks passed\n"; }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
