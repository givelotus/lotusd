// Copyright (c) 2026 The Lotus developers
// Socket-free selector/storage tests. Headers are explicitly synthetic mechanical
// index fixtures; body availability is injected, not a VM/consensus-valid claim.
#include "candidate_selection.h"
#include "disk_state.h"
#include "vendor/blake3/blake3.h"
#include <leveldb/db.h>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
using namespace lotus::v2;
namespace {
void Check(bool ok, const std::string &why) { if (!ok) throw std::runtime_error(why); }
Hash Tag(uint32_t n) { Hash h{}; for (unsigned i = 0; i < 4; ++i) h[i] = uint8_t(n >> (8 * i)); return h; }
struct Fixture {
    std::string path;
    HeaderChainProfile profile;
    DiskStateOptions options;
    DiskStateStore store;
    Header genesis, active;
    uint32_t sequence{1};
    std::set<Hash> bodies;
    std::vector<Hash> probes;
    explicit Fixture(const std::string &directory) : path(directory) {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        profile.chain_id = Tag(0x1234); profile.version = 2; profile.genesis_time = 1000;
        profile.genesis_bits = 0x207fffff; profile.half_life_seconds = 172800; profile.spacing_seconds = 120;
        Hash maximum; maximum.fill(255);
        Check(DecodeTarget(profile.genesis_bits, maximum, profile.pow_limit), "target");
        genesis.version = profile.version; genesis.bits = profile.genesis_bits;
        genesis.time = profile.genesis_time; genesis.size = HEADER_SIZE + 4;
        genesis.tx_root = Tag(sequence++); genesis.state_root = Tag(2); Mine(genesis);
        profile.genesis_id = Id(genesis);
        options.identity = profile.chain_id; options.profile_digest = Tag(0x5678); options.header_index = profile;
        options.recovery = DiskRecoveryOptions{65536, 65536};
        options.candidates = CandidateStoreOptions{1024, 1024, 16};
        options.cache_bytes = 1024; options.write_buffer_bytes = 65536;
        DiskStateError error;
        Check(DiskStateStore::Open(path, options, {}, store, error), "open: " + error.message);
        Commit(genesis);
    }
    ~Fixture() { store = {}; if (!std::uncaught_exceptions()) std::filesystem::remove_all(path); }
    Hash Id(const Header &h) const { Hash id; Check(BlockId(profile.chain_id, h, id), "ID"); return id; }
    void Mine(Header &h) const {
        Hash target; Check(DecodeTarget(h.bits, profile.pow_limit, target), "mine target");
        while (!MeetsTarget(Id(h), target)) ++h.nonce;
    }
    Header Child(const Header &parent, uint32_t bits = 0x207fffff, uint64_t time = 0) {
        Header h; h.prev_id = Id(parent); h.height = parent.height + 1; h.version = profile.version;
        h.bits = bits; h.time = time ? time : parent.time + 120;
        h.size = HEADER_SIZE + 4; h.tx_root = Tag(sequence++); h.state_root = Tag(sequence++);
        Mine(h); return h;
    }
    DiskStateMetadata Meta(const Header &h) const {
        DiskStateMetadata m; m.tip = Id(h); std::array<uint8_t, HEADER_SIZE> bytes;
        Check(SerializeHeader(h, bytes), "header serialization"); m.header.assign(bytes.begin(), bytes.end());
        m.monetary = {1, 2, 3}; m.auxiliary = {4, 5, 6}; return m;
    }
    void Commit(const Header &h) {
        DiskStateError error; DiskStateTransaction tx;
        Check(store.Begin(tx, error), "begin: " + error.message);
        Check(tx.Commit(Meta(h), h, error), "commit: " + error.message);
        active = h; bodies.insert(Id(h));
    }
    void Add(const Header &h, bool body = true) {
        DiskStateError error;
        Check(store.PutCheckedHeader(h, error), "header admission: " + error.message);
        if (body) bodies.insert(Id(h));
    }
    CandidateBodyProbe Probe() {
        return [&](const Hash &id, const Header &h, uint64_t maximum, std::string &) {
            Check(Id(h) == id && maximum, "authenticated bounded probe input"); probes.push_back(id);
            return bodies.contains(id) ? CandidateBodyResult::Available : CandidateBodyResult::Missing;
        };
    }
};
CandidateLimits Limits() {
    CandidateLimits l; l.query = {64, 20000, 20000, 1 << 20}; l.fork = {64, 64, 4096};
    l.max_probe_calls = 128; l.max_probe_bytes = 65536; l.max_missing_bodies = 8;
    l.max_resident_bytes = 1 << 20; return l;
}
CandidateResult Poll(Fixture &f, CandidateSelector &selector, CandidateChoices &choices,
    const CandidateLimits &limits, uint64_t now = 20000, uint64_t window = 0, uint64_t epoch = 1,
    const CandidateBodyProbe &custom = {}) {
    CandidatePollUsage used; DiskStateError error;
    const auto before = f.store.LastStats().database_reads;
    const auto result = selector.Poll(f.Id(f.active), now, window, epoch, limits,
                                     custom ? custom : f.Probe(), f.store, choices, used, error);
    Check(used.query.reads == f.store.LastStats().database_reads - before, "all actual Gets reported");
    Check(used.query.reads <= limits.query.max_reads && used.query.rows <= limits.query.max_rows &&
          used.query.iterator_steps <= limits.query.max_iterator_steps &&
          used.query.decoded_bytes <= limits.query.max_decoded_bytes && used.probe_calls <= limits.max_probe_calls,
          "all per-poll caps respected");
    Check(result != CandidateResult::StorageError, "unexpected storage error: " + error.message);
    return result;
}
CandidateResult Finish(Fixture &f, CandidateSelector &selector, CandidateChoices &choices,
    const CandidateLimits &limits, uint64_t now = 20000, uint64_t window = 0, uint64_t epoch = 1) {
    for (unsigned n = 0; n < 1000; ++n) {
        const auto result = Poll(f, selector, choices, limits, now, window, epoch);
        if (result != CandidateResult::Progress) return result;
    }
    throw std::runtime_error("finite stable workload made no bounded progress");
}
void Ranking(const std::string &base) {
    Fixture f(base + "/ranking"); f.Commit(f.Child(f.genesis)); f.Commit(f.Child(f.active));
    Header long_tip = f.genesis;
    for (unsigned n = 0; n < 5; ++n) { long_tip = f.Child(long_tip); f.Add(long_tip); }
    const Header short_tip = f.Child(f.genesis, 0x200fffff); f.Add(short_tip);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready &&
          choices.best_ready && choices.best_ready->target == f.Id(short_tip) &&
          short_tip.height < long_tip.height, "greatest work beats height and prior announcements");
    CandidatePollUsage used; DiskStateError error;
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::Ready, "exact choice revalidation");
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 20000, 0, 2, Limits(), f.store, used, error) ==
          CandidateResult::Stale, "body epoch fence");
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 19999, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::Stale, "clock rollback fence");
    auto altered = *choices.best_ready; altered.fork.connect.clear();
    Check(ValidateCandidateChoice(choices, altered, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::Stale, "public fork output is rechecked");
    const auto newer = f.Child(short_tip); f.Add(newer);
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::Stale, "inventory revision fence");
}
void Ties(const std::string &base) {
    Fixture f(base + "/ties"); f.Commit(f.Child(f.genesis));
    const auto equal = f.Child(f.genesis); f.Add(equal);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::RetainActive && !choices.best_ready,
          "exact active-work tie retains active");
    auto left = f.Child(equal), right = f.Child(equal); f.Add(left); f.Add(right);
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready && choices.best_ready &&
          choices.best_ready->target == std::max(f.Id(left), f.Id(right)), "equal nonactive work deterministic ID order");
}
void Bodies(const std::string &base) {
    Fixture f(base + "/bodies"); f.Commit(f.Child(f.genesis));
    auto ready = f.Child(f.genesis); f.Add(ready); ready = f.Child(ready); f.Add(ready);
    auto highest = f.Child(f.genesis, 0x200fffff); f.Add(highest, false);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready &&
          choices.best_fetch && choices.best_fetch->target == f.Id(highest) &&
          choices.best_fetch->missing.size() == 1 && choices.best_fetch->missing[0].id == f.Id(highest) &&
          choices.best_ready && choices.best_ready->target == f.Id(ready), "higher missing branch does not starve ready branch");
    Check(!choices.higher_operationally_blocked, "replacement missing is download-only");
    f.bodies.insert(f.Id(highest));
    Check(Finish(f, selector, choices, Limits(), 20000, 0, 2) == CandidateResult::Ready &&
          choices.best_ready->target == f.Id(highest), "body arrival reranks greatest work");
    f.bodies.erase(f.Id(f.active));
    Check(Finish(f, selector, choices, Limits(), 20000, 0, 3) == CandidateResult::CapacityRefused,
          "missing source restoration is operational, not replacement fetch or invalidity");
    CandidateView view; DiskStateError error;
    Check(f.store.ReadCandidateView(view, error) && view.invalid_root_count == 0, "availability never persists invalidity");
}
void Clock(const std::string &base) {
    Fixture f(base + "/clock"); f.Commit(f.Child(f.genesis, 0x207fffff, 5000));
    auto lower = f.Child(f.genesis); f.Add(lower); lower = f.Child(lower); f.Add(lower);
    const auto future = f.Child(f.genesis, 0x200fffff, 10000); f.Add(future);
    const auto early_child = f.Child(future, 0x207fffff, 1500); f.Add(early_child);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits(), 2000) == CandidateResult::Ready &&
          choices.best_ready->target == f.Id(lower) && choices.next_eligibility_time == 10000 &&
          choices.active_temporarily_ineligible, "all ancestors gate future descendant; stable active retained diagnostically");
    CandidatePollUsage usage; DiskStateError error;
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 9999, 0, 1, Limits(), f.store, usage, error) ==
          CandidateResult::Ready, "ordinary clock advance below future threshold does not invalidate");
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 10000, 0, 1, Limits(), f.store, usage, error) ==
          CandidateResult::Stale, "higher branch eligibility crossing requires rerank");
    Check(Finish(f, selector, choices, Limits(), 10000) == CandidateResult::Ready &&
          choices.best_ready->target == f.Id(early_child), "future branch eventually reconsidered");
    Check(Finish(f, selector, choices, Limits(), 0, std::numeric_limits<uint64_t>::max()) == CandidateResult::Ready,
          "overflow-safe future window");
}
void DeferredAndMissingPrefix(const std::string &base) {
    Fixture f(base + "/deferred"); f.Commit(f.Child(f.genesis));
    const auto future = f.Child(f.genesis, 0x200fffff, 10000); f.Add(future);
    const auto child = f.Child(future, 0x207fffff, 1500); f.Add(child);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits(), 9000) == CandidateResult::Deferred &&
          !choices.best_ready && choices.next_eligibility_time == 10000, "only future competitors produce explicit deferral");
    Check(Finish(f, selector, choices, Limits(), 10000) == CandidateResult::Ready &&
          choices.best_ready->target == f.Id(child), "deferred branch wakes at exact ancestor threshold");
    Check(Poll(f, selector, choices, Limits(), 9000) == CandidateResult::Deferred,
          "clock rollback reconsiders ancestry without invalidity");
    Fixture m(base + "/prefix"); m.Commit(m.Child(m.genesis));
    Header tip = m.genesis; std::vector<Header> branch;
    for (unsigned n = 0; n < 5; ++n) { tip = m.Child(tip); m.Add(tip, false); branch.push_back(tip); }
    auto limits = Limits(); limits.max_missing_bodies = 1;
    Check(Finish(m, selector, choices, limits) == CandidateResult::NeedBodies &&
          choices.best_fetch && choices.best_fetch->target == m.Id(tip) &&
          choices.best_fetch->missing.size() == 1 && choices.best_fetch->missing[0].id == m.Id(branch[0]),
          "bounded missing-body prefix requests parent-first data without whole inventory allocation");
    m.bodies.insert(m.Id(branch[0]));
    Check(Finish(m, selector, choices, limits, 20000, 0, 2) == CandidateResult::NeedBodies &&
          choices.best_fetch->missing[0].id == m.Id(branch[1]), "body epoch exposes next bounded missing prefix");
}
void BoundedProgress(const std::string &base) {
    Fixture f(base + "/progress"); f.Commit(f.Child(f.genesis));
    Header target = f.genesis;
    for (unsigned n = 0; n < 8; ++n) { target = f.Child(target); f.Add(target); }
    auto limits = Limits(); limits.query.max_rows = 1; limits.max_probe_calls = 1;
    CandidateSelector selector; CandidateChoices choices;
    Check(Poll(f, selector, choices, limits) == CandidateResult::Progress, "one bounded call cannot scan/probe branch");
    const size_t already = f.probes.size();
    const auto stronger = f.Child(f.genesis, 0x200fffff); f.Add(stronger);
    Check(Poll(f, selector, choices, limits) == CandidateResult::Progress && f.probes.size() > already,
          "insertion does not restart pending branch probe");
    Check(Finish(f, selector, choices, limits) == CandidateResult::Ready && choices.best_ready->target == f.Id(stronger),
          "completed pass verifies insertion revision and finite stable workload terminates");
    Check(Poll(f, selector, choices, limits) == CandidateResult::Progress, "new bounded scan");
    f.Commit(f.Child(f.active));
    Check(Poll(f, selector, choices, limits) == CandidateResult::Stale, "stable source change invalidates pending scan");
    Check(Finish(f, selector, choices, limits, 20000, 0, 2) == CandidateResult::Ready, "restart after stable tip fence");
}
void RecoveryFences(const std::string &base) {
    Fixture f(base + "/fences"); f.Commit(f.Child(f.genesis));
    const auto target = f.Child(f.genesis, 0x200fffff); f.Add(target);
    CandidateSelector selector; CandidateChoices choices;
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready, "choice before recovery");
    DiskRecoveryUpdate update; update.expected_tip = f.Id(f.active); update.expected_root = f.store.Root();
    update.next_tip = update.expected_tip; update.next_journal = std::vector<uint8_t>{1, 2, 3};
    DiskStateError error;
    Check(f.store.WriteRecoveryJournal(update, error), "journal fence: " + error.message);
    Check(Poll(f, selector, choices, Limits()) == CandidateResult::RecoveryRequired, "pending journal fences selection");
    CandidatePollUsage used;
    Check(ValidateCandidateChoice(choices, *choices.best_ready, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::RecoveryRequired, "pending journal fences dispatch");
    f.store = {};
    Check(DiskStateStore::Open(f.path, f.options, {}, f.store, error), "journal reopen");
    Check(Poll(f, selector, choices, Limits()) == CandidateResult::RecoveryRequired, "restart preserves recovery fence");
    update.expected_journal = update.next_journal; update.next_journal.reset();
    CandidateTerminalClaim claim; claim.attempt = Tag(999); claim.source = f.Id(f.active); claim.target = f.Id(target);
    claim.outcome = CandidateTerminalOutcome::RestoredSourceUnknown; claim.revision = 1;
    Check(f.store.FinishCandidateRecovery(update, claim, error), "durable unknown receipt: " + error.message);
    Check(Poll(f, selector, choices, Limits()) == CandidateResult::AcknowledgeRequired, "terminal receipt fences selection");
    std::optional<CandidateTerminalReceipt> receipt;
    Check(f.store.ReadCandidateReceipt(receipt, error) && receipt && !receipt->failure, "unknown receipt carries no invalid proof");
    Check(f.store.AcknowledgeCandidateReceipt(receipt->id, f.Id(f.active), error), "unknown receipt acknowledgement");
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready, "acknowledgement permits selection");
    CandidateView view;
    Check(f.store.ReadCandidateView(view, error) && view.invalid_root_count == 0, "unknown recovery outcome never creates invalid fact");
}
std::string Raw(const std::string &path, const std::string &key, const std::optional<std::string> &put = {}) {
    std::string error;
    if (put) {
        Check(RawDiskStateAccess(path, std::nullopt, nullptr, {{key, *put}}, &error),
              "raw mechanical fixture write: " + error);
        return {};
    }
    std::optional<std::string> value;
    Check(RawDiskStateAccess(path, key, &value, {}, &error) && value.has_value(),
          "raw mechanical fixture read: " + error);
    return *value;
}
Hash Digest(const char *domain, const std::string &bytes) {
    blake3_hasher hasher; blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, domain, std::char_traits<char>::length(domain) + 1);
    blake3_hasher_update(&hasher, bytes.data(), bytes.size()); Hash hash;
    blake3_hasher_finalize(&hasher, hash.data(), hash.size()); return hash;
}
// Explicit trusted-format storage mechanics fixture, adapted from the storage
// owner's InjectReceipt. Closed database injection is not VM failure evidence.
// Production R creation remains opaque typed-validator/trusted-journal owned.
Hash InjectMechanicalReceipt(Fixture &f, const Header &target, const Header &bad, const Hash &root) {
    const auto head = Raw(f.path, "S"); std::string bytes(1, 1);
    auto hash = [&](const Hash &h) { bytes.append(reinterpret_cast<const char *>(h.data()), h.size()); };
    hash(f.options.identity); hash(f.options.profile_digest); hash(Tag(444)); hash(f.Id(f.active));
    hash(f.Id(target)); hash(f.Id(f.active)); hash(root); hash(Digest("Lotus/v2/storage/head", head));
    for (unsigned i = 0; i < 8; ++i) bytes.push_back(i ? 0 : 7);
    bytes.push_back(3); bytes.push_back(1);
    hash(f.Id(bad)); hash(bad.prev_id); hash(f.options.profile_digest); hash(root);
    Raw(f.path, "R", bytes); return Digest("Lotus/v2/storage/receipt", bytes);
}
void PropagationFence(const std::string &base) {
    Fixture f(base + "/propagation"); f.Commit(f.Child(f.genesis));
    const auto bad = f.Child(f.active, 0x200fffff); f.Add(bad);
    const auto descendant = f.Child(bad); f.Add(descendant);
    const auto healthy = f.Child(f.active, 0x201fffff); f.Add(healthy);
    CandidateSelector selector; CandidateChoices before;
    Check(Finish(f, selector, before, Limits()) == CandidateResult::Ready &&
          before.best_ready->target == f.Id(descendant), "mechanical ranked subtree before exclusion fixture");
    const auto root = f.store.Root(); f.store = {};
    const auto receipt = InjectMechanicalReceipt(f, descendant, bad, root); DiskStateError error;
    Check(DiskStateStore::Open(f.path, f.options, {}, f.store, error), "mechanical receipt reopen");
    Check(f.store.AcknowledgeCandidateReceipt(receipt, f.Id(f.active), error), "mechanical receipt acknowledgement");
    CandidateChoices choices;
    Check(Poll(f, selector, choices, Limits()) == CandidateResult::InvalidationRequired, "pending propagation fences selection");
    CandidatePollUsage used;
    Check(ValidateCandidateChoice(before, *before.best_ready, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::InvalidationRequired, "pending propagation fences dispatch");
    bool complete{};
    auto step_limits = Limits().query; step_limits.max_rows = 1;
    for (unsigned i = 0; i < 32 && !complete; ++i) {
        CandidateInvalidationProgress progress;
        Check(f.store.StepCandidateInvalidation(step_limits, progress, error), "bounded propagation fixture step");
        complete = progress.complete; f.store = {};
        Check(DiskStateStore::Open(f.path, f.options, {}, f.store, error), "propagation restart");
    }
    Check(complete, "finite mechanical propagation completes");
    Check(Finish(f, selector, choices, Limits()) == CandidateResult::Ready &&
          choices.best_ready->target == f.Id(healthy), "excluded subtree cannot hide healthy candidate");
    // Public output mutability must not bypass explicit persisted invalidity.
    CandidateChoices forged = choices; CandidateChoice excluded;
    excluded.target = f.Id(descendant); std::optional<IndexedHeader> indexed;
    Check(f.store.ReadIndexedHeader(excluded.target, indexed, error) && indexed, "excluded H remains retained");
    excluded.indexed = *indexed;
    Check(PlanHeaderFork(f.store, f.Id(f.active), excluded.target, Limits().fork, 20000, 0,
                        excluded.fork, error) == ChainIndexResult::Complete, "legacy fork planner alone does not classify invalidity");
    forged.best_ready = excluded;
    Check(ValidateCandidateChoice(forged, excluded, 20000, 0, 1, Limits(), f.store, used, error) ==
          CandidateResult::Stale, "forged retained excluded target is refused by causal-invalidity lookup");
    Check(used.query.reads <= Limits().query.max_reads, "invalidity recheck bounded");
}
void ResourceAndCallbacks(const std::string &base) {
    Fixture f(base + "/resources"); f.Commit(f.Child(f.genesis));
    auto target = f.Child(f.genesis, 0x200fffff); f.Add(target);
    CandidateSelector selector; CandidateChoices choices; auto limits = Limits();
    const auto reads = f.store.LastStats().database_reads;
    limits.max_resident_bytes = 1;
    Check(Poll(f, selector, choices, limits) == CandidateResult::InvalidConfiguration &&
          f.store.LastStats().database_reads == reads, "resident reservation refusal before reads/copies");
    limits = Limits(); limits.query.max_decoded_bytes = 1;
    CandidatePollUsage partial; DiskStateError partial_error;
    choices.body_epoch = 999;
    const auto before_partial = f.store.LastStats().database_reads;
    Check(selector.Poll(f.Id(f.active), 20000, 0, 1, limits, f.Probe(), f.store, choices, partial, partial_error) ==
          CandidateResult::CapacityRefused && choices.body_epoch == 999 && partial.query.iterator_steps > 0 &&
          partial.query.reads == f.store.LastStats().database_reads - before_partial &&
          partial.query.decoded_bytes <= limits.query.max_decoded_bytes,
          "failed page reports partial usage and preserves choices");
    limits = Limits();
    const uint64_t exact_resident = (limits.fork.max_connect + limits.fork.max_disconnect) * 6 * sizeof(Hash) +
        limits.max_missing_bodies * 2 * sizeof(CandidateBodyNeed) + sizeof(CandidateRow);
    limits.max_resident_bytes = exact_resident - 1;
    Check(Poll(f, selector, choices, limits) == CandidateResult::InvalidConfiguration, "one byte below resident authorization rejected");
    limits.max_resident_bytes = exact_resident;
    Check(Finish(f, selector, choices, limits) == CandidateResult::Ready, "exact resident authorization boundary accepted");
    limits = Limits();
    auto unsupported = [](const Hash &, const Header &, uint64_t, std::string &) { return CandidateBodyResult::Unsupported; };
    Check(Poll(f, selector, choices, limits, 20000, 0, 1, unsupported) == CandidateResult::Unsupported,
          "unsupported body backend remains operational");
    CandidateBodyProbe reentrant = [&](const Hash &id, const Header &, uint64_t, std::string &) {
        Check(!selector.Reset(), "callback reset refused");
        CandidatePollUsage use; DiskStateError error; CandidateChoices other;
        Check(selector.Poll(f.Id(f.active), 20000, 0, 1, limits, f.Probe(), f.store, other, use, error) ==
              CandidateResult::StorageError, "callback poll reentry refused");
        return f.bodies.contains(id) ? CandidateBodyResult::Available : CandidateBodyResult::Missing;
    };
    Check(Poll(f, selector, choices, limits, 20000, 0, 1, reentrant) == CandidateResult::Ready,
          "reentry cannot cancel active scan");
    CandidatePollUsage outer_use; DiskStateError outer_error;
    CandidateBodyProbe aliased_reentry = [&](const Hash &id, const Header &, uint64_t, std::string &) {
        const auto reads_before = outer_use.query.reads;
        const auto probes_before = outer_use.probe_calls;
        Check(selector.Poll(f.Id(f.active), 20000, 0, 1, limits, f.Probe(), f.store,
                            choices, outer_use, outer_error) == CandidateResult::StorageError &&
              outer_use.query.reads == reads_before && outer_use.probe_calls == probes_before,
              "aliased reentry preserves outer counters and outputs");
        return f.bodies.contains(id) ? CandidateBodyResult::Available : CandidateBodyResult::Missing;
    };
    const auto before_alias = f.store.LastStats().database_reads;
    Check(selector.Poll(f.Id(f.active), 20000, 0, 1, limits, aliased_reentry, f.store,
                        choices, outer_use, outer_error) == CandidateResult::Ready &&
          outer_use.query.reads == f.store.LastStats().database_reads - before_alias && outer_use.probe_calls > 0,
          "outer accounting remains exact after aliased reentry attempts");
}
} // namespace
int main() {
    try {
        const auto base = (std::filesystem::temp_directory_path() / ("lotus-v2-selector-" + std::to_string(std::rand()))).string();
        Ranking(base); Ties(base); Bodies(base); Clock(base); DeferredAndMissingPrefix(base); BoundedProgress(base); RecoveryFences(base); PropagationFence(base); ResourceAndCallbacks(base);
        std::filesystem::remove_all(base);
        std::cout << "bounded candidate selection tests passed\n";
    } catch (const std::exception &e) { std::cerr << "candidate selection: " << e.what() << '\n'; return 1; }
}
