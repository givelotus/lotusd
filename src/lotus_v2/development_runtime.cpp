// Copyright (c) 2026 The Lotus developers
#include "development_runtime.h"
#include <algorithm>
#include <limits>
#include <map>
#include <stdexcept>
#include <type_traits>

namespace lotus::v2 {
namespace {
    using Result = DevelopmentRuntimeResult;
    void CountBytes(uint64_t &total, uint64_t bytes) {
        total = bytes > UINT64_MAX - total ? UINT64_MAX : total + bytes;
    }
    struct BusyGuard {
        bool &busy;
        explicit BusyGuard(bool &value) : busy(value) { busy = true; }
        ~BusyGuard() { busy = false; }
    };
    Result BodyResult(CandidateBodyStatus s) {
        switch (s) {
            case CandidateBodyStatus::RetainedAuthenticated:
            case CandidateBodyStatus::Duplicate:
            case CandidateBodyStatus::Available:
            case CandidateBodyStatus::Evicted:
                return Result::Progress;
            case CandidateBodyStatus::Missing:
                return Result::MissingBody;
            case CandidateBodyStatus::Malformed:
                return Result::MalformedBody;
            case CandidateBodyStatus::CapacityRefused:
            case CandidateBodyStatus::Pinned:
            case CandidateBodyStatus::EpochExhausted:
                return Result::CapacityRefused;
            default:
                return Result::StorageError;
        }
    }
    Result RecoveryResult(ReorgResult r) {
        switch (r) {
            case ReorgResult::Prepared:
                return Result::Prepared;
            case ReorgResult::Progress:
                return Result::Recovering;
            case ReorgResult::CompleteTarget:
                return Result::CompleteTarget;
            case ReorgResult::RestoredSource:
                return Result::RestoredSource;
            case ReorgResult::MissingBody:
                return Result::MissingBody;
            case ReorgResult::InvalidBody:
                return Result::MalformedBody;
            case ReorgResult::Deferred:
                return Result::Deferred;
            case ReorgResult::NotHeavier:
                return Result::RetainActive;
            case ReorgResult::CapacityRefused:
                return Result::CapacityRefused;
            case ReorgResult::StorageError:
                return Result::ReopenRequired;
            case ReorgResult::Inconclusive:
                return Result::Inconclusive;
            case ReorgResult::ExcludedTarget:
                return Result::ExcludedTarget;
            default:
                return Result::Progress;
        }
    }
} // namespace
bool SameDevelopmentBodyAuthority(const DevelopmentRuntimeSnapshot &a,
                                  const DevelopmentRuntimeSnapshot &b) {
    const auto ready = [](const DevelopmentRuntimeSnapshot &s) {
        return s.chain && !s.reopen_required && !s.execution_paused &&
               !s.chain->pending_journal && !s.chain->pending_receipt &&
               !s.chain->pending_propagation;
    };
    if (!ready(a) || !ready(b)) return false;
    return a.body_epoch == b.body_epoch &&
           a.context_generation == b.context_generation &&
           a.chain->identity == b.chain->identity &&
           a.chain->profile_digest == b.chain->profile_digest &&
           a.chain->stable_tip == b.chain->stable_tip &&
           a.chain->root == b.chain->root &&
           a.chain->revision == b.chain->revision &&
           a.chain->invalid_epoch == b.chain->invalid_epoch;
}
struct DevelopmentRuntime::Impl {
    DevelopmentRuntimeConfig config;
    DiskStateStore store;
    std::unique_ptr<CandidateBodyPool> pool;
    CandidateSelector selector;
    std::optional<CandidateChoices> choice;
    std::optional<CandidateView> view;
    uint64_t epoch{}, generation{};
    bool busy{}, reopen{}, paused{};
    Hash expected_profile_digest{};
    struct BodyCache {
        Hash id{};
        DevelopmentRuntimeSnapshot snapshot;
        std::vector<uint8_t> bytes;
    };
    struct PolicyCache {
        Hash id{};
        DevelopmentRuntimeSnapshot snapshot;
        DiskBlockPolicy policy{};
    };
    struct ObservationCache {
        DevelopmentRuntimeSnapshot snapshot;
        std::map<Hash, RuntimeBlockObservation> entries;
    };
    std::optional<BodyCache> body_cache;
    std::optional<PolicyCache> policy_cache;
    std::optional<ObservationCache> observation_cache;

    explicit Impl(DevelopmentRuntimeConfig c)
        : config(std::move(c)), epoch(config.initial_body_epoch),
          generation(config.initial_context_generation) {
        pool = std::make_unique<CandidateBodyPool>(
            config.profiles.header.chain_id,
            config.profiles.ordinary.transaction, config.bodies,
            config.initial_body_epoch);
    }
    DevelopmentRuntimeSnapshot Snapshot() const {
        return {epoch, generation, reopen, paused, view};
    }
    void ClearCaches() {
        body_cache.reset();
        policy_cache.reset();
        observation_cache.reset();
    }
    void ValidateCaches() {
        const auto current = Snapshot();
        if (body_cache && !SameDevelopmentBodyAuthority(body_cache->snapshot, current))
            body_cache.reset();
        if (policy_cache && !SameDevelopmentBodyAuthority(policy_cache->snapshot, current))
            policy_cache.reset();
        if (observation_cache &&
            !SameDevelopmentBodyAuthority(observation_cache->snapshot, current))
            observation_cache.reset();
    }
    bool Room(std::string &error) const {
        if (epoch == UINT64_MAX || generation == UINT64_MAX) {
            error = "runtime inventory/context epoch exhausted";
            return false;
        }
        return true;
    }
    void InventoryChanged() {
        ClearCaches();
        ++epoch;
        ++generation;
        choice.reset();
        selector.Reset();
    }
    void HeaderInserted() {
        ClearCaches();
        // CandidateSelector completes its bounded pass under insertion churn.
        choice.reset();
    }
    void Fault() {
        ClearCaches();
        reopen = true;
        view.reset();
        choice.reset();
        selector.Reset();
    }
    bool OpenStore(std::string &error) {
        auto &p = config.profiles;
        if (!OpenDevelopmentChain(config.directory, config.genesis_wire,
                                  p.header, p.ordinary, p.monetary, p.cost,
                                  config.initial_money, config.storage, store,
                                  error)) return false;
        // Preserve OpenDevelopmentChain's preflight/error ordering for invalid
        // profiles; only retain a digest after the store accepts its binding.
        expected_profile_digest = BlockValidationProfileDigest(
            p.header, p.ordinary, p.monetary, p.cost);
        return true;
    }
    bool Observe(std::string &error, DevelopmentTickUsage *usage = nullptr) {
        CandidateView next;
        DiskStateError e;
        if (usage) ++usage->view_calls;
        if (!store.ReadCandidateView(next, e)) {
            error = e.message;
            Fault();
            return false;
        }
        view = std::move(next);
        ValidateCaches();
        return true;
    }
    Result Access(std::string &error) const {
        if (busy) {
            error = "runtime operation already active";
            return Result::Busy;
        }
        if (reopen) {
            error = "runtime requires authoritative reopen";
            return Result::ReopenRequired;
        }
        if (!store.IsOpen()) {
            error = "runtime closed";
            return Result::Closed;
        }
        return Result::Progress;
    }
    RetainedBodyStatus DiskBody(const Hash &id, uint64_t cap,
                                std::vector<uint8_t> &out,
                                std::string &error) const {
        const auto &p = config.profiles;
        return ReadRetainedBlockBody(id, cap, p.header, p.ordinary, p.monetary,
                                     p.cost, store, out, error);
    }
    Result Body(const Hash &id, uint64_t cap, std::vector<uint8_t> &out,
                std::string &error, bool disk_only = false,
                DevelopmentTickUsage *usage = nullptr,
                DevelopmentBodyChunkUsage *chunk_usage = nullptr) {
        std::optional<IndexedHeader> h;
        DiskStateError e;
        if (!store.ReadIndexedHeader(id, h, e)) {
            error = e.message;
            Fault();
            return Result::ReopenRequired;
        }
        if (!h) return Result::MissingHeader;
        if (!disk_only) {
            CandidateBodyPin pin;
            const auto status = pool->Pin(id, h->header, cap, pin);
            if (status == CandidateBodyStatus::Available) {
                const auto copied = pin.CopyTo(cap, out);
                if (copied == CandidateBodyStatus::Available && usage)
                    CountBytes(usage->copied_body_bytes, out.size());
                return BodyResult(copied);
            }
            if (status != CandidateBodyStatus::Missing)
                return BodyResult(status);
        } else if (h->stage != HeaderStage::Connected) {
            return Result::MissingBody;
        }
        if (usage) ++usage->disk_probe_calls;
        if (chunk_usage) ++chunk_usage->body_load_attempts;
        switch (DiskBody(id, cap, out, error)) {
            case RetainedBodyStatus::Available:
                if (usage) CountBytes(usage->copied_body_bytes, out.size());
                return Result::Progress;
            case RetainedBodyStatus::Missing:
                return Result::MissingBody;
            case RetainedBodyStatus::CapacityRefused:
                return Result::CapacityRefused;
            default:
                Fault();
                return Result::ReopenRequired;
        }
    }
};
DevelopmentRuntime::DevelopmentRuntime(std::unique_ptr<Impl> p)
    : impl_(std::move(p)) {}
DevelopmentRuntime::~DevelopmentRuntime() = default;
DevelopmentRuntime::DevelopmentRuntime(DevelopmentRuntime &&) noexcept =
    default;
DevelopmentRuntime &
DevelopmentRuntime::operator=(DevelopmentRuntime &&) noexcept = default;
bool DevelopmentRuntime::Open(DevelopmentRuntimeConfig config,
                              std::unique_ptr<DevelopmentRuntime> &out,
                              std::string &error) {
    if (out || !config.storage.candidates || !config.storage.recovery ||
        config.initial_body_epoch == UINT64_MAX ||
        config.initial_context_generation == UINT64_MAX) {
        error = "runtime requires empty output, explicit V4 options and "
                "unexhausted epochs";
        return false;
    }
    try {
        auto p = std::make_unique<Impl>(std::move(config));
        if (!p->OpenStore(error) || !p->store.CandidatesEnabled() ||
            !p->Observe(error))
            return false;
        out = std::unique_ptr<DevelopmentRuntime>(
            new DevelopmentRuntime(std::move(p)));
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
DevelopmentRuntimeSnapshot DevelopmentRuntime::Snapshot() const {
    return impl_ ? impl_->Snapshot() : DevelopmentRuntimeSnapshot{};
}
bool DevelopmentRuntime::RetryPausedExecution() noexcept {
    if (!impl_ || impl_->busy || impl_->reopen || !impl_->paused) return false;
    impl_->ClearCaches();
    impl_->paused = false;
    return true;
}
DevelopmentTick DevelopmentRuntime::Tick(uint64_t now, uint64_t window,
                                         const DevelopmentTickLimits &limits) {
    DevelopmentTick tick;
    if (!impl_) {
        tick.result = Result::Closed;
        return tick;
    }
    auto &p = *impl_;
    auto finish = [&](Result result) {
        tick.result = result;
        tick.snapshot = p.Snapshot();
        return std::move(tick);
    };
    if (p.busy) return finish(Result::Busy);
    BusyGuard guard(p.busy);
    try {
        if (p.reopen) {
            p.ClearCaches();
            if (!p.Room(tick.diagnostic))
                return finish(Result::CapacityRefused);
            p.selector.Reset();
            p.choice.reset();
            p.store = DiskStateStore{};
            if (!p.OpenStore(tick.diagnostic) ||
                !p.Observe(tick.diagnostic, &tick.usage)) {
                p.Fault();
                return finish(Result::ReopenRequired);
            }
            p.reopen = false;
            p.InventoryChanged();
            tick.context_changed = true;
            tick.usage.reopened = true;
            return finish(Result::Reopened);
        }
        if (!p.Observe(tick.diagnostic, &tick.usage))
            return finish(Result::ReopenRequired);
        if (p.view->pending_journal) {
            if (p.paused) return finish(Result::Inconclusive);
            if (!p.Room(tick.diagnostic))
                return finish(Result::CapacityRefused);
            ReorgProgress progress;
            ++tick.usage.recovery_calls;
            const auto r = StepDevelopmentSwitch(now, window, limits.recovery,
                                                 p.config.profiles, p.store,
                                                 progress, tick.diagnostic);
            if (r == ReorgResult::StorageError) {
                p.Fault();
                return finish(Result::ReopenRequired);
            }
            if (r == ReorgResult::Inconclusive) {
                p.ClearCaches();
                p.paused = true;
                return finish(Result::Inconclusive);
            }
            if (r == ReorgResult::Progress ||
                r == ReorgResult::CompleteTarget ||
                r == ReorgResult::RestoredSource) {
                tick.recovery = progress;
                p.InventoryChanged();
                tick.context_changed = true;
                if (!p.Observe(tick.diagnostic, &tick.usage))
                    return finish(Result::ReopenRequired);
            }
            return finish(RecoveryResult(r));
        }
        if (p.view->pending_receipt) {
            if (!p.Room(tick.diagnostic))
                return finish(Result::CapacityRefused);
            std::optional<CandidateTerminalReceipt> receipt;
            DiskStateError e;
            if (!p.store.ReadCandidateReceipt(receipt, e) || !receipt ||
                !p.store.AcknowledgeCandidateReceipt(receipt->id,
                                                     p.view->stable_tip, e)) {
                tick.diagnostic = e.message;
                p.Fault();
                return finish(Result::ReopenRequired);
            }
            p.InventoryChanged();
            tick.context_changed = true;
            if (!p.Observe(tick.diagnostic, &tick.usage))
                return finish(Result::ReopenRequired);
            return finish(Result::Acknowledged);
        }
        if (p.view->pending_propagation) {
            if (!p.Room(tick.diagnostic))
                return finish(Result::CapacityRefused);
            CandidateInvalidationProgress progress;
            DiskStateError e;
            if (!p.store.StepCandidateInvalidation(
                    limits.propagation, progress, e, &tick.usage.propagation)) {
                tick.diagnostic = e.message;
                if (e.code == DiskStateErrorCode::Resource)
                    return finish(Result::CapacityRefused);
                p.Fault();
                return finish(Result::ReopenRequired);
            }
            p.InventoryChanged();
            tick.context_changed = true;
            if (!p.Observe(tick.diagnostic, &tick.usage))
                return finish(Result::ReopenRequired);
            return finish(Result::Invalidated);
        }
        DiskStateError e;
        if (p.store.AvalancheEnabled()) {
            DiskBlockPolicy policy;
            const auto snapshot = p.Snapshot();
            if (p.policy_cache && p.policy_cache->id == p.view->stable_tip &&
                SameDevelopmentBodyAuthority(p.policy_cache->snapshot, snapshot)) {
                policy = p.policy_cache->policy;
            } else {
                p.policy_cache.reset();
                const auto cap = p.config.storage.max_avalanche_reads;
                if (!p.store.ReadBlockPolicy(p.view->stable_tip, cap, policy, e)) {
                    tick.diagnostic = e.message;
                    if (e.code == DiskStateErrorCode::Resource) return finish(Result::CapacityRefused);
                    p.Fault(); return finish(Result::ReopenRequired);
                }
                if (SameDevelopmentBodyAuthority(snapshot, snapshot))
                    p.policy_cache = Impl::PolicyCache{p.view->stable_tip, snapshot, policy};
            }
            if (policy.parked && policy.park_root) {
                std::optional<IndexedHeader> root;
                if (!p.store.ReadIndexedHeader(*policy.park_root, root, e) || !root) {
                    tick.diagnostic = e.message; p.Fault(); return finish(Result::ReopenRequired);
                }
                if (!root->header.height) return finish(Result::ExcludedTarget);
                if (!p.Room(tick.diagnostic)) return finish(Result::CapacityRefused);
                ReorgBodySource bodies = [&](const Hash &id, uint64_t bytes,
                                             std::vector<uint8_t> &out, std::string &error) {
                    const auto r = p.Body(id, bytes, out, error, false, &tick.usage);
                    if (r == Result::Progress) return ReorgBodyResult::Found;
                    if (r == Result::MissingBody) return ReorgBodyResult::Missing;
                    if (r == Result::CapacityRefused) return ReorgBodyResult::CapacityRefused;
                    return ReorgBodyResult::Error;
                };
                ReorgProgress progress;
                ++tick.usage.recovery_calls;
                const auto r = PrepareDevelopmentSwitch(p.view->stable_tip, root->header.prev_id,
                    now, window, limits.recovery, p.config.profiles, bodies, p.store,
                    progress, tick.diagnostic, true);
                if (r == ReorgResult::StorageError || p.reopen) {
                    p.Fault(); return finish(Result::ReopenRequired);
                }
                if (r == ReorgResult::Prepared) {
                    tick.recovery = progress; p.InventoryChanged(); tick.context_changed = true;
                    if (!p.Observe(tick.diagnostic, &tick.usage)) return finish(Result::ReopenRequired);
                }
                return finish(RecoveryResult(r));
            }
        }
        if (p.choice && p.choice->best_ready) {
            const auto valid = ValidateCandidateChoice(
                *p.choice, *p.choice->best_ready, now, window, p.epoch,
                limits.selection, p.store, tick.usage.selection, e);
            if (valid != CandidateResult::Ready) {
                p.choice.reset();
                p.selector.Reset();
                tick.diagnostic = e.message;
                if (valid == CandidateResult::StorageError) {
                    p.Fault();
                    return finish(Result::ReopenRequired);
                }
                return finish(valid == CandidateResult::CapacityRefused
                                  ? Result::CapacityRefused
                                  : Result::Progress);
            }
            if (!p.Room(tick.diagnostic))
                return finish(Result::CapacityRefused);
            const auto target = p.choice->best_ready->target;
            const auto source = p.view->stable_tip;
            ReorgBodySource bodies = [&](const Hash &id, uint64_t cap,
                                         std::vector<uint8_t> &out,
                                         std::string &error) {
                const auto r = p.Body(id, cap, out, error, false, &tick.usage);
                if (r == Result::Progress) return ReorgBodyResult::Found;
                if (r == Result::MissingBody || r == Result::MissingHeader)
                    return ReorgBodyResult::Missing;
                if (r == Result::CapacityRefused)
                    return ReorgBodyResult::CapacityRefused;
                return ReorgBodyResult::Error;
            };
            ReorgProgress progress;
            ++tick.usage.recovery_calls;
            const auto r = PrepareDevelopmentSwitch(
                source, target, now, window, limits.recovery, p.config.profiles,
                bodies, p.store, progress, tick.diagnostic);
            p.choice.reset();
            p.selector.Reset();
            if (r == ReorgResult::StorageError || p.reopen) {
                p.Fault();
                return finish(Result::ReopenRequired);
            }
            if (r == ReorgResult::Prepared) {
                tick.recovery = progress;
                p.InventoryChanged();
                tick.context_changed = true;
                if (!p.Observe(tick.diagnostic, &tick.usage))
                    return finish(Result::ReopenRequired);
            }
            return finish(RecoveryResult(r));
        }
        CandidateBodyProbe probe = [&](const Hash &id, const Header &header,
                                       uint64_t cap, std::string &error) {
            ++tick.usage.body_probe_calls;
            const auto status = p.pool->Probe(id, header, cap);
            if (status == CandidateBodyStatus::Available)
                return CandidateBodyResult::Available;
            if (status == CandidateBodyStatus::CapacityRefused)
                return CandidateBodyResult::CapacityRefused;
            if (status != CandidateBodyStatus::Missing)
                return CandidateBodyResult::StorageError;
            ++tick.usage.disk_probe_calls;
            std::vector<uint8_t> wire;
            const auto disk = p.DiskBody(id, cap, wire, error);
            if (disk == RetainedBodyStatus::Available) {
                CountBytes(tick.usage.copied_body_bytes, wire.size());
                return CandidateBodyResult::Available;
            }
            if (error.size() > cap) error.resize(static_cast<size_t>(cap));
            if (disk == RetainedBodyStatus::Missing)
                return CandidateBodyResult::Missing;
            if (disk == RetainedBodyStatus::CapacityRefused)
                return CandidateBodyResult::CapacityRefused;
            return CandidateBodyResult::StorageError;
        };
        CandidateChoices choices;
        const auto selected = p.selector.Poll(
            p.view->stable_tip, now, window, p.epoch, limits.selection, probe,
            p.store, choices, tick.usage.selection, e);
        tick.diagnostic = e.message;
        switch (selected) {
            case CandidateResult::Ready:
                p.choice = choices;
                tick.choices = std::move(choices);
                return finish(Result::Progress);
            case CandidateResult::NeedBodies:
                tick.choices = std::move(choices);
                return finish(Result::NeedBodies);
            case CandidateResult::Deferred:
                tick.choices = std::move(choices);
                return finish(Result::Deferred);
            case CandidateResult::RetainActive:
                tick.choices = std::move(choices);
                return finish(Result::RetainActive);
            case CandidateResult::CapacityRefused:
                return finish(Result::CapacityRefused);
            case CandidateResult::InvalidConfiguration:
                return finish(Result::InvalidConfiguration);
            case CandidateResult::StorageError:
                p.Fault();
                return finish(Result::ReopenRequired);
            default:
                return finish(Result::Progress);
        }
    } catch (const std::exception &e) {
        tick.diagnostic = e.what();
        p.Fault();
        return finish(Result::ReopenRequired);
    }
}
bool DevelopmentRuntime::ObserveAvalancheBlock(const Hash &id, RuntimeBlockObservation &out,
                                                std::string &error) {
    if (!impl_) { error = "runtime closed"; return false; }
    auto &p = *impl_;
    if (p.Access(error) != Result::Progress) return false;
    BusyGuard guard(p.busy);
    if (!p.store.AvalancheEnabled()) { error = "Avalanche disabled"; return false; }
    const auto snapshot = p.Snapshot();
    const bool authoritative = SameDevelopmentBodyAuthority(snapshot, snapshot);
    if (authoritative && p.observation_cache &&
        SameDevelopmentBodyAuthority(p.observation_cache->snapshot, snapshot)) {
        if (const auto found = p.observation_cache->entries.find(id);
            found != p.observation_cache->entries.end()) {
            out = found->second; error.clear(); return true;
        }
    }
    auto publish = [&](const RuntimeBlockObservation &observed) {
        if (authoritative) {
            if (!p.observation_cache ||
                !SameDevelopmentBodyAuthority(p.observation_cache->snapshot, snapshot)) {
                p.observation_cache = Impl::ObservationCache{snapshot, {}};
            } else if (p.observation_cache->entries.size() >= 64) {
                p.observation_cache->entries.clear();
            }
            p.observation_cache->entries[id] = observed;
        }
        out = observed; error.clear(); return true;
    };
    DiskStateError e; DiskBlockPolicy policy;
    if (authoritative && p.policy_cache && p.policy_cache->id == id &&
        SameDevelopmentBodyAuthority(p.policy_cache->snapshot, snapshot)) {
        policy = p.policy_cache->policy;
    } else {
        if (!p.store.ReadBlockPolicy(id, p.config.storage.max_avalanche_reads, policy, e)) {
            error = e.message; if (e.code != DiskStateErrorCode::Resource) p.Fault(); return false;
        }
        if (authoritative && p.view && p.view->stable_tip == id)
            p.policy_cache = Impl::PolicyCache{id, snapshot, policy};
    }
    RuntimeBlockObservation observed; observed.known = policy.known;
    if (!observed.known) return publish(observed);
    std::optional<IndexedHeader> h; std::optional<Hash> invalid, active;
    if (!p.store.ReadIndexedHeader(id, h, e) || !h ||
        !p.store.ReadCandidateInvalidity(id, invalid, e) ||
        !p.store.ReadActiveId(h->header.height, active, e)) {
        error = e.message; p.Fault(); return false;
    }
    observed.valid = !invalid; observed.active = active && *active == id;
    observed.parked = policy.parked; observed.finalized = policy.finalized;
    observed.conflicting_finalized = policy.conflicting_finalized;
    observed.forks_active = false;
    if (!observed.active) {
        std::optional<ActiveChainIndex> index;
        if (!p.store.ReadActiveIndex(index, e) || !index) { error = e.message; p.Fault(); return false; }
        Hash cursor = id; IndexedHeader ancestor = *h;
        uint64_t remaining = p.config.storage.max_avalanche_reads;
        while (ancestor.header.height > index->height) {
            if (remaining < 3) { error = "Avalanche fork observation capacity"; return false; }
            cursor = ancestor.header.prev_id;
            std::optional<IndexedHeader> next;
            const auto before = p.store.LastStats().database_reads;
            if (!p.store.ReadIndexedHeader(cursor, next, e) || !next) { error = e.message; p.Fault(); return false; }
            remaining -= p.store.LastStats().database_reads - before; ancestor = *next;
        }
        std::optional<Hash> mapped;
        if (!p.store.ReadActiveId(ancestor.header.height, mapped, e) || !mapped) { error = e.message; p.Fault(); return false; }
        observed.forks_active = *mapped != cursor;
    }
    observed.has_data = h->stage == HeaderStage::Connected ||
        p.pool->Probe(id, h->header, p.config.bodies.max_body_bytes) == CandidateBodyStatus::Available;
    return publish(observed);
}
bool DevelopmentRuntime::ApplyAvalancheUpdates(const std::vector<RuntimeBlockUpdate> &updates,
                                               std::string &error) {
    if (!impl_) { error = "runtime closed"; return false; }
    auto &p = *impl_;
    if (p.Access(error) != Result::Progress) return false;
    BusyGuard guard(p.busy);
    if (!p.store.AvalancheEnabled()) { error = "Avalanche disabled"; return false; }
    if (!p.Room(error) || !p.Observe(error)) return false;
    const auto tip = p.view->stable_tip; const auto generation = p.generation;
    if (p.view->pending_journal || p.view->pending_receipt || p.view->pending_propagation) {
        error = "Avalanche recovery fence pending"; return false;
    }
    if (updates.size() > p.config.storage.max_pending_bytes / sizeof(RuntimeBlockUpdate)) {
        error = "Avalanche update capacity"; return false;
    }
    for (const auto &u : updates) {
        if (u.expected_tip != tip || u.expected_generation != generation) {
            error = "stale Avalanche batch tip/generation"; return false;
        }
    }
    if (updates.empty()) { error.clear(); return true; }
    try {
        DiskStateError e; std::map<Hash, bool> staged;
        // Headers are immutable during this serialized, single-owner batch.
        // Cache only successful checked reads, preserving every ordered staging
        // walk while charging actual database reads once per distinct header.
        std::map<Hash, IndexedHeader> headers;
        // Every staged key has a cached header. Reserve its existing 34-byte
        // policy payload with the cache key/value, sharing max_pending_bytes.
        // Map nodes/allocator overhead are outside this logical payload bound.
        constexpr uint64_t header_payload = sizeof(Hash) + sizeof(IndexedHeader) + 34;
        const uint64_t header_capacity = p.config.storage.max_pending_bytes / header_payload;
        std::optional<Hash> finalized;
        uint64_t remaining = p.config.storage.max_avalanche_reads;
        auto header = [&](const Hash &id, IndexedHeader &out) {
            if (const auto found = headers.find(id); found != headers.end()) {
                out = found->second; return true;
            }
            if (headers.size() >= header_capacity) { error = "Avalanche header cache capacity"; return false; }
            if (remaining < 3) { error = "Avalanche ancestry read capacity"; return false; }
            const auto before = p.store.LastStats().database_reads;
            std::optional<IndexedHeader> h;
            const auto ok = p.store.ReadIndexedHeader(id, h, e);
            remaining -= p.store.LastStats().database_reads - before;
            if (!ok) { error = e.message; p.Fault(); return false; }
            if (!h) { error = "unknown Avalanche block"; return false; }
            headers.emplace(id, *h);
            out = *h; return true;
        };
        for (const auto &u : updates) {
            IndexedHeader h;
            if (!header(u.block, h)) return false;
            if (u.status == RuntimeBlockStatus::Stale) continue;
            if (u.status == RuntimeBlockStatus::Rejected || u.status == RuntimeBlockStatus::Invalid) {
                if (!h.header.height) { error = "cannot park genesis"; return false; }
                staged[u.block] = true; continue;
            }
            if (u.status != RuntimeBlockStatus::Accepted && u.status != RuntimeBlockStatus::Finalized) {
                error = "unknown Avalanche status"; return false;
            }
            std::optional<Hash> invalid;
            if (remaining < CANDIDATE_INVALIDITY_MAX_READS) { error = "Avalanche validity read capacity"; return false; }
            auto before = p.store.LastStats().database_reads;
            if (!p.store.ReadCandidateInvalidity(u.block, invalid, e)) { error = e.message; p.Fault(); return false; }
            remaining -= p.store.LastStats().database_reads - before;
            if (invalid) { error = "Avalanche cannot clear deterministic invalidity"; return false; }
            Hash cursor = u.block;
            while (true) {
                staged[cursor] = false;
                if (staged.size() > p.config.storage.max_pending_bytes / 34) { error = "Avalanche ancestor capacity"; return false; }
                if (!h.header.height) break;
                cursor = h.header.prev_id;
                if (!header(cursor, h)) return false;
            }
            if (u.status == RuntimeBlockStatus::Finalized) {
                IndexedHeader f;
                if (!header(u.block, f)) return false;
                if (finalized) {
                    IndexedHeader prior; if (!header(*finalized, prior)) return false;
                    if (prior.header.height >= f.header.height) continue;
                }
                finalized = u.block;
            }
        }
        if (finalized) {
            Hash cursor = *finalized;
            while (true) {
                if (staged.contains(cursor) && staged.at(cursor)) { error = "batch parks finalized ancestry"; return false; }
                IndexedHeader h; if (!header(cursor, h)) return false;
                if (!h.header.height) break;
                cursor = h.header.prev_id;
            }
        }
        if (staged.empty() && !finalized) { error.clear(); return true; }
        // End the cache lifetime before allocating the existing policy vector.
        headers.clear();
        std::vector<DiskParkUpdate> batch; batch.reserve(staged.size());
        for (const auto &[id, parked] : staged) batch.push_back({id, parked});
        if (!p.store.ApplyBlockPolicy(tip, p.view->revision, batch, finalized, e)) {
            error = e.message;
            if (!p.store.IsOpen() || (e.code != DiskStateErrorCode::Resource &&
                e.code != DiskStateErrorCode::TransactionAborted && e.code != DiskStateErrorCode::Missing)) p.Fault();
            return false;
        }
        p.InventoryChanged();
        return p.Observe(error);
    } catch (const std::exception &e) { error = e.what(); return false; }
}
DevelopmentRuntimeResult DevelopmentRuntime::AdmitHeader(const Header &header,
                                                         HeaderAdmission &out,
                                                         std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    if (!p.Observe(error)) return Result::ReopenRequired;
    if (p.view->pending_journal || p.view->pending_receipt ||
        p.view->pending_propagation)
        return Result::Inconclusive;
    const auto &v = p.config.profiles;
    auto admitted = AdmitDevelopmentHeader(header, v.header, v.ordinary,
                                           v.monetary, v.cost, p.store, error);
    if (admitted == HeaderAdmission::StorageError) {
        p.Fault();
        return Result::ReopenRequired;
    }
    out = admitted;
    if (admitted == HeaderAdmission::Stored) {
        // Insertion revisions are handled by the selector without abandoning
        // its bounded pass. Header inventory does not change body availability.
        p.HeaderInserted();
        if (!p.Observe(error)) return Result::ReopenRequired;
    }
    return Result::Progress;
}
DevelopmentRuntimeResult
DevelopmentRuntime::RetainBody(const Hash &id, const std::vector<uint8_t> &wire,
                               CandidateBodyStatus &out, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    if (!p.Room(error)) return Result::CapacityRefused;
    std::optional<IndexedHeader> header;
    DiskStateError e;
    if (!p.store.ReadIndexedHeader(id, header, e)) {
        error = e.message;
        p.Fault();
        return Result::ReopenRequired;
    }
    if (!header) return Result::MissingHeader;
    const auto status = p.pool->PutAuthenticated(id, header->header, wire);
    out = status;
    if (status == CandidateBodyStatus::RetainedAuthenticated)
        p.InventoryChanged();
    return BodyResult(status);
}
DevelopmentRuntimeResult DevelopmentRuntime::EvictBody(const Hash &id,
                                                       CandidateBodyStatus &out,
                                                       std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    if (!p.Room(error)) return Result::CapacityRefused;
    out = p.pool->Evict(id);
    if (out == CandidateBodyStatus::Evicted) p.InventoryChanged();
    return BodyResult(out);
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadAvalancheCandidates(
    const std::optional<CandidateRankCursor> &after,
    const CandidateQueryLimits &limits, CandidatePage &out, std::string &error) {
    if (!impl_) {
        error = "runtime closed";
        return Result::Closed;
    }
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    if (!p.store.AvalancheEnabled()) {
        error = "Avalanche disabled";
        return Result::InvalidConfiguration;
    }
    CandidatePage page;
    DiskStateError e;
    // ReadCandidatePage charges its authority view to the same query budget.
    // Avoid an additional unbudgeted observation before this read.
    if (!p.store.ReadCandidatePage(after, limits, page, e)) {
        error = e.message;
        if (e.code == DiskStateErrorCode::Resource)
            return Result::CapacityRefused;
        if (e.code == DiskStateErrorCode::ProfileMismatch)
            return Result::InvalidConfiguration;
        p.Fault();
        return Result::ReopenRequired;
    }
    p.view = page.view;
    p.ValidateCaches();
    if (page.view.pending_journal || page.view.pending_receipt ||
        page.view.pending_propagation) {
        error = "Avalanche recovery fence pending";
        return Result::Recovering;
    }
    out = std::move(page);
    error.clear();
    return Result::Progress;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadHeader(
    const Hash &id, std::optional<IndexedHeader> &out, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadIndexedHeader(id, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult
DevelopmentRuntime::ReadInvalidity(const Hash &id, std::optional<Hash> &out,
                                   std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadCandidateInvalidity(id, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadBody(const Hash &id,
                                                      uint64_t cap,
                                                      std::vector<uint8_t> &out,
                                                      std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    return p.Body(id, cap, out, error);
}
DevelopmentRuntimeResult
DevelopmentRuntime::ReadConnectedBody(const Hash &id, uint64_t cap,
                                      std::vector<uint8_t> &out,
                                      std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    return p.Body(id, cap, out, error, true);
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadConnectedBodyChunk(
    const Hash &id, uint64_t cap, uint64_t offset, uint64_t length,
    DevelopmentBodyChunk &out, std::string &error,
    DevelopmentBodyChunkUsage *usage) {
    if (usage) *usage = {};
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    if (!length || length > 65536) {
        error = "readblock length must be1..65536";
        return Result::InvalidConfiguration;
    }
    try {
        if (usage) ++usage->view_calls;
        if (!p.Observe(error)) return Result::ReopenRequired;
        if (p.view->identity != p.config.profiles.header.chain_id ||
            p.view->profile_digest != p.expected_profile_digest) {
            error = "retained body validator profile mismatch";
            p.Fault();
            return Result::ReopenRequired;
        }
        const auto snapshot = p.Snapshot();
        if (!SameDevelopmentBodyAuthority(snapshot, snapshot)) {
            p.body_cache.reset();
            error = "connected body recovery fence pending";
            return p.paused ? Result::Inconclusive : Result::Recovering;
        }
        const bool hit = p.body_cache && p.body_cache->id == id &&
            SameDevelopmentBodyAuthority(p.body_cache->snapshot, snapshot);
        std::vector<uint8_t> loaded;
        const std::vector<uint8_t> *body;
        if (hit) {
            if (usage) ++usage->cache_hits;
            body = &p.body_cache->bytes;
        } else {
            // Release the previous entry before any full-body allocation.
            p.body_cache.reset();
            const auto result = p.Body(id, cap, loaded, error, true, nullptr, usage);
            if (result != Result::Progress) return result;
            body = &loaded;
        }
        if (body->size() > cap) {
            error = "retained body exceeds local response capacity";
            return Result::CapacityRefused;
        }
        if (offset > body->size()) {
            error = "readblock offset exceeds body size";
            return Result::InvalidConfiguration;
        }
        const auto count = std::min<uint64_t>(length, body->size() - offset);
        DevelopmentBodyChunk chunk;
        chunk.total_bytes = body->size();
        chunk.snapshot = snapshot;
        chunk.bytes.assign(body->begin() + offset, body->begin() + offset + count);
        if (usage) usage->copied_bytes = count;
        if (!hit) p.body_cache.emplace(Impl::BodyCache{id, snapshot, std::move(loaded)});
        // After cache publication the output transfer must not introduce a
        // failure that leaves a newly installed entry behind.
        static_assert(std::is_nothrow_move_assignable_v<DevelopmentBodyChunk>);
        out = std::move(chunk);
        error.clear();
        return Result::Progress;
    } catch (const std::bad_alloc &) {
        error = "connected body chunk allocation capacity";
        return Result::CapacityRefused;
    } catch (const std::length_error &) {
        error = "connected body chunk allocation length";
        return Result::CapacityRefused;
    } catch (const std::exception &failure) {
        error = failure.what();
        p.Fault();
        return Result::ReopenRequired;
    }
}
ChainIndexResult DevelopmentRuntime::BuildLocator(const Hash &tip, size_t count,
                                                  std::vector<Hash> &out,
                                                  DiskStateError &error) {
    if (!impl_ || impl_->busy || impl_->reopen) {
        error = {DiskStateErrorCode::Closed, "runtime unavailable"};
        return ChainIndexResult::StorageError;
    }
    auto &p = *impl_;
    BusyGuard guard(p.busy);
    const auto r = BuildActiveLocator(p.store, tip, count, out, error);
    if (r == ChainIndexResult::StorageError) p.Fault();
    return r;
}
ChainIndexResult
DevelopmentRuntime::ReadHeaders(const Hash &tip, std::span<const Hash> locator,
                                const Hash &stop, size_t max_locator,
                                size_t max_headers, std::vector<Header> &out,
                                DiskStateError &error) {
    if (!impl_ || impl_->busy || impl_->reopen) {
        error = {DiskStateErrorCode::Closed, "runtime unavailable"};
        return ChainIndexResult::StorageError;
    }
    auto &p = *impl_;
    BusyGuard guard(p.busy);
    const auto r = ReadActiveHeaders(p.store, tip, locator, stop, max_locator,
                                     max_headers, out, error);
    if (r == ChainIndexResult::StorageError) p.Fault();
    return r;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadCoin(const Outpoint &point,
                                                      std::optional<Coin> &out,
                                                      std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadCoin(point, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::ProveCoin(const Outpoint &point,
                                                       CoinProof &out,
                                                       std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.Prove(point, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::BuildTemplate(
    const LocalBlockRequest &request, const LocalBlockLimits &limits,
    LocalBlockBuildResult &status, LocalBlockTemplate &out, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto access = p.Access(error); access != Result::Progress)
        return access;
    BusyGuard guard(p.busy);
    const auto &profiles = p.config.profiles;
    try {
        status = BuildLocalDiskBlockTemplate(request, limits, profiles.header,
                                             profiles.ordinary, profiles.monetary,
                                             profiles.cost, p.store, out, error);
    } catch (const std::bad_alloc &) {
        // Profile argument copying occurs before the assembler's own guard.
        status = LocalBlockBuildResult::CapacityRefused;
    } catch (const std::length_error &) {
        status = LocalBlockBuildResult::CapacityRefused;
    }
    if (status == LocalBlockBuildResult::StorageError) {
        p.Fault();
        return Result::ReopenRequired;
    }
    if (status == LocalBlockBuildResult::CapacityRefused)
        return Result::CapacityRefused;
    return Result::Progress;
}
DevelopmentRuntimeResult
DevelopmentRuntime::ReadMetadata(uint64_t cap, DiskStateMetadata &out,
                                 Hash &root, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    // Metadata() takes a creation-capped snapshot before the caller return cap.
    auto metadata = p.store.Metadata();
    for (const auto size : {metadata.header.size(), metadata.monetary.size(),
                            metadata.auxiliary.size()}) {
        if (size > cap) return Result::CapacityRefused;
        cap -= size;
    }
    const auto snapshot_root = p.store.Root();
    out = std::move(metadata);
    root = snapshot_root;
    return Result::Progress;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadBlockLocation(
    const Hash &id, std::optional<DiskBlockLocation> &out, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadBlockLocation(id, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadUndoLocation(
    const Hash &id, std::optional<DiskUndoLocation> &out, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadUndoLocation(id, out, e)) return Result::Progress;
    error = e.message;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadBlockSlice(
    const Hash &id, uint64_t offset, uint64_t length,
    std::vector<uint8_t> &out, uint64_t *total_bytes, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadBlockSlice(id, offset, length, out, total_bytes, e))
        return Result::Progress;
    error = e.message;
    if (e.code == DiskStateErrorCode::Missing) return Result::MissingBody;
    if (e.code == DiskStateErrorCode::Resource) return Result::InvalidConfiguration;
    p.Fault();
    return Result::ReopenRequired;
}
DevelopmentRuntimeResult DevelopmentRuntime::ReadUndoSlice(
    const Hash &id, uint64_t offset, uint64_t length,
    std::vector<uint8_t> &out, uint64_t *total_bytes, std::string &error) {
    if (!impl_) return Result::Closed;
    auto &p = *impl_;
    if (const auto r = p.Access(error); r != Result::Progress) return r;
    BusyGuard guard(p.busy);
    DiskStateError e;
    if (p.store.ReadUndoSlice(id, offset, length, out, total_bytes, e))
        return Result::Progress;
    error = e.message;
    if (e.code == DiskStateErrorCode::Missing) return Result::MissingBody;
    if (e.code == DiskStateErrorCode::Resource) return Result::InvalidConfiguration;
    p.Fault();
    return Result::ReopenRequired;
}
} // namespace lotus::v2
