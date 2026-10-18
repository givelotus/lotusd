// Copyright (c) 2026 The Lotus developers
#include "candidate_selection.h"
#include "disk_state.h"
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>

namespace lotus::v2 {
namespace {
constexpr uint64_t HEADER_READS = 3; // ReadIndexedHeader's parent-binding Gets.
struct Stop { CandidateResult result; };
[[noreturn]] void End(CandidateResult result) { throw Stop{result}; }
CandidateResult ErrorResult(const DiskStateError &error) {
    return error.code == DiskStateErrorCode::Resource ? CandidateResult::CapacityRefused
                                                     : CandidateResult::StorageError;
}
bool Future(uint64_t maximum, uint64_t now, uint64_t window) {
    return maximum > now && maximum - now > window;
}
bool SameLimits(const CandidateLimits &a, const CandidateLimits &b) {
    return a.query.max_rows == b.query.max_rows && a.query.max_reads == b.query.max_reads &&
        a.query.max_iterator_steps == b.query.max_iterator_steps &&
        a.query.max_decoded_bytes == b.query.max_decoded_bytes &&
        a.fork.max_connect == b.fork.max_connect && a.fork.max_disconnect == b.fork.max_disconnect &&
        a.fork.max_reads == b.fork.max_reads && a.max_probe_calls == b.max_probe_calls &&
        a.max_probe_bytes == b.max_probe_bytes && a.max_missing_bodies == b.max_missing_bodies &&
        a.max_resident_bytes == b.max_resident_bytes;
}
bool Add(uint64_t a, uint64_t b, uint64_t &out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b; return true;
}
bool Product(uint64_t a, uint64_t b, uint64_t &out) {
    if (a && b > std::numeric_limits<uint64_t>::max() / a) return false;
    out = a * b; return true;
}
bool ValidLimits(const CandidateLimits &l) {
    uint64_t paths{}, path_bytes{}, needs{}, required{}, reads{};
    // Two retained choices and one in-flight plan. A one-row page never retains
    // an inventory-sized vector. Reserve vectors to their exact authorized cap.
    return l.query.max_rows && l.query.max_iterator_steps && l.query.max_decoded_bytes &&
        l.fork.max_connect && l.fork.max_reads && l.max_probe_calls && l.max_probe_bytes &&
        l.max_missing_bodies && l.max_resident_bytes &&
        Add(l.fork.max_connect, l.fork.max_disconnect, paths) &&
        // PlanHeaderFork uses vector growth; capacity can be below twice its
        // authorized element count. Include that spare capacity for each plan.
        Product(paths, 6 * sizeof(Hash), path_bytes) &&
        Product(l.max_missing_bodies, 2 * sizeof(CandidateBodyNeed), needs) &&
        Add(path_bytes, needs, required) && Add(required, sizeof(CandidateRow), required) &&
        required <= l.max_resident_bytes &&
        Add(l.fork.max_reads, 2 * CANDIDATE_VIEW_MAX_READS + HEADER_READS, reads) &&
        l.query.max_reads >= reads &&
        paths <= std::numeric_limits<size_t>::max() / sizeof(Hash) &&
        l.max_missing_bodies <= std::numeric_limits<size_t>::max() / sizeof(CandidateBodyNeed);
}
bool SameSource(const CandidateView &a, const CandidateView &b) {
    return a.identity == b.identity && a.profile_digest == b.profile_digest &&
        a.stable_tip == b.stable_tip && a.root == b.root && a.active_work == b.active_work &&
        a.active_max_ancestor_time == b.active_max_ancestor_time && a.invalid_epoch == b.invalid_epoch;
}
void Fence(const CandidateView &view, const Hash &expected) {
    if (view.pending_journal) End(CandidateResult::RecoveryRequired);
    if (view.pending_receipt) End(CandidateResult::AcknowledgeRequired);
    if (view.pending_propagation) End(CandidateResult::InvalidationRequired);
    if (view.stable_tip != expected) End(CandidateResult::Stale);
}
struct Budget {
    const DiskStateStore &store;
    const CandidateQueryLimits &limits;
    CandidatePollUsage &used;
    DiskStateError &error;
    uint64_t RemainingReads() const { return limits.max_reads - used.query.reads; }
    template <typename F> auto Read(uint64_t maximum, F &&f) {
        if (maximum > RemainingReads()) End(CandidateResult::CapacityRefused);
        const uint64_t before = store.LastStats().database_reads;
        auto account = [&] {
            const uint64_t after = store.LastStats().database_reads;
            if (after < before || after - before > maximum) {
                error = {DiskStateErrorCode::Corruption, "candidate query Get bound changed"};
                End(CandidateResult::StorageError);
            }
            used.query.reads += after - before;
        };
        decltype(f()) value;
        try { value = f(); }
        catch (...) { account(); throw; }
        account();
        return value;
    }
    CandidateView View() {
        CandidateView view;
        Read(CANDIDATE_VIEW_MAX_READS, [&] {
            if (!store.ReadCandidateView(view, error)) End(ErrorResult(error));
            return 0;
        });
        return view;
    }
};
struct Pending {
    CandidateChoice choice;
    CandidateRankCursor rank;
    size_t source_pos{}, target_pos{};
    bool source_blocked{}, target_blocked{}, operational{}, unsupported{};
};
} // namespace

struct CandidateSelector::Impl {
    bool busy{}, started{}, blocked{}, unsupported{};
    const DiskStateStore *store{};
    CandidateLimits limits;
    CandidateChoices choices;
    std::optional<CandidateRankCursor> cursor;
    std::optional<Pending> pending;
    uint64_t last_now{};
    void Clear() {
        started = blocked = unsupported = false; store = nullptr;
        choices = {}; cursor.reset(); pending.reset();
    }
    void Begin(const CandidateView &view, uint64_t now, uint64_t window,
               uint64_t epoch, const CandidateLimits &l, const DiskStateStore &s) {
        Clear(); started = true; store = &s; limits = l; last_now = now;
        choices.view = view; choices.body_epoch = epoch;
        choices.sampled_now = now; choices.future_window = window;
    }
};
CandidateSelector::CandidateSelector() : impl_(std::make_unique<Impl>()) {}
CandidateSelector::~CandidateSelector() = default;
CandidateSelector::CandidateSelector(CandidateSelector &&) noexcept = default;
CandidateSelector &CandidateSelector::operator=(CandidateSelector &&) noexcept = default;
bool CandidateSelector::Reset() noexcept {
    if (impl_ && impl_->busy) return false;
    if (impl_) impl_->Clear();
    return true;
}

CandidateResult CandidateSelector::Poll(const Hash &expected_tip, uint64_t now,
    uint64_t window, uint64_t body_epoch, const CandidateLimits &limits,
    const CandidateBodyProbe &probe, const DiskStateStore &store, CandidateChoices &out,
    CandidatePollUsage &usage, DiskStateError &error) {
    // Reentry can pass the outer operation's own output references. Refuse it
    // before clearing counters/errors or examining callback-controlled inputs.
    if (impl_ && impl_->busy) return CandidateResult::StorageError;
    usage = {}; error = {};
    if (!ValidLimits(limits) || !probe) return CandidateResult::InvalidConfiguration;
    if (!impl_) {
        try { impl_ = std::make_unique<Impl>(); }
        catch (const std::bad_alloc &) {
            error.code = DiskStateErrorCode::Resource;
            return CandidateResult::CapacityRefused;
        }
    }
    auto &state = *impl_;
    struct Guard { bool &flag; explicit Guard(bool &f) : flag(f) { flag = true; } ~Guard() { flag = false; } } guard(state.busy);
    try {
        Budget budget{store, limits.query, usage, error};
        const CandidateView initial = budget.View(); Fence(initial, expected_tip);
        if (state.started && (state.store != &store || !SameSource(state.choices.view, initial))) {
            state.Clear(); return CandidateResult::Stale;
        }
        if (!state.started || !SameLimits(state.limits, limits) ||
            state.choices.body_epoch != body_epoch || now < state.last_now ||
            state.choices.future_window != window ||
            (state.choices.next_eligibility_time && now >= *state.choices.next_eligibility_time))
            state.Begin(initial, now, window, body_epoch, limits, store);
        state.last_now = now;

        auto finish_pending = [&] {
            auto &pending = *state.pending;
            if (pending.source_blocked || pending.operational) {
                state.blocked = true;
                state.unsupported |= pending.unsupported;
            }
            if (!pending.choice.missing.empty() && !state.choices.best_fetch)
                state.choices.best_fetch = std::move(pending.choice);
            else if (!pending.source_blocked && !pending.target_blocked) {
                const bool capacity = budget.Read(CANDIDATE_CAPACITY_MAX_READS, [&] {
                    return store.CheckCandidateRecoveryCapacity(pending.choice.fork.disconnect.size(), error);
                });
                if (capacity) state.choices.best_ready = std::move(pending.choice);
                else if (error.code == DiskStateErrorCode::Resource) { state.blocked = true; error = {}; }
                else End(ErrorResult(error));
            }
            state.cursor = pending.rank; state.pending.reset();
        };
        bool complete = state.choices.best_ready.has_value();
        while (!complete) {
            if (state.pending) {
                auto &pending = *state.pending;
                const bool source = pending.source_pos < pending.choice.fork.disconnect.size();
                const bool target = pending.target_pos < pending.choice.fork.connect.size();
                if (!source && !target) {
                    if (budget.RemainingReads() < CANDIDATE_CAPACITY_MAX_READS + CANDIDATE_VIEW_MAX_READS)
                        return CandidateResult::Progress;
                    finish_pending();
                    if (state.choices.best_ready) complete = true;
                    continue;
                }
                if (usage.probe_calls >= limits.max_probe_calls ||
                    budget.RemainingReads() < HEADER_READS + CANDIDATE_VIEW_MAX_READS)
                    return CandidateResult::Progress;
                const Hash id = source ? pending.choice.fork.disconnect[pending.source_pos]
                                       : pending.choice.fork.connect[pending.target_pos];
                std::optional<IndexedHeader> indexed;
                budget.Read(HEADER_READS, [&] {
                    if (!store.ReadIndexedHeader(id, indexed, error)) End(ErrorResult(error));
                    return 0;
                });
                if (!indexed) {
                    error = {DiskStateErrorCode::Corruption, "candidate path header missing"};
                    End(CandidateResult::StorageError);
                }
                ++usage.probe_calls;
                std::string message;
                const auto result = probe(id, indexed->header, limits.max_probe_bytes, message);
                if (source) ++pending.source_pos;
                else ++pending.target_pos;
                if (result == CandidateBodyResult::StorageError) {
                    error = {DiskStateErrorCode::Database, std::move(message)};
                    End(CandidateResult::StorageError);
                }
                if (result != CandidateBodyResult::Available) {
                    if (source) {
                        pending.source_blocked = true;
                        pending.source_pos = pending.choice.fork.disconnect.size();
                    } else {
                        pending.target_blocked = true;
                        if (result == CandidateBodyResult::Missing && !state.choices.best_fetch) {
                            if (pending.choice.missing.empty())
                                pending.choice.missing.reserve(size_t(limits.max_missing_bodies));
                            pending.choice.missing.push_back({id, indexed->header});
                        }
                        if (result != CandidateBodyResult::Missing || state.choices.best_fetch ||
                            pending.choice.missing.size() >= limits.max_missing_bodies)
                            pending.target_pos = pending.choice.fork.connect.size();
                    }
                    pending.unsupported |= result == CandidateBodyResult::Unsupported;
                    pending.operational |= result != CandidateBodyResult::Missing;
                }
                continue;
            }
            if (usage.query.rows >= limits.query.max_rows ||
                usage.query.iterator_steps >= limits.query.max_iterator_steps ||
                usage.query.decoded_bytes >= limits.query.max_decoded_bytes ||
                budget.RemainingReads() < limits.fork.max_reads + CANDIDATE_VIEW_MAX_READS)
                return CandidateResult::Progress;
            CandidateQueryLimits page_limits{
                1, budget.RemainingReads() - limits.fork.max_reads,
                limits.query.max_iterator_steps - usage.query.iterator_steps,
                limits.query.max_decoded_bytes - usage.query.decoded_bytes};
            CandidatePage page;
            CandidateQueryUsage page_used;
            const uint64_t before = usage.query.reads;
            auto account_page = [&] {
                if (page_used.reads != usage.query.reads - before || page_used.rows > page_limits.max_rows ||
                    page_used.iterator_steps > page_limits.max_iterator_steps ||
                    page_used.decoded_bytes > page_limits.max_decoded_bytes) {
                    error = {DiskStateErrorCode::Corruption, "candidate page usage bound changed"};
                    End(CandidateResult::StorageError);
                }
                usage.query.rows += page_used.rows;
                usage.query.iterator_steps += page_used.iterator_steps;
                usage.query.decoded_bytes += page_used.decoded_bytes;
            };
            bool ok;
            try {
                ok = budget.Read(page_limits.max_reads, [&] {
                    return store.ReadCandidatePage(state.cursor, page_limits, page, error, &page_used);
                });
            } catch (...) { account_page(); throw; }
            account_page();
            if (!ok) End(ErrorResult(error));
            if (page.rows.size() > 1 || page.used.rows != page_used.rows || page.used.reads != page_used.reads ||
                page.used.iterator_steps != page_used.iterator_steps || page.used.decoded_bytes != page_used.decoded_bytes) {
                error = {DiskStateErrorCode::Corruption, "candidate successful page usage mismatch"};
                End(CandidateResult::StorageError);
            }
            Fence(page.view, expected_tip);
            if (!SameSource(state.choices.view, page.view)) End(CandidateResult::Stale);
            if (page.rows.empty()) {
                if (!page.complete) return CandidateResult::Progress;
                complete = true; continue;
            }
            const auto &row = page.rows.front();
            const CandidateRankCursor rank{row.indexed.chain_work, row.id};
            if (state.cursor && (CompareChainWork(rank.work, state.cursor->work) > 0 ||
                (rank.work == state.cursor->work && rank.id >= state.cursor->id))) {
                error = {DiskStateErrorCode::Corruption, "candidate cursor did not advance"};
                End(CandidateResult::StorageError);
            }
            if (CompareChainWork(row.indexed.chain_work, initial.active_work) <= 0) {
                complete = true; continue;
            }
            if (Future(row.indexed.max_ancestor_time, now, window)) {
                const uint64_t threshold = row.indexed.max_ancestor_time > window
                    ? row.indexed.max_ancestor_time - window : 0;
                if (!state.choices.next_eligibility_time || threshold < *state.choices.next_eligibility_time)
                    state.choices.next_eligibility_time = threshold;
                state.cursor = rank; continue;
            }
            Pending pending; pending.rank = rank; pending.choice.target = row.id;
            pending.choice.indexed = row.indexed;
            const auto result = budget.Read(limits.fork.max_reads, [&] {
                return PlanHeaderFork(store, expected_tip, row.id, limits.fork, now, window,
                                      pending.choice.fork, error);
            });
            if (result == ChainIndexResult::Excluded) {
                state.cursor = rank; continue;
            }
            if (result == ChainIndexResult::CapacityRefused) {
                state.blocked = true; state.cursor = rank; error = {}; continue;
            }
            if (result == ChainIndexResult::StaleTip) End(CandidateResult::Stale);
            if (result != ChainIndexResult::Complete) {
                if (result != ChainIndexResult::StorageError)
                    error = {DiskStateErrorCode::Corruption, "candidate summary and fork plan disagree"};
                End(ErrorResult(error));
            }
            state.pending = std::move(pending);
        }
        const CandidateView final_view = budget.View(); Fence(final_view, expected_tip);
        if (!SameSource(state.choices.view, final_view)) End(CandidateResult::Stale);
        if (state.choices.view.revision != final_view.revision) {
            state.Begin(final_view, now, window, body_epoch, limits, store);
            return CandidateResult::Progress;
        }
        state.choices.view = final_view; state.choices.sampled_now = now;
        state.choices.active_temporarily_ineligible = Future(final_view.active_max_ancestor_time, now, window);
        state.choices.higher_operationally_blocked = state.blocked;
        CandidateResult result = CandidateResult::RetainActive;
        if (state.choices.best_ready) result = CandidateResult::Ready;
        else if (state.choices.best_fetch) result = CandidateResult::NeedBodies;
        else if (state.blocked) result = state.unsupported ? CandidateResult::Unsupported : CandidateResult::CapacityRefused;
        else if (state.choices.next_eligibility_time) result = CandidateResult::Deferred;
        if (result == CandidateResult::Ready || result == CandidateResult::NeedBodies ||
            result == CandidateResult::Deferred || result == CandidateResult::RetainActive)
            out = std::move(state.choices);
        state.Clear(); return result;
    } catch (const Stop &stop) {
        if (stop.result != CandidateResult::CapacityRefused) state.Clear();
        return stop.result;
    } catch (const std::bad_alloc &) {
        state.Clear(); error.code = DiskStateErrorCode::Resource; error.message.clear();
        return CandidateResult::CapacityRefused;
    } catch (const std::length_error &) {
        state.Clear(); error.code = DiskStateErrorCode::Resource; error.message.clear();
        return CandidateResult::CapacityRefused;
    } catch (...) {
        state.Clear(); error.code = DiskStateErrorCode::TransactionAborted; error.message.clear();
        return CandidateResult::StorageError;
    }
}

CandidateResult ValidateCandidateChoice(const CandidateChoices &choices,
    const CandidateChoice &choice, uint64_t now, uint64_t window, uint64_t body_epoch,
    const CandidateLimits &limits, const DiskStateStore &store,
    CandidatePollUsage &usage, DiskStateError &error) {
    usage = {}; error = {};
    if (!ValidLimits(limits)) return CandidateResult::InvalidConfiguration;
    try {
        Budget budget{store, limits.query, usage, error};
        const auto view = budget.View(); Fence(view, choices.view.stable_tip);
        if (!SameSource(view, choices.view) || view.revision != choices.view.revision ||
            body_epoch != choices.body_epoch || now < choices.sampled_now || window != choices.future_window ||
            (choices.next_eligibility_time && now >= *choices.next_eligibility_time))
            return CandidateResult::Stale;
        if (Future(choice.indexed.max_ancestor_time, now, window)) return CandidateResult::Deferred;
        if (choice.fork.source != view.stable_tip || choice.fork.target != choice.target ||
            CompareChainWork(choice.indexed.chain_work, view.active_work) <= 0)
            return CandidateResult::Stale;
        if ((!choices.best_ready || choices.best_ready->target != choice.target) &&
            (!choices.best_fetch || choices.best_fetch->target != choice.target))
            return CandidateResult::Stale;
        std::optional<Hash> invalid_root;
        budget.Read(CANDIDATE_INVALIDITY_MAX_READS, [&] {
            if (!store.ReadCandidateInvalidity(choice.target, invalid_root, error)) End(ErrorResult(error));
            return 0;
        });
        if (invalid_root) return CandidateResult::Stale;
        std::optional<IndexedHeader> indexed;
        budget.Read(HEADER_READS, [&] {
            if (!store.ReadIndexedHeader(choice.target, indexed, error)) End(ErrorResult(error));
            return 0;
        });
        if (!indexed || indexed->chain_work != choice.indexed.chain_work ||
            indexed->max_ancestor_time != choice.indexed.max_ancestor_time)
            return CandidateResult::Stale;
        if (Future(indexed->max_ancestor_time, now, window)) return CandidateResult::Deferred;
        std::array<uint8_t, HEADER_SIZE> actual{}, observed{};
        if (!SerializeHeader(indexed->header, actual) ||
            !SerializeHeader(choice.indexed.header, observed) || actual != observed)
            return CandidateResult::Stale;
        ForkPlan current;
        const auto planned = budget.Read(limits.fork.max_reads, [&] {
            return PlanHeaderFork(store, view.stable_tip, choice.target, limits.fork,
                                  now, window, current, error);
        });
        if (planned == ChainIndexResult::CapacityRefused) return CandidateResult::CapacityRefused;
        if (planned == ChainIndexResult::Deferred) return CandidateResult::Deferred;
        if (planned == ChainIndexResult::StorageError) return ErrorResult(error);
        if (planned != ChainIndexResult::Complete || current.fork != choice.fork.fork ||
            current.disconnect != choice.fork.disconnect || current.connect != choice.fork.connect)
            return CandidateResult::Stale;
        return choice.missing.empty() ? CandidateResult::Ready : CandidateResult::NeedBodies;
    } catch (const Stop &stop) { return stop.result; }
    catch (const std::bad_alloc &) {
        error.code = DiskStateErrorCode::Resource; error.message.clear(); return CandidateResult::CapacityRefused;
    }
    catch (const std::length_error &) {
        error.code = DiskStateErrorCode::Resource; error.message.clear(); return CandidateResult::CapacityRefused;
    }
}
} // namespace lotus::v2
