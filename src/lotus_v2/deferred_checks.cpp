// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deferred_checks.h"

#include <algorithm>
#include <set>

namespace lotus::v2 {

DeferredTxRun::DeferredTxRun(const DeferredCheckRegistry &registry,
                             DeferredTxView view)
    : registry_(registry), view_(view), pending_(view.input_count),
      completed_(view.input_count) {
    accumulators_.reserve(registry.Kinds().size());
    for (const auto &kind : registry.Kinds())
        accumulators_.push_back(kind->NewAccumulator(view_));
}

DeferredOutcome DeferredTxRun::CompleteInput(uint32_t input, bool succeeded,
                                             DeferredRecords &&records,
                                             std::string &error) {
    if (input >= completed_.size() ||
        completed_[input].exchange(1, std::memory_order_acq_rel) != 0) {
        // A scheduling bug, never a script outcome: fail closed.
        error = "deferred-input-completed-twice";
        failed_.store(true, std::memory_order_release);
        return DeferredOutcome::Failed;
    }
    auto finish = [&](DeferredOutcome outcome) {
        pending_.fetch_sub(1, std::memory_order_acq_rel);
        return outcome;
    };
    if (!succeeded) {
        // The input's records are dropped: they never reach phase 2.
        failed_.store(true, std::memory_order_release);
        return finish(DeferredOutcome::Failed);
    }
    if (failed_.load(std::memory_order_acquire))
        return finish(DeferredOutcome::Abandoned);
    if (!records.Empty()) produced_.store(true, std::memory_order_release);
    for (auto &accumulator : accumulators_) {
        if (!accumulator->Update(input, records, error)) {
            failed_.store(true, std::memory_order_release);
            return finish(DeferredOutcome::Failed);
        }
    }
    if (pending_.fetch_sub(1, std::memory_order_acq_rel) != 1)
        return DeferredOutcome::Pending;
    // Every other input has completed; their updates happen-before this
    // point through the acquire-release decrements above.
    if (failed_.load(std::memory_order_acquire))
        return DeferredOutcome::Abandoned;
    for (auto &accumulator : accumulators_) {
        if (!accumulator->Final(error)) {
            failed_.store(true, std::memory_order_release);
            return DeferredOutcome::Failed;
        }
    }
    accepted_.store(true, std::memory_order_release);
    return DeferredOutcome::Accepted;
}

DeferredOutcome DeferredTxRun::FinishWithoutInputs(std::string &error) {
    if (view_.input_count != 0 || accepted_.load() || failed_.load()) {
        error = "deferred-run-has-inputs";
        return DeferredOutcome::Failed;
    }
    for (auto &accumulator : accumulators_) {
        if (!accumulator->Final(error)) {
            failed_.store(true, std::memory_order_release);
            return DeferredOutcome::Failed;
        }
    }
    accepted_.store(true, std::memory_order_release);
    return DeferredOutcome::Accepted;
}

DeferredOutcome RunDeferredChecks(const DeferredCheckRegistry &registry,
                                  const DeferredTxView &view,
                                  std::span<const DeferredRecords> per_input,
                                  std::string &error) {
    DeferredTxRun run(registry, view);
    if (view.input_count == 0) return run.FinishWithoutInputs(error);
    DeferredOutcome outcome = DeferredOutcome::Pending;
    for (size_t i = 0; i < view.input_count; ++i) {
        DeferredRecords records;
        if (i < per_input.size()) records.Merge(per_input[i]);
        outcome = run.CompleteInput(uint32_t(i), true, std::move(records),
                                    error);
        if (outcome == DeferredOutcome::Failed) return outcome;
    }
    return outcome;
}

const DeferredAccumulator *
DeferredTxRun::Accumulator(const DeferredKindKey &kind) const {
    const auto kinds = registry_.Kinds();
    for (size_t i = 0; i < kinds.size(); ++i)
        if (&kinds[i]->Key() == &kind) return accumulators_[i].get();
    return nullptr;
}

bool RunDeferredBlockChecks(const DeferredCheckRegistry &registry,
                            std::span<const DeferredTxRun *const> runs,
                            std::string &error) {
    for (const auto &hook : registry.BlockHooks())
        if (!hook->Check(runs, error)) return false;
    return true;
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Maximum flow (Dinic) over the bipartite claim graph. Nodes: 0 is the
// source, 1..C the claims, C+1..C+O the outputs, C+O+1 the sink. The
// augmenting search is iterative, so its depth does not depend on the
// graph size.

namespace {
    struct FlowEdge {
        uint32_t to;
        uint32_t reverse;
        uint64_t capacity;
    };

    class ClaimFlow {
    public:
        ClaimFlow(std::span<const OutputClaim> claims,
                  std::span<const uint64_t> values)
            : claims_(claims.size()), outputs_(values.size()),
              graph_(claims.size() + values.size() + 2) {
            const uint32_t source = 0, sink = Sink();
            std::vector<uint8_t> used(values.size());
            for (size_t c = 0; c < claims.size(); ++c) {
                const uint32_t node = uint32_t(1 + c);
                Connect(source, node, claims[c].amount);
                for (uint16_t j : claims[c].matches) {
                    Connect(node, OutputNode(j), claims[c].amount);
                    used[j] = 1;
                }
            }
            for (size_t j = 0; j < values.size(); ++j)
                if (used[j]) Connect(OutputNode(j), sink, values[j]);
        }

        __uint128_t Run() {
            __uint128_t total = 0;
            while (Levels()) {
                std::fill(next_.begin(), next_.end(), 0);
                for (;;) {
                    const uint64_t pushed = Augment();
                    if (!pushed) break;
                    total += pushed;
                }
            }
            return total;
        }

        // Flow into each output: the used capacity of its sink edge.
        std::vector<__uint128_t> Assigned(std::span<const uint64_t> values) const {
            std::vector<__uint128_t> out(outputs_);
            for (size_t j = 0; j < outputs_; ++j)
                for (const auto &edge : graph_[OutputNode(j)])
                    if (edge.to == Sink())
                        out[j] = values[j] - edge.capacity;
            return out;
        }

    private:
        uint32_t Sink() const { return uint32_t(claims_ + outputs_ + 1); }
        uint32_t OutputNode(size_t j) const {
            return uint32_t(claims_ + 1 + j);
        }
        void Connect(uint32_t from, uint32_t to, uint64_t capacity) {
            graph_[from].push_back(
                FlowEdge{to, uint32_t(graph_[to].size()), capacity});
            graph_[to].push_back(
                FlowEdge{from, uint32_t(graph_[from].size() - 1), 0});
        }
        // Breadth-first levels from the source; false when the sink is
        // unreachable in the residual graph.
        bool Levels() {
            level_.assign(graph_.size(), UINT32_MAX);
            next_.assign(graph_.size(), 0);
            std::vector<uint32_t> queue{0};
            level_[0] = 0;
            for (size_t head = 0; head < queue.size(); ++head) {
                const uint32_t v = queue[head];
                for (const auto &edge : graph_[v]) {
                    if (edge.capacity && level_[edge.to] == UINT32_MAX) {
                        level_[edge.to] = level_[v] + 1;
                        queue.push_back(edge.to);
                    }
                }
            }
            return level_[Sink()] != UINT32_MAX;
        }
        // One augmenting path in the level graph (iterative depth-first
        // search with per-node edge cursors); returns the flow pushed, or 0
        // when the level graph is blocked.
        uint64_t Augment() {
            path_.clear();
            uint32_t v = 0;
            for (;;) {
                if (v == Sink()) {
                    uint64_t pushed = UINT64_MAX;
                    for (const auto &[u, k] : path_)
                        pushed = std::min(pushed, graph_[u][k].capacity);
                    for (const auto &[u, k] : path_) {
                        FlowEdge &edge = graph_[u][k];
                        edge.capacity -= pushed;
                        graph_[edge.to][edge.reverse].capacity += pushed;
                    }
                    return pushed;
                }
                auto &cursor = next_[v];
                const auto &edges = graph_[v];
                while (cursor < edges.size() &&
                       (!edges[cursor].capacity ||
                        level_[edges[cursor].to] != level_[v] + 1))
                    ++cursor;
                if (cursor < edges.size()) {
                    path_.emplace_back(v, cursor);
                    v = edges[cursor].to;
                    continue;
                }
                // Dead end: retreat and skip the edge that led here.
                if (path_.empty()) return 0;
                level_[v] = UINT32_MAX;
                v = path_.back().first;
                path_.pop_back();
                ++next_[v];
            }
        }

        size_t claims_, outputs_;
        std::vector<std::vector<FlowEdge>> graph_;
        std::vector<uint32_t> level_;
        std::vector<uint32_t> next_;
        std::vector<std::pair<uint32_t, uint32_t>> path_;
    };
} // namespace

__uint128_t MaxClaimFlow(std::span<const OutputClaim> claims,
                         std::span<const uint64_t> output_values,
                         std::vector<__uint128_t> *assigned) {
    ClaimFlow flow(claims, output_values);
    const __uint128_t total = flow.Run();
    if (assigned) *assigned = flow.Assigned(output_values);
    return total;
}

bool OutputClaimsFeasible(std::span<const OutputClaim> claims,
                          std::span<const uint64_t> output_values,
                          std::vector<__uint128_t> *assigned) {
    __uint128_t claimed = 0;
    for (const auto &claim : claims) claimed += claim.amount;
    return MaxClaimFlow(claims, output_values, assigned) == claimed;
}

const DeferredKindKey kStateAuthorizationKind{"state-authorization"};
const DeferredKindKey kOutputClaimsKind{"output-claims"};

namespace {

    class StateAuthorizationAccumulator final : public DeferredAccumulator {
    public:
        explicit StateAuthorizationAccumulator(const DeferredTxView &view)
            : outputs_(view.outputs), authorized_(view.outputs.size()) {}
        bool Update(uint32_t, const DeferredRecords &records,
                    std::string &error) override {
            for (const auto *record :
                 records.Of<StateAuthorization>(kStateAuthorizationKind)) {
                for (uint16_t j : record->outputs) {
                    if (j >= authorized_.size()) {
                        error = "state-output-unauthorized";
                        return false;
                    }
                    authorized_[j].store(1, std::memory_order_relaxed);
                }
            }
            return true;
        }
        bool Final(std::string &error) override {
            for (size_t j = 0; j < outputs_.size(); ++j) {
                if (outputs_[j].HasState() &&
                    !authorized_[j].load(std::memory_order_relaxed)) {
                    error = "state-output-unauthorized";
                    return false;
                }
            }
            return true;
        }

    private:
        std::span<const Output> outputs_;
        std::vector<std::atomic<uint8_t>> authorized_;
    };

    class StateAuthorizationKind final : public DeferredCheckKind {
    public:
        StateAuthorizationKind() : DeferredCheckKind(kStateAuthorizationKind) {}
        std::unique_ptr<DeferredAccumulator>
        NewAccumulator(const DeferredTxView &view) const override {
            return std::make_unique<StateAuthorizationAccumulator>(view);
        }
    };

} // namespace

class OutputClaimsAccumulator final : public DeferredAccumulator {
public:
    explicit OutputClaimsAccumulator(const DeferredTxView &view)
        : outputs_(view.outputs), per_input_(view.input_count) {}
    // Each input writes only its own slot, so concurrent inputs never share
    // state here.
    bool Update(uint32_t input, const DeferredRecords &records,
                std::string &error) override {
        auto &slot = per_input_[input];
        const auto claims = records.Of<OutputClaim>(kOutputClaimsKind);
        size_t pairs = 0;
        for (const auto *claim : claims) pairs += claim->matches.size();
        // The pair cap bounds phase 2. Concurrent inputs share the count;
        // whichever crosses the cap fails, and so does the transaction.
        if (pairs > MAX_TX_CLAIM_PAIRS ||
            pairs_.fetch_add(pairs, std::memory_order_relaxed) + pairs >
                MAX_TX_CLAIM_PAIRS) {
            error = "claim-pairs-exceeded";
            return false;
        }
        for (const auto *claim : claims) {
            if (claim->matches.empty()) {
                error = "output-overclaimed";
                return false;
            }
            for (uint16_t j : claim->matches) {
                if (j >= outputs_.size()) {
                    error = "output-overclaimed";
                    return false;
                }
            }
            slot.push_back(*claim);
        }
        return true;
    }
    // Phase 2: one maximum-flow feasibility check over every claim.
    bool Final(std::string &error) override {
        std::vector<uint64_t> values(outputs_.size());
        for (size_t j = 0; j < outputs_.size(); ++j)
            values[j] = outputs_[j].value;
        const auto claims = Claims();
        if (!OutputClaimsFeasible(claims, values)) {
            error = "output-overclaimed";
            return false;
        }
        return true;
    }
    std::vector<OutputClaim> Claims() const {
        std::vector<OutputClaim> out;
        for (const auto &slot : per_input_)
            out.insert(out.end(), slot.begin(), slot.end());
        return out;
    }

private:
    std::span<const Output> outputs_;
    std::vector<std::vector<OutputClaim>> per_input_;
    std::atomic<size_t> pairs_{0};
};

namespace {
    class OutputClaimsKind final : public DeferredCheckKind {
    public:
        OutputClaimsKind() : DeferredCheckKind(kOutputClaimsKind) {}
        std::unique_ptr<DeferredAccumulator>
        NewAccumulator(const DeferredTxView &view) const override {
            return std::make_unique<OutputClaimsAccumulator>(view);
        }
    };
} // namespace

std::vector<OutputClaim> CollectOutputClaims(const DeferredTxRun &run) {
    const auto *accumulator = static_cast<const OutputClaimsAccumulator *>(
        run.Accumulator(kOutputClaimsKind));
    return accumulator ? accumulator->Claims() : std::vector<OutputClaim>{};
}

std::vector<OutputClaim> OutputClaimsOf(const DeferredRecords &records) {
    std::vector<OutputClaim> out;
    for (const auto *claim : records.Of<OutputClaim>(kOutputClaimsKind))
        out.push_back(*claim);
    return out;
}

std::vector<StateAuthorization>
StateAuthorizationsOf(const DeferredRecords &records) {
    std::vector<StateAuthorization> out;
    for (const auto *record :
         records.Of<StateAuthorization>(kStateAuthorizationKind))
        out.push_back(*record);
    return out;
}

const DeferredCheckRegistry &DeferredCheckRegistry::Consensus() {
    static const DeferredCheckRegistry registry = [] {
        DeferredCheckRegistry r;
        r.Add(std::make_shared<StateAuthorizationKind>());
        r.Add(std::make_shared<OutputClaimsKind>());
        return r;
    }();
    return registry;
}

// ---------------------------------------------------------------------------

namespace {
    bool CheckedAdd(__uint128_t &total, __uint128_t value) {
        if (total + value < total) return false;
        total += value;
        return true;
    }
} // namespace

bool NativeConservation::AddInput(__uint128_t value) {
    return CheckedAdd(inputs_, value);
}
bool NativeConservation::AddOutput(__uint128_t value) {
    return CheckedAdd(outputs_, value);
}
const char *ConservationFailureName(ConservationFailure failure) {
    switch (failure) {
    case ConservationFailure::None:
        return "";
    case ConservationFailure::Overflow:
        return "conservation-overflow";
    case ConservationFailure::NativeInflation:
        return "native-inflation";
    case ConservationFailure::MintWithoutDelta:
        return "mint-without-positive-delta";
    case ConservationFailure::TokenInflation:
        return "token-inflation";
    }
    return "conservation-unknown";
}

bool NativeConservation::Final(std::string &error) {
    const auto failure = Check();
    error = ConservationFailureName(failure);
    return failure == ConservationFailure::None;
}
bool TokenConservation::Final(std::string &error) {
    const auto failure = Check();
    error = ConservationFailureName(failure);
    return failure == ConservationFailure::None;
}

ConservationFailure NativeConservation::Check() const {
    return inputs_ < outputs_ ? ConservationFailure::NativeInflation
                              : ConservationFailure::None;
}

bool TokenConservation::AddInput(const Hash32 &token, __uint128_t value) {
    return CheckedAdd(totals_[token].inputs, value);
}
bool TokenConservation::AddOutput(const Hash32 &token, __uint128_t value) {
    return CheckedAdd(totals_[token].outputs, value);
}
ConservationFailure TokenConservation::Check() const {
    std::set<Hash32> positive;
    for (const auto &[token, totals] : totals_)
        if (totals.outputs > totals.inputs) positive.insert(token);
    // Mint inputs in transaction order; a second mint of one token finds
    // its delta already taken.
    for (const Hash32 &token : mints_)
        if (positive.erase(token) != 1)
            return ConservationFailure::MintWithoutDelta;
    return positive.empty() ? ConservationFailure::None
                            : ConservationFailure::TokenInflation;
}

} // namespace lotus::v2
