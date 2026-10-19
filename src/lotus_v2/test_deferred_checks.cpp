// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The generic two-phase (deferred) check framework: scheduling, ordering,
// failure isolation, the consensus kinds, a test-only kind and the block
// hook.

#include "deferred_checks.h"

#include <algorithm>
#include <atomic>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {

// ---------------------------------------------------------------------------
// A test-only kind, registered next to the consensus kinds without any
// scheduler change. Each record adds `amount` to a per-transaction atomic
// total; the inline rule fails fast when the running total exceeds `cap`
// (an upper bound, so it does not depend on order); the final rule requires
// the total to be even. It also counts the work it sees.
const DeferredKindKey kDummyKind{"test-dummy"};
struct DummyRecord {
    uint64_t amount = 0;
};
struct DummyStats {
    std::atomic<size_t> updates{0};
    std::atomic<size_t> records{0};
    std::atomic<size_t> finals{0};
    std::atomic<uint64_t> total_seen{0};
};

class DummyAccumulator final : public DeferredAccumulator {
public:
    DummyAccumulator(uint64_t cap, DummyStats &stats, size_t inputs)
        : cap_(cap), stats_(stats), per_input_(inputs) {}
    bool Update(uint32_t input, const DeferredRecords &records,
                std::string &error) override {
        stats_.updates.fetch_add(1);
        for (const auto *record : records.Of<DummyRecord>(kDummyKind)) {
            stats_.records.fetch_add(1);
            per_input_[input].push_back(record->amount);
            const uint64_t now =
                total_.fetch_add(record->amount) + record->amount;
            if (now > cap_) {
                error = "dummy-over-cap";
                return false;
            }
        }
        return true;
    }
    bool Final(std::string &error) override {
        stats_.finals.fetch_add(1);
        stats_.total_seen.store(total_.load());
        if (total_.load() % 2 != 0) {
            error = "dummy-odd";
            return false;
        }
        return true;
    }
    // Canonical order, independent of completion order.
    std::vector<uint64_t> Ordered() const {
        std::vector<uint64_t> out;
        for (const auto &slot : per_input_)
            out.insert(out.end(), slot.begin(), slot.end());
        return out;
    }

private:
    uint64_t cap_;
    DummyStats &stats_;
    std::atomic<uint64_t> total_{0};
    std::vector<std::vector<uint64_t>> per_input_;
};

class DummyKind final : public DeferredCheckKind {
public:
    DummyKind(uint64_t cap, DummyStats &stats)
        : DeferredCheckKind(kDummyKind), cap_(cap), stats_(stats) {}
    std::unique_ptr<DeferredAccumulator>
    NewAccumulator(const DeferredTxView &view) const override {
        return std::make_unique<DummyAccumulator>(cap_, stats_,
                                                  view.input_count);
    }

private:
    uint64_t cap_;
    DummyStats &stats_;
};

DeferredCheckRegistry WithDummy(uint64_t cap, DummyStats &stats) {
    DeferredCheckRegistry registry;
    for (const auto &kind : DeferredCheckRegistry::Consensus().Kinds())
        registry.Add(kind);
    registry.Add(std::make_shared<DummyKind>(cap, stats));
    return registry;
}

Output Plain(uint64_t value) {
    Output out;
    out.value = value;
    out.branches = {Hash32{}};
    out.paths = {{0}};
    return out;
}

DeferredRecords Dummy(std::initializer_list<uint64_t> amounts) {
    DeferredRecords records;
    uint16_t witness = 0;
    for (uint64_t amount : amounts)
        records.Add(kDummyKind, witness++, DummyRecord{amount});
    return records;
}

struct InputJob {
    bool succeeds = true;
    DeferredRecords records;
};

struct RunResult {
    DeferredOutcome outcome = DeferredOutcome::Pending;
    std::string error;
    std::vector<uint64_t> ordered;
    size_t finals = 0;
    size_t records_seen = 0;
};

// Completes the inputs in `order` on one thread, or concurrently with one
// thread per input. Returns the transaction outcome (the outcome of the
// completion that decided it) and what the dummy kind saw.
RunResult Execute(std::span<const Output> outputs, std::vector<InputJob> jobs,
                  const std::vector<size_t> &order, bool threads,
                  uint64_t cap = 1000) {
    DummyStats stats;
    const auto registry = WithDummy(cap, stats);
    DeferredTxRun run(registry, DeferredTxView{outputs, jobs.size()});
    std::vector<DeferredOutcome> outcomes(jobs.size());
    std::vector<std::string> errors(jobs.size());
    auto complete = [&](size_t i) {
        outcomes[i] = run.CompleteInput(uint32_t(i), jobs[i].succeeds,
                                        std::move(jobs[i].records), errors[i]);
    };
    if (threads) {
        std::vector<std::thread> pool;
        for (size_t i : order) pool.emplace_back(complete, i);
        for (auto &t : pool) t.join();
    } else {
        for (size_t i : order) complete(i);
    }
    RunResult result;
    result.outcome = run.Accepted() ? DeferredOutcome::Accepted
                                    : DeferredOutcome::Failed;
    for (size_t i = 0; i < jobs.size(); ++i)
        if (outcomes[i] == DeferredOutcome::Failed && !errors[i].empty())
            result.error = errors[i];
    const auto *dummy =
        static_cast<const DummyAccumulator *>(run.Accumulator(kDummyKind));
    result.ordered = dummy->Ordered();
    result.finals = stats.finals.load();
    result.records_seen = stats.records.load();
    CHECK(!run.Failed() == run.Accepted());
    return result;
}

std::vector<size_t> Ascending(size_t n) {
    std::vector<size_t> order(n);
    std::iota(order.begin(), order.end(), 0);
    return order;
}

void SchedulingAndOrder() {
    const std::vector<Output> outputs{Plain(10)};
    std::mt19937 rng(7);
    for (int round = 0; round < 50; ++round) {
        const size_t n = 1 + rng() % 12;
        std::vector<InputJob> jobs(n);
        std::vector<uint64_t> canonical;
        for (size_t i = 0; i < n; ++i) {
            const uint64_t a = 2 * (i + 1), b = 2 * (i + 3);
            jobs[i].records = Dummy({a, b});
            canonical.insert(canonical.end(), {a, b});
        }
        auto order = Ascending(n);
        const auto sequential = Execute(outputs, jobs, order, false);
        std::shuffle(order.begin(), order.end(), rng);
        const auto shuffled = Execute(outputs, jobs, order, false);
        const auto parallel = Execute(outputs, jobs, order, true);
        for (const auto *r : {&sequential, &shuffled, &parallel}) {
            CHECK(r->outcome == DeferredOutcome::Accepted);
            // Phase 2 ran exactly once, in the last completion.
            CHECK(r->finals == 1);
            // Records are seen by input index, then witness index.
            CHECK(r->ordered == canonical);
        }
    }
}

void FinalRulesAndFailFast() {
    const std::vector<Output> outputs{Plain(10)};
    // An odd total fails the dummy's final rule, whatever the order.
    for (bool threads : {false, true}) {
        std::vector<InputJob> jobs(3);
        jobs[0].records = Dummy({2});
        jobs[1].records = Dummy({3});
        jobs[2].records = Dummy({4});
        const auto r = Execute(outputs, jobs, {2, 0, 1}, threads);
        CHECK(r.outcome == DeferredOutcome::Failed && r.error == "dummy-odd");
        CHECK(r.finals == 1);
    }
    // Upper-bound rules fail inline: phase 2 never runs.
    for (bool threads : {false, true}) {
        std::vector<InputJob> jobs(4);
        for (auto &job : jobs) job.records = Dummy({4});
        const auto r = Execute(outputs, jobs, {3, 1, 2, 0}, threads, 10);
        CHECK(r.outcome == DeferredOutcome::Failed &&
              r.error == "dummy-over-cap");
        CHECK(r.finals == 0);
    }
}

void FailedInputsNeverReachPhaseTwo() {
    const std::vector<Output> outputs{Plain(10)};
    for (bool threads : {false, true}) {
        for (size_t failing = 0; failing < 4; ++failing) {
            std::vector<InputJob> jobs(4);
            for (size_t i = 0; i < jobs.size(); ++i)
                jobs[i].records = Dummy({uint64_t(100 + i)});
            jobs[failing].succeeds = false;
            const auto r =
                Execute(outputs, jobs, {3, 2, 1, 0}, threads, 1'000'000);
            CHECK(r.outcome == DeferredOutcome::Failed);
            CHECK(r.finals == 0);
            // The failed input's record was dropped before any inline update.
            for (uint64_t seen : r.ordered) CHECK(seen != 100 + failing);
            CHECK(r.records_seen <= 3);
        }
    }
    // A second completion of the same input fails closed.
    DummyStats stats;
    const auto registry = WithDummy(10, stats);
    DeferredTxRun run(registry, DeferredTxView{outputs, 2});
    std::string error;
    CHECK(run.CompleteInput(0, true, Dummy({2}), error) ==
          DeferredOutcome::Pending);
    CHECK(run.CompleteInput(0, true, Dummy({2}), error) ==
              DeferredOutcome::Failed &&
          error == "deferred-input-completed-twice");
    CHECK(run.CompleteInput(1, true, {}, error) == DeferredOutcome::Abandoned);
    CHECK(stats.finals.load() == 0 && !run.Accepted());
}

void ConsensusKinds() {
    Output stateful = Plain(50);
    stateful.flags = OUTPUT_FLAG_HAS_STATE;
    stateful.state_root.fill(9);
    const std::vector<Output> outputs{Plain(100), stateful};
    auto run = [&](std::vector<DeferredRecords> per_input,
                   std::string &error) {
        return RunDeferredChecks(DeferredCheckRegistry::Consensus(),
                                 DeferredTxView{outputs, per_input.size()},
                                 per_input, error);
    };
    auto claim = [](uint64_t amount, std::vector<uint16_t> matches) {
        DeferredRecords r;
        r.Add(kOutputClaimsKind, 0, OutputClaim{amount, std::move(matches)});
        return r;
    };
    auto authorize = [](uint16_t j) {
        DeferredRecords r;
        r.Add(kStateAuthorizationKind, 0, StateAuthorization{{j}});
        return r;
    };
    std::string error;
    // State authorization: pass and fail.
    CHECK(run({authorize(1)}, error) == DeferredOutcome::Accepted);
    CHECK(run({claim(0, {0})}, error) == DeferredOutcome::Failed &&
          error == "state-output-unauthorized");
    CHECK(run({authorize(2)}, error) == DeferredOutcome::Failed);
    // Output claims: pass and fail.
    {
        auto a = claim(60, {0});
        a.Merge(authorize(1));
        CHECK(run({a, claim(40, {0})}, error) == DeferredOutcome::Accepted);
        CHECK(run({a, claim(41, {0})}, error) == DeferredOutcome::Failed &&
              error == "output-overclaimed");
        CHECK(run({a, claim(0, {7})}, error) == DeferredOutcome::Failed &&
              error == "output-overclaimed");
    }
    // The kind assigns by maximum flow: output 0 is full, the second
    // claim also matches the (authorized, stateful) output 1.
    {
        auto a = claim(100, {0});
        a.Merge(authorize(1));
        CHECK(run({a, claim(50, {0, 1})}, error) == DeferredOutcome::Accepted);
        CHECK(run({a, claim(51, {0, 1})}, error) == DeferredOutcome::Failed &&
              error == "output-overclaimed");
        // An empty match mask is rejected inline.
        CHECK(run({a, claim(0, {})}, error) == DeferredOutcome::Failed &&
              error == "output-overclaimed");
    }
    // Canonical order of reject reasons: state authorization precedes
    // claims in the registry.
    CHECK(run({claim(1000, {0})}, error) == DeferredOutcome::Failed &&
          error == "state-output-unauthorized");
    // CollectOutputClaims reads claims by input, whatever the completion
    // order.
    {
        DeferredTxRun tx(DeferredCheckRegistry::Consensus(),
                         DeferredTxView{outputs, 3});
        auto a = claim(1, {0});
        a.Merge(authorize(1));
        CHECK(tx.CompleteInput(2, true, claim(3, {0}), error) ==
              DeferredOutcome::Pending);
        CHECK(tx.CompleteInput(0, true, std::move(a), error) ==
              DeferredOutcome::Pending);
        CHECK(tx.CompleteInput(1, true, claim(2, {0}), error) ==
              DeferredOutcome::Accepted);
        const auto claims = CollectOutputClaims(tx);
        CHECK(claims.size() == 3 && claims[0].amount == 1 &&
              claims[1].amount == 2 && claims[2].amount == 3);
        CHECK(tx.ProducedRecords());
    }
    // A run with no records still applies the final rules.
    {
        const std::vector<Output> plain{Plain(1)};
        DeferredTxRun tx(DeferredCheckRegistry::Consensus(),
                         DeferredTxView{plain, 1});
        CHECK(tx.CompleteInput(0, true, {}, error) ==
                  DeferredOutcome::Accepted &&
              !tx.ProducedRecords());
        DeferredTxRun none(DeferredCheckRegistry::Consensus(),
                           DeferredTxView{outputs, 0});
        CHECK(none.FinishWithoutInputs(error) == DeferredOutcome::Failed &&
              error == "state-output-unauthorized");
    }
}

// Gale/Hall condition: the claims are feasible iff every subset S of claims
// asks for at most the total value of the outputs matched by S.
bool BruteForceFeasible(const std::vector<OutputClaim> &claims,
                        const std::vector<uint64_t> &values) {
    for (uint32_t subset = 1; subset < (1u << claims.size()); ++subset) {
        __uint128_t asked = 0, room = 0;
        std::vector<uint8_t> neighbours(values.size());
        for (size_t c = 0; c < claims.size(); ++c) {
            if (!((subset >> c) & 1)) continue;
            asked += claims[c].amount;
            for (uint16_t j : claims[c].matches) neighbours[j] = 1;
        }
        for (size_t j = 0; j < values.size(); ++j)
            if (neighbours[j]) room += values[j];
        if (asked > room) return false;
    }
    return true;
}

void MaxFlowFeasibility() {
    using Claims = std::vector<OutputClaim>;
    using Values = std::vector<uint64_t>;
    auto feasible = [](const Claims &claims, const Values &values) {
        return OutputClaimsFeasible(claims, values);
    };
    // A greedy first-match assignment fails (A takes output 0, then B has
    // nowhere to go), but A -> 1, B -> 0 exists.
    CHECK(feasible({{10, {0, 1}}, {10, {0}}}, {10, 10}));
    // Output 0 is exhausted by the first claim; the second claim also
    // matches output 1, which has room.
    CHECK(feasible({{5, {0}}, {10, {0, 1}}}, {5, 20}));
    // Over-claims: in total, and locally (both claims only fit output 0,
    // whatever output 1 holds).
    CHECK(!feasible({{10, {0, 1}}, {11, {0, 1}}}, {10, 10}));
    CHECK(!feasible({{6, {0}}, {6, {0}}}, {10, 1000}));
    // Overlapping match sets around a cycle: each pair of claims shares an
    // output. Exactly enough room is feasible; one unit less is not.
    CHECK(feasible({{8, {0, 1}}, {8, {1, 2}}, {8, {0, 2}}}, {8, 8, 8}));
    CHECK(!feasible({{8, {0, 1}}, {8, {1, 2}}, {8, {0, 2}}}, {8, 8, 7}));
    // A Hall violation hidden among overlapping sets: claims 1 and 2 only
    // reach output 1.
    CHECK(!feasible({{1, {0, 1}}, {3, {1}}, {3, {1}}}, {100, 5}));
    // A flow may split one claim across the outputs it matches.
    CHECK(feasible({{10, {0, 1}}}, {5, 5}));
    // Zero claims are always feasible (they still had to match).
    CHECK(feasible({{0, {0}}, {0, {0}}}, {0}));
    // 128-bit totals: two maximal claims over two maximal outputs, and one
    // more unit overflows nothing but is infeasible.
    CHECK(feasible({{UINT64_MAX, {0, 1}}, {UINT64_MAX, {0, 1}}},
                   {UINT64_MAX, UINT64_MAX}));
    CHECK(!feasible({{UINT64_MAX, {0, 1}}, {UINT64_MAX, {0, 1}}, {1, {1}}},
                    {UINT64_MAX, UINT64_MAX}));
    // The flow into each output is a valid assignment.
    {
        std::vector<__uint128_t> assigned;
        CHECK(OutputClaimsFeasible(Claims{{10, {0, 1}}, {10, {0}}}, Values{10, 15},
                                   &assigned));
        CHECK(assigned.size() == 2 && assigned[0] == 10 && assigned[1] == 10);
    }
    // Randomized: the maximum flow agrees with the subset condition.
    std::mt19937 rng(11);
    for (int round = 0; round < 3000; ++round) {
        const size_t outputs = 1 + rng() % 5, n = 1 + rng() % 7;
        Values values(outputs);
        for (auto &v : values) v = rng() % 12;
        Claims claims(n);
        for (auto &claim : claims) {
            claim.amount = rng() % 9;
            for (size_t j = 0; j < outputs; ++j)
                if (rng() % 2) claim.matches.push_back(uint16_t(j));
            if (claim.matches.empty())
                claim.matches.push_back(uint16_t(rng() % outputs));
        }
        CHECK(feasible(claims, values) == BruteForceFeasible(claims, values));
    }
}

void ConservationKinds() {
    std::string error;
    // Native: inputs add, outputs subtract, the remainder is the fee.
    {
        NativeConservation native;
        CHECK(native.AddInput(700) && native.AddInput(300));
        CHECK(native.AddOutput(990));
        CHECK(native.Check() == ConservationFailure::None &&
              native.Fee() == 10 && native.Final(error));
        CHECK(native.AddOutput(11));
        CHECK(native.Check() == ConservationFailure::NativeInflation &&
              !native.Final(error) && error == "native-inflation");
        NativeConservation huge;
        CHECK(huge.AddInput(~__uint128_t{0}) && !huge.AddInput(1));
    }
    Hash32 a{}, b{};
    a.fill(0xaa);
    b.fill(0xbb);
    // Token: balanced transfers pass; a positive delta needs one mint.
    {
        TokenConservation token;
        CHECK(token.AddInput(a, 50) && token.AddOutput(a, 30) &&
              token.AddOutput(a, 20));
        CHECK(token.Check() == ConservationFailure::None);
        CHECK(token.AddOutput(a, 1)); // a: 51 out of 50 in
        CHECK(token.Check() == ConservationFailure::TokenInflation &&
              !token.Final(error) && error == "token-inflation");
        token.AddMint(a);
        CHECK(token.Check() == ConservationFailure::None);
        token.AddMint(a); // a second mint of a finds its delta taken
        CHECK(token.Check() == ConservationFailure::MintWithoutDelta);
    }
    {
        // A mint whose token has no positive delta, and burns (outputs) of
        // a token below its inputs.
        TokenConservation token;
        CHECK(token.AddInput(b, 10) && token.AddOutput(b, 4));
        CHECK(token.Check() == ConservationFailure::None);
        token.AddMint(b);
        CHECK(token.Check() == ConservationFailure::MintWithoutDelta &&
              !token.Final(error) && error == "mint-without-positive-delta");
    }
}

class CountingHook final : public DeferredBlockHook {
public:
    explicit CountingHook(bool fail) : fail_(fail) {}
    std::string_view Name() const override { return "test-counting-hook"; }
    bool Check(std::span<const DeferredTxRun *const> transactions,
               std::string &error) const override {
        calls.fetch_add(1);
        seen.store(transactions.size());
        if (fail_) error = "test-block-hook";
        return !fail_;
    }
    mutable std::atomic<size_t> calls{0};
    mutable std::atomic<size_t> seen{0};

private:
    bool fail_;
};

void BlockHook() {
    std::string error;
    // The consensus registry's block phase is a no-op.
    CHECK(DeferredCheckRegistry::Consensus().BlockHooks().empty());
    CHECK(RunDeferredBlockChecks(DeferredCheckRegistry::Consensus(), {},
                                 error));
    const std::vector<Output> outputs{Plain(1)};
    DeferredTxRun a(DeferredCheckRegistry::Consensus(),
                    DeferredTxView{outputs, 1});
    CHECK(a.CompleteInput(0, true, {}, error) == DeferredOutcome::Accepted);
    const std::vector<const DeferredTxRun *> runs{&a, &a};
    for (bool fail : {false, true}) {
        DeferredCheckRegistry registry;
        auto hook = std::make_shared<CountingHook>(fail);
        registry.AddBlockHook(hook);
        CHECK(RunDeferredBlockChecks(registry, runs, error) == !fail);
        CHECK(hook->calls.load() == 1 && hook->seen.load() == 2);
        if (fail) CHECK(error == "test-block-hook");
    }
}

} // namespace

int main() {
    try {
        SchedulingAndOrder();
        FinalRulesAndFailFast();
        FailedInputsNeverReachPhaseTwo();
        ConsensusKinds();
        MaxFlowFeasibility();
        ConservationKinds();
        BlockHook();
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "Lotus V2 deferred check vectors pass\n";
    return 0;
}
