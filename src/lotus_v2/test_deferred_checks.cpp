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
        BlockHook();
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "Lotus V2 deferred check vectors pass\n";
    return 0;
}
