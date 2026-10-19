// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Phase 2 of ENFORCEOUTPUT: the maximum-flow claim assignment, at the
// per-transaction cap on (claim, matching output) pairs, and the time of
// one VM cost unit, from which the per-pair weight is set.

#include <bench/bench.h>
#include <lotus_v2/deferred_checks.h>
#include <lotus_v2/vm.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <random>
#include <set>
#include <vector>

namespace {

using lotus::v2::OutputClaim;

struct ClaimGraph {
    std::vector<OutputClaim> claims;
    std::vector<uint64_t> values;
};

constexpr size_t kMaxOutputs = 256;

// The slowest shape found (see the commit adding this file): pairs of
// adjacent outputs on a chain of 256, each claim assigned to the upper end,
// and one more claim on output 0 whose room is at the far end. Augmenting
// paths run along the chain, so Dinic needs a phase per path length. It is
// one unit short: infeasible, after the full search.
ClaimGraph Ladder(size_t pairs) {
    std::mt19937_64 rng(1);
    ClaimGraph g;
    g.values.assign(kMaxOutputs, 0);
    const size_t n = (pairs - 1) / 2;
    for (size_t i = 0; i < n; ++i) {
        const uint16_t a = uint16_t(i % (kMaxOutputs - 1));
        OutputClaim c;
        c.amount = 1 + rng() % 1'000'000;
        c.matches = {a, uint16_t(a + 1)};
        g.values[a + 1] += c.amount;
        g.claims.push_back(std::move(c));
    }
    g.claims.push_back(OutputClaim{1, {0}});
    g.values[kMaxOutputs - 1] += 1;
    return g;
}

// Random claims over two of 256 outputs, each with room planted on one of
// them: feasible, with many short augmenting paths.
ClaimGraph Planted(size_t pairs) {
    std::mt19937_64 rng(2);
    ClaimGraph g;
    g.values.assign(kMaxOutputs, 0);
    for (size_t i = 0; i < pairs / 2; ++i) {
        std::set<uint16_t> s;
        while (s.size() < 2) s.insert(uint16_t(rng() % kMaxOutputs));
        OutputClaim c;
        c.amount = 1 + rng() % 1'000'000;
        c.matches.assign(s.begin(), s.end());
        g.values[c.matches[rng() % 2]] += c.amount;
        g.claims.push_back(std::move(c));
    }
    return g;
}

// Every claim matches every output.
ClaimGraph Complete(size_t pairs) {
    std::mt19937_64 rng(3);
    ClaimGraph g;
    g.values.assign(kMaxOutputs, 0);
    for (size_t i = 0; i < pairs / kMaxOutputs; ++i) {
        OutputClaim c;
        c.amount = 1 + rng() % 1'000'000;
        for (size_t j = 0; j < kMaxOutputs; ++j) c.matches.push_back(uint16_t(j));
        g.values[rng() % kMaxOutputs] += c.amount;
        g.claims.push_back(std::move(c));
    }
    return g;
}

size_t Pairs(const ClaimGraph &g) {
    size_t p = 0;
    for (const auto &c : g.claims) p += c.matches.size();
    return p;
}

void RunFlow(benchmark::Bench &bench, const ClaimGraph &g, bool feasible) {
    assert(Pairs(g) <= lotus::v2::MAX_TX_CLAIM_PAIRS);
    bench.batch(Pairs(g)).unit("pair").run([&] {
        const bool ok = lotus::v2::OutputClaimsFeasible(g.claims, g.values);
        assert(ok == feasible);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

} // namespace

static void V2ClaimFlowLadderAtCap(benchmark::Bench &bench) {
    RunFlow(bench, Ladder(lotus::v2::MAX_TX_CLAIM_PAIRS), false);
}

static void V2ClaimFlowPlantedAtCap(benchmark::Bench &bench) {
    RunFlow(bench, Planted(lotus::v2::MAX_TX_CLAIM_PAIRS), true);
}

static void V2ClaimFlowCompleteAtCap(benchmark::Bench &bench) {
    RunFlow(bench, Complete(lotus::v2::MAX_TX_CLAIM_PAIRS), true);
}

// The time of one cost unit under the node schedule: an invocation of
// cheap stack opcodes (one unit each, plus one per script byte).
static void V2VmCostUnit(benchmark::Bench &bench) {
    std::vector<uint8_t> script{0x4e};
    while (script.size() + 2 <= NodeV2VmProfile().max_script_bytes) {
        script.push_back(0x7a); // DUP
        script.push_back(0x79); // DROP
    }
    const std::vector<lotus::v2::VmBytes> arguments;
    const auto probe = lotus::v2::EvaluateVmCharged(
        script, arguments, NodeV2VmProfile(), NodeV2VmCost());
    assert(probe.invocation.status == lotus::v2::VmStatus::Success);
    bench.batch(uint64_t(probe.accounting_cost)).unit("cost unit").run([&] {
        const auto r = lotus::v2::EvaluateVmCharged(
            script, arguments, NodeV2VmProfile(), NodeV2VmCost());
        ankerl::nanobench::doNotOptimizeAway(r.accounting_cost);
    });
}

BENCHMARK(V2ClaimFlowLadderAtCap);
BENCHMARK(V2ClaimFlowPlantedAtCap);
BENCHMARK(V2ClaimFlowCompleteAtCap);
BENCHMARK(V2VmCostUnit);
