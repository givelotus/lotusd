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
        for (const auto *claim : records.Of<OutputClaim>(kOutputClaimsKind)) {
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
    // Interim rule: each claim names one output, and the claims on output j
    // sum to at most its value.
    bool Final(std::string &error) override {
        std::vector<__uint128_t> claimed(outputs_.size());
        for (const auto &slot : per_input_) {
            for (const auto &claim : slot) {
                if (claim.matches.size() != 1) {
                    error = "output-overclaimed";
                    return false;
                }
                claimed[claim.matches[0]] += claim.amount;
            }
        }
        for (size_t j = 0; j < outputs_.size(); ++j) {
            if (claimed[j] > outputs_[j].value) {
                error = "output-overclaimed";
                return false;
            }
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
