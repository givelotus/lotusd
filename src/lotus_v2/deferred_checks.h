// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Generic two-phase (deferred) transaction checks.
//
// Phase 1 runs each input's invocations, possibly in parallel. A successful
// input hands its staged records to every registered check kind's inline
// update. Inputs share no mutable state other than these accumulators, and
// every accumulator tolerates any update order.
//
// Phase 2 runs once per transaction, after every input succeeded: each
// kind's optional final rule reads its accumulator. Kinds see records
// ordered by input index, then witness index, whatever order the inputs ran
// in. A failed input marks the transaction failed and phase 2 is skipped,
// so a failed input's records never reach phase 2.
//
// Scheduling is separate from the kinds. `DeferredTxRun` keeps an atomic
// count of pending inputs; the input that brings it to zero runs phase 2,
// so block validation needs no block-wide barrier. Sequential callers
// (mempool, RPC, simulation) complete inputs in ascending order through the
// same object, which is also the canonical order used to pick a reject
// reason when several rules fail.
//
// Adding a kind means one record type, one accumulator and one registry
// entry; nothing in the scheduler changes.
#ifndef LOTUS_V2_DEFERRED_CHECKS_H
#define LOTUS_V2_DEFERRED_CHECKS_H

#include "output.h"

#include <any>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lotus::v2 {

// Identity of a check kind. Records refer to their kind by the address of
// its key, so two kinds never collide even if they share a name.
struct DeferredKindKey {
    const char *name;
};

// One typed record staged by a successful invocation.
struct DeferredRecord {
    const DeferredKindKey *kind = nullptr;
    uint16_t witness = 0;
    std::any payload;
};

// The records of one input (or one invocation while it runs), in the order
// they were staged. An invocation's records are merged into its input's
// only when the invocation succeeds.
class DeferredRecords {
public:
    template <typename T>
    void Add(const DeferredKindKey &kind, uint16_t witness, T &&payload) {
        items_.push_back(
            DeferredRecord{&kind, witness, std::any(std::forward<T>(payload))});
    }
    void Merge(DeferredRecords &&other) {
        for (auto &item : other.items_) items_.push_back(std::move(item));
        other.items_.clear();
    }
    void Merge(const DeferredRecords &other) {
        items_.insert(items_.end(), other.items_.begin(), other.items_.end());
    }
    bool Empty() const { return items_.empty(); }
    void Clear() { items_.clear(); }
    std::span<const DeferredRecord> Items() const { return items_; }
    // Payloads of one kind, in staging order.
    template <typename T>
    std::vector<const T *> Of(const DeferredKindKey &kind) const {
        std::vector<const T *> out;
        for (const auto &item : items_)
            if (item.kind == &kind) out.push_back(std::any_cast<T>(&item.payload));
        return out;
    }

private:
    std::vector<DeferredRecord> items_;
};

// The parts of a transaction every kind may read. The spans must outlive
// the run that uses them.
struct DeferredTxView {
    std::span<const Output> outputs;
    size_t input_count = 0;
};

// Per-transaction state of one kind.
class DeferredAccumulator {
public:
    virtual ~DeferredAccumulator() = default;
    // Inline update with the records of one successful input. Called at most
    // once per input, concurrently for distinct inputs; must be order-free.
    // Returning false fails the transaction immediately (an upper-bound rule
    // that the input pushed over its limit).
    virtual bool Update(uint32_t input, const DeferredRecords &records,
                        std::string &error) {
        (void)input;
        (void)records;
        (void)error;
        return true;
    }
    // Final rule, run once after every input succeeded. Kinds without one
    // keep the default.
    virtual bool Final(std::string &error) {
        (void)error;
        return true;
    }
};

// A registered kind: a name and a factory for its per-transaction state.
class DeferredCheckKind {
public:
    explicit DeferredCheckKind(const DeferredKindKey &key) : key_(key) {}
    virtual ~DeferredCheckKind() = default;
    const DeferredKindKey &Key() const { return key_; }
    std::string_view Name() const { return key_.name; }
    virtual std::unique_ptr<DeferredAccumulator>
    NewAccumulator(const DeferredTxView &view) const = 0;

private:
    const DeferredKindKey &key_;
};

class DeferredTxRun;

// Optional phase 3: rules spanning the transactions of one block. None exist
// yet; the consensus registry has a no-op hook so the call site and its
// tests are in place.
class DeferredBlockHook {
public:
    virtual ~DeferredBlockHook() = default;
    virtual std::string_view Name() const = 0;
    virtual bool Check(std::span<const DeferredTxRun *const> transactions,
                       std::string &error) const = 0;
};

// An ordered list of kinds. The order is the canonical order of final rules
// (and so of reject reasons).
class DeferredCheckRegistry {
public:
    DeferredCheckRegistry() = default;
    // The consensus kinds that run over script records, in canonical
    // order: state authorization, then ENFORCEOUTPUT claims.
    static const DeferredCheckRegistry &Consensus();
    void Add(std::shared_ptr<const DeferredCheckKind> kind) {
        kinds_.push_back(std::move(kind));
    }
    void AddBlockHook(std::shared_ptr<const DeferredBlockHook> hook) {
        hooks_.push_back(std::move(hook));
    }
    std::span<const std::shared_ptr<const DeferredCheckKind>> Kinds() const {
        return kinds_;
    }
    std::span<const std::shared_ptr<const DeferredBlockHook>> BlockHooks() const {
        return hooks_;
    }

private:
    std::vector<std::shared_ptr<const DeferredCheckKind>> kinds_;
    std::vector<std::shared_ptr<const DeferredBlockHook>> hooks_;
};

// The phase-2 result once known.
enum class DeferredOutcome {
    Pending,  // other inputs have not completed yet
    Failed,    // this input, an inline update, or a final rule failed
    Abandoned, // another input already failed the transaction
    Accepted,  // every input succeeded and every final rule passed
};

// One validation run of one transaction. Never cached or reused: create a
// fresh run for every validation.
class DeferredTxRun {
public:
    DeferredTxRun(const DeferredCheckRegistry &registry, DeferredTxView view);
    DeferredTxRun(const DeferredTxRun &) = delete;
    DeferredTxRun &operator=(const DeferredTxRun &) = delete;

    // Completes input `input` (thread-safe across distinct inputs). With
    // `succeeded` false the records are dropped and the transaction fails.
    // Otherwise each kind's inline update sees them; when this completion
    // brings the pending count to zero and nothing failed, the final rules
    // run here, in registry order. `error` receives the reason when this
    // call reports Failed because of an inline or final rule.
    DeferredOutcome CompleteInput(uint32_t input, bool succeeded,
                                  DeferredRecords &&records,
                                  std::string &error);
    // Runs the final rules of a transaction with no inputs (every
    // completion path above needs at least one input).
    DeferredOutcome FinishWithoutInputs(std::string &error);
    // Whether any input staged records. Such transactions must not be
    // answered from a pass/fail script cache.
    bool ProducedRecords() const {
        return produced_.load(std::memory_order_acquire);
    }
    bool Failed() const { return failed_.load(std::memory_order_acquire); }
    // Valid once Accepted: every input completed and the finals passed.
    bool Accepted() const { return accepted_.load(std::memory_order_acquire); }
    // The accumulator of `kind`, or null if the registry lacks it. Read it
    // only after the run is Accepted (or from block hooks).
    const DeferredAccumulator *Accumulator(const DeferredKindKey &kind) const;
    const DeferredTxView &View() const { return view_; }

private:
    const DeferredCheckRegistry &registry_;
    DeferredTxView view_;
    std::vector<std::unique_ptr<DeferredAccumulator>> accumulators_;
    std::atomic<size_t> pending_;
    std::vector<std::atomic<uint8_t>> completed_;
    std::atomic<bool> failed_{false};
    std::atomic<bool> produced_{false};
    std::atomic<bool> accepted_{false};
};

// Sequential driver over records already collected per input, used by the
// RPC and simulation paths: completes inputs in ascending order, then
// reports Accepted or Failed (with `error`).
DeferredOutcome RunDeferredChecks(const DeferredCheckRegistry &registry,
                                  const DeferredTxView &view,
                                  std::span<const DeferredRecords> per_input,
                                  std::string &error);

// Phase 3 over the accepted runs of one block, in block order.
bool RunDeferredBlockChecks(const DeferredCheckRegistry &registry,
                            std::span<const DeferredTxRun *const> runs,
                            std::string &error);

// ---------------------------------------------------------------------------
// Consensus kinds.

// HAS_STATE outputs must each be authorized by a state-constraining
// ENFORCEOUTPUT. Record: StateAuthorization. Final: every HAS_STATE output
// was set ("state-output-unauthorized").
extern const DeferredKindKey kStateAuthorizationKind;
struct StateAuthorization {
    std::vector<uint16_t> outputs;
    bool operator==(const StateAuthorization &) const = default;
};

// ENFORCEOUTPUT claims. Record: OutputClaim, the claimed amount and the
// outputs its template matched.
extern const DeferredKindKey kOutputClaimsKind;
struct OutputClaim {
    uint64_t amount = 0;
    std::vector<uint16_t> matches;
    bool operator==(const OutputClaim &) const = default;
};

// Claims in canonical order (input, then witness, then staging order).
std::vector<OutputClaim> CollectOutputClaims(const DeferredTxRun &run);
// The payloads of one kind in a record list, by value, for comparisons.
std::vector<OutputClaim> OutputClaimsOf(const DeferredRecords &records);
std::vector<StateAuthorization>
StateAuthorizationsOf(const DeferredRecords &records);

// ---------------------------------------------------------------------------
// Conservation kinds. Their contributions are structural (input and output
// values), applied when the transaction is prepared; no script contributes,
// so their final rules are decided before any input runs, by the caller
// that prepares the transaction (the ordinary V2 path and the node's
// CheckTxInputs variants). Each caller keeps its own reject reasons and its
// historical precedence between these and its other structural rules: the
// failure code below is mapped by the caller.

enum class ConservationFailure {
    None,
    Overflow,              // a running total does not fit
    NativeInflation,       // native outputs exceed native inputs
    MintWithoutDelta,      // a mint input whose token has no positive delta
    TokenInflation,        // a positive token delta without a mint input
};

// Generic names of the conservation failures (callers may map the code to
// their own reasons instead).
const char *ConservationFailureName(ConservationFailure failure);

// Native conservation: one counter per transaction. Inputs add, outputs
// (including burns) subtract; the remainder is the fee and must be >= 0.
class NativeConservation final : public DeferredAccumulator {
public:
    bool AddInput(__uint128_t value);
    bool AddOutput(__uint128_t value);
    ConservationFailure Check() const;
    bool Final(std::string &error) override;
    __uint128_t Inputs() const { return inputs_; }
    __uint128_t Outputs() const { return outputs_; }
    // Valid when Check() passes.
    __uint128_t Fee() const { return inputs_ - outputs_; }

private:
    __uint128_t inputs_ = 0;
    __uint128_t outputs_ = 0;
};

// Token conservation: one counter per token id. Spent amounts add, outputs
// (including burns) subtract. Final: every token whose outputs exceed its
// inputs (a positive delta) is matched by exactly one mint input for that
// token, and every mint input names a token with a positive delta.
class TokenConservation final : public DeferredAccumulator {
public:
    struct Totals {
        __uint128_t inputs = 0;
        __uint128_t outputs = 0;
    };
    bool AddInput(const Hash32 &token, __uint128_t value);
    bool AddOutput(const Hash32 &token, __uint128_t value);
    // Mint inputs in transaction order.
    void AddMint(const Hash32 &token) { mints_.push_back(token); }
    ConservationFailure Check() const;
    bool Final(std::string &error) override;
    const std::map<Hash32, Totals> &PerToken() const { return totals_; }

private:
    std::map<Hash32, Totals> totals_;
    std::vector<Hash32> mints_;
};

} // namespace lotus::v2

#endif
