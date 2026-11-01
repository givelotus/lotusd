// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "peeler_engine.h"
#include "store_engine.h"
#include <snowstorm/messages.h>
namespace snowstorm::detail {
/** Actual-decode provenance belongs only to this live plus entry. */
struct SessionPlusEntry { ShortId item{}; bool decoded{}; };
/** Requester membership model. Store and Limits outlive this owner. Explicit
 * prepare() performs proportional growth outside allocation-free peel/own_delta.
 * Node owns correlation, host policy, donor actions, and evidence-window release.
 */
class SessionModel {
    const StoreEngine &own_;
    const Limits &limits_;
    std::unique_ptr<PeelerEngine> engine_;
    std::vector<SessionPlusEntry> plus_;
    std::vector<ShortId> minus_, exclusions_;
    Root root_{};
    Sequence snapshot_{}, current_{};
    std::uint64_t version_{}, snapshot_size_{}, budget_{}, reference_at_zero_{};
    std::int64_t initial_zero_{};
    bool active_{}, inferred_{};
    struct RunContext { SessionModel &model; DecodePolicy policy; PeelObserver observer; };
    static Error accept(void *context, const DecodeResult &decoded) noexcept;
    static void committed(void *context, const DecodeAudit &proof) noexcept;
    Error create_engine();
    bool has_plus(ShortId item) const noexcept;
    void insert_plus(ShortId item, bool decoded) noexcept;
    void erase_plus(ShortId item) noexcept;
public:
    SessionModel(const StoreEngine &own, const Limits &limits) noexcept : own_(own), limits_(limits) {}
    Error open(std::span<const ShortId> pending);
    /** Validate pinned flags/metadata before a RootMatched decision, without
     * constructing an engine or accepting raw-snapshot evidence. */
    Error check_metadata(const ReconSymbols &response, std::optional<std::uint64_t> known) const noexcept;
    Error prepare_membership(std::size_t plus, std::size_t minus);
    Error prepare(std::size_t reference, std::size_t symbols, std::size_t claims,
                  std::size_t plus, std::size_t minus);
    Error append(const ReconSymbols &response, std::optional<std::uint64_t> known);
    PeelResult run(std::span<SignedItem> output, std::span<DecodeAudit> audit,
                   DecodePolicy policy = {}, PeelObserver observer = {}) noexcept;
    /** Called after Store mutation; the caller preflights/prepares before it. */
    Error own_delta(ShortId item, Sign sign) noexcept;
    /** Pool a positive into an open model, only if neither plus nor minus masks
     * it. Caller prepares membership/reference capacity and checks global policy. */
    Error import_pending(ShortId item) noexcept;
    /** Sequential next fragment after a completed response; uses the current
     * residual0 and actual normal-response wire overhead with known exclusions. */
    Error next_range(std::uint64_t stuck, std::int32_t residual_zero,
                     SymbolIndex next, Range &range) const;
    void compact_done() noexcept;
    void clear() noexcept;
    bool contains(ShortId item) const noexcept;
    void assert_reference() const noexcept;
    const PeelerEngine *engine() const noexcept { return engine_.get(); }
    std::span<const SessionPlusEntry> plus() const noexcept { return plus_; }
    bool decoded_support(ShortId item) const noexcept;
    std::span<const ShortId> minus() const noexcept { return minus_; }
    std::span<const ShortId> exclusions() const noexcept { return exclusions_; }
    std::size_t plus_capacity() const noexcept { return plus_.capacity(); }
    std::size_t minus_capacity() const noexcept { return minus_.capacity(); }
    std::size_t exclusions_capacity() const noexcept { return exclusions_.capacity(); }
    const Root &root() const noexcept { return root_; }
    Sequence snapshot() const noexcept { return snapshot_; }
    Sequence current() const noexcept { return current_; }
    std::uint64_t exclusion_version() const noexcept { return version_; }
    std::uint64_t snapshot_size() const noexcept { return snapshot_size_; }
    std::uint64_t symbol_budget() const noexcept { return budget_; }
    std::uint64_t reference_at_zero() const noexcept { return reference_at_zero_; }
    std::int64_t initial_zero() const noexcept { return initial_zero_; }
    bool inferred() const noexcept { return inferred_; }
};
} // namespace snowstorm::detail
