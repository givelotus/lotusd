// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "store_engine.h"
#include <snowstorm/stats.h>
namespace snowstorm::detail {
struct DonorConnection {
    PeerId peer{};
    std::uint64_t generation{};
    bool operator==(const DonorConnection &) const = default;
};
/** One reservation for the union of mathematical Pending and active fetch IDs.
 * Expected hash is meaningful only in awaiting state; no per-ID tip copy.
 */
struct PendingEntry {
    ShortId item{};
    std::uint64_t supports{};
    FetchId token{};
    DonorConnection donor{};
    TxHash expected_hash{};
    FetchState state{FetchState::in_flight};
};
struct PendingDonor { ShortId item{}; DonorConnection connection; std::uint64_t order{}; };
struct PendingUnavailable { ShortId item{}; DonorConnection connection; };
struct FetchTicket { ShortId item{}; PeerId peer{}; FetchId token{}; };
/** Returned immediately, never retained as an oversized public Stats view.
 * Node applies model/confidence invalidation before processing another event.
 * On suspension, keep confidence for own IDs and surviving is_pending IDs;
 * clear_confidence never means discarding preserved awaiting support.
 * A nonzero fetch token is an actual newly started fetch, not an intention.
 */
struct PendingEffect {
    Error error{Error::ok};
    Limit limit{Limit::pending_fetch_union};
    ShortId item{};
    PeerId blamed{};
    Misbehavior reason{Misbehavior::body_not_found};
    bool penalize{}, clear_models{}, clear_confidence{}, suspended{}, pending_changed{};
    FetchTicket fetch;
};
enum class ClaimDisposition { eligible, admitted, probation, rejected, local_rejected, suspended };
struct PendingCapacity {
    std::size_t entries{}, donors{}, unavailable{}, probation{}, rejected{}, local_rejected{};
};
struct PendingMemory {
    PendingCapacity capacity;
    std::size_t requested_bytes() const noexcept {
        return capacity.entries * sizeof(PendingEntry) + capacity.donors * sizeof(PendingDonor) +
            capacity.unavailable * sizeof(PendingUnavailable) +
            (capacity.probation + capacity.rejected + capacity.local_rejected) * sizeof(ShortId);
    }
};
/** Bounded global pooling/body lifecycle. Store and Limits outlive this owner.
 * Only prepare allocates; mutating calls require prepared capacity and never
 * invoke host code. Node recomputes actual decoded-plus support from open models after every close
 * and applies returned cross-model effects before its next protocol action.
 */
class Pending {
    const StoreEngine &own_;
    const Limits &limits_;
    ShortIdKey key_;
    std::vector<PendingEntry> entries_;
    std::vector<PendingDonor> donors_;
    std::vector<PendingUnavailable> unavailable_;
    std::vector<ShortId> probation_, rejected_, local_rejected_;
    FetchId last_token_{};
    std::uint64_t last_discovery_{}, height_generation_{};
    bool suspended_{};
    PendingEntry *find(ShortId item) noexcept;
    const PendingEntry *find(ShortId item) const noexcept;
    bool pending(const PendingEntry &entry) const noexcept;
    const PendingDonor *first_donor(ShortId item, std::optional<DonorConnection> skip = {}) const noexcept;
    bool has_donor(ShortId item, DonorConnection connection) const noexcept;
    bool unavailable(ShortId item, DonorConnection connection) const noexcept;
    Error validate_result(ShortId item, const BodyResult &result) const noexcept;
    PendingEffect preflight_failure(ShortId item, DonorConnection donor, const BodyResult &result) const noexcept;
    PendingEffect failure(PendingEntry &entry, const BodyResult &result) noexcept;
    void erase_donors(ShortId item) noexcept;
    void erase_entry(ShortId item) noexcept;
    FetchTicket start(PendingEntry &entry, const PendingDonor &donor) noexcept;
    PendingEffect suspend(ShortId item, Limit limit) noexcept;
public:
    Pending(const StoreEngine &own, const Limits &limits, ShortIdKey key) noexcept
        : own_(own), limits_(limits), key_(key) {}
    Error prepare(PendingCapacity capacity);
    ClaimDisposition disposition(ShortId item) const noexcept;
    bool is_pending(ShortId item) const noexcept;
    /** Read-only batch preflight for an atomic decode group; no donor insertion
     * or host action is performed from the Peeler precommit policy. */
    PendingEffect check_discover(std::span<const ShortId> items, DonorConnection donor) const noexcept;
    PendingEffect discover(ShortId item, DonorConnection donor) noexcept;
    /** Count only live decoded_support entries, never copied/own-removal plus. */
    PendingEffect support(ShortId item, std::uint64_t decoded_plus_count) noexcept;
    PendingEffect body_result(DonorConnection donor, ShortId item, const BodyResult &result) noexcept;
    /** Call after successful authoritative Store admission. Awaiting records for
     * a different colliding hash survive; in-flight records are consumed. */
    PendingEffect admitted(ShortId item, const TxHash &hash) noexcept;
    Error disconnect(DonorConnection donor, std::span<PendingEffect> effects, std::size_t &written) noexcept;
    /** Cancels the old height, preserving never-reused fetch-token identity. */
    Error reset(ShortIdKey key) noexcept;
    bool suspended() const noexcept { return suspended_; }
    std::uint64_t height_generation() const noexcept { return height_generation_; }
    std::span<const PendingEntry> entries() const noexcept { return entries_; }
    std::span<const PendingDonor> donors() const noexcept { return donors_; }
    std::span<const PendingUnavailable> unavailable() const noexcept { return unavailable_; }
    std::span<const ShortId> probation() const noexcept { return probation_; }
    std::span<const ShortId> rejected() const noexcept { return rejected_; }
    std::span<const ShortId> local_rejected() const noexcept { return local_rejected_; }
    PendingMemory memory() const noexcept;
};
} // namespace snowstorm::detail
