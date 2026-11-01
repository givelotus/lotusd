// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "store_engine.h"
#include <snowstorm/messages.h>
namespace snowstorm::detail {
/** Borrowed only during a new open; retained fields are copied before return. */
struct ResponderMetadata {
    Root root;
    std::uint64_t exclusion_version;
    std::span<const ShortId> exclusions;
    std::span<const TxHandle> candidates;
};
struct ResponderMemory {
    std::size_t raw_bodies{}, candidates{}, exclusions{}, served_indices{};
    std::size_t requested_bytes() const noexcept {
        return (raw_bodies + candidates) * sizeof(TxHandle) +
            exclusions * sizeof(ShortId) + served_indices * sizeof(SymbolIndex);
    }
};
/** One immutable responder snapshot per connection. Store must outlive this
 * owner. Node expires this owner immediately when its Store pin expires.
 * No host callback occurs here; candidate metadata belongs to the same open.
 */
class SessionResponder {
    StoreEngine &store_;
    SessionId highwater_{};
    std::uint64_t token_{}, declared_{}, budget_{}, exclusion_version_{};
    Sequence snapshot_{};
    Root root_{};
    std::vector<TxHandle> raw_bodies_, candidates_;
    std::vector<ShortId> exclusions_;
    std::vector<SymbolIndex> served_;
    Error open(const ReconReq &request, const ResponderMetadata &metadata,
               std::uint64_t token, const Limits &limits);
    Error route(const ReconReq &request, const ResponderMetadata *metadata,
                std::uint64_t token, const Limits &limits, ReconSymbols &response);
    Error normal(const ReconReq &request, const Limits &limits, ReconSymbols &response);
public:
    explicit SessionResponder(StoreEngine &store) noexcept : store_(store) {}
    ~SessionResponder();
    SessionResponder(const SessionResponder &) = delete;
    SessionResponder &operator=(const SessionResponder &) = delete;
    /** Static syntax/context validation precedes this call. New opens require
     * a globally unique local pin token and metadata; duplicates never repin.
     * Terminal wire outcomes return ok; structural faults return an Error.
     */
    Error respond(const ReconReq &request, const ResponderMetadata *metadata,
                  std::uint64_t token, const Limits &limits, ReconSymbols &response);
    void close(SessionId session) noexcept;
    void expire() noexcept;
    bool active() const noexcept { return token_ != 0; }
    bool sweep() noexcept;
    SessionId latest_session() const noexcept { return highwater_; }
    Sequence snapshot_sequence() const noexcept { return snapshot_; }
    std::span<const TxHandle> raw_bodies() const noexcept { return raw_bodies_; }
    std::span<const TxHandle> candidates() const noexcept { return candidates_; }
    std::span<const ShortId> exclusions() const noexcept { return exclusions_; }
    ResponderMemory memory() const noexcept;
};
} // namespace snowstorm::detail
