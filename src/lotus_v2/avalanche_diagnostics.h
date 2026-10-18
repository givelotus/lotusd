// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_DIAGNOSTICS_H
#define LOTUS_V2_AVALANCHE_DIAGNOSTICS_H
#include <array>
#include <cstdint>
#include <cstddef>
#include <limits>
namespace lotus::v2::ava {
// Diagnostics never feed protocol decisions. Counters saturate; gauges are
// current container sizes and are named live_* to distinguish them.
inline void IncrementDiagnostic(uint64_t &counter) {
    if(counter!=std::numeric_limits<uint64_t>::max()) ++counter;
}
struct PollDiagnostics {
    uint64_t queries_created{}, queries_expired{}, queries_cancelled{}, responses_matched{};
    // Applied means a matched response was processed, including duplicate or
    // inconclusive votes; it does not promise a confidence increase.
    uint64_t responses_applied{}, responses_ignored{}, responses_rejected{}, responses_local_failure{};
    uint64_t live_queries{}, live_records{};
    bool operator==(const PollDiagnostics &) const = default;
};
enum class PeerRejection {
    Signature, Framing, Content, LateResponseAbuse, DiscoveryCooldown,
    ProofCooldown, NegotiatedCapacity, PayloadCapacity, Other, Count
};
struct PeerDiagnostics {
    // These four count only response handler outcomes. The
    // rejection categories below cover all application commands, so response
    // rejections are also included there. Each rejection gets one category.
    uint64_t responses_applied{}, responses_ignored{}, responses_rejected{}, responses_local_failure{};
    uint64_t dead_applications{};
    std::array<uint64_t,static_cast<size_t>(PeerRejection::Count)> application_rejections{};
    bool operator==(const PeerDiagnostics &) const = default;
};
enum class DisconnectCause {
    Unknown, ApplicationRejected, DeadTarget, NegotiatedCapacity,
    TransportRequested, TransportEndOfStream, TransportStreamError,
    TransportStreamContract, TransportPeerRejected, TransportLocalFailure,
    TransportCapacity, TransportTimedOut, Count
};
struct DriverDiagnostics {
    // Queued means accepted into the adapter action queue, not socket-written.
    // Backpressure counts attempts, including retries of the same pending poll.
    uint64_t poll_actions_queued{}, poll_backpressure{}, poll_dead_targets{}, poll_capacity_rejected{};
    uint64_t discovery_dead_targets{}, discovery_capacity_rejected{}, dispatch_dead_targets{}, dispatch_local_failures{};
    // Public driver Handle outcomes count attempts; retained notices can retry.
    uint64_t dead_applications{}, applications_local_failure{};
    uint64_t disconnects{};
    // Exactly one cause per tracked connection removed. Unknown is explicit;
    // no external reason is inferred by subtracting overlapping counters.
    std::array<uint64_t,static_cast<size_t>(DisconnectCause::Count)> disconnect_causes{};
    bool operator==(const DriverDiagnostics &) const = default;
};
}
#endif
