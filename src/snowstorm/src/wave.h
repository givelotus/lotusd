// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "params.h"
#include <snowstorm/voting.h>
#include <snowstorm/stats.h>
#include <random>
namespace snowstorm::detail {
struct WavePeer { PeerId peer{}; Time rtt{}; };
/** Borrowed canonical connected population; at() is pure and allocation-free. */
struct WavePopulation {
    const void *context{};
    std::size_t size{};
    WavePeer (*at)(const void *, std::size_t) noexcept{};
};
struct WaveSlot { PeerId peer{}; SessionId session{}; bool answered{}, matching{}, root_matched{}, abstain{}; };
struct ItemEvidence { bool eligible{}, yes{}, root_matched{}; SessionId session{}; };
/** Borrowed only during score(). The owner supplies pinned Done membership;
 * callbacks cannot mutate voting/model state, allocate, or invoke host code. */
struct EvidenceSource {
    const void *context{};
    ItemEvidence (*read)(const void *, PeerId, ShortId, WaveId) noexcept{};
};
struct EvidenceSink {
    void *context{};
    void (*record)(void *, const EvidenceAudit &) noexcept{};
};
struct WaveScore {
    Error error{Error::ok};
    bool scored{};
    double increment{}, before{}, after{};
};
/** Global owner, not a per-peer object. Fixed sample metadata does not consume
 * the narrow idle peer floor. Variable candidate IDs and confidence records are
 * reported at their actual capacities. Explicit prepare precedes hot methods. */
class VotingState {
    double beta_, epsilon_, confidence_{};
    VotingParameters parameters_{};
    std::minstd_rand random_;
    std::array<WaveSlot, params::VOTING_SAMPLE> slots_{};
    std::vector<ShortId> candidates_;
    std::vector<ConfidenceObservation> items_;
    Root root_{}, current_root_{};
    WaveId number_{};
    Time start_{}, deadline_{};
    std::uint64_t alternative_{}, prior_matches_{}, prior_sample_{};
    std::size_t sample_size_{};
    bool active_{}, invalidated_{}, prior_{}, frozen_{};
    std::uint64_t item_limit_;
    void score_item(ConfidenceObservation &item, EvidenceSource evidence, EvidenceSink sink) noexcept;
public:
    VotingState(double beta, double epsilon, std::uint64_t seed, std::uint64_t item_limit);
    Error prepare(std::size_t candidates, std::size_t confidence);
    /** Population changes abandon the old wave and all population estimates. */
    Error population(std::uint64_t size) noexcept;
    /** Body/root transitions reset C/frozen and invalidate the whole captured
     * sample. Root generation starts with the configured transaction alternative. */
    void root_changed(const Root &root) noexcept;
    /** All validation/deadline/capacity checks precede RNG or protocol mutation. */
    Error begin(WavePopulation peers, std::span<const ShortId> candidates, Time now) noexcept;
    bool reply(PeerId peer, PollId poll, bool normal, const Root &vote,
               const Root &current, SessionId session) noexcept;
    void discard_peer(PeerId peer) noexcept;
    bool due(Time now) const noexcept;
    WaveScore score(Time now, EvidenceSource evidence, EvidenceSink sink = {}) noexcept;
    /** Call after authoritative own mutation; preserve Lambda across Pending
     * admission. erase() starts a later independent lifetime at zero. */
    Error track(ShortId item, bool admitted, Sequence sequence) noexcept;
    void erase(ShortId item) noexcept;
    const ConfidenceObservation *find(ShortId item) const noexcept;
    bool candidate(ShortId item) const noexcept;
    bool freeze_transition(bool all_candidates_confirmed) noexcept;
    void reset(const Root &root) noexcept;
    WaveObservation observation() const;
    std::span<const WaveSlot> sample() const noexcept { return {slots_.data(),sample_size_}; }
    std::span<const ShortId> captured_candidates() const noexcept { return candidates_; }
    std::span<const ConfidenceObservation> items() const noexcept { return items_; }
    std::size_t candidate_capacity() const noexcept { return candidates_.capacity(); }
    std::size_t confidence_capacity() const noexcept { return items_.capacity(); }
    std::size_t allocated_bytes() const noexcept;
    const VotingParameters &parameters() const noexcept { return parameters_; }
    double confidence() const noexcept { return confidence_; }
    WaveId number() const noexcept { return number_; }
    bool active() const noexcept { return active_; }
    bool invalidated() const noexcept { return invalidated_; }
    Time deadline() const noexcept { return deadline_; }
};
/** Exact reconciled eligibility, distinct from Pending provenance. */
ItemEvidence reconciled_evidence(ShortId item, WaveId scoring, WaveId completed,
    SessionId session, Sequence own_sequence_at_done, std::optional<Sequence> admission,
    bool plus, bool member, bool excluded) noexcept;
} // namespace snowstorm::detail
