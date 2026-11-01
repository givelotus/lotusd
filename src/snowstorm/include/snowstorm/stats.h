// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/peeler.h>
#include <snowstorm/messages.h>
/** @defgroup snowstorm_stats_contract Snowstorm stats public contract
 * §§5–8,10: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §10: unique-ID/body inventory; collision bodies have separate entries. */
struct BodyObservation {
    ShortId item{};
    TxId txid{};
    TxHash tx_hash{};
    Sequence admission_seq{};
};
/** §§6.4,10: exact allocated capacity attribution, including padding. */
struct AllocationObservation {
    Limit resource{Limit::admitted_ids};
    std::uint64_t live_records{};
    std::uint64_t capacity_records{};
    std::uint64_t record_bytes{};
    std::uint64_t variable_bytes{};
    std::uint64_t requested_bytes{};
    std::uint64_t maximum_records{};
};
/** §§6.2,8,10: truthful completion kind; RootMatched is never raw Done. */
enum class SessionState : std::uint8_t {
    idle, open, done, root_matched, expired, resource_limited, invalidated,
};
/** §§6.2,10: immutable value copy of current or evidence-window peer state. */
struct PeerStats {
    PeerId peer{};
    bool compatible{};
    std::uint64_t state_bytes{};
    std::uint64_t fixed_floor_bytes{};
    std::uint64_t dynamic_bytes{};
    std::uint64_t stored_symbols{};
    std::uint64_t symbols_requested{};
    std::uint64_t decode_steps{};
    std::uint64_t resends{};
    Time rtt{};
    SessionState state{SessionState::idle};
    SessionId session_id{};
    RequestId request_id{};
    PollId poll_id{};
    Sequence snapshot_seq{};
    Sequence current_seq{};
    Sequence own_seq_at_done{};
    WaveId done_wave{};
    WaveId evidence_expires_after_wave{};
    std::uint64_t snapshot_size{};
    std::uint64_t reference_bound{};
    std::uint64_t reference_size_at_symbol0{};
    std::int64_t initial_symbol0_count{};
    std::uint64_t symbol_budget{};
    Time original_sent_time{};
    Time latest_sent_time{};
    Time request_deadline{};
    bool request_outstanding{};
    std::vector<Range> outstanding_ranges;
    std::vector<ShortId> plus;
    std::vector<ShortId> minus;
    std::vector<ShortId> exclusions;
    std::vector<ShortId> unavailable;
    std::vector<ResidualObservation> residuals;
    Root pinned_root{};
    std::uint64_t exclusion_version{};
    std::vector<AllocationObservation> allocations;
};
/** §§6.3,10: body token state, including the result/callback gap. */
enum class FetchState : std::uint8_t { in_flight, awaiting_admission };
/** §§6.3,10: exactly one record per pending/fetching ID. */
struct FetchObservation {
    ShortId item{};
    PeerId peer{};
    FetchId fetch_id{};
    FetchState state{FetchState::in_flight};
    std::optional<TxHash> expected_tx_hash;
    TipContext tip_context{};
};
/** §§6.3,10: candidate donor identity, never authenticated remote truth. */
struct DonorObservation {
    ShortId item{};
    PeerId peer{};
    std::uint64_t discovery_order{};
};
/** §§6.3,10: height-long unavailable ownership counted globally. */
struct UnavailableObservation { PeerId peer{}; ShortId item{}; };
/** §§8,10: per-item accumulated score and most recently scored sample. */
struct ConfidenceObservation {
    ShortId item{};
    double lambda{};
    std::uint64_t k{};
    std::uint64_t y{};
    double increment{};
    Sequence admission_seq{};
    bool admitted{};
};
/** §§8,10: captured current wave, canonical peer IDs and vote eligibility. */
struct WaveObservation {
    WaveId number{};
    bool active{};
    bool invalidated{};
    Time started{};
    Time deadline{};
    Root root{};
    std::uint64_t population{};
    std::uint64_t k{};
    std::uint64_t y{};
    std::uint64_t m0{};
    std::uint64_t m1hat{};
    std::uint64_t m1tx{};
    std::vector<PeerId> sampled;
    std::vector<PeerId> answered;
    std::vector<PeerId> matching;
};
/** §§6.2,10: committed atomic One/Two only, retained even after model release.
 * Policy-rejected or probation-only candidates never appear as committed decodes.
 */
struct NodeDecodeAudit {
    /** §§6.2,10: ordinal in the single ordered per-call audit event sequence. */
    std::uint64_t event_order{};
    PeerId peer{};
    SessionId session_id{};
    Sequence snapshot_seq{};
    Sequence own_seq{};
    DecodeAudit decode{};
};
/** §§6.2,8,10: terminal model capture before any lifetime/close cleanup. */
struct CompletionAudit {
    /** §§6.2,10: ordinal in the single ordered per-call audit event sequence. */
    std::uint64_t event_order{};
    PeerId peer{};
    SessionId session_id{};
    SessionState state{SessionState::idle};
    Sequence snapshot_seq{};
    Sequence own_seq_at_done{};
    WaveId wave{};
    Root root{};
    /** §§6.2,10: raw reconstructed reference for Done; never a RootMatched proof. */
    std::vector<ShortId> reference;
    /** §§8,10: sorted captured own candidate IDs underlying this RootMatched
     * poll/root assertion, recorded before completion cleanup or wave scoring.
     * Empty for other completion states; distinct from the raw reference.
     */
    std::vector<ShortId> candidate_ids_at_completion;
    std::vector<ShortId> exclusions;
};
/** §§6.5,8,10: completed wave timing survives opening the next wave. */
struct WaveAudit {
    WaveObservation wave;
    Time ended{};
    double root_increment{};
    double confidence_before{};
    double confidence_after{};
};
/** §10: exact peer/item evidence used for a scored wave, no imputed abstention. */
struct EvidenceAudit {
    PeerId peer{};
    ShortId item{};
    WaveId wave{};
    SessionId session_id{};
    bool eligible{};
    bool yes{};
    bool root_matched{};
    double lambda_before{};
    double lambda_after{};
};
/** §§6.1,6.5,8,10: response correlation/timing decision before session cleanup. */
struct ReplyAudit {
    PeerId peer{};
    SessionId session_id{};
    RequestId request_id{};
    PollId poll_id{};
    Sequence snapshot_seq{};
    SymbolsStatus status{SymbolsStatus::normal};
    Time original_sent_time{};
    Time received_time{};
    bool accepted_data{};
    bool accepted_root_vote{};
    bool answered_current_wave{};
    bool ignored{};
    Root root_vote{};
};
/** §10: operation failure trace, distinct from remote peer penalty. */
struct ErrorAudit {
    Error error{Error::ok};
    std::optional<PeerId> peer;
    std::optional<ShortId> item;
    std::optional<Limit> limit;
};
/** §10: plain deterministic action record avoids recursive owning variants. */
enum class ActionKind : std::uint8_t { send, fetch_body, frozen, misbehaved, timer };
/** §10: complete action values in original emission order. */
struct ActionAudit {
    /** §§6.2,10: ordinal in the single ordered per-call audit event sequence. */
    std::uint64_t event_order{};
    ActionKind kind{ActionKind::send};
    PeerId peer{};
    Bytes bytes;
    ShortId item{};
    FetchId fetch_id{};
    Root root{};
    std::vector<TxId> txids;
    Misbehavior reason{Misbehavior::malformed_message};
    Time at{};
};
/** §§6.2,8,10: lifecycle of retained requester models, excluding responder pins. */
enum class ModelLifecycleKind : std::uint8_t { created, released };
/** §§6.2,6.4,8,10: model creation/destruction; charged to other_audit capacity.
 * Done completion retains its evidence model and is not a release. Replacement,
 * expiry, invalidation, disconnect and tip reset emit released on actual model
 * destruction. Creation precedes every committed decode for that model; release
 * follows its final committed decode, completion and emitted fetch-support action.
 */
struct SessionLifecycleAudit {
    std::uint64_t event_order{};
    PeerId peer{};
    SessionId session_id{};
    ModelLifecycleKind kind{ModelLifecycleKind::created};
};
/** §§6.2,6.4,10: bounded last-call snapshots, reset before the next API call.
 * NodeDecodeAudit, CompletionAudit, ActionAudit and SessionLifecycleAudit share
 * one strictly increasing per-call event_order sequence, including across classes.
 * These public records are caller-owned observational value-copy views; their
 * allocation is separately attributed. Core-retained records use compact/SoA
 * storage with each fixed record <=128 bytes; every retained byte and returned
 * Action allocation remains counted under the resource contract.
 */
struct CallAudit {
    std::uint64_t call_sequence{};
    Time time{};
    std::vector<SessionLifecycleAudit> lifecycle;
    std::vector<NodeDecodeAudit> decodes;
    std::vector<CompletionAudit> completions;
    std::vector<WaveAudit> waves;
    std::vector<EvidenceAudit> evidence;
    std::vector<ReplyAudit> replies;
    std::vector<ErrorAudit> errors;
    std::vector<ActionAudit> actions;
};
/** §§6.4,10: caller-owned immutable diagnostic copy, outside hot-path checks.
 * Observational copy allocations are separately attributed, never used to hide
 * core-retained compact records, their variable payloads or returned Actions.
 */
struct Stats {
    Sequence own_seq{};
    TipContext tip_context{};
    Root own_root{};
    double root_confidence{};
    std::uint64_t b_root{};
    std::uint64_t b_tx{};
    bool frozen{};
    std::uint64_t state_bytes{};
    std::uint64_t fixed_floor_bytes{};
    std::uint64_t global_dynamic_bytes{};
    std::uint64_t action_bytes{};
    std::uint64_t audit_bytes{};
    std::uint64_t change_log_length{};
    std::uint64_t open_sessions{};
    std::uint64_t decode_steps{};
    /** §§6.3,10: operational failed-candidate outcome count, NOT fake truth.
     * Increment once per current-token unadmitted not_found, invalid/unbound,
     * or invalid/matched outcome. Stale/duplicate/local_rejected do not count.
     * The simulator independently classifies genuine fake IDs using its truth.
     */
    std::uint64_t fakes_rejected{};
    std::uint64_t unavailable_marks{};
    std::uint64_t local_model_expiry{};
    bool suspended_unadmitted{};
    Error last_api_error{Error::ok};
    std::array<std::uint64_t, static_cast<std::size_t>(Limit::count)> limit_hits{};
    std::vector<ShortId> own_ids;
    std::vector<BodyObservation> bodies;
    std::vector<ShortId> candidate_ids;
    std::vector<ShortId> pending;
    std::vector<ShortId> probation;
    std::vector<ShortId> rejected;
    std::vector<ShortId> local_rejected;
    std::vector<ConfidenceObservation> confidence;
    std::vector<PeerStats> peers;
    std::vector<FetchObservation> fetches;
    std::vector<DonorObservation> donors;
    std::vector<UnavailableObservation> unavailable;
    std::vector<AllocationObservation> global_allocations;
    Limits limits;
    WaveObservation wave;
    CallAudit last_call;
};
} // namespace snowstorm
/** @} */
