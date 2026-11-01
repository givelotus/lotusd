// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#pragma once
#include "transcript.h"
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <snowstorm/node.h>
#include <snowstorm/stats.h>
#include <string_view>
namespace snowstorm::test {
using NodeId = std::size_t;
struct LinkOptions {
    Time delay{500};
    Time jitter{};
    std::uint32_t loss_per_million{};
    Time initial_rtt{1000};
};
struct Connection {
    NodeId left{}, right{};
    PeerId left_peer{}, right_peer{};
};
struct WireInput {
    NodeId node{};
    PeerId peer{};
    Time time{};
    Bytes bytes;
};
struct WireReply {
    Bytes bytes;
    Time delay{};
};
using WireHandler = std::function<std::vector<WireReply>(const WireInput &)>;
struct BodyRule {
    BodyStatus status{BodyStatus::admitted};
    BodyBinding binding{BodyBinding::matched};
    TxHandle body;
    std::optional<TxHash> expected_tx_hash;
    Time result_delay{500};
    Time admission_delay{};
    bool deliver_admission{true};
};
struct BodyFetchContext {
    NodeId requester{};
    PeerId donor_peer{};
    std::optional<NodeId> donor;
    ShortId item{};
    FetchId token{};
    TipContext tip{};
    ShortIdKey key{};
    Time sent{}, deadline{};
};
struct BodyRequestDelivery {
    BodyFetchContext fetch;
    Time now{};
    TxHandle available_body;
};
struct BodyResponsePlan {
    Bytes bytes;
    BodyRule result;
    Time service_delay{};
};
struct BodyServicePolicy {
    Time timeout{};
    std::size_t max_payload_bytes{};
    std::function<Bytes(const BodyFetchContext &)> request_bytes;
    std::function<BodyResponsePlan(const BodyRequestDelivery &)> serve;
};
enum class TrafficClass {
    reconciliation,
    body_request,
    body_response,
    body_result,
    body_admission
};
enum class DeliveryStage {
    offered,
    scheduled,
    arrived,
    policy_drop,
    disconnected,
    terminal_timeout,
    result_callback,
    admission_callback
};
enum class ApplicationDisposition {
    not_applicable,
    delivered_to_core,
    served,
    stale,
    expired,
    canceled
};
struct DeliveryObservation {
    std::uint64_t packet_id{};
    std::optional<std::uint64_t> parent_packet_id;
    TrafficClass traffic_class{TrafficClass::reconciliation};
    DeliveryStage stage{DeliveryStage::offered};
    ApplicationDisposition disposition{ApplicationDisposition::not_applicable};
    std::optional<NodeId> sender, receiver;
    NodeId local_node{};
    PeerId local_peer{};
    std::uint64_t connection_generation{};
    std::optional<FetchId> fetch_id{};
    std::optional<ShortId> item;
    TipContext tip{};
    Time time{};
    std::optional<Time> scheduled_arrival;
    std::size_t byte_count{};
    ByteSpan bytes;
    std::optional<BodyStatus> result;
};
struct Observation {
    NodeId node{};
    Time time{};
    std::string call;
    Stats before, after;
    Actions actions;
};
struct Completion {
    NodeId node{};
    Time time{};
    CompletionAudit audit;
    bool honest_source{};
    std::set<ShortId> raw, candidate;
    Root candidate_root{};
};
/** sent/bytes count actual node Send actions only, not reverse WireReplies or
 * modeled body packets. Use the delivery observer for physical bidirectional
 * and body-byte ledgers; transport-policy instrumentation counts queue offers.
 */
struct Traffic {
    std::uint64_t sent{}, delivered{}, dropped{}, bytes{}, calls{},
        residual_checks{}, decode_checks{};
};
enum class ObservationMode { full_every_call, simulation_observation };
struct TransportInput {
    NodeId local_node{};
    PeerId local_peer{};
    bool from_wire_peer{};
    std::optional<NodeId> sender, receiver;
    std::optional<PeerId> receiver_peer;
    Time now{};
    ByteSpan bytes;
    TrafficClass traffic_class{TrafficClass::reconciliation};
    std::optional<FetchId> fetch_id{};
    std::optional<TipContext> tip_context{};
};
struct TransportDecision {
    Time delay{};
    bool drop{};
};
/** Deterministic external link policy; owns any regional RNG or queue state. */
using TransportPolicy =
    std::function<TransportDecision(const TransportInput &)>;
struct HostOptions {
    bool retain_observations{true};
    bool retain_transcript{true};
    bool retain_completions{true};
    /** Simulation omits automatic Stats/deep audits; all acceptance defaults
     * remain full. It requires both observation/completion retention disabled.
     * Explicit stats() snapshots remain available; omitted transient history
     * cannot be audited later.
     */
    ObservationMode observation_mode{ObservationMode::full_every_call};
};
/** Pure SHA-256 commitment to context and canonical txid/hash pairs; no host
 * capture. */
Root canonical_root(const TipContext &, std::span<const TxHandle>);
TipParams default_tip(std::uint64_t height = 0);
Config default_config(std::uint64_t max_set_size, std::uint64_t seed = 1);
/** Deterministic event host. All truth checks are outside the actual node. */
class Host {
public:
    explicit Host(std::uint64_t seed, HostOptions options = {});
    Host(std::uint64_t seed, std::size_t nodes, std::uint64_t max_set_size,
         HostOptions options = {});
    ~Host();
    Host(const Host &) = delete;
    Host &operator=(const Host &) = delete;
    NodeId add_node(Config, TipParams);
    Connection connect(NodeId, NodeId, LinkOptions = {});
    PeerId connect_wire(NodeId, WireHandler, LinkOptions = {});
    void disconnect(Connection);
    void disconnect_peer(NodeId, PeerId);
    void set_link(NodeId, PeerId, LinkOptions);
    void set_link(Connection, LinkOptions);
    /** Replaces Send link delay/loss. Policy-enabled scripted replies first
     * complete their service delay, then invoke the current policy with now
     * equal to service-ready time; its delay is added from that time. Empty
     * policy preserves original delivery order and RNG draws. Body service
     * remains independently timed by BodyRule, not this policy.
     */
    void set_transport_policy(TransportPolicy);
    /** Explicit modeled body transport; requires transport policy. Both
     * policies are immutable while any body operation/phase remains. Payload
     * cap1..16MiB; positive timeout; service plans require
     * result.result_delay==0.
     */
    void set_body_service_policy(std::optional<BodyServicePolicy>);
    /** Borrowed synchronous events, no retained history or callback mutation.
     * arrived counts physical bytes even when application ownership is stale.
     */
    void observe_delivery(std::function<void(const DeliveryObservation &)>);
    void admit(NodeId, TxHandle);
    void remove(NodeId, ShortId, RemovalReason = RemovalReason::other);
    void remove_body(NodeId, ShortId, const TxHash &,
                     RemovalReason = RemovalReason::other);
    void change_tip(NodeId, TipParams, bool block_disconnected = false);
    void body_rule(NodeId, PeerId, ShortId, BodyRule);
    void clear_body_rule(NodeId, PeerId, ShortId);
    void send_wire(NodeId, PeerId, Bytes, Time delay = 0);
    void inject(NodeId, PeerId, ByteSpan);
    void timer(NodeId);
    bool step();
    void advance_to(Time, std::uint64_t max_events = 1000000);
    void run_for(Time duration, std::uint64_t max_events = 1000000);
    bool run_until(const std::function<bool(const Host &)> &, Time deadline,
                   std::uint64_t max_events = 1000000);
    Time now() const;
    std::size_t size() const;
    Stats stats(NodeId) const;
    std::set<ShortId> truth(NodeId) const;
    /** Actual host bodies, including admitted bodies awaiting notification. */
    std::vector<TxHandle> bodies(NodeId) const;
    /** Delivered admission notifications, including explicitly rejected
     * collisions. */
    std::vector<TxHandle> notified_bodies(NodeId) const;
    /** Independent expected core projection: notified IDs minus expected
     * rejections. */
    std::set<ShortId> projected_truth(NodeId) const;
    const std::vector<Observation> &observations() const;
    const std::vector<Completion> &completions() const;
    const Transcript &transcript() const;
    const Traffic &traffic() const;
    void observe(std::function<void(const Observation &)>);
    /** Lightweight actual returned Actions, available in both observation
     * modes. */
    void observe_actions(std::function<void(NodeId, Time, std::string_view,
                                            std::span<const Action>)>);
    /** Checks independently on every call; this also explicitly rechecks
     * current state. */
    void audit() const;
    bool equal_truth() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace snowstorm::test
