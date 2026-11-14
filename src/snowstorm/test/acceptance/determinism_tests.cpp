// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../harness/host.h"
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include "../oracle/schedule.h"

namespace {
using namespace snowstorm;
Bytes deterministic_transcript(bool write) {
    test::Host host(0x715deadbeef, 5, 128);
    std::vector<test::Connection> links;
    for (std::size_t i = 0; i < 5; ++i)
        for (std::size_t j = i + 1; j < 5; ++j)
            links.push_back(host.connect(i, j, test::LinkOptions{750, 100, 100000, 1000}));
    for (std::size_t i = 0; i < 5; ++i)
        for (unsigned j = 0; j < 3; ++j) host.admit(i, snowstorm_test::make_body(100 * i + j));
    host.run_for(2000000, 2000000);
    host.audit();
    BOOST_REQUIRE(host.equal_truth());
    BOOST_REQUIRE_EQUAL(host.truth(0).size(), 15U);
    host.disconnect(links.front());
    host.connect(0, 1, test::LinkOptions{1500, 200, 100000, 1000});
    for (std::size_t i = 0; i < 5; ++i) {
        auto tip = test::default_tip(1); tip.surviving = host.bodies(i);
        host.change_tip(i, tip);
    }
    host.admit(3, snowstorm_test::make_body(999));
    host.run_for(2000000, 2000000);
    host.audit();
    BOOST_REQUIRE(host.equal_truth());
    BOOST_REQUIRE_EQUAL(host.truth(0).size(), 16U);
    BOOST_REQUIRE_GT(host.traffic().dropped, 0U);
    BOOST_REQUIRE_GT(host.traffic().delivered, 0U);
    BOOST_REQUIRE(!host.transcript().bytes().empty());
    if (write) host.transcript().write_from_environment();
    return host.transcript().bytes();
}
struct HostRun {
    Bytes transcript, actions;
    std::vector<std::set<ShortId>> actual, projected;
    std::vector<std::vector<TxHash>> hashes;
    test::Traffic traffic;
};
HostRun observation_run(test::HostOptions options,
                        const std::function<void(test::Host &)> &configure = {}) {
    test::Host host(0x7150b5e, 3, 128, options);
    if (configure) configure(host);
    test::Transcript actual_actions;
    host.observe_actions([&](test::NodeId node, Time time, std::string_view, std::span<const Action> actions) {
        for (const auto &a : actions) actual_actions.action(node, time, a);
    });
    for (std::size_t i = 0; i < 3; ++i) {
        for (unsigned j = 0; j < 2; ++j)
            host.admit(i, snowstorm_test::make_body(150000 + 100 * i + j));
        for (std::size_t j = 0; j < i; ++j) host.connect(i, j);
    }
    host.run_for(100000, 1000000);
    if (options.observation_mode == test::ObservationMode::full_every_call) host.audit();
    BOOST_REQUIRE(host.equal_truth());
    BOOST_REQUIRE_EQUAL(host.truth(0).size(), 6U);
    HostRun run;
    run.transcript = host.transcript().bytes();
    run.actions = actual_actions.bytes();
    run.traffic = host.traffic();
    for (std::size_t i = 0; i < 3; ++i) {
        run.actual.push_back(host.truth(i));
        run.projected.push_back(host.projected_truth(i));
        BOOST_CHECK(run.actual.back() == run.projected.back());
        std::vector<TxHash> hashes;
        for (const auto &body : host.bodies(i)) hashes.push_back(body->tx_hash());
        std::sort(hashes.begin(), hashes.end());
        run.hashes.push_back(std::move(hashes));
    }
    BOOST_REQUIRE(!run.actions.empty());
    BOOST_REQUIRE(!run.transcript.empty());
    return run;
}
void require_same_run(const HostRun &a, const HostRun &b) {
    BOOST_CHECK_EQUAL_COLLECTIONS(a.actions.begin(), a.actions.end(), b.actions.begin(), b.actions.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(a.transcript.begin(), a.transcript.end(), b.transcript.begin(), b.transcript.end());
    BOOST_CHECK(a.actual == b.actual);
    BOOST_CHECK(a.projected == b.projected);
    BOOST_CHECK(a.hashes == b.hashes);
    BOOST_CHECK_EQUAL(a.traffic.sent, b.traffic.sent);
    BOOST_CHECK_EQUAL(a.traffic.delivered, b.traffic.delivered);
    BOOST_CHECK_EQUAL(a.traffic.dropped, b.traffic.dropped);
    BOOST_CHECK_EQUAL(a.traffic.bytes, b.traffic.bytes);
    BOOST_CHECK_EQUAL(a.traffic.calls, b.traffic.calls);
}

struct BodyEvent {
    test::TrafficClass traffic_class;
    test::DeliveryStage stage;
    test::ApplicationDisposition disposition;
    std::uint64_t packet;
    std::optional<FetchId> token;
    Time time;
    std::optional<Time> arrival;
    std::size_t bytes;
    std::optional<BodyStatus> result;
    std::optional<std::uint64_t> parent;
    std::optional<test::NodeId> sender, receiver;
    test::NodeId local_node;
    PeerId local_peer;
    std::uint64_t generation;
    std::optional<ShortId> item;
    TipContext tip;
    Bytes payload;
    bool operator==(const BodyEvent &) const = default;
};
test::BodyServicePolicy body_policy(Time timeout = 10000, Time service = 20,
                                     Time admission = 0) {
    test::BodyServicePolicy policy;
    policy.timeout = timeout; policy.max_payload_bytes = 256;
    policy.request_bytes = [](const test::BodyFetchContext &) { return Bytes(17, 0x51); };
    policy.serve = [=](const test::BodyRequestDelivery &delivery) {
        test::BodyResponsePlan plan;
        plan.bytes = Bytes(64, 0x52); plan.service_delay = service;
        plan.result.result_delay = 0; plan.result.admission_delay = admission;
        if (delivery.available_body) {
            plan.result.body = delivery.available_body;
            plan.result.expected_tx_hash = delivery.available_body->tx_hash();
            plan.result.status = BodyStatus::admitted;
            plan.result.binding = BodyBinding::matched;
        } else {
            plan.result.status = BodyStatus::not_found;
            plan.result.binding = BodyBinding::unbound;
        }
        return plan;
    };
    return policy;
}
void collect_body(test::Host &host, std::vector<BodyEvent> &events) {
    host.observe_delivery([&events](const test::DeliveryObservation &o) {
        BOOST_CHECK_EQUAL(o.byte_count, o.bytes.size());
        events.push_back({o.traffic_class, o.stage, o.disposition, o.packet_id,
                          o.fetch_id, o.time, o.scheduled_arrival, o.byte_count, o.result,
                          o.parent_packet_id, o.sender, o.receiver, o.local_node, o.local_peer,
                          o.connection_generation, o.item, o.tip, Bytes(o.bytes.begin(), o.bytes.end())});
    });
}
void exactly_one_terminal_per_token(const std::vector<BodyEvent> &events) {
    std::set<FetchId> issued;
    std::map<FetchId, unsigned> results, admissions;
    std::map<FetchId, std::uint64_t> requests;
    std::set<std::uint64_t> packets;
    for (const auto &e : events) {
        if (e.stage == test::DeliveryStage::offered) {
            BOOST_CHECK_NE(e.packet, 0U); BOOST_CHECK(packets.insert(e.packet).second);
            BOOST_CHECK_EQUAL(e.generation, e.local_peer);
        }
        if (e.traffic_class == test::TrafficClass::body_request &&
            e.stage == test::DeliveryStage::offered) {
            BOOST_REQUIRE(e.token); issued.insert(*e.token); requests[*e.token] = e.packet;
        }
        if (e.traffic_class == test::TrafficClass::body_response &&
            e.stage == test::DeliveryStage::offered) {
            BOOST_REQUIRE(e.token); BOOST_REQUIRE(e.parent);
            BOOST_CHECK_EQUAL(*e.parent, requests.at(*e.token));
        }
        if (e.stage == test::DeliveryStage::result_callback) {
            BOOST_REQUIRE(e.token); ++results[*e.token];
        }
        if (e.stage == test::DeliveryStage::admission_callback) {
            BOOST_REQUIRE(e.token); ++admissions[*e.token];
        }
    }
    BOOST_REQUIRE(!issued.empty());
    for (auto token : issued) {
        BOOST_CHECK_EQUAL(results[token], 1U);
        BOOST_CHECK_LE(admissions[token], 1U);
    }
}

}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T15_same_process_full_transcript) {
    const auto a = deterministic_transcript(false);
    const auto b = deterministic_transcript(false);
    BOOST_CHECK_EQUAL_COLLECTIONS(a.begin(), a.end(), b.begin(), b.end());
}
BOOST_AUTO_TEST_CASE(T15_transcript_process) {
    // Ordinary full-suite runs also exercise this scenario; the CMake process
    // checker sets the path and compares the complete independent-run artifacts.
    const bool output_requested = std::getenv("SNOWSTORM_TRANSCRIPT_FILE") != nullptr;
    const auto bytes = deterministic_transcript(output_requested);
    BOOST_REQUIRE(!bytes.empty());
}
BOOST_AUTO_TEST_CASE(Host_observation_mode_preserves_actual_actions_and_truth) {
    test::HostOptions full;
    test::HostOptions simulation;
    simulation.retain_observations = false;
    simulation.retain_completions = false;
    simulation.observation_mode = test::ObservationMode::simulation_observation;
    const auto a = observation_run(full);
    const auto b = observation_run(simulation);
    require_same_run(a, b);
    BOOST_CHECK_GT(a.traffic.residual_checks, 0U);
    BOOST_CHECK_EQUAL(b.traffic.residual_checks, 0U);
    BOOST_CHECK_EQUAL(b.traffic.decode_checks, 0U);
}
BOOST_AUTO_TEST_CASE(Host_fixed_transport_policy_preserves_default_delivery) {
    const auto absent = observation_run(test::HostOptions{});
    std::uint64_t calls = 0;
    const auto fixed = observation_run(test::HostOptions{}, [&](test::Host &h) {
        h.set_transport_policy([&](const test::TransportInput &input) {
            ++calls;
            BOOST_CHECK(!input.from_wire_peer);
            BOOST_REQUIRE(input.sender.has_value());
            BOOST_REQUIRE(input.receiver.has_value());
            BOOST_REQUIRE(input.receiver_peer.has_value());
            BOOST_CHECK(!input.bytes.empty());
            return test::TransportDecision{500, false};
        });
    });
    BOOST_CHECK_GT(calls, 0U);
    require_same_run(absent, fixed);
}
BOOST_AUTO_TEST_CASE(Host_transport_policy_directed_byte_queue_and_reverse_reply_loss) {
    using Direction = std::tuple<test::NodeId, PeerId, bool>;
    test::Host h(0x715b17e, 2, 128);
    std::map<Direction, Time> free_at;
    std::map<Direction, std::uint64_t> ordinals;
    std::multiset<std::pair<test::NodeId, Time>> expected_messages, expected_reverse;
    std::multiset<std::tuple<test::NodeId, PeerId, Time, Bytes>> expected_wire, expected_ready;
    std::set<std::size_t> payload_sizes;
    std::uint64_t honest_calls = 0, outbound_wire_calls = 0, reverse_calls = 0;
    std::uint64_t policy_drops = 0, queued = 0, received_messages = 0, received_wire = 0;
    std::uint64_t reverse_drop = 0, reverse_delivery = 0;
    h.set_transport_policy([&](const test::TransportInput &input) {
        BOOST_REQUIRE(!input.bytes.empty());
        payload_sizes.insert(input.bytes.size());
        const Direction direction{input.local_node, input.local_peer, input.from_wire_peer};
        const Time start = std::max(input.now, free_at[direction]);
        if (start > input.now) ++queued;
        // Independent per-directed-link serializer:20us/byte plus20us propagation.
        free_at[direction] = start + Time(input.bytes.size()) * 20;
        const Time delay = free_at[direction] - input.now + 20;
        const auto ordinal = ++ordinals[direction];
        const bool drop = input.from_wire_peer ? ordinal % 3 == 0 : ordinal % 7 == 0;
        if (drop) ++policy_drops;
        if (input.from_wire_peer) {
            ++reverse_calls;
            const auto ready = expected_ready.find({input.local_node, input.local_peer,
                input.now, Bytes(input.bytes.begin(), input.bytes.end())});
            BOOST_REQUIRE(ready != expected_ready.end());
            expected_ready.erase(ready);
            if (drop) ++reverse_drop;
            BOOST_CHECK(!input.sender.has_value());
            BOOST_REQUIRE(input.receiver.has_value());
            BOOST_CHECK_EQUAL(*input.receiver, input.local_node);
            BOOST_REQUIRE(input.receiver_peer.has_value());
            BOOST_CHECK_EQUAL(*input.receiver_peer, input.local_peer);
            BOOST_CHECK_EQUAL(input.bytes[1], 1U);
            if (!drop) {
                expected_messages.insert({*input.receiver, input.now + delay});
                expected_reverse.insert({*input.receiver, input.now + delay});
            }
        } else {
            BOOST_REQUIRE(input.sender.has_value());
            BOOST_CHECK_EQUAL(*input.sender, input.local_node);
            if (input.receiver) {
                ++honest_calls;
                BOOST_REQUIRE(input.receiver_peer.has_value());
                if (!drop) expected_messages.insert({*input.receiver, input.now + delay});
            } else {
                ++outbound_wire_calls;
                BOOST_CHECK(!input.receiver_peer.has_value());
                if (!drop) expected_wire.insert({input.local_node, input.local_peer,
                    input.now + delay, Bytes(input.bytes.begin(), input.bytes.end())});
            }
        }
        return test::TransportDecision{delay, drop};
    });
    h.observe_actions([&](test::NodeId node, Time now, std::string_view call,
                         std::span<const Action>) {
        if (call != "message") return;
        const auto expected = expected_messages.find({node, now});
        BOOST_REQUIRE(expected != expected_messages.end());
        expected_messages.erase(expected);
        const auto reverse = expected_reverse.find({node, now});
        if (reverse != expected_reverse.end()) {
            expected_reverse.erase(reverse); ++reverse_delivery;
        }
        ++received_messages;
    });
    h.connect(0, 1, test::LinkOptions{999999, 0, 1000000, 1000});
    h.connect_wire(0, [&](const test::WireInput &input) {
        const auto expected = expected_wire.find({input.node, input.peer, input.time, input.bytes});
        BOOST_REQUIRE(expected != expected_wire.end());
        expected_wire.erase(expected);
        ++received_wire;
        const auto parsed = parse(input.bytes, h.stats(0).limits);
        BOOST_REQUIRE(parsed.error == Error::ok);
        std::vector<test::WireReply> out;
        if (const auto *q = std::get_if<ReconReq>(&*parsed.message)) {
            ReconSymbols r; r.tip_context = q->tip_context; r.session_id = q->session_id;
            r.request_id = q->request_id; r.poll_id = q->poll_id;
            r.status = SymbolsStatus::expired;
            Bytes bytes; BOOST_REQUIRE(serialize(r, h.stats(0).limits, bytes) == Error::ok);
            expected_ready.insert({input.node, input.peer, input.time + 17, bytes});
            out.push_back({std::move(bytes), 17});
        }
        return out;
    }, test::LinkOptions{999999, 0, 1000000, 1000});
    h.admit(0, snowstorm_test::make_body(715151));
    h.admit(1, snowstorm_test::make_body(715152));
    h.run_for(200000, 1000000);
    BOOST_CHECK_GT(honest_calls, 0U);
    BOOST_CHECK_GT(outbound_wire_calls, 0U);
    BOOST_CHECK_GT(reverse_calls, 0U);
    BOOST_CHECK_GT(reverse_drop, 0U);
    BOOST_CHECK_GT(reverse_delivery, 0U);
    BOOST_CHECK_GT(policy_drops, 0U);
    BOOST_CHECK_GT(queued, 0U);
    BOOST_CHECK_GT(received_messages, 0U);
    BOOST_CHECK_GT(received_wire, 0U);
    BOOST_CHECK_GE(payload_sizes.size(), 2U);
    BOOST_CHECK_EQUAL(h.traffic().dropped, policy_drops);
    for (const auto &[node, at] : expected_messages) { (void)node; BOOST_CHECK_GT(at, h.now()); }
    for (const auto &entry : expected_wire) BOOST_CHECK_GT(std::get<2>(entry), h.now());
    for (const auto &entry : expected_ready) BOOST_CHECK_GT(std::get<2>(entry), h.now());
    h.audit();
}
BOOST_AUTO_TEST_CASE(Host_transport_rejects_negative_and_overflow_delays_in_both_directions) {
    for (const Time delay : {Time{-1}, std::numeric_limits<Time>::max()}) {
        for (bool drop : {false, true}) {
            for (bool reverse : {false, true}) {
                test::Host h(0x715bad, 1, 128);
                h.advance_to(1); // max Time + current time necessarily overflows.
                std::uint64_t message_calls = 0;
                h.observe_actions([&](test::NodeId, Time, std::string_view call,
                                      std::span<const Action>) {
                    if (call == "message") ++message_calls;
                });
                h.set_transport_policy([&](const test::TransportInput &input) {
                    if (input.from_wire_peer == reverse)
                        return test::TransportDecision{delay, drop};
                    return test::TransportDecision{0, false};
                });
                const auto attempt = [&] {
                    h.connect_wire(0, [&](const test::WireInput &input) {
                        const auto p = parse(input.bytes, h.stats(0).limits);
                        BOOST_REQUIRE(p.error == Error::ok);
                        std::vector<test::WireReply> replies;
                        if (const auto *q = std::get_if<ReconReq>(&*p.message)) {
                            ReconSymbols r; r.tip_context = q->tip_context;
                            r.session_id = q->session_id; r.request_id = q->request_id;
                            r.poll_id = q->poll_id; r.status = SymbolsStatus::expired;
                            Bytes bytes;
                            BOOST_REQUIRE(serialize(r, h.stats(0).limits, bytes) == Error::ok);
                            replies.push_back({std::move(bytes), 3});
                        }
                        return replies;
                    });
                    h.run_for(10000);
                };
                BOOST_CHECK_THROW(attempt(), std::runtime_error);
                BOOST_CHECK_EQUAL(message_calls, 0U);
            }
        }
    }
}
BOOST_AUTO_TEST_CASE(Host_default_seeded_nonzero_jitter_and_loss_matches_independent_draws) {
    constexpr std::uint64_t seed = 0;
    constexpr Time base_delay = 31, jitter_bound = 97;
    constexpr std::uint64_t loss_per_million = 300000;
    test::Host h(seed, 1, 128);
    std::uint64_t independent_state = seed;
    std::uint64_t loss_draws = 0, jitter_draws = 0, expected_drops = 0, delivered = 0;
    std::multiset<std::pair<Time, Bytes>> expected;
    std::set<Time> observed_jitters;
    h.observe_actions([&](test::NodeId node, Time now, std::string_view,
                          std::span<const Action> actions) {
        BOOST_CHECK_EQUAL(node, 0U);
        for (const auto &a : actions) if (const auto *send = std::get_if<Send>(&a)) {
            // Separate oracle SplitMix implementation; no host RNG/state access.
            const auto loss_draw = snowstorm_oracle::splitmix_next(independent_state);
            if (loss_draws == 0) BOOST_CHECK_EQUAL(loss_draw, 0xe220a8397b1dcdafULL);
            ++loss_draws;
            if (loss_draw % 1000000 < loss_per_million) { ++expected_drops; continue; }
            const auto draw = snowstorm_oracle::splitmix_next(independent_state);
            ++jitter_draws;
            const Time jitter = Time(draw % (jitter_bound + 1));
            observed_jitters.insert(jitter);
            expected.insert({now + base_delay + jitter, send->bytes});
        }
    });
    h.connect_wire(0, [&](const test::WireInput &input) {
        const auto match = expected.find({input.time, input.bytes});
        BOOST_REQUIRE(match != expected.end());
        expected.erase(match); ++delivered;
        return std::vector<test::WireReply>{};
    }, test::LinkOptions{base_delay, jitter_bound, loss_per_million, 1000});
    h.run_for(100000, 1000000);
    BOOST_CHECK_GT(loss_draws, 10U);
    BOOST_CHECK_GT(jitter_draws, 0U);
    BOOST_CHECK_GT(expected_drops, 0U);
    BOOST_CHECK_GT(delivered, 0U);
    BOOST_CHECK_GT(observed_jitters.size(), 1U);
    BOOST_CHECK_EQUAL(h.traffic().sent, loss_draws);
    BOOST_CHECK_EQUAL(h.traffic().dropped, expected_drops);
    BOOST_CHECK_EQUAL(h.traffic().delivered, delivered);
    BOOST_CHECK_EQUAL(jitter_draws, delivered + expected.size());
    for (const auto &[at, bytes] : expected) { (void)bytes; BOOST_CHECK_GT(at, h.now()); }
    h.audit();
}
BOOST_AUTO_TEST_CASE(Host_reverse_queue_reserves_in_service_ready_order) {
    test::Host h(0x7155e12, 1, 128);
    std::vector<RequestId> creation_order, reservation_order;
    std::map<RequestId, Time> expected_ready;
    std::vector<Time> expected_arrivals, actual_arrivals;
    Time free_at = 0;
    h.set_transport_policy([&](const test::TransportInput &input) {
        if (!input.from_wire_peer) return test::TransportDecision{0, false};
        const auto p = parse(input.bytes, h.stats(0).limits);
        BOOST_REQUIRE(p.error == Error::ok);
        const auto *r = std::get_if<ReconSymbols>(&*p.message);
        BOOST_REQUIRE(r);
        BOOST_REQUIRE(expected_ready.count(r->request_id));
        BOOST_CHECK_EQUAL(input.now, expected_ready.at(r->request_id));
        reservation_order.push_back(r->request_id);
        const Time start = std::max(input.now, free_at);
        free_at = start + Time(input.bytes.size()) * 10;
        expected_arrivals.push_back(free_at);
        return test::TransportDecision{free_at - input.now, false};
    });
    h.observe_actions([&](test::NodeId, Time now, std::string_view call,
                          std::span<const Action>) {
        if (call == "message") actual_arrivals.push_back(now);
    });
    bool emitted = false;
    h.connect_wire(0, [&](const test::WireInput &input) {
        std::vector<test::WireReply> replies;
        if (emitted) return replies;
        const auto p = parse(input.bytes, h.stats(0).limits);
        BOOST_REQUIRE(p.error == Error::ok);
        const auto *q = std::get_if<ReconReq>(&*p.message);
        if (!q) return replies;
        emitted = true;
        // Deliberately create the slow service first. Only the fast reply is
        // correlated to the live request; the late one is harmless stale data.
        for (const auto [id, service] : {
                std::pair<RequestId, Time>{q->request_id + 100000, 100},
                std::pair<RequestId, Time>{q->request_id, 2}}) {
            ReconSymbols r; r.tip_context = q->tip_context; r.session_id = q->session_id;
            r.request_id = id; r.poll_id = q->poll_id; r.status = SymbolsStatus::expired;
            Bytes wire; BOOST_REQUIRE(serialize(r, h.stats(0).limits, wire) == Error::ok);
            BOOST_REQUIRE_EQUAL(wire.size(), 59U);
            creation_order.push_back(id);
            expected_ready.emplace(id, input.time + service);
            replies.push_back({std::move(wire), service});
        }
        return replies;
    });
    h.run_for(2000, 100000);
    BOOST_REQUIRE_EQUAL(creation_order.size(), 2U);
    BOOST_REQUIRE_EQUAL(reservation_order.size(), 2U);
    BOOST_CHECK_EQUAL(reservation_order[0], creation_order[1]);
    BOOST_CHECK_EQUAL(reservation_order[1], creation_order[0]);
    // First readiness is2, each59-byte payload consumes590us. The later
    // readiness100 is before first transmission ends592, so it queues next.
    BOOST_REQUIRE_EQUAL(expected_arrivals.size(), 2U);
    BOOST_CHECK_EQUAL(expected_arrivals[0], 592);
    BOOST_CHECK_EQUAL(expected_arrivals[1], 1182);
    BOOST_CHECK_EQUAL_COLLECTIONS(actual_arrivals.begin(), actual_arrivals.end(),
                                  expected_arrivals.begin(), expected_arrivals.end());
    h.audit();
}
BOOST_AUTO_TEST_CASE(Host_body_service_phase_loss_deadline_tie_and_late_once) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    using AD = test::ApplicationDisposition;
    // request drop, response drop, exact deadline, one-us late, timely.
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        test::Host h(0x715b000 + scenario, 2, 128);
        std::vector<BodyEvent> events; collect_body(h, events);
        unsigned serves = 0;
        h.set_transport_policy([&](const test::TransportInput &in) {
            if (in.traffic_class == TC::reconciliation) {
                BOOST_CHECK(!in.fetch_id); BOOST_CHECK(!in.tip_context);
                return test::TransportDecision{300, false};
            }
            BOOST_REQUIRE(in.fetch_id); BOOST_REQUIRE(in.tip_context);
            if (in.traffic_class == TC::body_request)
                return test::TransportDecision{10, scenario == 0};
            BOOST_CHECK(in.traffic_class == TC::body_response);
            return test::TransportDecision{scenario == 2 ? 970 : scenario == 3 ? 971 : 10,
                                           scenario == 1};
        });
        auto policy = body_policy(1000, 20, 5);
        const auto serve = policy.serve;
        policy.serve = [&](const test::BodyRequestDelivery &in) { ++serves; return serve(in); };
        h.set_body_service_policy(policy);
        h.admit(1, snowstorm_test::make_body(715000)); h.connect(0, 1);
        h.run_for(20000, 1000000);
        exactly_one_terminal_per_token(events);
        BOOST_CHECK_EQUAL(serves, scenario == 0 ? 0U : 1U);
        std::optional<Time> offered;
        unsigned results = 0, admissions = 0, timeouts = 0, arrivals = 0, drops = 0;
        for (const auto &e : events) {
            if (e.traffic_class == TC::body_request && e.stage == DS::offered) offered = e.time;
            if (e.stage == DS::result_callback) {
                ++results; BOOST_REQUIRE(e.result);
                BOOST_CHECK(*e.result == (scenario == 4 ? BodyStatus::admitted : BodyStatus::not_found));
                if (scenario != 4) { BOOST_REQUIRE(offered); BOOST_CHECK_EQUAL(e.time, *offered + 1000); }
            }
            if (e.stage == DS::admission_callback) ++admissions;
            if (e.stage == DS::terminal_timeout) ++timeouts;
            if (e.traffic_class == TC::body_response && e.stage == DS::arrived) {
                ++arrivals;
                if (scenario == 2 || scenario == 3) BOOST_CHECK(e.disposition == AD::expired);
            }
            if (e.traffic_class != TC::reconciliation && e.stage == DS::policy_drop) ++drops;
        }
        BOOST_CHECK_EQUAL(results, 1U);
        BOOST_CHECK_EQUAL(admissions, scenario == 4 ? 1U : 0U);
        BOOST_CHECK_EQUAL(timeouts, scenario == 4 ? 0U : 1U);
        BOOST_CHECK_EQUAL(arrivals, scenario >= 2 ? 1U : 0U);
        BOOST_CHECK_EQUAL(drops, scenario < 2 ? 1U : 0U);
        BOOST_CHECK_EQUAL(h.truth(0).size(), scenario == 4 ? 1U : 0U);
        // All phase/deadline references have drained, so replacement is now legal.
        BOOST_CHECK_NO_THROW(h.set_body_service_policy(std::nullopt));
    }
}
BOOST_AUTO_TEST_CASE(Host_body_cancellation_preserves_physical_arrivals_and_terminal_once) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    using AD = test::ApplicationDisposition;
    for (bool response_phase : {false, true}) for (bool tip_change : {false, true}) {
        test::Host h(0x715ca11, 2, 128);
        std::vector<BodyEvent> events; collect_body(h, events);
        unsigned serves = 0;
        h.set_transport_policy([&](const test::TransportInput &in) {
            if (in.traffic_class == TC::reconciliation) return test::TransportDecision{300, false};
            return test::TransportDecision{in.traffic_class == TC::body_request ?
                (response_phase ? 10 : 1000) : 1000, false};
        });
        auto policy = body_policy(2000, 20);
        const auto serve = policy.serve;
        policy.serve = [&](const test::BodyRequestDelivery &in) { ++serves; return serve(in); };
        h.set_body_service_policy(policy);
        h.admit(1, snowstorm_test::make_body(715001)); const auto connection = h.connect(0, 1);
        const auto phase = response_phase ? TC::body_response : TC::body_request;
        BOOST_REQUIRE(h.run_until([&](const test::Host &) {
            return std::any_of(events.begin(), events.end(), [&](const BodyEvent &e) {
                return e.traffic_class == phase && e.stage == DS::scheduled;
            });
        }, 10000));
        BOOST_CHECK_THROW(h.set_body_service_policy(std::nullopt), std::exception);
        BOOST_CHECK_THROW(h.set_transport_policy({}), std::exception);
        if (tip_change) h.change_tip(0, test::default_tip(1));
        else h.disconnect(connection);
        h.run_for(10000, 1000000);
        exactly_one_terminal_per_token(events);
        unsigned physically_arrived = 0;
        for (const auto &e : events) if (e.traffic_class == phase && e.stage == DS::arrived) {
            ++physically_arrived;
            BOOST_CHECK(e.disposition == AD::canceled || e.disposition == AD::stale);
            BOOST_CHECK_EQUAL(e.bytes, response_phase ? 64U : 17U);
        }
        BOOST_CHECK_EQUAL(physically_arrived, 1U);
        BOOST_CHECK_EQUAL(serves, response_phase ? 1U : 0U);
        BOOST_CHECK(h.truth(0).empty());
        BOOST_CHECK_NO_THROW(h.set_body_service_policy(std::nullopt));
    }
}
BOOST_AUTO_TEST_CASE(Host_body_observer_noninterference_and_full_light_equivalence) {
    const auto baseline = observation_run(test::HostOptions{});
    std::uint64_t observations = 0;
    const auto observed = observation_run(test::HostOptions{}, [&](test::Host &h) {
        h.observe_delivery([&](const test::DeliveryObservation &) { ++observations; });
    });
    BOOST_CHECK_GT(observations, 0U);
    require_same_run(baseline, observed); // absent body policy retains defaults exactly.
    const auto configure = [](test::Host &h) {
        h.set_transport_policy([](const test::TransportInput &in) {
            return test::TransportDecision{
                in.traffic_class == test::TrafficClass::reconciliation ? 500 : 100, false};
        });
        h.set_body_service_policy(body_policy(10000, 50));
    };
    test::HostOptions light; light.retain_observations = false; light.retain_completions = false;
    light.observation_mode = test::ObservationMode::simulation_observation;
    std::vector<BodyEvent> full_events, light_events;
    const auto full = observation_run(test::HostOptions{}, [&](test::Host &h) {
        configure(h); collect_body(h, full_events);
    });
    const auto simulation = observation_run(light, [&](test::Host &h) {
        configure(h); collect_body(h, light_events);
    });
    require_same_run(full, simulation);
    BOOST_CHECK(full_events == light_events);
}
BOOST_AUTO_TEST_CASE(Host_body_and_reconciliation_share_service_ready_directed_queue) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    using Direction = std::tuple<test::NodeId, PeerId, bool>;
    struct Offered { Direction direction; TC kind; Time ready, arrival; std::size_t bytes; };
    test::Host h(0x7150ee, 2, 128);
    std::vector<BodyEvent> events; collect_body(h, events);
    std::vector<Offered> offered;
    std::map<Direction, Time> free_at;
    std::uint64_t body_contended = 0;
    h.set_transport_policy([&](const test::TransportInput &in) {
        const Direction key{in.local_node, in.local_peer, in.from_wire_peer};
        const Time start = std::max(in.now, free_at[key]);
        if (in.traffic_class != TC::reconciliation && start > in.now) ++body_contended;
        free_at[key] = start + Time(in.bytes.size()) * 10;
        const auto arrival = free_at[key] + 20;
        offered.push_back({key, in.traffic_class, in.now, arrival, in.bytes.size()});
        if (in.traffic_class == TC::body_response) {
            BOOST_REQUIRE(in.sender); BOOST_REQUIRE(in.receiver);
            BOOST_CHECK_EQUAL(*in.sender, 1U); BOOST_CHECK_EQUAL(*in.receiver, 0U);
            BOOST_CHECK(!in.from_wire_peer);
        }
        return test::TransportDecision{arrival - in.now, false};
    });
    h.set_body_service_policy(body_policy(50000, 5000));
    h.admit(1, snowstorm_test::make_body(715002)); const auto link = h.connect(0, 1);
    BOOST_REQUIRE(h.run_until([&](const test::Host &) {
        return std::any_of(events.begin(), events.end(), [](const BodyEvent &e) {
            return e.traffic_class == TC::body_request && e.stage == DS::arrived;
        });
    }, 20000));
    const Time request_time = h.now();
    h.advance_to(request_time + 4999);
    // A valid extra reconciliation request makes its reply ready one us before
    // the body service finishes, forcing real cross-class FIFO contention.
    ReconReq extra; extra.tip_context = test::default_tip().context;
    extra.session_id = 0x715eeee; extra.request_id = 0x715dddd;
    extra.poll_id = 1; extra.open = true; extra.reference_size = h.stats(1).limits.reference_bound;
    extra.ranges = {{0, 1}};
    Bytes wire; BOOST_REQUIRE(serialize(extra, h.stats(1).limits, wire) == Error::ok);
    h.inject(1, link.right_peer, wire);
    h.run_for(100000, 1000000);
    BOOST_REQUIRE_EQUAL(h.truth(0).size(), 1U);
    exactly_one_terminal_per_token(events);
    const auto response = std::find_if(offered.begin(), offered.end(), [](const Offered &o) {
        return o.kind == TC::body_response;
    });
    BOOST_REQUIRE(response != offered.end());
    std::optional<Time> request_arrival;
    for (const auto &e : events) if (e.traffic_class == TC::body_request && e.stage == DS::arrived)
        request_arrival = e.time;
    BOOST_REQUIRE(request_arrival);
    BOOST_CHECK_EQUAL(response->ready, *request_arrival + 5000);
    BOOST_CHECK(std::any_of(offered.begin(), offered.end(), [&](const Offered &o) {
        return o.kind == TC::reconciliation && o.direction == response->direction &&
               o.ready > *request_arrival && o.ready < response->ready;
    }));
    // The independent single map handles every class. Check all physical arrivals
    // against the policy's exact queue outputs, not a separate body delay model.
    for (const auto &e : events) if (e.stage == DS::arrived && e.traffic_class == TC::body_response)
        BOOST_CHECK_EQUAL(e.time, response->arrival);
    BOOST_CHECK_GT(body_contended, 0U);
}
BOOST_AUTO_TEST_CASE(Host_body_callback_guards_and_policy_install_boundaries) {
    for (bool light : {false, true}) {
    test::HostOptions options;
    if (light) {
        options.retain_observations = false; options.retain_completions = false;
        options.observation_mode = test::ObservationMode::simulation_observation;
    }
    test::Host h(0x7159a1, 2, 128, options);
    BOOST_CHECK_THROW(h.set_body_service_policy(body_policy()), std::exception);
    h.set_transport_policy([](const test::TransportInput &) { return test::TransportDecision{10, false}; });
    for (unsigned invalid = 0; invalid < 5; ++invalid) {
        auto p = body_policy();
        if (invalid == 0) p.timeout = 0;
        if (invalid == 1) p.max_payload_bytes = 0;
        if (invalid == 2) p.max_payload_bytes = 16 * 1024 * 1024 + 1;
        if (invalid == 3) p.request_bytes = {};
        if (invalid == 4) p.serve = {};
        BOOST_CHECK_THROW(h.set_body_service_policy(p), std::exception);
    }
    auto boundary = body_policy(); boundary.max_payload_bytes = 16 * 1024 * 1024;
    BOOST_CHECK_NO_THROW(h.set_body_service_policy(boundary));
    BOOST_CHECK_NO_THROW(h.set_body_service_policy(std::nullopt));
    unsigned observer_checks = 0, policy_checks = 0;
    const auto mutations_rejected = [&] {
        BOOST_CHECK_THROW(h.timer(0), std::exception);
        BOOST_CHECK_THROW(h.run_for(1), std::exception);
        BOOST_CHECK_THROW(h.admit(0, snowstorm_test::make_body(715777)), std::exception);
        BOOST_CHECK_THROW(h.connect(0, 1), std::exception);
        BOOST_CHECK_THROW(h.set_body_service_policy(std::nullopt), std::exception);
        BOOST_CHECK_THROW(h.set_transport_policy({}), std::exception);
        BOOST_CHECK_THROW(h.observe_delivery({}), std::exception);
        BOOST_CHECK_THROW(h.body_rule(0, 1, 1, test::BodyRule{}), std::exception);
        BOOST_CHECK_GE(h.now(), 0); // read-only access remains permitted.
    };
    h.observe_delivery([&](const test::DeliveryObservation &) {
        if (observer_checks++ == 0) mutations_rejected();
    });
    h.set_transport_policy([&](const test::TransportInput &) {
        if (policy_checks++ == 0) mutations_rejected();
        return test::TransportDecision{10, false};
    });
    h.set_body_service_policy(body_policy());
    h.admit(1, snowstorm_test::make_body(715003)); h.connect(0, 1);
    h.run_for(20000, 1000000);
    BOOST_CHECK_GT(observer_checks, 0U); BOOST_CHECK_GT(policy_checks, 0U);
    BOOST_CHECK_EQUAL(h.truth(0).size(), 1U);
    if (light) { BOOST_CHECK(h.observations().empty()); BOOST_CHECK(h.completions().empty()); }
    }
}
BOOST_AUTO_TEST_CASE(Host_body_payload_and_time_boundaries) {
    // valid one-byte payloads, oversized request/response, negative service,
    // forbidden legacy delay, negative admission, service/admission overflow.
    for (unsigned scenario = 0; scenario < 9; ++scenario) {
        test::Host h(0x715b0ad + scenario, 2, 128); h.advance_to(1);
        h.set_transport_policy([](const test::TransportInput &) { return test::TransportDecision{10, false}; });
        auto p = body_policy(1000, 0);
        p.max_payload_bytes = 1;
        if (scenario == 8) p.timeout = std::numeric_limits<Time>::max();
        p.request_bytes = [=](const test::BodyFetchContext &) { return Bytes(scenario == 1 ? 2 : 1, 0x51); };
        const auto serve = p.serve;
        p.serve = [=](const test::BodyRequestDelivery &in) {
            auto plan = serve(in); plan.bytes = Bytes(scenario == 2 ? 2 : 1, 0x52);
            if (scenario == 3) plan.service_delay = -1;
            if (scenario == 4) plan.result.result_delay = 1;
            if (scenario == 5) plan.result.admission_delay = -1;
            if (scenario == 6) plan.service_delay = std::numeric_limits<Time>::max();
            if (scenario == 7) plan.result.admission_delay = std::numeric_limits<Time>::max();
            return plan;
        };
        h.set_body_service_policy(p);
        h.admit(1, snowstorm_test::make_body(715004)); h.connect(0, 1);
        if (scenario == 0) {
            BOOST_CHECK_NO_THROW(h.run_for(10000, 1000000));
            BOOST_CHECK_EQUAL(h.truth(0).size(), 1U);
        } else BOOST_CHECK_THROW(h.run_for(10000, 1000000), std::exception);
    }
}
BOOST_AUTO_TEST_CASE(Host_body_terminal_does_not_release_late_phase_policy_ownership) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    test::Host h(0x7151a7e, 2, 128);
    std::vector<BodyEvent> events; collect_body(h, events);
    h.set_transport_policy([](const test::TransportInput &in) {
        return test::TransportDecision{in.traffic_class == TC::body_response ? 5000 : 10, false};
    });
    h.set_body_service_policy(body_policy(1000, 20));
    h.admit(1, snowstorm_test::make_body(715005)); h.connect(0, 1);
    BOOST_REQUIRE(h.run_until([&](const test::Host &) {
        return std::any_of(events.begin(), events.end(), [](const BodyEvent &e) {
            return e.stage == DS::result_callback;
        });
    }, 10000));
    BOOST_CHECK_THROW(h.set_body_service_policy(std::nullopt), std::exception);
    BOOST_CHECK_THROW(h.set_transport_policy({}), std::exception);
    h.run_for(10000, 1000000);
    exactly_one_terminal_per_token(events);
    BOOST_CHECK_NO_THROW(h.set_body_service_policy(std::nullopt));
    BOOST_CHECK_NO_THROW(h.set_transport_policy({}));
}
BOOST_AUTO_TEST_CASE(Host_body_admitted_notification_survives_disconnect_but_not_tip) {
    using DS = test::DeliveryStage;
    for (bool tip : {false, true}) {
        test::Host h(0x715ad01, 2, 128);
        std::vector<BodyEvent> events; collect_body(h, events);
        h.set_transport_policy([](const test::TransportInput &) { return test::TransportDecision{10, false}; });
        h.set_body_service_policy(body_policy(1000, 20, 5000));
        h.admit(1, snowstorm_test::make_body(715006)); const auto connection = h.connect(0, 1);
        BOOST_REQUIRE(h.run_until([&](const test::Host &) {
            return std::any_of(events.begin(), events.end(), [](const BodyEvent &e) {
                return e.stage == DS::result_callback && e.result == BodyStatus::admitted;
            });
        }, 10000));
        BOOST_CHECK_EQUAL(h.truth(0).size(), 1U);
        BOOST_CHECK(h.projected_truth(0).empty());
        if (tip) h.change_tip(0, test::default_tip(1)); else h.disconnect(connection);
        h.run_for(10000, 1000000);
        exactly_one_terminal_per_token(events);
        const auto callbacks = std::count_if(events.begin(), events.end(), [](const BodyEvent &e) {
            return e.stage == DS::admission_callback;
        });
        BOOST_CHECK_EQUAL(callbacks, tip ? 0 : 1);
        BOOST_CHECK_EQUAL(h.projected_truth(0).size(), tip ? 0U : 1U);
    }
}
BOOST_AUTO_TEST_CASE(Host_scheduled_reconciliation_disconnect_counts_both_honest_directions) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    using AD = test::ApplicationDisposition;
    test::Host h(0x715d15c, 2, 128);
    std::vector<BodyEvent> events; collect_body(h, events);
    unsigned core_messages = 0;
    h.observe_actions([&](test::NodeId, Time, std::string_view call, std::span<const Action>) {
        if (call == "message") ++core_messages;
    });
    const auto connection = h.connect(0, 1, test::LinkOptions{1000, 0, 0, 1000});
    std::vector<BodyEvent> scheduled;
    std::set<std::pair<test::NodeId, test::NodeId>> directions;
    for (const auto &e : events) if (e.traffic_class == TC::reconciliation && e.stage == DS::scheduled) {
        BOOST_REQUIRE(e.sender); BOOST_REQUIRE(e.receiver);
        scheduled.push_back(e); directions.insert({*e.sender, *e.receiver});
    }
    BOOST_REQUIRE_EQUAL(directions.size(), 2U);
    BOOST_CHECK(directions.count({0, 1})); BOOST_CHECK(directions.count({1, 0}));
    h.disconnect(connection); h.run_for(2000);
    for (const auto &packet : scheduled) {
        unsigned arrivals = 0;
        for (const auto &e : events) if (e.packet == packet.packet && e.stage == DS::arrived) {
            ++arrivals; BOOST_REQUIRE(packet.arrival);
            BOOST_CHECK_EQUAL(e.time, *packet.arrival);
            BOOST_CHECK_EQUAL(e.bytes, packet.bytes);
            BOOST_CHECK(e.payload == packet.payload);
            BOOST_CHECK(e.disposition == AD::canceled || e.disposition == AD::stale);
            BOOST_CHECK_EQUAL(e.generation, packet.generation);
        }
        BOOST_CHECK_EQUAL(arrivals, 1U);
    }
    BOOST_CHECK_EQUAL(core_messages, 0U);
}
BOOST_AUTO_TEST_CASE(Host_scheduled_reconciliation_wire_disconnect_counts_outbound_and_reply) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    using AD = test::ApplicationDisposition;
    for (bool reverse : {false, true}) {
        test::Host h(0x715d15d, 1, 128);
        std::vector<BodyEvent> events; collect_body(h, events);
        unsigned service_calls = 0, core_messages = 0;
        h.set_transport_policy([&](const test::TransportInput &in) {
            return test::TransportDecision{in.from_wire_peer || !reverse ? 1000 : 10, false};
        });
        h.observe_actions([&](test::NodeId, Time, std::string_view call, std::span<const Action>) {
            if (call == "message") ++core_messages;
        });
        const auto peer = h.connect_wire(0, [&](const test::WireInput &input) {
            ++service_calls;
            const auto p = parse(input.bytes, h.stats(0).limits); BOOST_REQUIRE(p.error == Error::ok);
            std::vector<test::WireReply> replies;
            if (const auto *q = std::get_if<ReconReq>(&*p.message)) {
                ReconSymbols r; r.tip_context = q->tip_context; r.session_id = q->session_id;
                r.request_id = q->request_id; r.poll_id = q->poll_id; r.status = SymbolsStatus::expired;
                Bytes wire; BOOST_REQUIRE(serialize(r, h.stats(0).limits, wire) == Error::ok);
                replies.push_back({std::move(wire), 3});
            }
            return replies;
        });
        const auto selected = [&](const BodyEvent &e) {
            return e.traffic_class == TC::reconciliation && e.stage == DS::scheduled &&
                (reverse ? !e.sender.has_value() : !e.receiver.has_value());
        };
        BOOST_REQUIRE(h.run_until([&](const test::Host &) {
            return std::any_of(events.begin(), events.end(), selected);
        }, 1000));
        const auto packet = *std::find_if(events.begin(), events.end(), selected);
        h.disconnect_peer(0, peer); h.run_for(2000);
        unsigned arrivals = 0;
        for (const auto &e : events) if (e.packet == packet.packet && e.stage == DS::arrived) {
            ++arrivals; BOOST_REQUIRE(packet.arrival);
            BOOST_CHECK_EQUAL(e.time, *packet.arrival);
            BOOST_CHECK_EQUAL(e.bytes, packet.bytes);
            BOOST_CHECK(e.payload == packet.payload);
            BOOST_CHECK(e.disposition == AD::canceled || e.disposition == AD::stale);
        }
        BOOST_CHECK_EQUAL(arrivals, 1U);
        BOOST_CHECK_EQUAL(service_calls, reverse ? 1U : 0U);
        BOOST_CHECK_EQUAL(core_messages, 0U);
    }
}
BOOST_AUTO_TEST_CASE(Host_body_request_and_serve_callbacks_reject_mutation) {
    for (bool light : {false, true}) {
        test::HostOptions options;
        if (light) {
            options.retain_observations = false; options.retain_completions = false;
            options.observation_mode = test::ObservationMode::simulation_observation;
        }
        test::Host h(0x715ca11, 2, 128, options);
        unsigned request_calls = 0, serve_calls = 0;
        const auto reject_mutation = [&] {
            BOOST_CHECK_THROW(h.timer(0), std::exception);
            BOOST_CHECK_THROW(h.step(), std::exception);
            BOOST_CHECK_THROW(h.run_for(1), std::exception);
            BOOST_CHECK_THROW(h.admit(0, snowstorm_test::make_body(715778)), std::exception);
            BOOST_CHECK_THROW(h.connect(0, 1), std::exception);
            BOOST_CHECK_THROW(h.set_body_service_policy(std::nullopt), std::exception);
            BOOST_CHECK_THROW(h.set_transport_policy({}), std::exception);
            BOOST_CHECK_THROW(h.observe_delivery({}), std::exception);
            BOOST_CHECK_THROW(h.body_rule(0, 1, 1, test::BodyRule{}), std::exception);
            BOOST_CHECK_GE(h.now(), 0);
            BOOST_CHECK_EQUAL(h.truth(1).size(), 1U);
        };
        h.set_transport_policy([](const test::TransportInput &) { return test::TransportDecision{10, false}; });
        auto policy = body_policy();
        const auto request = policy.request_bytes; const auto serve = policy.serve;
        policy.request_bytes = [&](const test::BodyFetchContext &in) {
            ++request_calls; reject_mutation(); return request(in);
        };
        policy.serve = [&](const test::BodyRequestDelivery &in) {
            ++serve_calls; reject_mutation(); return serve(in);
        };
        h.set_body_service_policy(policy);
        h.admit(1, snowstorm_test::make_body(715007)); h.connect(0, 1);
        h.run_for(20000, 1000000);
        BOOST_CHECK_EQUAL(request_calls, 1U); BOOST_CHECK_EQUAL(serve_calls, 1U);
        BOOST_CHECK_EQUAL(h.truth(0).size(), 1U);
    }
}
BOOST_AUTO_TEST_CASE(Host_body_inventory_is_looked_up_at_request_arrival) {
    using TC = test::TrafficClass; using DS = test::DeliveryStage;
    for (bool admit_after_fetch : {false, true}) {
        test::Host h(0x71510ca, 2, 128);
        std::vector<BodyEvent> events; collect_body(h, events);
        unsigned serves = 0;
        std::optional<bool> available_at_arrival;
        h.set_transport_policy([](const test::TransportInput &in) {
            return test::TransportDecision{in.traffic_class == TC::body_request ? 2000 : 300, false};
        });
        auto policy = body_policy(10000, 20);
        const auto serve = policy.serve;
        policy.serve = [&](const test::BodyRequestDelivery &in) {
            ++serves; available_at_arrival = bool(in.available_body);
            if (in.available_body) BOOST_CHECK(in.available_body->tx_hash() == snowstorm_test::make_body(715008)->tx_hash());
            return serve(in);
        };
        h.set_body_service_policy(policy);
        const auto body = snowstorm_test::make_body(715008);
        h.admit(1, body); const auto item = *h.truth(1).begin(); h.connect(0, 1);
        if (admit_after_fetch) {
            // Preserve an already-scheduled honest snapshot response while
            // removing the actual donor body before it triggers FetchBody.
            BOOST_REQUIRE(h.run_until([&](const test::Host &) {
                return std::any_of(events.begin(), events.end(), [&](const BodyEvent &e) {
                    if (e.traffic_class != TC::reconciliation || e.stage != DS::scheduled ||
                        e.sender != 1 || e.receiver != 0) return false;
                    const auto p = parse(e.payload, h.stats(0).limits);
                    if (p.error != Error::ok) return false;
                    const auto *r = std::get_if<ReconSymbols>(&*p.message);
                    return r && r->status == SymbolsStatus::normal && !r->cells.empty() && r->cells.front().count == 1;
                });
            }, 10000));
            h.remove(1, item);
        }
        BOOST_REQUIRE(h.run_until([&](const test::Host &) {
            return std::any_of(events.begin(), events.end(), [](const BodyEvent &e) {
                return e.traffic_class == TC::body_request && e.stage == DS::offered;
            });
        }, h.now() + 10000));
        if (admit_after_fetch) { BOOST_CHECK(h.truth(1).empty()); h.admit(1, body); }
        else { BOOST_CHECK_EQUAL(h.truth(1).size(), 1U); h.remove(1, item); }
        h.run_for(20000, 1000000);
        BOOST_CHECK_EQUAL(serves, 1U); BOOST_REQUIRE(available_at_arrival);
        BOOST_CHECK_EQUAL(*available_at_arrival, admit_after_fetch);
        exactly_one_terminal_per_token(events);
        BOOST_CHECK_EQUAL(h.truth(0).size(), admit_after_fetch ? 1U : 0U);
    }
}
BOOST_AUTO_TEST_CASE(Host_removal_flushes_token_associated_admission_once_before_removal) {
    using DS = test::DeliveryStage; using TC = test::TrafficClass;
    for (bool body_specific : {false, true}) for (bool light : {false, true}) {
        test::HostOptions options;
        if (light) {
            options.retain_observations = false; options.retain_completions = false;
            options.observation_mode = test::ObservationMode::simulation_observation;
        }
        test::Host h(0x715f105, 2, 128, options);
        std::vector<std::string> order;
        std::optional<FetchId> token;
        std::optional<ShortId> item;
        std::optional<std::uint64_t> response_packet;
        std::map<FetchId, unsigned> terminal, notification;
        std::vector<Time> notification_times;
        h.observe_actions([&](test::NodeId node, Time, std::string_view call,
                              std::span<const Action>) {
            if (node == 0 && (call == "admit" || call == "remove" || call == "remove_body"))
                order.emplace_back(call);
        });
        h.observe_delivery([&](const test::DeliveryObservation &o) {
            if (o.stage == DS::result_callback) {
                BOOST_REQUIRE(o.fetch_id); ++terminal[*o.fetch_id];
                if (o.result == BodyStatus::admitted) {
                    token = o.fetch_id; item = o.item; response_packet = o.packet_id;
                }
            }
            if (o.stage == DS::admission_callback) {
                BOOST_REQUIRE(o.fetch_id); BOOST_REQUIRE(token);
                BOOST_CHECK(o.traffic_class == TC::body_admission);
                BOOST_CHECK_EQUAL(*o.fetch_id, *token);
                BOOST_CHECK(o.item == item);
                BOOST_REQUIRE(response_packet);
                BOOST_CHECK_EQUAL(o.packet_id, *response_packet);
                BOOST_CHECK(o.result == BodyStatus::admitted);
                BOOST_CHECK(o.disposition == test::ApplicationDisposition::delivered_to_core);
                ++notification[*o.fetch_id]; notification_times.push_back(o.time);
                order.emplace_back("admission_callback");
            }
        });
        h.set_transport_policy([](const test::TransportInput &) {
            return test::TransportDecision{10, false};
        });
        h.set_body_service_policy(body_policy(1000, 20, 5000));
        const auto body = snowstorm_test::make_body(715009);
        h.admit(1, body); const auto connection = h.connect(0, 1);
        BOOST_REQUIRE(h.run_until([&](const test::Host &) { return token.has_value(); }, 10000));
        BOOST_REQUIRE(item); BOOST_CHECK_EQUAL(terminal[*token], 1U);
        BOOST_CHECK_EQUAL(notification[*token], 0U);
        BOOST_CHECK_EQUAL(h.truth(0).size(), 1U);
        BOOST_CHECK(h.projected_truth(0).empty());
        const Time removal_time = h.now();
        if (body_specific) h.remove_body(0, *item, body->tx_hash(), RemovalReason::trim);
        else h.remove(0, *item, RemovalReason::trim);
        const std::vector<std::string> expected{
            "admit", "admission_callback", body_specific ? "remove_body" : "remove"};
        BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(), expected.end());
        BOOST_CHECK_EQUAL(notification[*token], 1U);
        BOOST_REQUIRE_EQUAL(notification_times.size(), 1U);
        BOOST_CHECK_EQUAL(notification_times.front(), removal_time);
        BOOST_CHECK(h.truth(0).empty()); BOOST_CHECK(h.projected_truth(0).empty());
        h.disconnect(connection); // no unrelated later re-fetch of the removed body
        h.run_for(10000, 1000000);
        BOOST_CHECK_EQUAL(terminal[*token], 1U);
        BOOST_CHECK_EQUAL(notification[*token], 1U);
        BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(), expected.end());
        BOOST_CHECK(h.truth(0).empty()); BOOST_CHECK(h.projected_truth(0).empty());
    }
}
BOOST_AUTO_TEST_SUITE_END()
