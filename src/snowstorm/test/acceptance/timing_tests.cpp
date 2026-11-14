// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include <snowstorm/node.h>
#include "../harness/host.h"

namespace {
using namespace snowstorm;
Config timing_config() {
    Config c; c.max_set_size = 128; c.rng_seed = 0x716;
    c.root_fn = [](const TipContext &, std::span<const TxHandle>) { return Root{}; };
    return c;
}
std::optional<ReconReq> request_in(const Actions &actions, const Limits &limits) {
    for (const auto &a : actions) if (const auto *send = std::get_if<Send>(&a)) {
        auto p = parse(send->bytes, limits);
        BOOST_REQUIRE(p.error == Error::ok);
        if (const auto *req = std::get_if<ReconReq>(&*p.message)) return *req;
    }
    return std::nullopt;
}
Bytes encode(const Message &m, const Limits &limits) {
    Bytes b; BOOST_REQUIRE(serialize(m, limits, b) == Error::ok); return b;
}
void bounded_waves(const Stats &s) {
    for (const auto &a : s.last_call.waves) {
        BOOST_CHECK_GE(a.ended, a.wave.started);
        BOOST_CHECK_LE(a.ended, a.wave.deadline);
    }
}
}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T16_no_peers_positive_rtt_and_monotonic_time) {
    using namespace snowstorm;
    SnowstormNode n(timing_config());
    for (Time t : {Time{0}, Time{1}, Time{1000000}}) {
        auto a = n.on_timer(t);
        BOOST_CHECK(a.empty());
        BOOST_CHECK(!n.stats().wave.active);
        BOOST_CHECK(!n.stats().frozen);
    }
    const auto before = n.stats();
    BOOST_CHECK(n.on_timer(999999).empty());
    BOOST_CHECK(n.stats().last_api_error == Error::nonmonotonic_time);
    BOOST_CHECK_EQUAL(n.stats().own_seq, before.own_seq);
    BOOST_CHECK(n.on_peer_connected(1, PeerCaps{1, 0}, 1000000).empty());
    BOOST_CHECK(n.stats().last_api_error != Error::ok);
}
BOOST_AUTO_TEST_CASE(T16_terminal_status_correlation_and_no_immediate_reopen) {
    using namespace snowstorm;
    for (const auto status : {SymbolsStatus::expired, SymbolsStatus::resource_limited}) {
        SnowstormNode n(timing_config());
        auto actions = n.on_peer_connected(1, PeerCaps{1, 1000}, 0);
        auto req = request_in(actions, n.stats().limits);
        if (!req) req = request_in(n.on_timer(0), n.stats().limits);
        BOOST_REQUIRE(req.has_value());
        ReconSymbols reply;
        reply.tip_context = req->tip_context;
        reply.session_id = req->session_id;
        reply.request_id = req->request_id;
        reply.poll_id = req->poll_id;
        reply.status = status;
        reply.resource_reason = ResourceReason::declared_reference_capacity;
        const auto bytes = encode(reply, n.stats().limits);
        const auto terminal = n.on_message(1, bytes, 1);
        BOOST_CHECK(!request_in(terminal, n.stats().limits).has_value());
        bounded_waves(n.stats());
        const auto st = n.stats();
        BOOST_REQUIRE_EQUAL(st.peers.size(), 1U);
        BOOST_CHECK(st.peers.front().state != SessionState::open);
        BOOST_CHECK(!st.peers.front().request_outstanding);
        BOOST_CHECK(st.last_call.decodes.empty());
        // An obsolete response must never acquire ownership of the next session.
        const auto next = n.on_timer(10000);
        bounded_waves(n.stats());
        const auto fresh = request_in(next, n.stats().limits);
        BOOST_REQUIRE(fresh.has_value());
        {
            BOOST_CHECK_NE(fresh->session_id, req->session_id);
            const auto sid = n.stats().peers.front().session_id;
            n.on_message(1, bytes, 10001);
            BOOST_CHECK_EQUAL(n.stats().peers.front().session_id, sid);
            BOOST_CHECK(n.stats().peers.front().state == SessionState::open);
        }
    }
}
BOOST_AUTO_TEST_CASE(T16_loss_and_rtt_jump_eventual_exact_reconciliation) {
    using namespace snowstorm;
    for (std::size_t nodes : {2U, 5U}) {
        for (Time rtt : {Time{3000}, Time{20000}}) {
            for (std::uint32_t loss : {0U, 100000U}) {
                test::Host host(0x716000 + nodes * 100 + rtt + loss, nodes, 128,
                                test::HostOptions{false, false});
                std::uint64_t late_data = 0, fresh_votes = 0, waves = 0;
                host.observe([&](const test::Observation &o) {
                    bounded_waves(o.after);
                    waves += o.after.last_call.waves.size();
                    for (const auto &r : o.after.last_call.replies) {
                        if (r.accepted_data && !r.accepted_root_vote) ++late_data;
                        if (r.accepted_root_vote) ++fresh_votes;
                        if (r.accepted_root_vote) BOOST_CHECK(r.answered_current_wave);
                    }
                });
                for (std::size_t i = 0; i < nodes; ++i)
                    for (std::size_t j = i + 1; j < nodes; ++j)
                        host.connect(i, j, test::LinkOptions{rtt / 2, 0, loss, 1000});
                for (std::size_t i = 0; i < nodes; ++i)
                    for (unsigned j = 0; j < 4; ++j)
                        host.admit(i, snowstorm_test::make_body(1000 * i + j + 1));
                const bool reached = host.run_until([&](const test::Host &h) {
                    if (!h.equal_truth() || h.truth(0).size() != nodes * 4) return false;
                    const auto candidate = h.stats(0).candidate_ids;
                    for (std::size_t i = 0; i < nodes; ++i)
                        if (!h.stats(i).frozen || h.stats(i).candidate_ids != candidate) return false;
                    return true;
                }, 10000000, 3000000);
                BOOST_REQUIRE(reached);
                host.audit();
                BOOST_CHECK_GT(waves, 0U);
                BOOST_CHECK_GT(late_data, 0U);
                BOOST_CHECK_GT(fresh_votes, 0U);
                BOOST_CHECK_GT(host.traffic().residual_checks, 0U);
                if (loss) BOOST_CHECK_GT(host.traffic().dropped, 0U);
                else BOOST_CHECK_EQUAL(host.traffic().dropped, 0U);
                for (const auto &c : host.completions()) if (c.honest_source) {
                    const std::set<ShortId> ref(c.audit.reference.begin(), c.audit.reference.end());
                    if (c.audit.state == SessionState::done) BOOST_CHECK(ref == c.raw);
                    if (c.audit.state == SessionState::root_matched)
                        BOOST_CHECK(c.audit.root == c.candidate_root);
                }
            }
        }
    }
}
BOOST_AUTO_TEST_CASE(T16_late_timer_uses_captured_deadline_without_catchup) {
    using namespace snowstorm;
    SnowstormNode n(timing_config());
    n.on_peer_connected(1, PeerCaps{1, 1000}, 0);
    n.on_timer(0);
    const auto before = n.stats();
    BOOST_REQUIRE(before.wave.active);
    const Time late = before.wave.deadline + 1000000;
    n.on_timer(late);
    const auto after = n.stats();
    BOOST_REQUIRE_EQUAL(after.last_call.waves.size(), 1U);
    BOOST_CHECK_EQUAL(after.last_call.waves.front().ended, before.wave.deadline);
    BOOST_CHECK_EQUAL(after.wave.started, late);
    const auto duplicate = n.on_timer(late);
    BOOST_CHECK(std::none_of(duplicate.begin(), duplicate.end(), [](const Action &a) {
        return std::holds_alternative<Send>(a);
    }));
}
BOOST_AUTO_TEST_CASE(T16_forced_lost_continuations_and_live_edit) {
    using namespace snowstorm;
    test::Host h(0x7161055, 2, 256, test::HostOptions{false, false});
    for (std::size_t i = 0; i < 2; ++i)
        for (unsigned j = 0; j < 32; ++j)
            h.admit(i, snowstorm_test::make_body(900000 + 100 * i + j));
    const auto link = h.connect(0, 1);
    BOOST_REQUIRE(h.run_until([](const test::Host &host) {
        for (std::size_t i = 0; i < 2; ++i)
            for (const auto &p : host.stats(i).peers)
                if (p.request_outstanding && !p.outstanding_ranges.empty() &&
                    p.outstanding_ranges.front().begin > 0) return true;
        return false;
    }, 100000));
    const auto dropped_before = h.traffic().dropped;
    h.set_link(link, test::LinkOptions{500, 0, 1000000, 1000});
    h.admit(0, snowstorm_test::make_body(999999));
    h.run_for(50000);
    BOOST_CHECK_GE(h.traffic().dropped - dropped_before, 2U);
    std::uint64_t resends = 0;
    for (std::size_t i = 0; i < 2; ++i)
        for (const auto &p : h.stats(i).peers) resends += p.resends;
    BOOST_CHECK_GE(resends, 2U);
    h.set_link(link, test::LinkOptions{500, 0, 0, 1000});
    BOOST_REQUIRE(h.run_until([](const test::Host &host) {
        return host.equal_truth() && host.truth(0).size() == 65;
    }, h.now() + 5000000));
    h.audit();
}
BOOST_AUTO_TEST_CASE(T16_open_retry_keeps_logical_identity_across_own_edit) {
    using namespace snowstorm;
    SnowstormNode n(timing_config());
    auto req = request_in(n.on_peer_connected(1, PeerCaps{1, 1000}, 0), n.stats().limits);
    if (!req) req = request_in(n.on_timer(0), n.stats().limits);
    BOOST_REQUIRE(req.has_value());
    n.on_tx_admitted(snowstorm_test::make_body(716123), 1);
    const auto retry = request_in(n.on_timer(2000), n.stats().limits);
    BOOST_REQUIRE(retry.has_value());
    BOOST_CHECK_EQUAL(retry->session_id, req->session_id);
    BOOST_CHECK_EQUAL(retry->request_id, req->request_id);
    BOOST_CHECK(retry->open);
    BOOST_CHECK_EQUAL(retry->ranges.size(), 1U);
    BOOST_CHECK_EQUAL(retry->ranges.front().begin, 0U);
    BOOST_CHECK_EQUAL(retry->ranges.front().end, 1U);
    BOOST_CHECK_EQUAL(retry->reference_size, req->reference_size);
}
BOOST_AUTO_TEST_SUITE_END()
