// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../harness/host.h"
#include <snowstorm/messages.h>
#include <snowstorm/short_id.h>
#include <map>

namespace {
using namespace snowstorm;
using namespace snowstorm::test;
using namespace snowstorm_test;

bool contains_id(const std::vector<ShortId> &ids, ShortId id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

void require_absent_everywhere(const Stats &s, ShortId id) {
    BOOST_CHECK(!contains_id(s.own_ids, id));
    BOOST_CHECK(!contains_id(s.candidate_ids, id));
    BOOST_CHECK(!contains_id(s.pending, id));
    for (const auto &peer : s.peers) {
        IdSet ref(s.own_ids.begin(), s.own_ids.end());
        ref.insert(peer.plus.begin(), peer.plus.end());
        for (auto x : peer.minus) ref.erase(x);
        BOOST_CHECK(!ref.contains(id));
    }
}

// A malicious transport endpoint, not an alternate honest protocol. Its fixed
// claim is encoded directly by the independent polynomial/schedule oracle.
// It cannot consult the receiver's reference or inject diagnostic truth.
struct FixedClaim {
    IdSet ids;
    Root root{};
    Limits limits;
    Bytes reply(ByteSpan wire) const {
        const auto parsed = parse(wire, limits);
        BOOST_REQUIRE(parsed.error == Error::ok);
        BOOST_REQUIRE(parsed.message.has_value());
        const auto *request = std::get_if<ReconReq>(&*parsed.message);
        if (!request) return {};
        ReconSymbols response;
        response.tip_context = request->tip_context;
        response.session_id = request->session_id;
        response.request_id = request->request_id;
        response.poll_id = request->poll_id;
        response.snapshot_seq = 1;
        response.current_seq = 1;
        response.ranges = request->ranges;
        response.root_vote = root;
        response.exclusion_version = 1;
        response.exclusions = std::vector<ShortId>{};
        for (auto range : request->ranges) {
            for (const auto &cell : snowstorm_oracle::encode(ids, range.begin,
                                                           range.end)) {
                response.cells.push_back(to_core(cell));
            }
        }
        Bytes result;
        BOOST_REQUIRE(serialize(Message{response}, limits, result) == Error::ok);
        return result;
    }
};

PeerId claim_peer(Host &host, NodeId node, const IdSet &ids) {
    FixedClaim claim; claim.ids = ids; claim.root.fill(0xa7);
    claim.limits = host.stats(node).limits;
    return host.connect_wire(node, [claim](const WireInput &input) {
        auto bytes = claim.reply(input.bytes);
        if (bytes.empty()) return std::vector<WireReply>{};
        return std::vector<WireReply>{{std::move(bytes), 500}};
    });
}

void honest_completions(const Host &host) {
    for (const auto &c : host.completions()) {
        if (!c.honest_source) continue;
        if (c.audit.state == SessionState::done) {
            BOOST_CHECK(IdSet(c.audit.reference.begin(), c.audit.reference.end()) == c.raw);
        } else if (c.audit.state == SessionState::root_matched) {
            BOOST_CHECK(c.audit.root == c.candidate_root);
        }
    }
}

std::size_t fetch_count(const Host &h, NodeId node, ShortId id,
                        std::optional<PeerId> peer = std::nullopt) {
    std::size_t count = 0;
    for (const auto &o : h.observations()) {
        if (o.node != node) continue;
        for (const auto &action : o.actions) {
            const auto *fetch = std::get_if<FetchBody>(&action);
            if (fetch && fetch->short_id == id && (!peer || fetch->peer == *peer)) ++count;
        }
    }
    return count;
}

bool penalized(const Host &h, NodeId node, PeerId peer) {
    for (const auto &o : h.observations()) {
        if (o.node != node) continue;
        for (const auto &action : o.actions)
            if (const auto *p = std::get_if<PeerMisbehaved>(&action); p && p->peer == peer)
                return true;
    }
    return false;
}

void no_failed_reference_after(const Host &h, NodeId node, ShortId id,
                                std::uint64_t call) {
    for (const auto &o : h.observations())
        if (o.node == node && o.after.last_call.call_sequence >= call)
            require_absent_everywhere(o.after, id);
}
} // namespace

BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)

BOOST_AUTO_TEST_CASE(T9_full_mesh_5_20_100_nodes_with_always_on_pooling) {
    for (std::size_t nodes : {5, 20, 100}) {
        BOOST_TEST_CONTEXT("T9 nodes=" << nodes) {
            // Keep traces for the small explicit lifecycle fixture below; this
            // mesh checks all calls online without storing quadratic histories.
            Host host(0x74396d657368ULL + nodes, nodes, 256, {false, false});
            Rng assignment(0x7439706f6f6cULL + nodes);
            for (std::size_t i = 0; i < 60; ++i) {
                auto body = make_body(assignment.next());
                // Reproducible independent Bernoulli draws, conditioned only
                // on a genuine overlap/difference: at least two holders and
                // one nonholder. No periodic node classes or three-pool cycle.
                std::vector<NodeId> holders;
                do {
                    holders.clear();
                    for (NodeId n = 0; n < nodes; ++n)
                        if (assignment.bounded(3) != 0) holders.push_back(n);
                } while (holders.size() < 2 || holders.size() == nodes);
                for (auto n : holders) host.admit(n, body);
            }
            bool saw_rare_sample = false;
            std::vector<std::set<PeerId>> full_population_samples;
            std::vector<IdSet> positively_decoded(nodes);
            std::size_t positive_count = 0;
            host.observe([&](const Observation &o) {
                if (nodes == 100 && o.after.wave.active) {
                    BOOST_CHECK_LE(o.after.wave.k, 8U);
                    if (o.after.wave.population == 99 && o.after.wave.k == 8)
                        saw_rare_sample = true;
                }
                for (const auto &d : o.after.last_call.decodes) {
                    for (const auto &item : to_oracle(d.decode.decoded)) {
                        if (item.sign != 1) continue;
                        // No removals or body failures occur in this mesh.
                        // Pending followed by admission must prevent a second
                        // positive decode, even at another peer/session.
                        BOOST_CHECK(positively_decoded[o.node].insert(item.item).second);
                        ++positive_count;
                    }
                }
                if (nodes == 100 && o.node == 0) {
                    for (const auto &wave : o.after.last_call.waves) {
                        if (wave.wave.population != 99 || wave.wave.sampled.size() != 8)
                            continue;
                        if (full_population_samples.size() < 8)
                            full_population_samples.emplace_back(wave.wave.sampled.begin(),
                                                                 wave.wave.sampled.end());
                    }
                }
            });
            for (NodeId a = 0; a < nodes; ++a)
                for (NodeId b = a + 1; b < nodes; ++b) host.connect(a, b);
            BOOST_REQUIRE(host.run_until([&](const Host &h) {
                if (nodes == 100 && full_population_samples.size() < 4) return false;
                const auto root = h.stats(0).own_root;
                for (NodeId n = 0; n < h.size(); ++n) {
                    const auto s = h.stats(n);
                    if (s.own_root != root || !s.fetches.empty()) return false;
                }
                return true;
            }, 20000000, 10000000));
            if (nodes == 100) {
                BOOST_CHECK(saw_rare_sample);
                BOOST_REQUIRE_GE(full_population_samples.size(), 4U);
                bool sampled_then_absent_for_three_waves = false;
                for (auto peer : full_population_samples[0]) {
                    if (!full_population_samples[1].contains(peer) &&
                        !full_population_samples[2].contains(peer) &&
                        !full_population_samples[3].contains(peer))
                        sampled_then_absent_for_three_waves = true;
                }
                BOOST_CHECK(sampled_then_absent_for_three_waves);
            }
            BOOST_CHECK_GT(positive_count, 0U);
            honest_completions(host);
            BOOST_CHECK_GT(host.traffic().residual_checks, 0U);
            BOOST_CHECK_GT(host.traffic().decode_checks, 0U);
            for (NodeId n = 0; n < nodes; ++n) {
                auto truth = host.truth(n);
                for (auto id : host.stats(n).candidate_ids) BOOST_CHECK(truth.contains(id));
            }
            host.audit();
        }
    }
}

BOOST_AUTO_TEST_CASE(T9_three_node_pending_reference_holder_and_absent_peer) {
    for (bool third_holds : {false, true}) {
        Host host(0x743970656e64ULL + third_holds, 3, 32);
        auto body = make_body(777);
        auto id = short_id(default_tip().key, body->tx_hash());
        host.admit(1, body);
        if (third_holds) host.admit(2, body);
        else host.admit(2, make_body(778)); // force candidate mismatch, hence peel -x
        const auto first = host.connect(0, 1);
        BodyRule delayed; delayed.body = body; delayed.result_delay = 500000;
        host.body_rule(0, first.left_peer, id, delayed);
        BOOST_REQUIRE(host.run_until([id](const Host &h) {
            return contains_id(h.stats(0).pending, id);
        }, 100000));
        BOOST_CHECK(!host.truth(0).contains(id));
        const auto second = host.connect(0, 2);
        host.body_rule(0, second.left_peer, id, delayed);
        BOOST_REQUIRE(host.run_until([second](const Host &h) {
            for (const auto &c : h.completions())
                if (c.node == 0 && c.audit.peer == second.left_peer) return true;
            return false;
        }, host.now() + 100000));
        bool negative = false;
        for (const auto &o : host.observations()) {
            if (o.node != 0) continue;
            for (const auto &d : o.after.last_call.decodes) {
                if (d.peer != second.left_peer) continue;
                for (const auto &item : to_oracle(d.decode.decoded)) {
                    if (item.item != id) continue;
                    BOOST_CHECK_EQUAL(item.sign, -1);
                    negative = true;
                }
            }
        }
        BOOST_CHECK_EQUAL(negative, !third_holds);
        honest_completions(host);
        host.audit();
    }
}

BOOST_AUTO_TEST_CASE(T10_fake_failures_cleanup_all_references_and_repeated_sources) {
    for (auto status : {BodyStatus::not_found, BodyStatus::invalid}) {
        Host host(0x743a66616b65ULL + static_cast<unsigned>(status), 2, 64);
        const auto key = default_tip().key;
        auto real = make_body(8001), fake = make_body(8002);
        auto real_id = short_id(key, real->tx_hash());
        auto fake_id = short_id(key, fake->tx_hash());
        host.admit(1, real);
        const auto malicious = claim_peer(host, 0, {real_id, fake_id});
        BodyRule failure; failure.status = status;
        failure.binding = status == BodyStatus::invalid ? BodyBinding::matched : BodyBinding::unbound;
        if (status == BodyStatus::invalid) failure.expected_tx_hash = fake->tx_hash();
        failure.deliver_admission = false; failure.result_delay = 4000;
        host.body_rule(0, malicious, fake_id, failure);
        BodyRule valid; valid.body = real;
        host.body_rule(0, malicious, real_id, valid);
        BOOST_REQUIRE(host.run_until([fake_id](const Host &h) {
            return contains_id(h.stats(0).pending, fake_id);
        }, 100000));
        // A second direct malicious claim must not keep the failed assumption
        // alive after the first donor's callback.
        auto second = claim_peer(host, 0, {real_id, fake_id});
        host.body_rule(0, second, fake_id, failure);
        host.body_rule(0, second, real_id, valid);
        BOOST_REQUIRE(host.run_until([](const Host &h) {
            return h.stats(0).fakes_rejected > 0;
        }, host.now() + 100000));
        const auto failed_call = host.stats(0).last_call.call_sequence;
        BOOST_CHECK_GT(fetch_count(host, 0, fake_id), 0U);
        BOOST_CHECK(penalized(host, 0, malicious));
        host.connect(0, 1);
        host.run_for(20000);
        no_failed_reference_after(host, 0, fake_id, failed_call);
        BOOST_CHECK(host.truth(0).contains(real_id));
        if (status == BodyStatus::invalid) BOOST_CHECK(contains_id(host.stats(0).rejected, fake_id));
        else BOOST_CHECK(contains_id(host.stats(0).probation, fake_id));
        host.audit();
    }
}

BOOST_AUTO_TEST_CASE(T10_done_honest_donor_survives_false_not_found) {
    Host host(0x743a646f6e65ULL, 2, 32);
    auto body = make_body(8901);
    auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body);
    auto bad = claim_peer(host, 0, {id});
    BodyRule failure; failure.status = BodyStatus::not_found;
    failure.binding = BodyBinding::unbound; failure.result_delay = 20000;
    failure.deliver_admission = false;
    host.body_rule(0, bad, id, failure);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return contains_id(h.stats(0).pending, id);
    }, 100000));
    auto honest = host.connect(0, 1);
    BOOST_REQUIRE(host.run_until([honest](const Host &h) {
        for (const auto &c : h.completions())
            if (c.node == 0 && c.audit.peer == honest.left_peer &&
                c.audit.state == SessionState::done) return true;
        return false;
    }, host.now() + 10000));
    for (const auto &o : host.observations()) {
        if (o.node != 0) continue;
        for (const auto &d : o.after.last_call.decodes)
            if (d.peer == honest.left_peer)
                for (const auto &x : to_oracle(d.decode.decoded))
                    BOOST_CHECK(x.item != id || x.sign != 1);
    }
    BOOST_REQUIRE(host.run_until([id](const Host &h) { return h.projected_truth(0).contains(id); },
                                 host.now() + 100000));
    BOOST_CHECK(penalized(host, 0, bad));
    BOOST_CHECK_GT(fetch_count(host, 0, id, honest.left_peer), 0U);
    BOOST_CHECK(!contains_id(host.stats(0).probation, id));
    honest_completions(host);
}

BOOST_AUTO_TEST_CASE(T10_failed_donor_slots_released_for_honest_ninth) {
    Host host(0x743a6e696e65ULL, 2, 64);
    auto body = make_body(9001);
    auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body);
    for (unsigned source = 0; source < 9; ++source) {
        const auto bad = claim_peer(host, 0, {id});
        BodyRule failure; failure.status = BodyStatus::not_found;
        failure.binding = BodyBinding::unbound; failure.deliver_admission = false;
        host.body_rule(0, bad, id, failure);
        BOOST_REQUIRE(host.run_until([source](const Host &h) {
            return h.stats(0).fakes_rejected >= source + 1;
        }, host.now() + 100000));
        BOOST_CHECK_EQUAL(fetch_count(host, 0, id, bad), 1U);
        require_absent_everywhere(host.stats(0), id);
        BOOST_CHECK(penalized(host, 0, bad));
        host.disconnect_peer(0, bad);
    }
    const auto honest = host.connect(0, 1);
    BOOST_REQUIRE(host.run_until([id](const Host &h) { return h.projected_truth(0).contains(id); },
                                 host.now() + 100000));
    BOOST_CHECK_GT(fetch_count(host, 0, id, honest.left_peer), 0U);
    BOOST_CHECK(!contains_id(host.stats(0).probation, id));
}

BOOST_AUTO_TEST_CASE(T10_wrong_body_is_peer_local_and_policy_rejection_is_not_fraud) {
    for (auto status : {BodyStatus::invalid, BodyStatus::local_rejected}) {
        Host host(0x743a62696e64ULL + static_cast<unsigned>(status), 2, 32);
        auto body = make_body(9101);
        auto id = short_id(default_tip().key, body->tx_hash());
        host.admit(1, body);
        auto bad = claim_peer(host, 0, {id});
        BodyRule result; result.status = status; result.deliver_admission = false;
        result.binding = status == BodyStatus::invalid ? BodyBinding::unbound : BodyBinding::matched;
        if (status == BodyStatus::local_rejected) result.expected_tx_hash = body->tx_hash();
        host.body_rule(0, bad, id, result);
        BOOST_REQUIRE(host.run_until([id, status](const Host &h) {
            return status == BodyStatus::invalid ? contains_id(h.stats(0).probation, id) :
                contains_id(h.stats(0).local_rejected, id);
        }, 100000));
        BOOST_CHECK(!contains_id(host.stats(0).rejected, id));
        if (status == BodyStatus::invalid) {
            BOOST_CHECK(penalized(host, 0, bad));
            host.connect(0, 1);
            BOOST_REQUIRE(host.run_until([id](const Host &h) { return h.projected_truth(0).contains(id); },
                                         host.now() + 100000));
        } else {
            BOOST_CHECK(!penalized(host, 0, bad));
            BOOST_CHECK_EQUAL(host.stats(0).fakes_rejected, 0U);
            const auto requests = fetch_count(host, 0, id);
            host.connect(0, 1); host.run_for(20000);
            BOOST_CHECK_EQUAL(fetch_count(host, 0, id), requests);
            require_absent_everywhere(host.stats(0), id);
            host.admit(0, body); // independent successful admission lifts suppression
            BOOST_CHECK(!contains_id(host.stats(0).local_rejected, id));
            BOOST_CHECK(host.truth(0).contains(id));
        }
    }
}

BOOST_AUTO_TEST_CASE(T10_late_failed_token_cannot_poison_reconnected_honest_admission) {
    Host host(0x743a6c617465ULL, 2, 32);
    auto body = make_body(9201);
    auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body);
    auto old_peer = claim_peer(host, 0, {id});
    BodyRule failure; failure.status = BodyStatus::invalid;
    failure.binding = BodyBinding::matched; failure.expected_tx_hash = body->tx_hash();
    failure.result_delay = 30000; failure.deliver_admission = false;
    host.body_rule(0, old_peer, id, failure);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return fetch_count(h, 0, id) != 0;
    }, 100000));
    host.disconnect_peer(0, old_peer);
    const auto honest = host.connect(0, 1);
    BOOST_CHECK_NE(honest.left_peer, old_peer);
    // An independent valid admission consumes any old fetch; its eventual
    // invalid result must not remove the admitted body or poison the new peer.
    host.admit(0, body);
    const auto failures = host.stats(0).fakes_rejected;
    host.run_for(40000);
    BOOST_CHECK(host.truth(0).contains(id));
    BOOST_CHECK(contains_id(host.stats(0).own_ids, id));
    BOOST_CHECK(!contains_id(host.stats(0).rejected, id));
    BOOST_CHECK_EQUAL(host.stats(0).fakes_rejected, failures);
    BOOST_CHECK(!penalized(host, 0, honest.left_peer));
    host.audit();
}

BOOST_AUTO_TEST_CASE(T10_matching_invalid_collision_rejects_late_valid_body_explicitly) {
    Host host(0x743a636f6c6cULL);
    auto tip = default_tip(); tip.key = collision_key;
    host.add_node(default_config(32), tip);
    const auto bodies = collision_bodies();
    auto peer = claim_peer(host, 0, {collision_id});
    BodyRule invalid; invalid.status = BodyStatus::invalid;
    invalid.binding = BodyBinding::matched;
    invalid.expected_tx_hash = bodies[0]->tx_hash(); invalid.deliver_admission = false;
    host.body_rule(0, peer, collision_id, invalid);
    BOOST_REQUIRE(host.run_until([](const Host &h) {
        return contains_id(h.stats(0).rejected, collision_id);
    }, 100000));
    host.admit(0, bodies[1]);
    BOOST_CHECK(host.stats(0).last_api_error == Error::rejected_id);
    require_absent_everywhere(host.stats(0), collision_id);
    // Actual validation/admission remains host authority. The conservative
    // short-ID rejection prevents representation in this core at this height;
    // it cannot rewrite the independent host's accepted body inventory.
    BOOST_CHECK(host.truth(0).contains(collision_id));
    const auto accepted = host.bodies(0);
    BOOST_REQUIRE_EQUAL(accepted.size(), 1U);
    BOOST_CHECK(accepted.front()->tx_hash() == bodies[1]->tx_hash());
    host.audit();
}

BOOST_AUTO_TEST_SUITE_END()
