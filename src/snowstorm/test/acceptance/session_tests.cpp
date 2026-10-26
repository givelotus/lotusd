// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../harness/host.h"
#include <snowstorm/messages.h>
#include <snowstorm/short_id.h>
#include <cmath>
#include <limits>
#include <set>
#include <stdexcept>

namespace {
using namespace snowstorm;
using namespace snowstorm::test;
using namespace snowstorm_test;

// Rebuild from membership, never from a production sketch/cache/peeler.
void check_residuals(const Stats &stats) {
    for (const auto &peer : stats.peers) {
        IdSet ref(stats.own_ids.begin(), stats.own_ids.end());
        ref.insert(peer.plus.begin(), peer.plus.end());
        for (auto id : peer.minus) ref.erase(id);
        for (const auto &symbol : peer.residuals) {
            const auto encoded = snowstorm_oracle::encode(ref, symbol.index,
                                                         symbol.index + 1);
            require_cell_equal(symbol.residual, snowstorm_oracle::subtract(
                to_oracle(symbol.raw), encoded.at(0)));
        }
    }
}

bool has_id(const std::vector<ShortId> &ids, ShortId id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

std::size_t initial_exchanges(const Host &, NodeId, PeerId, SessionId);

void truthful_completions(const Host &host) {
    for (const auto &c : host.completions()) {
        if (!c.honest_source) continue;
        const IdSet ref(c.audit.reference.begin(), c.audit.reference.end());
        if (c.audit.state == SessionState::done) {
            BOOST_CHECK(ref == c.raw);
        } else if (c.audit.state == SessionState::root_matched) {
            BOOST_CHECK(c.audit.root == c.candidate_root);
            // RootMatched attests the candidate commitment, never raw membership.
            for (const auto &o : host.observations()) {
                if (o.node != c.node) continue;
                for (const auto &d : o.after.last_call.decodes) {
                    BOOST_CHECK(d.peer != c.audit.peer ||
                                d.session_id != c.audit.session_id);
                }
                for (const auto &a : o.actions) {
                    const auto *send = std::get_if<Send>(&a);
                    if (!send || send->peer != c.audit.peer) continue;
                    auto parsed = parse(send->bytes, o.after.limits);
                    BOOST_REQUIRE(parsed.error == Error::ok && parsed.message);
                    const auto *req = std::get_if<ReconReq>(&*parsed.message);
                    if (!req || req->session_id != c.audit.session_id) continue;
                    BOOST_REQUIRE_EQUAL(req->ranges.size(), 1U);
                    BOOST_CHECK_EQUAL(req->ranges[0].begin, 0U);
                    BOOST_CHECK_EQUAL(req->ranges[0].end, 1U);
                }
            }
        }
    }
}

bool candidates_equal(const Host &h) {
    const auto root = h.stats(0).own_root;
    for (NodeId n = 1; n < h.size(); ++n)
        if (h.stats(n).own_root != root) return false;
    return true;
}

std::size_t initial_exchanges(const Host &host, NodeId node, PeerId peer,
                             SessionId session) {
    std::size_t requests = 0;
    std::size_t responses = 0;
    for (const auto &o : host.observations()) {
        if (o.node != node) continue;
        for (const auto &reply : o.after.last_call.replies)
            if (reply.peer == peer && reply.session_id == session && !reply.ignored)
                ++responses;
        for (const auto &action : o.actions) {
            const auto *send = std::get_if<Send>(&action);
            if (!send || send->peer != peer) continue;
            const auto parsed = parse(send->bytes, o.after.limits);
            BOOST_REQUIRE(parsed.error == Error::ok && parsed.message);
            const auto *req = std::get_if<ReconReq>(&*parsed.message);
            if (req && req->session_id == session) ++requests;
        }
    }
    BOOST_CHECK_EQUAL(requests, responses);
    return requests;
}

// Boundary tests below obtain their token through an actual request/serialized
// response. No private node state or fabricated FetchId is installed.
struct LiveFetch {
    std::unique_ptr<SnowstormNode> node;
    TxHandle body;
    FetchBody fetch;
    Time now{};
};

LiveFetch live_fetch() {
    LiveFetch f;
    f.node = std::make_unique<SnowstormNode>(default_config(32));
    f.body = make_body(0x626f647972657375ULL);
    auto tip = default_tip();
    f.node->on_new_tip(tip, 0);
    auto actions = f.node->on_peer_connected(1, {1, 1000}, 0);
    std::optional<ReconReq> request;
    for (unsigned attempt = 0; attempt < 16 && !request; ++attempt) {
        std::optional<Time> timer;
        for (const auto &action : actions) {
            if (const auto *send = std::get_if<Send>(&action)) {
                auto parsed = parse(send->bytes, f.node->stats().limits);
                BOOST_REQUIRE(parsed.error == Error::ok && parsed.message);
                if (const auto *req = std::get_if<ReconReq>(&*parsed.message)) request = *req;
            } else if (const auto *next = std::get_if<ScheduleTimer>(&action)) {
                if (!timer || next->at < *timer) timer = next->at;
            }
        }
        if (!request) {
            BOOST_REQUIRE(timer.has_value());
            f.now = *timer;
            actions = f.node->on_timer(f.now);
        }
    }
    BOOST_REQUIRE(request.has_value());
    ReconSymbols response;
    response.tip_context = request->tip_context;
    response.session_id = request->session_id;
    response.request_id = request->request_id;
    response.poll_id = request->poll_id;
    response.snapshot_seq = 1; response.current_seq = 1;
    response.ranges = request->ranges;
    response.root_vote = canonical_root(tip.context, std::span<const TxHandle>(&f.body, 1));
    response.exclusion_version = 1;
    response.exclusions = std::vector<ShortId>{};
    const auto id = short_id(tip.key, f.body->tx_hash());
    for (const auto &range : request->ranges)
        for (const auto &cell : snowstorm_oracle::encode({id}, range.begin, range.end))
            response.cells.push_back(to_core(cell));
    Bytes bytes;
    BOOST_REQUIRE(serialize(Message{response}, f.node->stats().limits, bytes) == Error::ok);
    f.now += 1000;
    const auto result = f.node->on_message(1, bytes, f.now);
    bool found = false;
    for (const auto &action : result)
        if (const auto *fetch = std::get_if<FetchBody>(&action)) {
            BOOST_REQUIRE(!found);
            f.fetch = *fetch; found = true;
        }
    BOOST_REQUIRE(found);
    BOOST_REQUIRE_EQUAL(f.fetch.short_id, id);
    return f;
}

// Diagnostics for the attempted call may change; protocol state may not.
void unchanged_body_state(const Stats &a, const Stats &b) {
    BOOST_CHECK_EQUAL(a.own_seq, b.own_seq);
    BOOST_CHECK(a.tip_context == b.tip_context);
    BOOST_CHECK(a.own_root == b.own_root);
    BOOST_CHECK_EQUAL(a.root_confidence, b.root_confidence);
    BOOST_CHECK_EQUAL(a.frozen, b.frozen);
    BOOST_CHECK_EQUAL(a.fakes_rejected, b.fakes_rejected);
    BOOST_CHECK_EQUAL(a.decode_steps, b.decode_steps);
    BOOST_CHECK_EQUAL(a.suspended_unadmitted, b.suspended_unadmitted);
    BOOST_CHECK(a.own_ids == b.own_ids);
    BOOST_CHECK(a.candidate_ids == b.candidate_ids);
    BOOST_CHECK(a.pending == b.pending);
    BOOST_CHECK(a.probation == b.probation);
    BOOST_CHECK(a.rejected == b.rejected);
    BOOST_CHECK(a.local_rejected == b.local_rejected);
    BOOST_REQUIRE_EQUAL(a.bodies.size(), b.bodies.size());
    for (std::size_t i = 0; i < a.bodies.size(); ++i) {
        BOOST_CHECK_EQUAL(a.bodies[i].item, b.bodies[i].item);
        BOOST_CHECK(a.bodies[i].txid == b.bodies[i].txid);
        BOOST_CHECK(a.bodies[i].tx_hash == b.bodies[i].tx_hash);
        BOOST_CHECK_EQUAL(a.bodies[i].admission_seq, b.bodies[i].admission_seq);
    }
    BOOST_REQUIRE_EQUAL(a.donors.size(), b.donors.size());
    for (std::size_t i = 0; i < a.donors.size(); ++i) {
        BOOST_CHECK_EQUAL(a.donors[i].item, b.donors[i].item);
        BOOST_CHECK_EQUAL(a.donors[i].peer, b.donors[i].peer);
        BOOST_CHECK_EQUAL(a.donors[i].discovery_order, b.donors[i].discovery_order);
    }
    BOOST_REQUIRE_EQUAL(a.unavailable.size(), b.unavailable.size());
    for (std::size_t i = 0; i < a.unavailable.size(); ++i) {
        BOOST_CHECK_EQUAL(a.unavailable[i].peer, b.unavailable[i].peer);
        BOOST_CHECK_EQUAL(a.unavailable[i].item, b.unavailable[i].item);
    }
    BOOST_REQUIRE_EQUAL(a.fetches.size(), b.fetches.size());
    for (std::size_t i = 0; i < a.fetches.size(); ++i) {
        BOOST_CHECK_EQUAL(a.fetches[i].item, b.fetches[i].item);
        BOOST_CHECK_EQUAL(a.fetches[i].peer, b.fetches[i].peer);
        BOOST_CHECK_EQUAL(a.fetches[i].fetch_id, b.fetches[i].fetch_id);
        BOOST_CHECK(a.fetches[i].state == b.fetches[i].state);
        BOOST_CHECK(a.fetches[i].expected_tx_hash == b.fetches[i].expected_tx_hash);
        BOOST_CHECK(a.fetches[i].tip_context == b.fetches[i].tip_context);
    }
    BOOST_REQUIRE_EQUAL(a.confidence.size(), b.confidence.size());
    for (std::size_t i = 0; i < a.confidence.size(); ++i) {
        BOOST_CHECK_EQUAL(a.confidence[i].item, b.confidence[i].item);
        BOOST_CHECK_EQUAL(a.confidence[i].lambda, b.confidence[i].lambda);
        BOOST_CHECK_EQUAL(a.confidence[i].admitted, b.confidence[i].admitted);
    }
    BOOST_REQUIRE_EQUAL(a.peers.size(), b.peers.size());
    for (std::size_t i = 0; i < a.peers.size(); ++i) {
        const auto &x = a.peers[i]; const auto &y = b.peers[i];
        BOOST_CHECK_EQUAL(x.peer, y.peer);
        BOOST_CHECK_EQUAL(x.session_id, y.session_id);
        BOOST_CHECK_EQUAL(x.request_id, y.request_id);
        BOOST_CHECK_EQUAL(x.poll_id, y.poll_id);
        BOOST_CHECK(x.state == y.state);
        BOOST_CHECK(x.plus == y.plus);
        BOOST_CHECK(x.minus == y.minus);
        BOOST_CHECK(x.exclusions == y.exclusions);
        BOOST_CHECK(x.unavailable == y.unavailable);
        BOOST_CHECK(x.pinned_root == y.pinned_root);
        BOOST_REQUIRE_EQUAL(x.residuals.size(), y.residuals.size());
        for (std::size_t j = 0; j < x.residuals.size(); ++j) {
            BOOST_CHECK_EQUAL(x.residuals[j].index, y.residuals[j].index);
            require_cell_equal(x.residuals[j].raw, to_oracle(y.residuals[j].raw));
            require_cell_equal(x.residuals[j].residual, to_oracle(y.residuals[j].residual));
        }
    }
    BOOST_CHECK_EQUAL(a.wave.number, b.wave.number);
    BOOST_CHECK(a.wave.sampled == b.wave.sampled);
    BOOST_CHECK(a.wave.answered == b.wave.answered);
    BOOST_CHECK(a.wave.matching == b.wave.matching);
    BOOST_CHECK_EQUAL(a.wave.invalidated, b.wave.invalidated);
}
} // namespace

BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)

BOOST_AUTO_TEST_CASE(T8_node_constructor_rejects_invalid_local_config_domains) {
    const auto nan = std::numeric_limits<double>::quiet_NaN();
    const auto inf = std::numeric_limits<double>::infinity();
    for (double beta : {-1.0, -std::numeric_limits<double>::denorm_min(),
                        1.0 / 3.0, 1.0, nan, inf, -inf}) {
        auto cfg = default_config(32); cfg.beta_max = beta;
        BOOST_CHECK_THROW(SnowstormNode{cfg}, std::invalid_argument);
    }
    for (double epsilon : {-1.0, 0.0, 1.0, 2.0, nan, inf, -inf}) {
        auto cfg = default_config(32); cfg.epsilon = epsilon;
        BOOST_CHECK_THROW(SnowstormNode{cfg}, std::invalid_argument);
    }
    constexpr std::uint64_t largest = ((1ULL << 21) - 256) / 8;
    for (std::uint64_t size : {0ULL, largest + 1, std::numeric_limits<std::uint64_t>::max()}) {
        auto cfg = default_config(32); cfg.max_set_size = size;
        BOOST_CHECK_THROW(SnowstormNode{cfg}, std::invalid_argument);
    }
    auto empty_root = default_config(32); empty_root.root_fn = {};
    BOOST_CHECK_THROW(SnowstormNode{empty_root}, std::invalid_argument);
    for (double beta : {0.0, std::nextafter(1.0 / 3.0, 0.0)}) {
        for (double epsilon : {std::numeric_limits<double>::min(),
                               std::nextafter(1.0, 0.0)}) {
            auto cfg = default_config(1); cfg.beta_max = beta; cfg.epsilon = epsilon;
            BOOST_CHECK_NO_THROW(SnowstormNode{cfg});
        }
    }
    BOOST_CHECK_NO_THROW(SnowstormNode{default_config(largest)});
}

BOOST_AUTO_TEST_CASE(T8_live_body_result_validation_and_stale_precedence) {
    auto f = live_fetch();
    auto wrong_hash = make_hash(0x77726f6e67ULL);
    BOOST_REQUIRE(short_id(default_tip().key, wrong_hash) != f.fetch.short_id);
    const auto correct_hash = f.body->tx_hash();
    std::vector<BodyResult> malformed;
    auto add = [&](BodyStatus status, BodyBinding binding, std::optional<TxHash> hash) {
        malformed.push_back({f.fetch.fetch_id, status, binding, hash});
    };
    add(static_cast<BodyStatus>(255), BodyBinding::matched, correct_hash);
    add(BodyStatus::admitted, static_cast<BodyBinding>(255), correct_hash);
    add(BodyStatus::invalid, static_cast<BodyBinding>(255), correct_hash);
    add(BodyStatus::local_rejected, static_cast<BodyBinding>(255), correct_hash);
    add(BodyStatus::not_found, static_cast<BodyBinding>(255), correct_hash);
    for (auto status : {BodyStatus::admitted, BodyStatus::invalid, BodyStatus::local_rejected}) {
        add(status, BodyBinding::matched, std::nullopt);
        add(status, BodyBinding::matched, wrong_hash);
    }
    for (auto status : {BodyStatus::admitted, BodyStatus::local_rejected}) {
        add(status, BodyBinding::unbound, correct_hash);
        add(status, BodyBinding::unbound, std::nullopt);
    }
    BOOST_REQUIRE_EQUAL(malformed.size(), 15U);
    for (const auto &result : malformed) {
        auto before = f.node->stats();
        auto actions = f.node->on_tx_bodies_result(f.fetch.peer, f.fetch.short_id,
                                                  result, ++f.now);
        BOOST_CHECK(actions.empty());
        const auto after = f.node->stats();
        BOOST_CHECK(after.last_api_error == Error::host_contract_error);
        unchanged_body_state(before, after);
    }
    // Unknown token/peer/item must be classified before even illegal enums.
    auto garbage = malformed.front();
    garbage.binding = static_cast<BodyBinding>(255);
    for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
        auto result = garbage;
        auto peer = f.fetch.peer; auto item = f.fetch.short_id;
        if (mismatch == 0) result.fetch_id = std::numeric_limits<FetchId>::max();
        if (mismatch == 1) ++peer;
        if (mismatch == 2) item = item == 1 ? 2 : 1;
        const auto before = f.node->stats();
        BOOST_CHECK(f.node->on_tx_bodies_result(peer, item, result, ++f.now).empty());
        BOOST_CHECK(f.node->stats().last_api_error != Error::host_contract_error);
        unchanged_body_state(before, f.node->stats());
    }
    BodyResult admitted{f.fetch.fetch_id, BodyStatus::admitted,
                        BodyBinding::matched, correct_hash};
    f.node->on_tx_bodies_result(f.fetch.peer, f.fetch.short_id, admitted, ++f.now);
    BOOST_REQUIRE_EQUAL(f.node->stats().fetches.size(), 1U);
    BOOST_REQUIRE(f.node->stats().fetches.front().state == FetchState::awaiting_admission);
    // A result token is completed even while its separate admission is pending.
    for (unsigned phase = 0; phase < 3; ++phase) {
        for (const auto &result : malformed) {
            const auto before = f.node->stats();
            BOOST_CHECK(f.node->on_tx_bodies_result(f.fetch.peer, f.fetch.short_id,
                                                   result, ++f.now).empty());
            BOOST_CHECK(f.node->stats().last_api_error != Error::host_contract_error);
            unchanged_body_state(before, f.node->stats());
        }
        if (phase == 0) f.node->on_tx_admitted(f.body, ++f.now);
        if (phase == 1) f.node->on_new_tip(default_tip(1), ++f.now);
    }
}

BOOST_AUTO_TEST_CASE(T8_body_result_ignored_hash_fields_do_not_become_contract_errors) {
    for (auto status : {BodyStatus::not_found, BodyStatus::invalid}) {
      for (auto binding : {BodyBinding::unbound, BodyBinding::matched}) {
        if (status == BodyStatus::invalid && binding == BodyBinding::matched) continue;
       for (unsigned hash_case = 0; hash_case < 3; ++hash_case) {
        auto f = live_fetch();
        std::optional<TxHash> hash;
        if (hash_case == 1) hash = f.body->tx_hash();
        if (hash_case == 2) hash = make_hash(0x69676e6f726564ULL);
        BodyResult result{f.fetch.fetch_id, status, binding, hash};
        const auto actions = f.node->on_tx_bodies_result(f.fetch.peer, f.fetch.short_id,
                                                       result, ++f.now);
        BOOST_CHECK(f.node->stats().last_api_error != Error::host_contract_error);
        BOOST_CHECK(has_id(f.node->stats().probation, f.fetch.short_id));
        BOOST_CHECK(!has_id(f.node->stats().rejected, f.fetch.short_id));
        bool penalty = false;
        for (const auto &action : actions)
            if (const auto *p = std::get_if<PeerMisbehaved>(&action)) {
                BOOST_CHECK_EQUAL(p->peer, f.fetch.peer);
                BOOST_CHECK(p->reason == (status == BodyStatus::not_found ?
                    Misbehavior::body_not_found : Misbehavior::wrong_body_binding));
                penalty = true;
            }
        BOOST_CHECK(penalty);
       }
      }
    }
}

BOOST_AUTO_TEST_CASE(T7_static_reconciliation_7000_fresh_trials) {
    constexpr std::array<std::size_t, 7> deltas{0, 1, 2, 3, 10, 100, 1000};
    Rng seeds(0x7437737461746963ULL);
    std::size_t trials = 0;
    for (const auto delta : deltas) {
        for (std::size_t trial = 0; trial < 1000; ++trial) {
            const auto seed = seeds.next();
            BOOST_TEST_CONTEXT("T7 delta=" << delta << " trial=" << trial << " seed=" << seed) {
                Host host(seed, 2, 2048);
                Rng bodies(seed);
                for (unsigned i = 0; i < 8; ++i) {
                    auto body = make_body(bodies.next());
                    host.admit(0, body); host.admit(1, body);
                }
                std::vector<std::pair<NodeId, TxHandle>> differences;
                for (std::size_t i = 0; i < delta; ++i) {
                    auto body = make_body(bodies.next());
                    NodeId holder = (i + trial) % 2;
                    host.admit(holder, body);
                    differences.emplace_back(holder, body);
                }
                const auto link = host.connect(0, 1);
                for (const auto &[holder, body] : differences) {
                    BodyRule rule;
                    rule.body = body;
                    rule.result_delay = 100000;
                    host.body_rule(1 - holder,
                        holder == 0 ? link.right_peer : link.left_peer,
                        short_id(default_tip().key, body->tx_hash()), rule);
                }
                BOOST_REQUIRE(host.run_until([](const Host &h) {
                    bool left = false, right = false;
                    for (const auto &c : h.completions()) {
                        left |= c.node == 0; right |= c.node == 1;
                    }
                    return left && right;
                }, 90000));
                if (delta <= 2) {
                    std::array<bool, 2> checked{};
                    for (const auto &c : host.completions()) {
                        if (checked[c.node]) continue;
                        BOOST_CHECK_EQUAL(initial_exchanges(host, c.node,
                            c.audit.peer, c.audit.session_id), 1U);
                        checked[c.node] = true;
                    }
                    BOOST_CHECK(checked[0] && checked[1]);
                }
                BOOST_REQUIRE(host.run_until([](const Host &h) {
                    return candidates_equal(h) && h.stats(0).fetches.empty() &&
                           h.stats(1).fetches.empty();
                }, 2000000));
                truthful_completions(host);
                host.audit();
                for (NodeId n = 0; n < 2; ++n) {
                    check_residuals(host.stats(n));
                    const auto truth = host.truth(n);
                    for (auto id : host.stats(n).candidate_ids)
                        BOOST_CHECK(truth.contains(id));
                }
                ++trials;
            }
        }
    }
    BOOST_CHECK_EQUAL(trials, 7000U);
}

BOOST_AUTO_TEST_CASE(T8_ten_sessions_with_all_removal_reasons_and_live_churn) {
    Host host(0x7438636875726eULL, 2, 512);
    const auto key = default_tip().key;
    Rng rng(0x743872656d6f7665ULL);
    std::array<std::vector<TxHandle>, 2> inventory;
    for (NodeId n = 0; n < 2; ++n) {
        for (unsigned i = 0; i < 80; ++i) {
            auto body = make_body(rng.next());
            inventory[n].push_back(body); host.admit(n, body);
        }
    }
    host.observe([](const Observation &o) { check_residuals(o.after); });
    std::array<bool, 8> reasons{};
    std::array<bool, 6> counts{};
    unsigned mutation = 0;
    auto churn = [&](unsigned round, unsigned phase) {
        for (NodeId n = 0; n < 2; ++n) {
            const auto count = (round + phase + n) % 6;
            counts[count] = true;
            for (unsigned j = 0; j < count; ++j) {
                auto removed = inventory[n].back(); inventory[n].pop_back();
                const unsigned reason = mutation++ % 8;
                reasons[reason] = true;
                host.remove(n, short_id(key, removed->tx_hash()),
                            static_cast<RemovalReason>(reason));
                // Re-admission exercises the same identity after removal; the
                // other additions exercise entirely new sequence entries.
                auto added = j == 0 ? removed : make_body(rng.next());
                inventory[n].insert(inventory[n].begin(), added);
                host.admit(n, added);
            }
        }
    };
    for (unsigned round = 0; round < 10; ++round) {
        churn(round, 0); // before
        const auto link = host.connect(0, 1);
        BOOST_REQUIRE(host.step());
        churn(round, 1); // while requests/snapshots are in flight
        const auto start = host.completions().size();
        BOOST_REQUIRE(host.run_until([start](const Host &h) {
            return h.completions().size() >= start + 2;
        }, host.now() + 2000000));
        truthful_completions(host);
        host.disconnect(link);
        churn(round, 2); // between sessions
    }
    for (bool covered : reasons) BOOST_CHECK(covered);
    for (bool covered : counts) BOOST_CHECK(covered);
    const auto final_start = host.completions().size();
    host.connect(0, 1);
    BOOST_REQUIRE(host.run_until([final_start](const Host &h) {
        return h.completions().size() >= final_start + 2 && candidates_equal(h);
    }, host.now() + 3000000));
    truthful_completions(host);
    BOOST_CHECK_GT(host.traffic().decode_checks, 0U);
    BOOST_CHECK_GT(host.traffic().residual_checks, 0U);
    host.audit();
}

BOOST_AUTO_TEST_CASE(T8_awaiting_admission_survives_timer_and_transfers_score) {
    Host host(0x74386177616974ULL, 2, 32);
    auto body = make_body(0x123876ULL);
    const auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body);
    auto link = host.connect(0, 1);
    BodyRule rule; rule.body = body; rule.result_delay = 500; rule.admission_delay = 20000;
    host.body_rule(0, link.left_peer, id, rule);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        for (const auto &f : h.stats(0).fetches)
            if (f.item == id && f.state == FetchState::awaiting_admission) return true;
        return false;
    }, 100000));
    BOOST_CHECK(host.truth(0).contains(id));
    BOOST_CHECK(!host.projected_truth(0).contains(id));
    BOOST_CHECK(!has_id(host.stats(0).own_ids, id));
    BOOST_CHECK(has_id(host.stats(0).pending, id));
    host.timer(0);
    BOOST_CHECK(has_id(host.stats(0).pending, id));
    bool saw_transfer = false;
    host.observe([&](const Observation &o) {
        check_residuals(o.after);
        if (o.node != 0 || has_id(o.before.own_ids, id) ||
            !has_id(o.after.own_ids, id)) return;
        for (const auto &before : o.before.confidence) {
            if (before.item != id) continue;
            for (const auto &after : o.after.confidence) {
                if (after.item == id) {
                    BOOST_CHECK_EQUAL(before.lambda, after.lambda);
                    saw_transfer = true;
                }
            }
        }
    });
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return h.projected_truth(0).contains(id);
    }, host.now() + 100000));
    BOOST_CHECK(saw_transfer);
    BOOST_CHECK(!has_id(host.stats(0).pending, id));
    host.audit();
}

BOOST_AUTO_TEST_CASE(T8_tip_reset_cancels_awaiting_old_body_callback) {
    Host host(0x7438616261ULL, 2, 32);
    auto body = make_body(1234);
    auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body);
    auto link = host.connect(0, 1);
    BodyRule rule; rule.body = body; rule.admission_delay = 20000;
    host.body_rule(0, link.left_peer, id, rule);
    BOOST_REQUIRE(host.run_until([](const Host &h) {
        for (const auto &f : h.stats(0).fetches)
            if (f.state == FetchState::awaiting_admission) return true;
        return false;
    }, 100000));
    host.change_tip(0, default_tip(1));
    BOOST_CHECK(host.stats(0).pending.empty());
    BOOST_CHECK(host.stats(0).fetches.empty());
    BOOST_CHECK(host.stats(0).confidence.empty());
    host.disconnect(link);
    host.run_for(30000);
    BOOST_CHECK(host.truth(0).empty());
    BOOST_CHECK(host.stats(0).own_ids.empty());
}

BOOST_AUTO_TEST_CASE(T7_honest_root_match_with_excluded_raw_extra) {
    Host host(0x74376578636cULL, 5, 32);
    auto common = make_body(7720), extra = make_body(7721);
    auto id = short_id(default_tip().key, extra->tx_hash());
    for (NodeId n = 0; n < 5; ++n) host.admit(n, common);
    host.admit(0, extra);
    for (NodeId a = 0; a < 5; ++a) {
        for (NodeId b = a + 1; b < 5; ++b) {
            auto link = host.connect(a, b);
            BodyRule delayed; delayed.body = extra; delayed.result_delay = 1000000;
            if (a == 0) host.body_rule(b, link.right_peer, id, delayed);
        }
    }
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return has_id(h.stats(0).own_ids, id) && !has_id(h.stats(0).candidate_ids, id);
    }, 900000));
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        for (const auto &c : h.completions())
            if (c.audit.state == SessionState::root_matched && c.honest_source &&
                c.raw.contains(id) && !c.candidate.contains(id)) return true;
        return false;
    }, 950000));
    truthful_completions(host);
    BOOST_CHECK(host.truth(0).contains(id));
    host.audit();
}

BOOST_AUTO_TEST_CASE(T7_echoed_root_never_authenticates_fake_raw_body) {
    Host host(0x74376563686fULL, 1, 32);
    auto fake = make_body(7878);
    auto id = short_id(default_tip().key, fake->tx_hash());
    const auto limits = host.stats(0).limits;
    const auto root = host.stats(0).own_root;
    auto peer = host.connect_wire(0, [=](const WireInput &in) {
        const auto parsed = parse(in.bytes, limits);
        BOOST_REQUIRE(parsed.error == Error::ok && parsed.message);
        const auto *req = std::get_if<ReconReq>(&*parsed.message);
        if (!req) return std::vector<WireReply>{};
        ReconSymbols msg;
        msg.tip_context = req->tip_context; msg.session_id = req->session_id;
        msg.request_id = req->request_id; msg.poll_id = req->poll_id;
        msg.snapshot_seq = 1; msg.current_seq = 1; msg.ranges = req->ranges;
        msg.root_vote = root; msg.exclusion_version = 1;
        msg.exclusions = std::vector<ShortId>{};
        for (const auto &range : req->ranges)
            for (const auto &cell : snowstorm_oracle::encode({id}, range.begin, range.end))
                msg.cells.push_back(to_core(cell));
        Bytes out;
        BOOST_REQUIRE(serialize(Message{msg}, limits, out) == Error::ok);
        return std::vector<WireReply>{{std::move(out), 500}};
    });
    BOOST_REQUIRE(host.run_until([](const Host &h) {
        return !h.completions().empty();
    }, 100000));
    const auto &c = host.completions().front();
    BOOST_CHECK(c.audit.state == SessionState::root_matched);
    BOOST_CHECK_EQUAL(initial_exchanges(host, 0, peer, c.audit.session_id), 1U);
    BOOST_CHECK(host.stats(0).own_ids.empty());
    BOOST_CHECK(host.stats(0).pending.empty());
    BOOST_CHECK_EQUAL(host.stats(0).decode_steps, 0U);
    for (const auto &o : host.observations())
        for (const auto &action : o.actions) BOOST_CHECK(!std::holds_alternative<FetchBody>(action));
}

BOOST_AUTO_TEST_CASE(T8_real_collision_body_removal_updates_root_and_tip_rekeys) {
    Host host(0x7438636f6c6cULL);
    auto tip = default_tip(); tip.key = collision_key;
    host.add_node(default_config(32), tip);
    const auto bodies = collision_bodies();
    for (const auto &body : bodies) {
        BOOST_REQUIRE_EQUAL(short_id(collision_key, body->tx_hash()), collision_id);
        host.admit(0, body);
    }
    const auto before = host.stats(0);
    BOOST_REQUIRE_EQUAL(before.own_ids.size(), 1U);
    BOOST_REQUIRE_EQUAL(before.bodies.size(), 2U);
    host.remove_body(0, collision_id, bodies[0]->tx_hash(), RemovalReason::variant);
    const auto after = host.stats(0);
    BOOST_CHECK_EQUAL(after.own_ids.size(), 1U);
    BOOST_REQUIRE_EQUAL(after.bodies.size(), 1U);
    BOOST_CHECK(after.bodies.front().tx_hash == bodies[1]->tx_hash());
    BOOST_CHECK(after.own_root != before.own_root);
    BOOST_CHECK(after.own_root == canonical_root(tip.context,
        std::span<const TxHandle>(&bodies[1], 1)));
    BOOST_CHECK_GT(after.own_seq, before.own_seq);
    for (bool disconnected : {false, true}) {
        auto next = default_tip(disconnected ? 2 : 1);
        next.surviving = {bodies[1]};
        host.change_tip(0, next, disconnected);
        BOOST_REQUIRE_EQUAL(host.stats(0).own_ids.size(), 1U);
        BOOST_CHECK_EQUAL(host.stats(0).own_ids.front(),
                          short_id(next.key, bodies[1]->tx_hash()));
        for (const auto &score : host.stats(0).confidence) BOOST_CHECK_EQUAL(score.lambda, 0U);
    }
    host.audit();
}

BOOST_AUTO_TEST_CASE(T8_same_peer_positive_after_negative_and_removed_readmitted_id) {
    Host host(0x74387369676eULL, 3, 32);
    auto x = make_body(8301), y = make_body(8302);
    auto id = short_id(default_tip().key, x->tx_hash());
    host.admit(1, x); host.admit(2, y);
    auto first = host.connect(0, 1);
    BodyRule delayed; delayed.body = x; delayed.result_delay = 30000;
    host.body_rule(0, first.left_peer, id, delayed);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return has_id(h.stats(0).pending, id);
    }, 100000));
    auto second = host.connect(0, 2);
    auto saw_sign = [&](int sign, std::uint64_t after_call) {
        for (const auto &o : host.observations()) {
            if (o.node != 0 || o.after.last_call.call_sequence <= after_call) continue;
            for (const auto &d : o.after.last_call.decodes)
                if (d.peer == second.left_peer)
                    for (const auto &item : to_oracle(d.decode.decoded))
                        if (item.item == id && item.sign == sign) return true;
        }
        return false;
    };
    BOOST_REQUIRE(host.run_until([&](const Host &) { return saw_sign(-1, 0); },
                                 host.now() + 10000));
    BOOST_REQUIRE(host.run_until([id](const Host &h) { return h.projected_truth(0).contains(id); },
                                 host.now() + 100000));
    host.disconnect(first);
    host.remove(0, id, RemovalReason::expiry);
    host.admit(2, x);
    const auto boundary = host.stats(0).last_call.call_sequence;
    bool saw_positive_membership = false;
    host.observe([&](const Observation &o) {
        check_residuals(o.after);
        if (o.node != 0) return;
        for (const auto &d : o.after.last_call.decodes) {
            if (d.peer != second.left_peer) continue;
            for (const auto &item : to_oracle(d.decode.decoded)) {
                if (item.item != id || item.sign != 1) continue;
                for (const auto &p : o.after.peers) {
                    if (p.peer != second.left_peer || p.session_id != d.session_id) continue;
                    BOOST_CHECK(!has_id(p.minus, id));
                    saw_positive_membership = true;
                }
            }
        }
    });
    BOOST_REQUIRE(host.run_until([&](const Host &) { return saw_sign(1, boundary); },
                                 host.now() + 200000));
    BOOST_CHECK(saw_positive_membership);
    BOOST_REQUIRE(host.run_until([id](const Host &h) { return h.projected_truth(0).contains(id); },
                                 host.now() + 100000));
    truthful_completions(host);
    host.audit();
}

BOOST_AUTO_TEST_CASE(T8_disconnect_cancels_inflight_token_before_payload_validation) {
    auto f = live_fetch();
    f.node->on_peer_disconnected(f.fetch.peer, ++f.now);
    BOOST_CHECK(f.node->stats().fetches.empty());
    // Reconnection has a distinct identity; the old token cannot be rebound.
    f.node->on_peer_connected(f.fetch.peer + 1, {1, 1000}, ++f.now);
    const auto before = f.node->stats();
    BodyResult garbage{f.fetch.fetch_id, static_cast<BodyStatus>(255),
                       static_cast<BodyBinding>(255), std::nullopt};
    BOOST_CHECK(f.node->on_tx_bodies_result(f.fetch.peer, f.fetch.short_id,
                                           garbage, ++f.now).empty());
    BOOST_CHECK(f.node->stats().last_api_error != Error::host_contract_error);
    unchanged_body_state(before, f.node->stats());
}

BOOST_AUTO_TEST_CASE(T8_disconnect_retries_known_alternate_without_waiting_old_result) {
    Host host(0x743864697363ULL, 3, 32);
    auto body = make_body(0x646973636f6eULL);
    const auto id = short_id(default_tip().key, body->tx_hash());
    host.admit(1, body); host.admit(2, body);
    const auto first = host.connect(0, 1);
    BodyRule stalled;
    stalled.status = BodyStatus::invalid;
    stalled.binding = BodyBinding::matched;
    stalled.expected_tx_hash = body->tx_hash();
    stalled.result_delay = 50000;
    stalled.deliver_admission = false;
    host.body_rule(0, first.left_peer, id, stalled);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        for (const auto &fetch : h.stats(0).fetches)
            if (fetch.item == id && fetch.state == FetchState::in_flight) return true;
        return false;
    }, 100000));
    const auto old_token = host.stats(0).fetches.front().fetch_id;
    const auto second = host.connect(0, 2);
    BOOST_REQUIRE(host.run_until([id, second](const Host &h) {
        for (const auto &donor : h.stats(0).donors)
            if (donor.item == id && donor.peer == second.left_peer) return true;
        return false;
    }, host.now() + 10000));
    const auto failure_count = host.stats(0).fakes_rejected;
    host.disconnect_peer(0, first.left_peer);
    bool immediate_retry = false;
    for (const auto &action : host.observations().back().actions) {
        if (const auto *fetch = std::get_if<FetchBody>(&action)) {
            BOOST_CHECK_EQUAL(fetch->peer, second.left_peer);
            BOOST_CHECK_EQUAL(fetch->short_id, id);
            BOOST_CHECK_NE(fetch->fetch_id, old_token);
            immediate_retry = true;
        }
        BOOST_CHECK(!std::holds_alternative<PeerMisbehaved>(action));
    }
    BOOST_CHECK(immediate_retry);
    BOOST_REQUIRE(host.run_until([id](const Host &h) {
        return h.projected_truth(0).contains(id);
    }, host.now() + 10000));
    // The canceled donor's matching-invalid reply still arrives: it is stale
    // and cannot reject the genuine independently admitted body.
    host.run_for(60000);
    BOOST_CHECK_EQUAL(host.stats(0).fakes_rejected, failure_count);
    BOOST_CHECK(!has_id(host.stats(0).rejected, id));
    BOOST_CHECK(host.projected_truth(0).contains(id));
    host.audit();
}

BOOST_AUTO_TEST_CASE(T8_awaiting_admission_survives_donor_disconnect_until_callback_or_tip) {
    for (bool cancel_by_tip : {false, true}) {
        Host host(0x743861776469ULL + cancel_by_tip, 2, 32);
        auto body = make_body(0x617761697464ULL);
        const auto id = short_id(default_tip().key, body->tx_hash());
        host.admit(1, body);
        const auto link = host.connect(0, 1);
        BodyRule rule; rule.body = body; rule.admission_delay = 20000;
        host.body_rule(0, link.left_peer, id, rule);
        BOOST_REQUIRE(host.run_until([id](const Host &h) {
            for (const auto &fetch : h.stats(0).fetches)
                if (fetch.item == id && fetch.state == FetchState::awaiting_admission)
                    return true;
            return false;
        }, 100000));
        BOOST_CHECK(host.truth(0).contains(id));
        BOOST_CHECK(!host.projected_truth(0).contains(id));
        const auto token = host.stats(0).fetches.front().fetch_id;
        host.disconnect(link);
        const auto disconnected = host.stats(0);
        BOOST_REQUIRE_EQUAL(disconnected.fetches.size(), 1U);
        BOOST_CHECK_EQUAL(disconnected.fetches.front().fetch_id, token);
        BOOST_CHECK(disconnected.fetches.front().state == FetchState::awaiting_admission);
        BOOST_CHECK(disconnected.fetches.front().expected_tx_hash == body->tx_hash());
        BOOST_CHECK(has_id(disconnected.pending, id));
        host.timer(0);
        BOOST_CHECK(has_id(host.stats(0).pending, id));
        if (cancel_by_tip) {
            host.change_tip(0, default_tip(1));
            BOOST_CHECK(host.stats(0).fetches.empty());
            BOOST_CHECK(host.stats(0).pending.empty());
            host.run_for(30000);
            BOOST_CHECK(host.truth(0).empty());
            BOOST_CHECK(host.projected_truth(0).empty());
        } else {
            BOOST_REQUIRE(host.run_until([id](const Host &h) {
                return h.projected_truth(0).contains(id);
            }, host.now() + 30000));
            BOOST_CHECK(host.stats(0).fetches.empty());
            BOOST_CHECK(!has_id(host.stats(0).pending, id));
            BOOST_CHECK(has_id(host.stats(0).own_ids, id));
        }
        host.audit();
    }
}

BOOST_AUTO_TEST_CASE(T8_same_session_negative_then_positive_reachability_trace) {
    // Reachability only: deliberately contradictory remote cells cause -x,
    // then a genuine host change resets the claim ledger, then +x in the SAME
    // session. The old source immediately produces a repeated claim and closes.
    // This public trace cannot kill a mutant that updates Peeler correctly but
    // omits Node.minus.erase(x), then clears both on that close. The later
    // implementation gate MUST inspect actual postcommit Node state and prove
    // by mutation that omitted minus erasure fails an invariant BEFORE close.
    // Do not describe replay of prescribed transitions as observing that state.
    SnowstormNode node(default_config(32));
    auto tip = default_tip(); tip.key = collision_key;
    tip.surviving = {collision_bodies()[0]};
    node.on_new_tip(tip, 0);
    constexpr ShortId x = collision_id;
    constexpr ShortId w = 0x7127512f72f27cceULL;
    TxHash w_hash{};
    for (std::size_t i = 0; i < w_hash.size(); ++i) w_hash[i] = static_cast<Byte>(i);
    auto w_body = std::make_shared<SyntheticBody>(make_hash(0x747261636577ULL), w_hash, w);
    BOOST_REQUIRE_EQUAL(short_id(tip.key, w_hash), w);

    auto request_from = [&](const Actions &actions) {
        std::optional<ReconReq> request;
        for (const auto &action : actions) {
            BOOST_CHECK(!std::holds_alternative<FetchBody>(action));
            if (const auto *send = std::get_if<Send>(&action)) {
                const auto parsed = parse(send->bytes, node.stats().limits);
                BOOST_REQUIRE(parsed.error == Error::ok && parsed.message);
                if (const auto *req = std::get_if<ReconReq>(&*parsed.message)) request = *req;
            }
        }
        return request;
    };
    auto actions = node.on_peer_connected(1, {1, 1000}, 0);
    auto request = request_from(actions);
    if (!request) request = request_from(node.on_timer(0));
    BOOST_REQUIRE(request.has_value());
    const auto session = request->session_id;
    const std::array<Range, 5> expected{{{0, 1}, {1, 3}, {3, 6}, {6, 12}, {12, 24}}};
    bool saw_negative = false, saw_positive = false, saw_close = false;
    const auto raw0 = snowstorm_oracle::encode({3, 4, 8}, 0, 1).front();
    BOOST_CHECK(raw0 == (snowstorm_oracle::Cell{3, 0xf, 0x24f, 0x8433}));
    const auto raw_x = snowstorm_oracle::encode({x}, 14, 15).front();
    BOOST_REQUIRE_EQUAL(raw_x.count, 1);
    for (std::size_t round = 0; round < expected.size(); ++round) {
        BOOST_REQUIRE(request.has_value());
        BOOST_CHECK_EQUAL(request->session_id, session);
        BOOST_REQUIRE_EQUAL(request->ranges.size(), 1U);
        BOOST_CHECK_EQUAL(request->ranges.front().begin, expected[round].begin);
        BOOST_CHECK_EQUAL(request->ranges.front().end, expected[round].end);
        ReconSymbols response;
        response.tip_context = tip.context;
        response.session_id = session;
        response.request_id = request->request_id;
        response.poll_id = request->poll_id;
        response.snapshot_seq = 1; response.current_seq = 1;
        response.ranges = request->ranges;
        response.root_vote.fill(0xa7);
        response.exclusion_version = 1;
        response.exclusions = std::vector<ShortId>{};
        for (auto i = expected[round].begin; i < expected[round].end; ++i) {
            if (i == 0) response.cells.push_back(to_core(raw0));
            else if (i == 1) response.cells.push_back(Cell{});
            else if (i == 14) response.cells.push_back(to_core(raw_x));
            else response.cells.push_back(Cell{0, 0, 1, 0});
        }
        Bytes bytes;
        BOOST_REQUIRE(serialize(Message{response}, node.stats().limits, bytes) == Error::ok);
        // Equal monotonic timestamps keep unrelated timer-wave expiry out of
        // this serialized boundary fixture; data RTT is still positive.
        actions = node.on_message(1, bytes, 1);
        const auto stats = node.stats();
        for (const auto &audit : stats.last_call.decodes) {
            BOOST_CHECK_EQUAL(audit.session_id, session);
            BOOST_REQUIRE_EQUAL(audit.decode.decoded.size, 1U);
            const auto item = audit.decode.decoded.items[0];
            BOOST_CHECK_EQUAL(item.item, x);
            if (item.sign == Sign::negative) {
                BOOST_CHECK_EQUAL(audit.decode.index, 1U);
                BOOST_CHECK(audit.decode.in_reference_before[0]);
                BOOST_CHECK(snowstorm_oracle::verifies_decode(
                    to_oracle(audit.decode.source_before), 1,
                    to_oracle(audit.decode.decoded), saw_positive ? IdSet{x, w} : IdSet{x}));
                if (!saw_positive) {
                    BOOST_CHECK(!saw_negative);
                    saw_negative = true;
                }
                // A rejected repeated candidate may also be audited before
                // termination; it is not evidence of a second committed delta.
            } else {
                BOOST_CHECK(saw_negative && !saw_positive);
                BOOST_CHECK_EQUAL(audit.decode.index, 14U);
                BOOST_CHECK(!audit.decode.in_reference_before[0]);
                BOOST_CHECK(snowstorm_oracle::verifies_decode(
                    to_oracle(audit.decode.source_before), 14, to_oracle(audit.decode.decoded), {w}));
                saw_positive = true;
            }
        }
        for (const auto &action : actions) {
            if (const auto *penalty = std::get_if<PeerMisbehaved>(&action)) {
                BOOST_CHECK_EQUAL(penalty->peer, 1U);
                BOOST_CHECK(penalty->reason == Misbehavior::inconsistent_symbols);
                BOOST_CHECK(saw_positive);
                saw_close = true;
            }
        }
        request = request_from(actions);
        if (round == 1) {
            BOOST_REQUIRE(saw_negative);
            BOOST_REQUIRE_EQUAL(stats.peers.size(), 1U);
            BOOST_CHECK(stats.peers.front().state == SessionState::open);
            BOOST_CHECK(has_id(stats.peers.front().minus, x));
            // w excludes the old source index1, preserving its zero residual
            // while starting a new claim pass through a real host admission.
            node.on_tx_admitted(w_body, 1);
            BOOST_CHECK(has_id(node.stats().own_ids, w));
            BOOST_REQUIRE_EQUAL(node.stats().peers.size(), 1U);
            BOOST_CHECK(has_id(node.stats().peers.front().minus, x));
        }
    }
    BOOST_CHECK(saw_negative && saw_positive && saw_close);
    for (const auto &peer : node.stats().peers) {
        BOOST_CHECK(peer.state != SessionState::open);
        BOOST_CHECK(peer.residuals.empty());
    }
    BOOST_CHECK(has_id(node.stats().own_ids, x));
    BOOST_CHECK(has_id(node.stats().own_ids, w));
}

BOOST_AUTO_TEST_SUITE_END()
