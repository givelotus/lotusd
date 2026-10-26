// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include <snowstorm/messages.h>
#include <snowstorm/node.h>
#include <snowstorm/short_id.h>
#include <limits>
#include "../oracle/schedule.h"
#include "../harness/host.h"

namespace {
using namespace snowstorm;
void u64(Bytes &b, std::uint64_t n) {
    for (unsigned i = 0; i != 8; ++i) b.push_back(Byte(n >> (8 * i)));
}
Bytes header(Byte kind) { Bytes b{1, kind}; b.resize(34, 0); return b; }
// Independent literal wire construction: deliberately does not use serialize.
Bytes golden_request(std::uint64_t bound) {
    auto b = header(0); u64(b, 1); u64(b, 2); u64(b, 3);
    b.push_back(1); u64(b, bound); b.push_back(0); b.push_back(1);
    u64(b, 0); u64(b, 1); return b;
}
Bytes golden_symbols() {
    auto b = header(1); u64(b, 1); u64(b, 2); u64(b, 3);
    b.push_back(0); u64(b, 0); u64(b, 0); b.push_back(1);
    u64(b, 0); u64(b, 1); b.push_back(1);
    b.resize(b.size() + 28 + 32, 0); // empty cell and root
    u64(b, 0); b.push_back(1); b.push_back(0); return b;
}
Bytes golden_close() { auto b = header(2); u64(b, 1); return b; }
void allocation_bounds(const Stats &s) {
    BOOST_CHECK_LE(s.fixed_floor_bytes, 4096U);
    const std::uint64_t m = s.limits.max_set_size;
    const std::uint64_t envelope = 16 * (s.peers.size() + 1) +
        4 * std::min<std::uint64_t>(65536, 6 * m + 32) + 4 * (2 * m + 32);
    BOOST_CHECK_LE(s.last_call.actions.size(), envelope);
    const auto other = s.last_call.completions.size() + s.last_call.waves.size() +
        s.last_call.evidence.size() + s.last_call.errors.size() + s.last_call.actions.size() +
        s.last_call.replies.size() + s.last_call.lifecycle.size();
    BOOST_CHECK_LE(other, envelope);
    std::map<std::pair<PeerId, SessionId>, std::uint64_t> claims;
    for (const auto &d : s.last_call.decodes) {
        claims[{d.peer, d.session_id}] += d.decode.decoded.size;
        BOOST_CHECK_LE((claims[{d.peer, d.session_id}]), 6 * m + 64);
    }

    std::uint64_t peer_bytes = 0;
    const auto check = [](const AllocationObservation &a) {
        BOOST_CHECK_LE(a.live_records, a.capacity_records);
        BOOST_CHECK_LE(a.capacity_records, a.maximum_records);
        BOOST_CHECK_LE(a.record_bytes, 128U);
        BOOST_CHECK_EQUAL(a.requested_bytes,
                          a.capacity_records * a.record_bytes + a.variable_bytes);
    };
    for (const auto &a : s.global_allocations) check(a);
    for (const auto &p : s.peers) {
        BOOST_CHECK_LE(p.fixed_floor_bytes, 1024U);
        BOOST_CHECK_EQUAL(p.state_bytes, p.fixed_floor_bytes + p.dynamic_bytes);
        peer_bytes += p.state_bytes;
        for (const auto &a : p.allocations) check(a);
        if (p.state == SessionState::idle) BOOST_CHECK_EQUAL(p.dynamic_bytes, 0U);
    }
    BOOST_CHECK_EQUAL(s.state_bytes, s.fixed_floor_bytes + peer_bytes +
                      s.global_dynamic_bytes + s.action_bytes + s.audit_bytes);
}
}

BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T11_wire_goldens_and_every_truncation) {
    using namespace snowstorm;
    Limits limits; BOOST_REQUIRE(derive_limits(128, 100, limits) == Error::ok);
    const std::array<Bytes, 3> goldens{golden_request(limits.reference_bound),
                                     golden_symbols(), golden_close()};
    for (const auto &bytes : goldens) {
        auto parsed = parse(bytes, limits);
        BOOST_REQUIRE(parsed.error == Error::ok);
        BOOST_REQUIRE(parsed.message.has_value());
        Bytes actual; BOOST_REQUIRE(serialize(*parsed.message, limits, actual) == Error::ok);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), bytes.begin(), bytes.end());
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            const auto cut = parse(ByteSpan(bytes.data(), n), limits);
            BOOST_CHECK(cut.error != Error::ok);
            BOOST_CHECK(!cut.message.has_value());
        }
    }
}
BOOST_AUTO_TEST_CASE(T11_100000_malformed_messages_per_wire_type) {
    using namespace snowstorm;
    Limits limits; BOOST_REQUIRE(derive_limits(128, 100, limits) == Error::ok);
    test::Host host(0x711cafe, 2, 128, test::HostOptions{false, false});
    host.observe([](const test::Observation &o) { allocation_bounds(o.after); });
    host.connect(0, 1);
    const auto attacker = host.connect_wire(0, [](const test::WireInput &) {
        return std::vector<test::WireReply>{};
    });
    for (unsigned i = 0; i < 8; ++i)
        host.admit(i % 2, snowstorm_test::make_body(i + 1));
    const std::array<Bytes, 3> goldens{golden_request(limits.reference_bound),
                                     golden_symbols(), golden_close()};
    snowstorm_test::Rng rng(0x71100000);
    std::array<std::uint64_t, 3> attempted{};
    for (std::size_t kind = 0; kind < goldens.size(); ++kind) {
        Bytes oversized(limits.max_message_bytes + 1, 0);
        oversized[0] = 1; oversized[1] = Byte(kind);
        for (std::uint64_t trial = 0; trial < 100000; ++trial) {
            Bytes malformed = goldens[kind];
            ByteSpan input;
            switch (trial % 4) {
            case 0: malformed.resize(rng.bounded(malformed.size())); input = malformed; break;
            case 1: malformed.push_back(Byte(rng.next())); input = malformed; break;
            case 2: malformed[0] = Byte(2 + rng.bounded(254)); input = malformed; break;
            default: input = oversized; break;
            }
            const auto parsed = parse(input, limits);
            BOOST_REQUIRE(parsed.error != Error::ok);
            BOOST_REQUIRE(!parsed.message.has_value());
            host.inject(0, attacker, input);
            const auto state = host.stats(0);
            BOOST_CHECK(std::any_of(state.last_call.actions.begin(), state.last_call.actions.end(),
                [](const ActionAudit &a) { return a.kind == ActionKind::misbehaved; }));
            if (trial % 1000 == 0) host.run_for(1000);
            ++attempted[kind];
        }
    }
    for (auto n : attempted) BOOST_CHECK_EQUAL(n, 100000U);
    BOOST_REQUIRE(host.run_until([](const test::Host &h) {
        return h.equal_truth() && h.truth(0).size() == 8;
    }, host.now() + 1000000));
    host.audit();
    std::uint64_t exact = 0;
    for (const auto &c : host.completions()) if (c.honest_source && c.audit.state == SessionState::done) {
        BOOST_CHECK(std::set<ShortId>(c.audit.reference.begin(), c.audit.reference.end()) == c.raw);
        ++exact;
    }
    BOOST_CHECK_GT(exact, 0U);
}
BOOST_AUTO_TEST_CASE(T12_admission_capacity_is_atomic_and_removal_releases_space) {
    using namespace snowstorm;
    Config cfg; cfg.max_set_size = 4; cfg.rng_seed = 0x712;
    cfg.root_fn = [](const TipContext &, std::span<const TxHandle> bodies) {
        Root r{}; r[0] = Byte(bodies.size()); return r;
    };
    SnowstormNode n(cfg);
    for (unsigned i = 0; i != 4; ++i) {
        n.on_tx_admitted(snowstorm_test::make_body(i + 1), 0);
        BOOST_REQUIRE(n.stats().last_api_error == Error::ok);
        allocation_bounds(n.stats());
    }
    const auto before = n.stats();
    BOOST_REQUIRE_EQUAL(before.bodies.size(), 4U);
    n.on_tx_admitted(snowstorm_test::make_body(5), 0);
    const auto full = n.stats();
    BOOST_CHECK(full.last_api_error == Error::capacity);
    BOOST_CHECK_EQUAL(full.own_seq, before.own_seq);
    BOOST_CHECK(full.own_ids == before.own_ids);
    BOOST_CHECK(full.own_root == before.own_root);
    allocation_bounds(full);
    n.on_tx_removed(before.bodies.front().item, RemovalReason::trim, 0);
    n.on_tx_admitted(snowstorm_test::make_body(5), 0);
    BOOST_CHECK(n.stats().last_api_error == Error::ok);
    BOOST_CHECK_EQUAL(n.stats().bodies.size(), 4U);
    allocation_bounds(n.stats());
}
BOOST_AUTO_TEST_CASE(T12_connection_capacity_and_fixed_floor) {
    using namespace snowstorm;
    Config cfg; cfg.max_set_size = 128; cfg.rng_seed = 0x712100;
    cfg.root_fn = [](const TipContext &, std::span<const TxHandle>) { return Root{}; };
    SnowstormNode n(cfg);
    for (PeerId p = 1; p <= 1024; ++p) {
        n.on_peer_connected(p, PeerCaps{1, 1000}, 0);
        BOOST_REQUIRE(n.stats().last_api_error == Error::ok);
        allocation_bounds(n.stats());
    }
    const auto before = n.stats();
    BOOST_REQUIRE_EQUAL(before.peers.size(), 1024U);
    n.on_peer_connected(1025, PeerCaps{1, 1000}, 0);
    BOOST_CHECK(n.stats().last_api_error == Error::capacity);
    BOOST_CHECK_EQUAL(n.stats().peers.size(), before.peers.size());
    allocation_bounds(n.stats());
    for (PeerId p = 101; p <= 1024; ++p) n.on_peer_disconnected(p, 0);
    BOOST_REQUIRE_EQUAL(n.stats().peers.size(), 100U);
    // Reset removes all per-height model capacities while preserving connections.
    n.on_new_tip(TipParams{}, 0);
    const auto reset = n.stats();
    BOOST_REQUIRE_EQUAL(reset.peers.size(), 100U);
    std::size_t idle = 0;
    for (const auto &p : reset.peers) if (p.state == SessionState::idle) {
        ++idle; BOOST_CHECK_EQUAL(p.dynamic_bytes, 0U);
        BOOST_CHECK_EQUAL(p.state_bytes, p.fixed_floor_bytes);
    }
    // At most the selected eight peers may own an active model after reset.
    BOOST_CHECK_GE(idle, 92U);
    allocation_bounds(reset);
}
BOOST_AUTO_TEST_CASE(T11_inconsistent_raw_cells_terminate_without_iteration_cap) {
    using namespace snowstorm;
    constexpr ShortId x = 0x711abad1;
    const auto positions = snowstorm_oracle::schedule(x, 1024);
    BOOST_REQUIRE_GE(positions.size(), 2U);
    snowstorm_oracle::Cell positive;
    BOOST_REQUIRE(snowstorm_oracle::add(positive, x, 1));
    // Claim +x at zero, but contradict that claim at another included index.
    // Naive +x/-x peeling cycles forever on these two raw cells.
    const std::array<IndexedCell, 2> cells{{{0, snowstorm_test::to_core(positive)},
                                           {positions[1], Cell{}}}};
    Peeler p(PeelerCapacity{16, 2, 16, 1024});
    BOOST_REQUIRE(p.reset({}) == Error::ok);
    BOOST_REQUIRE(p.append(cells) == Error::ok);
    std::array<SignedItem, 16> decoded;
    std::array<DecodeAudit, 16> audit;
    const auto r = p.run(decoded, audit);
    BOOST_CHECK(r.error == Error::inconsistent_symbols);
    BOOST_CHECK(!r.done);
    BOOST_CHECK_LE(r.item_count, decoded.size());
    BOOST_CHECK_LE(r.audit_count, audit.size());
}
BOOST_AUTO_TEST_CASE(T12_fifty_heights_twenty_nodes_allocated_byte_soak) {
    using namespace snowstorm;
    test::Host host(0x7125020, 20, 256, test::HostOptions{false, false});
    host.observe([](const test::Observation &o) {
        allocation_bounds(o.after);
        for (const auto &a : o.after.global_allocations)
            if (a.maximum_records) BOOST_CHECK_LT(2 * a.live_records, a.maximum_records);
        for (const auto &p : o.after.peers)
            for (const auto &a : p.allocations)
                if (a.maximum_records) BOOST_CHECK_LT(2 * a.live_records, a.maximum_records);
        for (auto hits : o.after.limit_hits) BOOST_CHECK_EQUAL(hits, 0U);
    });
    for (std::size_t i = 0; i < 20; ++i)
        for (std::size_t j = i + 1; j < 20; ++j) host.connect(i, j);
    std::array<long double, 50> mean{};
    for (std::uint64_t height = 0; height < 50; ++height) {
        for (std::size_t i = 0; i < 20; ++i) host.change_tip(i, test::default_tip(height + 1));
        for (std::size_t i = 0; i < 20; ++i)
            host.admit(i, snowstorm_test::make_body(10000 * height + i + 1));
        BOOST_REQUIRE(host.run_until([](const test::Host &h) {
            if (!h.equal_truth() || h.truth(0).size() != 20) return false;
            for (std::size_t i = 0; i < 20; ++i) if (!h.stats(i).frozen) return false;
            return true;
        }, host.now() + 5000000, 2000000));
        host.run_for(100000, 1000000);
        host.audit();
        for (std::size_t i = 0; i < 20; ++i) mean[height] += host.stats(i).state_bytes / 20.0L;
        BOOST_CHECK_GT(mean[height], 0.0L);
    }
    long double first = 0, last = 0;
    for (std::size_t i = 0; i < 10; ++i) { first += mean[i]; last += mean[40 + i]; }
    BOOST_CHECK_LE(last, 1.1L * first);
}
BOOST_AUTO_TEST_CASE(T12_height_failure_tables_exhaust_without_eviction_or_refetch) {
    using namespace snowstorm;
    for (auto outcome : {BodyStatus::not_found, BodyStatus::invalid, BodyStatus::local_rejected}) {
        test::Host host(0x712fa11 + unsigned(outcome), 1, 1,
                        test::HostOptions{false, false});
        const auto limits = host.stats(0).limits;
        const auto tip = test::default_tip();
        std::map<SessionId, ShortId> snapshots;
        std::vector<TxHandle> bodies;
        for (std::uint64_t i = 0; i < limits.max_probation + 2; ++i)
            bodies.push_back(snowstorm_test::make_body(i + 100000));
        std::size_t next = 0;
        const auto peer = host.connect_wire(0, [&](const test::WireInput &input) {
            std::vector<test::WireReply> replies;
            auto parsed = parse(input.bytes, limits);
            BOOST_REQUIRE(parsed.error == Error::ok);
            if (const auto *req = std::get_if<ReconReq>(&*parsed.message)) {
                if (!snapshots.count(req->session_id)) {
                    if (next == bodies.size()) return replies;
                    snapshots.emplace(req->session_id, short_id(tip.key, bodies[next++]->tx_hash()));
                }
                const auto item = snapshots.at(req->session_id);
                ReconSymbols response; response.tip_context = req->tip_context;
                response.session_id = req->session_id; response.request_id = req->request_id;
                response.poll_id = req->poll_id; response.snapshot_seq = item;
                response.current_seq = item; response.ranges = req->ranges;
                response.root_vote = snowstorm_test::make_hash(item);
                response.exclusions = std::vector<ShortId>{};
                for (const auto &range : req->ranges)
                    for (const auto &c : snowstorm_oracle::encode({item}, range.begin, range.end))
                        response.cells.push_back(snowstorm_test::to_core(c));
                Bytes wire; BOOST_REQUIRE(serialize(response, limits, wire) == Error::ok);
                replies.push_back(test::WireReply{std::move(wire), 100});
            }
            return replies;
        });
        for (const auto &body : bodies) {
            test::BodyRule rule; rule.status = outcome;
            rule.binding = outcome == BodyStatus::not_found ? BodyBinding::unbound : BodyBinding::matched;
            rule.body = body; rule.expected_tx_hash = body->tx_hash();
            rule.deliver_admission = false; rule.result_delay = 1;
            host.body_rule(0, peer, short_id(tip.key, body->tx_hash()), rule);
        }
        std::uint64_t largest = 0;
        std::set<ShortId> fetched;
        host.observe([&](const test::Observation &o) {
            allocation_bounds(o.after);
            for (const auto &a : o.actions) if (const auto *f = std::get_if<FetchBody>(&a))
                BOOST_CHECK(fetched.insert(f->short_id).second);
            const auto n = outcome == BodyStatus::not_found ? o.after.probation.size() :
                outcome == BodyStatus::invalid ? o.after.rejected.size() : o.after.local_rejected.size();
            largest = std::max(largest, std::uint64_t(n));
            BOOST_CHECK_LE(n, limits.max_probation);
        });
        BOOST_REQUIRE(host.run_until([](const test::Host &h) {
            return h.stats(0).suspended_unadmitted;
        }, 3000000, 1000000));
        BOOST_CHECK_EQUAL(largest, limits.max_probation);
        const auto suspended = host.stats(0);
        BOOST_CHECK(suspended.pending.empty());
        BOOST_CHECK(suspended.fetches.empty());
        BOOST_CHECK(suspended.own_ids.empty());
        const auto fetch_count = fetched.size();
        host.run_for(100000, 100000);
        BOOST_CHECK(host.stats(0).suspended_unadmitted);
        BOOST_CHECK_EQUAL(fetched.size(), fetch_count);
        // Height reset is the only release of height-long failure suppression.
        host.change_tip(0, test::default_tip(1));
        BOOST_CHECK(!host.stats(0).suspended_unadmitted);
        BOOST_CHECK(host.stats(0).probation.empty());
        BOOST_CHECK(host.stats(0).rejected.empty());
        BOOST_CHECK(host.stats(0).local_rejected.empty());
    }
}
BOOST_AUTO_TEST_CASE(T12_wire_vector_limit_boundaries) {
    using namespace snowstorm;
    Limits limits; BOOST_REQUIRE(derive_limits(128, 100, limits) == Error::ok);
    const auto roundtrip = [&](const Message &m, bool valid) {
        Bytes bytes; const auto err = serialize(m, limits, bytes);
        if (valid) {
            BOOST_REQUIRE(err == Error::ok);
            BOOST_CHECK(parse(bytes, limits).error == Error::ok);
        } else BOOST_CHECK(err != Error::ok);
    };
    ReconReq req; req.session_id = 1; req.request_id = 1; req.poll_id = 1;
    req.reference_size = limits.reference_bound; req.known_excl_version = 0;
    for (std::uint64_t i = 0; i < limits.max_ranges; ++i) req.ranges.push_back({2 * i, 2 * i + 1});
    roundtrip(req, true);
    req.ranges.push_back({2 * limits.max_ranges, 2 * limits.max_ranges + 1});
    roundtrip(req, false);
    req.ranges = {{limits.max_symbol_index, limits.max_symbol_index + 1}};
    roundtrip(req, true);
    req.ranges.front().end++;
    roundtrip(req, false);
    ReconSymbols sym; sym.session_id = 1; sym.request_id = 1; sym.poll_id = 1;
    sym.ranges = {{0, limits.max_cells}};
    sym.cells.resize(limits.max_cells); sym.exclusions = std::vector<ShortId>{};
    roundtrip(sym, true);
    sym.cells.emplace_back(); sym.ranges.front().end++;
    roundtrip(sym, false);
    sym.ranges = {{0, 1}}; sym.cells.resize(1);
    for (ShortId i = 1; i <= limits.max_exclusions; ++i) sym.exclusions->push_back(i);
    roundtrip(sym, true);
    sym.exclusions->push_back(limits.max_exclusions + 1);
    roundtrip(sym, false);
}
BOOST_AUTO_TEST_CASE(T12_own_churn_expires_bounded_reference_before_authoritative_change) {
    using namespace snowstorm;
    SnowstormNode n(test::default_config(1, 0x712c));
    n.on_peer_connected(1, PeerCaps{1, 1000000}, 0);
    n.on_timer(0);
    std::uint64_t greatest_plus = 0;
    for (std::uint64_t i = 0; i < 256; ++i) {
        n.on_tx_admitted(snowstorm_test::make_body(700000 + i), 0);
        BOOST_REQUIRE(n.stats().last_api_error == Error::ok);
        BOOST_REQUIRE_EQUAL(n.stats().own_ids.size(), 1U);
        n.on_tx_removed(n.stats().own_ids.front(), RemovalReason::trim, 0);
        const auto s = n.stats();
        BOOST_CHECK(s.own_ids.empty());
        allocation_bounds(s);
        for (const auto &p : s.peers) {
            greatest_plus = std::max(greatest_plus, std::uint64_t(p.plus.size()));
            BOOST_CHECK_LE(p.plus.size(), s.limits.max_plus);
            BOOST_CHECK_LE(p.minus.size(), s.limits.max_minus);
            std::set<ShortId> ref(s.own_ids.begin(), s.own_ids.end());
            ref.insert(p.plus.begin(), p.plus.end());
            for (auto id : p.minus) ref.erase(id);
            BOOST_CHECK_LE(ref.size(), s.limits.reference_bound);
        }
    }
    BOOST_CHECK_GT(greatest_plus, 0U);
    BOOST_CHECK_GT(n.stats().local_model_expiry, 0U);
}
// T12 derived-envelope coverage: these limits are not independent knobs. Tests
// must not inject unreachable private state merely to force all counters to cap.
// Reference <= admitted M + plus (4M+64) = 5M+64. Donor records <= eight per ID
// over Pending/fetch union (2M+32) and probation (8M+128) = 8*(10M+160).
// Snapshot and candidate body pins are subsets of <=M admitted body records.
// Each worklist has <=one entry per stored symbol. Pass claims are distinct
// claimed IDs in snapshot union reference; Two consumes two claims/audit slots.
// These are checked against observable counts below, independent of derive_limits.
BOOST_AUTO_TEST_CASE(T12_derived_capacity_envelopes_follow_live_components) {
    using namespace snowstorm;
    test::Host h(0x712de, 5, 128, test::HostOptions{false, false});
    h.observe([](const test::Observation &o) {
        const auto &s = o.after;
        std::set<ShortId> union_ids(s.pending.begin(), s.pending.end());
        for (const auto &f : s.fetches) union_ids.insert(f.item);
        BOOST_CHECK_LE(union_ids.size(), 2 * 128 + 32U);
        union_ids.insert(s.probation.begin(), s.probation.end());
        BOOST_CHECK_LE(s.donors.size(), 8 * union_ids.size());
        std::map<ShortId, std::size_t> donors;
        for (const auto &d : s.donors) BOOST_CHECK_LE(++donors[d.item], 8U);
        for (const auto &p : s.peers) {
            std::set<ShortId> reference(s.own_ids.begin(), s.own_ids.end());
            reference.insert(p.plus.begin(), p.plus.end());
            for (auto id : p.minus) reference.erase(id);
            BOOST_CHECK_LE(reference.size(), 5 * 128 + 64U);
            BOOST_CHECK_LE(p.stored_symbols, 3 * (p.snapshot_size + 5 * 128 + 64) + 32);
            for (const auto &a : p.allocations) {
                if (a.resource == Limit::worklist) BOOST_CHECK_LE(a.live_records, p.stored_symbols);
                if (a.resource == Limit::pass_claims)
                    BOOST_CHECK_LE(a.live_records, p.snapshot_size + 5 * 128 + 64);
                if (a.resource == Limit::snapshot_bodies || a.resource == Limit::candidate_bodies)
                    BOOST_CHECK_LE(a.live_records, 128U);
            }
        }
        allocation_bounds(s);
    });
    for (std::size_t i = 0; i < 5; ++i) {
        h.admit(i, snowstorm_test::make_body(800000 + i));
        for (std::size_t j = 0; j < i; ++j) h.connect(i, j);
    }
    BOOST_REQUIRE(h.run_until([](const test::Host &host) {
        return host.equal_truth() && host.truth(0).size() == 5;
    }, 1000000));
    h.audit();
}
BOOST_AUTO_TEST_CASE(T12_pending_and_fetch_union_capacity) {
    using namespace snowstorm;
    test::Host h(0x712feed, 1, 1, test::HostOptions{false, false});
    const auto limits = h.stats(0).limits;
    const auto tip = test::default_tip();
    std::size_t peak = 0;
    h.observe([&](const test::Observation &o) {
        allocation_bounds(o.after);
        std::set<ShortId> ids(o.after.pending.begin(), o.after.pending.end());
        for (const auto &f : o.after.fetches) ids.insert(f.item);
        peak = std::max(peak, ids.size());
        BOOST_CHECK_LE(ids.size(), 34U); // 2*M+32, independent literal M=1
        BOOST_CHECK_LE(o.after.fetches.size(), 34U);
    });
    for (unsigned i = 0; i < 48; ++i) {
        const auto body = snowstorm_test::make_body(1000000 + i);
        const auto item = short_id(tip.key, body->tx_hash());
        const auto peer = h.connect_wire(0, [&, item](const test::WireInput &input) {
            std::vector<test::WireReply> replies;
            const auto p = parse(input.bytes, limits);
            BOOST_REQUIRE(p.error == Error::ok);
            if (const auto *req = std::get_if<ReconReq>(&*p.message)) {
                ReconSymbols r; r.tip_context = req->tip_context;
                r.session_id = req->session_id; r.request_id = req->request_id;
                r.poll_id = req->poll_id; r.snapshot_seq = 1; r.current_seq = 1;
                r.ranges = req->ranges; r.root_vote = snowstorm_test::make_hash(item);
                r.exclusions = std::vector<ShortId>{};
                for (const auto &range : req->ranges)
                    for (const auto &cell : snowstorm_oracle::encode({item}, range.begin, range.end))
                        r.cells.push_back(snowstorm_test::to_core(cell));
                Bytes wire; BOOST_REQUIRE(serialize(r, limits, wire) == Error::ok);
                replies.push_back(test::WireReply{std::move(wire), 100});
            }
            return replies;
        });
        test::BodyRule rule; rule.body = body; rule.expected_tx_hash = body->tx_hash();
        rule.result_delay = 100000000; rule.deliver_admission = false;
        h.body_rule(0, peer, item, rule);
    }
    BOOST_REQUIRE(h.run_until([&](const test::Host &) { return peak == 34; }, 5000000));
    h.run_for(100000);
    BOOST_CHECK_EQUAL(peak, 34U);
    const auto s = h.stats(0);
    BOOST_CHECK(s.own_ids.empty());
    BOOST_CHECK_GT(s.limit_hits[std::size_t(Limit::pending_fetch_union)] +
                   s.limit_hits[std::size_t(Limit::pending)] +
                   s.limit_hits[std::size_t(Limit::fetch_records)], 0U);
    h.change_tip(0, test::default_tip(1));
    BOOST_CHECK(h.stats(0).pending.empty());
    BOOST_CHECK(h.stats(0).fetches.empty());
}
BOOST_AUTO_TEST_CASE(T12_session_symbol_budget_exact_and_duplicate_free) {
    using namespace snowstorm;
    SnowstormNode n(test::default_config(1, 0x712b));
    n.on_peer_connected(1, PeerCaps{1, 1000}, 0);
    ReconReq req; req.tip_context = n.stats().tip_context;
    req.session_id = 777; req.request_id = 1; req.poll_id = 1;
    req.open = true; req.reference_size = 0; req.ranges = {{0, 1}};
    const auto exchange = [&](const ReconReq &q) {
        Bytes wire; BOOST_REQUIRE(serialize(q, n.stats().limits, wire) == Error::ok);
        const auto actions = n.on_message(1, wire, 0);
        std::optional<ReconSymbols> response;
        for (const auto &a : actions) if (const auto *send = std::get_if<Send>(&a)) {
            auto parsed = parse(send->bytes, n.stats().limits);
            BOOST_REQUIRE(parsed.error == Error::ok);
            if (const auto *r = std::get_if<ReconSymbols>(&*parsed.message))
                if (r->session_id == q.session_id && r->request_id == q.request_id) response = *r;
        }
        BOOST_REQUIRE(response.has_value());
        allocation_bounds(n.stats());
        return *response;
    };
    auto first = exchange(req);
    BOOST_REQUIRE(first.status == SymbolsStatus::normal);
    req.open = false; req.request_id = 2; req.known_excl_version = first.exclusion_version;
    req.ranges = {{1, 32}}; // snapshot=0, declared bound=0: exactly 32 unique slots.
    auto at = exchange(req);
    BOOST_REQUIRE(at.status == SymbolsStatus::normal);
    BOOST_CHECK_EQUAL(at.cells.size(), 31U);
    auto duplicate = exchange(req);
    BOOST_REQUIRE(duplicate.status == SymbolsStatus::normal);
    BOOST_CHECK_EQUAL(duplicate.cells.size(), 31U);
    req.request_id = 3; req.ranges = {{32, 33}};
    const auto beyond = exchange(req);
    BOOST_CHECK(beyond.status == SymbolsStatus::resource_limited);
    BOOST_CHECK(beyond.resource_reason == ResourceReason::symbol_budget);
}
BOOST_AUTO_TEST_CASE(T12_eight_simultaneous_donors_and_ninth_replacement) {
    using namespace snowstorm;
    test::Host h(0x712d090, 1, 1, test::HostOptions{false, false});
    const auto limits = h.stats(0).limits;
    const auto body = snowstorm_test::make_body(121212);
    const auto item = short_id(test::default_tip().key, body->tx_hash());
    std::set<PeerId> answered;
    std::uint64_t fetches = 0;
    h.observe([&](const test::Observation &o) {
        allocation_bounds(o.after);
        BOOST_CHECK_LE(o.after.donors.size(), 8U);
        for (const auto &a : o.actions) if (std::holds_alternative<FetchBody>(a)) ++fetches;
    });
    for (unsigned i = 0; i < 9; ++i) {
        const auto peer = h.connect_wire(0, [&](const test::WireInput &input) {
            std::vector<test::WireReply> out;
            const auto p = parse(input.bytes, limits); BOOST_REQUIRE(p.error == Error::ok);
            if (const auto *q = std::get_if<ReconReq>(&*p.message)) {
                answered.insert(input.peer);
                ReconSymbols r; r.tip_context = q->tip_context; r.session_id = q->session_id;
                r.request_id = q->request_id; r.poll_id = q->poll_id;
                r.snapshot_seq = 1; r.current_seq = 1; r.ranges = q->ranges;
                r.root_vote = snowstorm_test::make_hash(item); r.exclusions = std::vector<ShortId>{};
                for (const auto &range : q->ranges)
                    for (const auto &cell : snowstorm_oracle::encode({item}, range.begin, range.end))
                        r.cells.push_back(snowstorm_test::to_core(cell));
                Bytes bytes; BOOST_REQUIRE(serialize(r, limits, bytes) == Error::ok);
                out.push_back({std::move(bytes), 100});
            }
            return out;
        });
        test::BodyRule rule; rule.body = body; rule.expected_tx_hash = body->tx_hash();
        rule.result_delay = 100000000; rule.deliver_admission = false;
        h.body_rule(0, peer, item, rule);
    }
    BOOST_REQUIRE(h.run_until([&](const test::Host &host) {
        return answered.size() == 9 && host.stats(0).donors.size() == 8;
    }, 1000000));
    BOOST_CHECK_EQUAL(fetches, 1U);
    auto donors = h.stats(0).donors;
    std::set<PeerId> retained;
    for (const auto &d : donors) retained.insert(d.peer);
    PeerId ninth = 0;
    for (auto peer : answered) if (!retained.count(peer)) ninth = peer;
    BOOST_REQUIRE_NE(ninth, 0U);
    const auto removed = donors.back().peer;
    h.disconnect_peer(0, removed);
    BOOST_CHECK_EQUAL(h.stats(0).donors.size(), 7U);
    BOOST_REQUIRE(h.run_until([&](const test::Host &host) {
        const auto current = host.stats(0).donors;
        return current.size() == 8 && std::any_of(current.begin(), current.end(),
            [&](const DonorObservation &d) { return d.peer == ninth; });
    }, h.now() + 1000000));
}
BOOST_AUTO_TEST_CASE(T12_minus_capacity_rejects_sixty_ninth_distinct_claim) {
    using namespace snowstorm;
    SnowstormNode n(test::default_config(1, 0x71268));
    n.on_new_tip(test::default_tip(), 0);
    std::optional<ReconReq> next;
    const auto capture = [&](const Actions &actions) {
        next.reset();
        for (const auto &a : actions) if (const auto *send = std::get_if<Send>(&a)) {
            const auto p = parse(send->bytes, n.stats().limits);
            BOOST_REQUIRE(p.error == Error::ok);
            if (const auto *q = std::get_if<ReconReq>(&*p.message)) next = *q;
        }
    };
    capture(n.on_peer_connected(1, PeerCaps{1, 1000000}, 0));
    if (!next) capture(n.on_timer(0));
    BOOST_REQUIRE(next.has_value());
    const auto respond = [&](const ReconReq &q, bool initial) {
        ReconSymbols r; r.tip_context = q.tip_context; r.session_id = q.session_id;
        r.request_id = q.request_id; r.poll_id = q.poll_id;
        r.snapshot_seq = 1; r.current_seq = 1; r.ranges = q.ranges;
        r.root_vote = snowstorm_test::make_hash(0x71268);
        r.exclusions = std::vector<ShortId>{};
        for (const auto &range : q.ranges)
            for (auto index = range.begin; index < range.end; ++index)
                r.cells.push_back(initial && index == 0 ? Cell{1, 1, 2, 3} : Cell{});
        Bytes wire; BOOST_REQUIRE(serialize(r, n.stats().limits, wire) == Error::ok);
        capture(n.on_message(1, wire, 0));
        allocation_bounds(n.stats());
    };
    respond(*next, true);
    std::uint64_t seed = 2000000;
    for (std::size_t expected = 1; expected <= 69; ++expected) {
        BOOST_REQUIRE(next.has_value());
        const auto request = *next;
        BOOST_REQUIRE(!request.ranges.empty());
        // Pick a real body's ID that includes the first newly requested index.
        // This is test data selection, never a hash override or private-state edit.
        TxHandle body; ShortId item = 0;
        for (unsigned search = 0; search < 100000; ++search) {
            body = snowstorm_test::make_body(seed++);
            item = short_id(test::default_tip().key, body->tx_hash());
            if (snowstorm_oracle::includes(item, request.ranges.front().begin)) break;
            body.reset();
        }
        BOOST_REQUIRE(body);
        n.on_tx_admitted(body, 0);
        BOOST_REQUIRE(n.stats().last_api_error == Error::ok);
        respond(request, false);
        const auto s = n.stats();
        BOOST_REQUIRE_EQUAL(s.peers.size(), 1U);
        if (expected <= 68) {
            BOOST_CHECK_EQUAL(s.peers.front().minus.size(), expected);
            BOOST_CHECK(s.peers.front().state == SessionState::open);
        } else {
            BOOST_CHECK(s.peers.front().state != SessionState::open);
            BOOST_CHECK_GT(s.limit_hits[std::size_t(Limit::minus)], 0U);
            BOOST_CHECK(std::any_of(s.last_call.actions.begin(), s.last_call.actions.end(),
                [](const ActionAudit &a) {
                    return a.kind == ActionKind::misbehaved && a.reason == Misbehavior::resource_limit;
                }));
        }
        n.on_tx_removed(item, RemovalReason::trim, 0);
        BOOST_CHECK(n.stats().own_ids.empty());
    }
}
BOOST_AUTO_TEST_CASE(T11_literal_valid_version_malformed_fields) {
    using namespace snowstorm;
    Limits limits; BOOST_REQUIRE(derive_limits(128, 100, limits) == Error::ok);
    std::vector<Bytes> corpus;
    const auto request = golden_request(limits.reference_bound);
    const auto symbols = golden_symbols();
    const auto replace_byte = [&](Bytes bytes, std::size_t offset, Byte value) {
        bytes.at(offset) = value; corpus.push_back(std::move(bytes));
    };
    replace_byte(request, 58, 2); // open boolean
    replace_byte(request, 67, 2); // known-exclusion boolean
    replace_byte(symbols, 161, 2); // full-exclusion boolean
    for (auto original : {request, symbols}) {
        const std::size_t offset = original[1] == 0 ? 68 : 75;
        // Literal nonminimal CompactSize encodings of the value one.
        for (const Bytes &nonminimal : {Bytes{253, 1, 0},
                Bytes{254, 1, 0, 0, 0}, Bytes{255, 1, 0, 0, 0, 0, 0, 0, 0}}) {
            auto bytes = original;
            bytes.erase(bytes.begin() + offset);
            bytes.insert(bytes.begin() + offset, nonminimal.begin(), nonminimal.end());
            corpus.push_back(std::move(bytes));
        }
        for (Byte marker : {Byte{253}, Byte{254}, Byte{255}}) {
            auto bytes = original; bytes.resize(offset); bytes.push_back(marker);
            corpus.push_back(std::move(bytes)); // truncated length payload
        }
        auto enormous = original; enormous.resize(offset);
        enormous.push_back(255); u64(enormous, UINT64_MAX);
        corpus.push_back(std::move(enormous)); // reject before allocation
    }
    auto empty_range = request;
    std::fill(empty_range.begin() + 77, empty_range.begin() + 85, 0);
    corpus.push_back(empty_range);
    auto overlap = request; overlap[58] = 0; overlap[68] = 2;
    u64(overlap, 0); u64(overlap, 1); corpus.push_back(overlap);
    auto reversed = request;
    reversed[69] = 2; // [2,1)
    corpus.push_back(reversed);
    auto out_of_order = request; out_of_order[58] = 0; out_of_order[68] = 2;
    out_of_order[69] = 2; out_of_order[77] = 3;
    u64(out_of_order, 0); u64(out_of_order, 1); corpus.push_back(out_of_order);
    auto no_cells = symbols; no_cells[92] = 0;
    no_cells.erase(no_cells.begin() + 93, no_cells.begin() + 121);
    corpus.push_back(no_cells); // one requested index, no cell
    auto extra_cell = symbols; extra_cell[92] = 2;
    extra_cell.insert(extra_cell.begin() + 121, 28, 0); corpus.push_back(extra_cell);
    auto forbidden_count = symbols; forbidden_count[96] = 128;
    corpus.push_back(forbidden_count); // literal INT32_MIN little endian
    for (const auto &ids : {std::vector<ShortId>{0}, std::vector<ShortId>{1, 1},
                            std::vector<ShortId>{2, 1}}) {
        auto bytes = symbols; bytes[162] = Byte(ids.size());
        for (auto id : ids) u64(bytes, id);
        corpus.push_back(std::move(bytes));
    }
    auto too_many_exclusions = symbols; too_many_exclusions[162] = 129;
    for (ShortId id = 1; id <= 129; ++id) u64(too_many_exclusions, id);
    corpus.push_back(std::move(too_many_exclusions));
    test::Host h(0x711f1e1d, 2, 128, test::HostOptions{false, false});
    h.connect(0, 1);
    const auto bad = h.connect_wire(0, [](const test::WireInput &) {
        return std::vector<test::WireReply>{};
    });
    h.admit(1, snowstorm_test::make_body(711));
    for (const auto &bytes : corpus) {
        BOOST_REQUIRE_EQUAL(bytes.front(), 1U);
        const auto p = parse(bytes, limits); // Never sanitize via serialize first.
        BOOST_CHECK(p.error != Error::ok);
        BOOST_CHECK(!p.message.has_value());
        h.inject(0, bad, bytes);
        allocation_bounds(h.stats(0));
        const auto actions = h.stats(0).last_call.actions;
        BOOST_CHECK(std::any_of(actions.begin(), actions.end(), [](const ActionAudit &a) {
            return a.kind == ActionKind::misbehaved;
        }));
        h.run_for(100);
    }
    BOOST_REQUIRE(h.run_until([](const test::Host &host) {
        return host.equal_truth() && host.truth(0).size() == 1;
    }, h.now() + 1000000));
    h.audit();
}
BOOST_AUTO_TEST_CASE(T11_normal_response_order_identity_and_snapshot_binding) {
    using namespace snowstorm;
    test::Host h(0x711b1ad, 2, 128, test::HostOptions{false, false});
    const auto limits = h.stats(0).limits;
    std::vector<ReconReq> requests;
    const auto bad = h.connect_wire(0, [&](const test::WireInput &input) {
        auto p = parse(input.bytes, limits); BOOST_REQUIRE(p.error == Error::ok);
        if (const auto *q = std::get_if<ReconReq>(&*p.message)) requests.push_back(*q);
        return std::vector<test::WireReply>{};
    });
    h.connect(0, 1);
    h.admit(1, snowstorm_test::make_body(711991));
    BOOST_REQUIRE(h.run_until([&](const test::Host &) { return !requests.empty(); }, 10000));
    const auto response = [&](const ReconReq &q, Sequence snapshot) {
        ReconSymbols r; r.tip_context = q.tip_context; r.session_id = q.session_id;
        r.request_id = q.request_id; r.poll_id = q.poll_id;
        r.snapshot_seq = snapshot; r.current_seq = snapshot; r.ranges = q.ranges;
        r.root_vote = snowstorm_test::make_hash(7119919);
        r.exclusions = std::vector<ShortId>{};
        for (const auto &range : q.ranges)
            for (auto index = range.begin; index < range.end; ++index)
                r.cells.push_back(index == 0 ? Cell{1, 1, 2, 3} : Cell{});
        return r;
    };
    const auto inject = [&](const ReconSymbols &r) {
        Bytes wire; BOOST_REQUIRE(serialize(r, limits, wire) == Error::ok);
        h.inject(0, bad, wire); allocation_bounds(h.stats(0));
    };
    auto initial = response(requests.front(), 10);
    inject(initial);
    const auto initial_id = initial.request_id;
    BOOST_REQUIRE(h.run_until([&](const test::Host &) {
        return std::any_of(requests.begin(), requests.end(), [&](const ReconReq &q) {
            return q.session_id == initial.session_id && q.request_id != initial_id;
        });
    }, h.now() + 10000));
    const auto next = *std::find_if(requests.rbegin(), requests.rend(), [&](const ReconReq &q) {
        return q.session_id == initial.session_id && q.request_id != initial_id;
    });
    auto future = response(next, 10); future.request_id += 100000;
    auto unknown = response(next, 10); unknown.session_id += 100000;
    for (const auto &r : {initial, future, unknown}) {
        const auto before = h.stats(0);
        inject(r);
        const auto after = h.stats(0);
        BOOST_CHECK(after.own_ids == before.own_ids);
        BOOST_CHECK(after.pending == before.pending);
        BOOST_CHECK(after.last_call.decodes.empty());
        BOOST_CHECK(after.last_call.completions.empty());
        const auto peer = std::find_if(after.peers.begin(), after.peers.end(),
            [&](const PeerStats &p) { return p.peer == bad; });
        BOOST_REQUIRE(peer != after.peers.end());
        BOOST_CHECK_EQUAL(peer->request_id, next.request_id);
        BOOST_CHECK_EQUAL(peer->snapshot_seq, 10U);
    }
    inject(response(next, 11)); // same active request, changed immutable S
    const auto changed = h.stats(0);
    BOOST_CHECK(std::any_of(changed.last_call.actions.begin(), changed.last_call.actions.end(),
        [](const ActionAudit &a) {
            return a.kind == ActionKind::misbehaved && a.reason == Misbehavior::snapshot_changed;
        }));
    const auto peer = std::find_if(changed.peers.begin(), changed.peers.end(),
        [&](const PeerStats &p) { return p.peer == bad; });
    BOOST_REQUIRE(peer != changed.peers.end());
    BOOST_CHECK(peer->state != SessionState::open);
    BOOST_REQUIRE(h.run_until([](const test::Host &host) {
        return host.equal_truth() && host.truth(0).size() == 1;
    }, h.now() + 1000000));
    h.audit();
}
BOOST_AUTO_TEST_SUITE_END()
