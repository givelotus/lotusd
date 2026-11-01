// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include <snowstorm/setstore.h>
#include <snowstorm/short_id.h>
using namespace snowstorm_test;
namespace {
void check_snapshot(const snowstorm::SetStore &store, std::uint64_t seq,
                    const std::vector<snowstorm_oracle::Operation> &log) {
    const auto expected = snowstorm_oracle::snapshot(log, seq);
    const auto snapshot = store.snapshot(seq);
    BOOST_REQUIRE(snapshot.error == snowstorm::Error::ok);
    BOOST_REQUIRE(snapshot.ids == sorted_ids(expected));
    BOOST_REQUIRE_EQUAL(snapshot.bodies.size(), expected.size());
    const auto cells = snowstorm_oracle::encode(expected, 0, 32);
    std::array<snowstorm::Cell, 32> actual;
    BOOST_REQUIRE(store.encode_snapshot(seq, {0, 32}, actual) == snowstorm::Error::ok);
    for (std::size_t i = 0; i < cells.size(); ++i) require_cell_equal(actual[i], cells[i]);
}
}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T6_interleaved_logs_and_pinned_snapshots) {
    Rng rng(0x7436000000000001ULL);
    for (unsigned trial = 0; trial < 100; ++trial) {
        snowstorm::SetStore store(128);
        BOOST_REQUIRE(store.cache_range({0, 32}) == snowstorm::Error::ok);
        IdSet current;
        std::vector<snowstorm_oracle::Operation> log;
        std::vector<std::uint64_t> pinned;
        for (unsigned step = 0; step < 256; ++step) {
            const auto id = 1 + rng.bounded(64);
            const bool present = current.contains(id);
            const auto before = store.sequence();
            const auto error = present ? store.remove(id) : store.admit(id, make_body(id));
            BOOST_REQUIRE(error == snowstorm::Error::ok);
            BOOST_REQUIRE_EQUAL(store.sequence(), before + 1);
            log.push_back({store.sequence(), id, present ? -1 : 1});
            if (present) current.erase(id); else current.insert(id);
            check_snapshot(store, store.sequence(), log);
            if (step % 32 != 0) continue;
            const auto seq = store.sequence();
            BOOST_REQUIRE(store.pin(seq, seq) == snowstorm::Error::ok);
            pinned.push_back(seq);
            for (const auto old : pinned) check_snapshot(store, old, log);
        }
        for (const auto seq : pinned) {
            check_snapshot(store, seq, log);
            store.release(seq);
            std::uint64_t actual = 999;
            BOOST_REQUIRE(store.pinned(seq, actual) != snowstorm::Error::ok);
        }
    }
}
BOOST_AUTO_TEST_CASE(T6_log_cap_expires_oldest_pin_without_retargeting) {
    snowstorm::SetStore store(2);
    BOOST_REQUIRE(store.pin(1, 0) == snowstorm::Error::ok);
    BOOST_REQUIRE(store.admit(7, make_body(7)) == snowstorm::Error::ok);
    BOOST_REQUIRE(store.pin(2, store.sequence()) == snowstorm::Error::ok);
    for (unsigned i = 0; i < 100; ++i) {
        BOOST_REQUIRE(store.remove(7) == snowstorm::Error::ok);
        BOOST_REQUIRE(store.admit(7, make_body(7)) == snowstorm::Error::ok);
    }
    const auto stats = store.stats();
    BOOST_REQUIRE_LE(stats.log_length, 8U * 2U + 64U);
    BOOST_REQUIRE_GE(stats.expired_pins, 2U);
    std::uint64_t seq = 999;
    BOOST_REQUIRE(store.pinned(1, seq) != snowstorm::Error::ok);
    BOOST_REQUIRE(store.pinned(2, seq) != snowstorm::Error::ok);
    BOOST_REQUIRE(store.snapshot(0).error == snowstorm::Error::snapshot_expired);
    store.release(1);
    store.release(2);
    store.release(999);
    BOOST_REQUIRE(store.pinned(999, seq) != snowstorm::Error::ok);
    BOOST_REQUIRE(store.contains(7));
}
BOOST_AUTO_TEST_CASE(T6_real_short_id_vector_and_collision_bucket_snapshots) {
    snowstorm::TxHash message{};
    for (std::size_t i = 0; i < message.size(); ++i) message[i] = i;
    BOOST_REQUIRE_EQUAL(snowstorm::short_id(collision_key, message), 0x7127512f72f27cceULL);
    BOOST_REQUIRE_EQUAL(snowstorm::normalize_short_id(0), 1U);
    BOOST_REQUIRE_EQUAL(snowstorm::normalize_short_id(1), 1U);
    const auto bodies = collision_bodies();
    BOOST_REQUIRE(bodies[0]->tx_hash() != bodies[1]->tx_hash());
    for (const auto &body : bodies)
        BOOST_REQUIRE_EQUAL(snowstorm::short_id(collision_key, body->tx_hash()), collision_id);
    snowstorm::SetStore store(4);
    BOOST_REQUIRE(store.admit(collision_id, bodies[0]) == snowstorm::Error::ok);
    const auto first = store.sequence();
    BOOST_REQUIRE(store.pin(1, first) == snowstorm::Error::ok);
    BOOST_REQUIRE(store.admit(collision_id, bodies[1]) == snowstorm::Error::ok);
    const auto both = store.sequence();
    BOOST_REQUIRE_EQUAL(both, first + 1);
    BOOST_REQUIRE(store.pin(2, both) == snowstorm::Error::ok);
    BOOST_REQUIRE(store.admit(collision_id, bodies[0]) == snowstorm::Error::ok);
    BOOST_REQUIRE_EQUAL(store.sequence(), both);
    BOOST_REQUIRE_EQUAL(store.stats().id_count, 1U);
    BOOST_REQUIRE_EQUAL(store.stats().body_count, 2U);
    BOOST_REQUIRE(store.remove_body(collision_id, bodies[0]->tx_hash()) == snowstorm::Error::ok);
    BOOST_REQUIRE(store.contains(collision_id));
    BOOST_REQUIRE_EQUAL(store.sequence(), both + 1);
    BOOST_REQUIRE_EQUAL(store.snapshot(first).bodies.size(), 1U);
    BOOST_REQUIRE_EQUAL(store.snapshot(both).bodies.size(), 2U);
    const auto remaining = store.snapshot(store.sequence());
    BOOST_REQUIRE_EQUAL(remaining.bodies.size(), 1U);
    BOOST_REQUIRE(remaining.bodies[0]->tx_hash() == bodies[1]->tx_hash());
    BOOST_REQUIRE_EQUAL(*store.admission_sequence(collision_id), first);
    BOOST_REQUIRE(store.remove_body(collision_id, bodies[1]->tx_hash()) == snowstorm::Error::ok);
    BOOST_REQUIRE(!store.contains(collision_id));
    BOOST_REQUIRE(!store.admission_sequence(collision_id));
    const std::array<snowstorm::ShortId, 2> reset_ids{3, 5};
    const std::array<snowstorm::TxHandle, 2> reset_bodies{make_body(3), make_body(5)};
    BOOST_REQUIRE(store.reset(reset_ids, reset_bodies) == snowstorm::Error::ok);
    BOOST_REQUIRE(!store.contains(collision_id));
    BOOST_REQUIRE(store.contains(3));
    BOOST_REQUIRE(store.contains(5));
    BOOST_REQUIRE(store.stats().pins.empty());
    BOOST_REQUIRE(store.stats().changes.empty());
}
BOOST_AUTO_TEST_SUITE_END()
