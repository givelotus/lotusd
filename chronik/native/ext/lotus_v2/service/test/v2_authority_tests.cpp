// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-lib/src/v2tests/authority.rs tests.

#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/service/authority.h>

#include <boost/test/unit_test.hpp>

#include <thread>

using namespace chronik::native::lotus_v2;
using chronik::native::ChronikError;
using chronik::native::lotus_v2::test::B32;

namespace {

Anchor TestAnchor(uint64_t height) {
    return Anchor{B32(uint8_t(height % 256)), height};
}

bool Fails(const std::function<void()> &f) {
    try {
        f();
    } catch (const ChronikError &) {
        return true;
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_authority_tests)

BOOST_AUTO_TEST_CASE(
    idle_turns_preserve_durable_generation_and_fence_observations) {
    Authority authority;
    BOOST_CHECK(authority.Observe() == (AuthoritativeState{0, 0, std::nullopt}));
    const uint64_t generation =
        authority.PublishContext(TestAnchor(1), 7, 11);
    const AuthoritativeState first = authority.Observe();
    for (int i = 0; i < 100; ++i) {
        BOOST_CHECK_EQUAL(authority.Suspend(), generation);
        const AuthoritativeState suspended = authority.Observe();
        BOOST_CHECK(!suspended.anchor);
        BOOST_CHECK(suspended.observation > first.observation);
        BOOST_CHECK_EQUAL(authority.PublishContext(TestAnchor(1), 7, 11),
                          generation);
        BOOST_CHECK(authority.Observe().anchor == TestAnchor(1));
    }
    BOOST_CHECK(authority.Observe().observation != first.observation);
    BOOST_CHECK_EQUAL(authority.Observe().generation, first.generation);
}

BOOST_AUTO_TEST_CASE(
    context_aba_and_durable_invalidation_never_resurrect_generations) {
    Authority authority;
    uint64_t previous = authority.PublishContext(TestAnchor(1), 7, 11);
    const std::tuple<Anchor, uint64_t, uint64_t> stamps[] = {
        {TestAnchor(1), 8, 11}, {TestAnchor(1), 7, 11}, {TestAnchor(1), 7, 12},
        {TestAnchor(2), 7, 12}, {TestAnchor(1), 7, 11}};
    for (const auto &[a, c, r] : stamps) {
        authority.Suspend();
        const uint64_t next = authority.PublishContext(a, c, r);
        BOOST_CHECK(next > previous);
        previous = next;
    }
    const uint64_t invalidated = authority.Publish(std::nullopt);
    BOOST_CHECK(invalidated > previous);
    BOOST_CHECK_EQUAL(authority.PublishContext(TestAnchor(1), 7, 11),
                      invalidated);
    const uint64_t generic = authority.Publish(TestAnchor(1));
    BOOST_CHECK(generic > invalidated);
    BOOST_CHECK(authority.PublishContext(TestAnchor(1), 7, 11) > generic);
}

BOOST_AUTO_TEST_CASE(coherent_nonblocking_stamps_and_terminal_overflow) {
    Authority authority;
    std::thread writer([&] {
        for (uint64_t n = 1; n < 10000; ++n) {
            authority.Suspend();
            authority.PublishContext(TestAnchor(n), n, n);
        }
    });
    // Collected first: Boost assertions are not thread-safe.
    bool coherent = true;
    for (int i = 0; i < 20000; ++i) {
        const AuthoritativeState state = authority.Observe();
        if (state.anchor) {
            coherent &= state.observation % 2 == 0 &&
                        state.generation == state.anchor->height &&
                        state.anchor->block_id ==
                            B32(uint8_t(state.anchor->height % 256));
        }
    }
    writer.join();
    BOOST_CHECK(coherent);
    {
        const auto guard = authority.TestLockWriter();
        BOOST_CHECK(authority.Observe().anchor);
    }
    authority.TestSetSequence(UINT64_MAX - 1);
    BOOST_CHECK(Fails([&] { authority.PublishContext(TestAnchor(1), 7, 11); }));
    BOOST_CHECK(authority.Observe() ==
                (AuthoritativeState{UINT64_MAX, UINT64_MAX, std::nullopt}));
    BOOST_CHECK(Fails([&] { authority.Publish(std::nullopt); }));
    BOOST_CHECK(Fails([&] { authority.Suspend(); }));
    BOOST_CHECK(!authority.Observe().anchor);
}

// The Rust test's second half (a panic poisoning the writer mutex) has no
// C++ equivalent: std::mutex cannot be poisoned.
BOOST_AUTO_TEST_CASE(durable_exhaustion_is_terminal_unknown) {
    Authority authority;
    authority.PublishContext(TestAnchor(1), 7, 11);
    authority.TestSetGeneration(UINT64_MAX - 1);
    BOOST_CHECK(Fails([&] { authority.Publish(std::nullopt); }));
    BOOST_CHECK(Fails([&] { authority.PublishContext(TestAnchor(1), 7, 11); }));
    BOOST_CHECK(Fails([&] { authority.Suspend(); }));
    BOOST_CHECK(!authority.Observe().anchor);
}

BOOST_AUTO_TEST_SUITE_END()
