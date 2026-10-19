// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// avalanche.rs has no Rust #[test]s; these cover its behavior and messages.

#include <chronik/native/avalanche.h>
#include <chronik/native/error.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace chronik::native;

namespace {
bool HasMsg(const ChronikError &e, const std::string &msg) {
    return std::string(e.what()) == msg;
}
} // namespace

BOOST_AUTO_TEST_SUITE(avalanche_tests)

BOOST_AUTO_TEST_CASE(default_height) {
    Avalanche a;
    BOOST_CHECK_EQUAL(a.height, -1);
    BOOST_CHECK(a == Avalanche{-1});
    BOOST_CHECK(a.IsFinalHeight(-1));
    BOOST_CHECK(!a.IsFinalHeight(0));
}

BOOST_AUTO_TEST_CASE(finalize_block) {
    Avalanche a;
    a.FinalizeBlock(0);
    BOOST_CHECK_EQUAL(a.height, 0);
    a.FinalizeBlock(0); // same height is fine
    a.FinalizeBlock(5);
    BOOST_CHECK_EQUAL(a.height, 5);
    BOOST_CHECK(a.IsFinalHeight(0));
    BOOST_CHECK(a.IsFinalHeight(5));
    BOOST_CHECK(!a.IsFinalHeight(6));
    BOOST_CHECK_EXCEPTION(
        a.FinalizeBlock(4), ChronikError, [](const ChronikError &e) {
            return HasMsg(e, "Inconsistent DB: Decreasing finalized height: "
                             "indexer 5 > finalized 4");
        });
    BOOST_CHECK_EQUAL(a.height, 5);
}

BOOST_AUTO_TEST_CASE(disconnect_block) {
    Avalanche a;
    a.FinalizeBlock(5);
    // Not finalized: no change
    a.DisconnectBlock(7);
    BOOST_CHECK_EQUAL(a.height, 5);
    // Last finalized: decrement
    a.DisconnectBlock(5);
    BOOST_CHECK_EQUAL(a.height, 4);
    BOOST_CHECK_EXCEPTION(
        a.DisconnectBlock(2), ChronikError, [](const ChronikError &e) {
            return HasMsg(e, "Inconsistent DB: Disconnected block 2 that's not "
                             "the last finalized block in the indexer 4");
        });
    BOOST_CHECK_EQUAL(a.height, 4);
    // Default state: disconnecting any non-negative height is fine
    Avalanche b;
    b.DisconnectBlock(0);
    BOOST_CHECK_EQUAL(b.height, -1);
    b.DisconnectBlock(-1);
    BOOST_CHECK_EQUAL(b.height, -2);
}

BOOST_AUTO_TEST_SUITE_END()
