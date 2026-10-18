// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <hash.h>
#include <lotus_v2/utxo_fast_filter.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

namespace lotus::v2 {
struct UtxoFastFilterTestAccess {
    static bool CollisionSurvivesErase() {
        UtxoFastFilter::FlatFpSet set;
        set.Insert(42); // first outpoint's fingerprint
        set.Insert(42); // different outpoint, same fingerprint
        set.Reserve(1024); // growth must carry both collision references
        if (!set.Erase(42) || !set.Contains(42)) return false;
        return set.Erase(42) && !set.Contains(42);
    }
};
}

BOOST_FIXTURE_TEST_SUITE(utxo_fast_filter_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(shard_growth_erase_and_clear_lifecycle) {
    lotus::v2::UtxoFastFilter filter;
    const auto txid = Hash(std::string("UTXO fingerprint lifecycle fixture"));
    filter.ReservePerShard(1, 1);
    for (uint32_t i = 0; i < 1024; ++i) {
        BOOST_CHECK(!filter.IsSpentInMempool(txid.begin(), i));
        BOOST_CHECK(filter.MarkSpentInMempool(txid.begin(), i));
        BOOST_CHECK(!filter.MarkSpentInMempool(txid.begin(), i));
        BOOST_CHECK(filter.IsSpentInMempool(txid.begin(), i));
        BOOST_CHECK(filter.AddUnspent(txid.begin(), i));
        BOOST_CHECK(filter.ContainsUnspent(txid.begin(), i));
    }
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), 1024U);
    BOOST_CHECK_EQUAL(filter.UnspentCount(), 1024U);
    for (uint32_t i = 0; i < 1024; i += 2) {
        BOOST_CHECK(filter.UnmarkSpentInMempool(txid.begin(), i));
        BOOST_CHECK(!filter.IsSpentInMempool(txid.begin(), i));
        BOOST_CHECK(filter.RemoveUnspent(txid.begin(), i));
    }
    for (uint32_t i = 1; i < 1024; i += 2) {
        BOOST_CHECK(filter.IsSpentInMempool(txid.begin(), i));
        BOOST_CHECK(filter.ContainsUnspent(txid.begin(), i));
    }
    filter.ClearMempool();
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), 0U);
    BOOST_CHECK_EQUAL(filter.UnspentCount(), 512U);
    filter.SetChainUhsAuthoritative(true);
    filter.ClearAll();
    BOOST_CHECK(!filter.IsChainUhsAuthoritative());
    BOOST_CHECK_EQUAL(filter.UnspentCount(), 0U);
    for (uint32_t i = 0; i < 1024; ++i) {
        BOOST_CHECK(!filter.ContainsUnspent(txid.begin(), i));
    }
}
BOOST_AUTO_TEST_CASE(colliding_outpoint_removal_preserves_other_membership) {
    lotus::v2::UtxoFastFilter filter;
    lotus::v2::Outpoint first{};
    first.tx_id[0] = 42;
    lotus::v2::Outpoint second = first;
    // The historical fixed mixer ignores the last 16 txid bytes entirely.
    second.tx_id[31] = 1;
    BOOST_REQUIRE(first.tx_id != second.tx_id);
    filter.MarkSpentInMempool(first);
    filter.MarkSpentInMempool(second);
    filter.AddUnspent(first);
    filter.AddUnspent(second);
    BOOST_CHECK(filter.UnmarkSpentInMempool(first));
    BOOST_CHECK(filter.RemoveUnspent(first));
    BOOST_CHECK(filter.IsSpentInMempool(second));
    BOOST_CHECK(filter.ContainsUnspent(second));
}
BOOST_AUTO_TEST_CASE(fingerprint_collision_retains_reference_until_last_erase) {
    BOOST_CHECK(lotus::v2::UtxoFastFilterTestAccess::CollisionSurvivesErase());
}
BOOST_AUTO_TEST_SUITE_END()
