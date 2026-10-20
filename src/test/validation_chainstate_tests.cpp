// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <lotus_v2/mempool_overlay.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches) {
    ChainstateManager &manager = *Assert(m_node.chainman);
    CTxMemPool &mempool = *Assert(m_node.mempool);

    Chainstate &c1 =
        WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /* cache_size_bytes */ 1 << 23, /* in_memory */ true,
        /* should_wipe */ false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    // Need at least one block loaded to be able to flush caches
    BOOST_REQUIRE(c1.LoadGenesisBlock());

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(m_rng, c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise
        // we won't flush during ResizecoinsCaches() and will subsequently hit
        // an assertion.
        c1.CoinsTip().SetBestBlock(BlockHash{m_rng.rand256()});

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(/* upsizing the coinsview cache */ 1 << 24,
                             /* downsizing the coinsdb cache */ 1 << 22);

        // View should still have the coin cached, since we haven't destructed
        // the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(/* upsizing the coinsview cache */ 1 << 22,
                             /* downsizing the coinsdb cache */ 1 << 23);

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex *curr_tip = ::g_best_block;

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo
    // value can be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlock(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this, NoMalleation,
                                                /*reset_chainstate=*/true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = ::g_best_block;

    // Mine a new block on top of the activated snapshot chainstate.
    // Defined in TestChain100Setup.
    mineBlocks(1);

    // After adding some blocks to the snapshot tip, best block should have
    // changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    curr_tip = ::g_best_block;

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2);

    Chainstate &background_cs{*[&] {
        for (Chainstate *cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        assert(false);
    }()};

    // Append the first block to the background chain.
    BlockValidationState state;
    bool newblock = false;

    const Config &config = chainman.GetConfig();
    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        BlockValidationOptions options{config};
        bool checked = CheckBlock(
            *pblockone, state, config.GetChainParams().GetConsensus(), options);
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(pblockone, state, true, nullptr,
                                             &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(),
                      pblockone->GetHash());

    // g_best_block should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, ::g_best_block);
}

// Loading into a fresh node must build its native parent state from the
// authenticated snapshot, rather than accidentally reuse the miner's cache.
BOOST_FIXTURE_TEST_CASE(snapshot_bootstraps_native_state_without_parent_cache,
                        TestChain100Setup) {
    auto &manager = *m_node.chainman;
    mineBlocks(10);
    CBlockIndex *anchor = WITH_LOCK(cs_main, return manager.ActiveChain().Tip());
    const auto anchor_hash = anchor->GetBlockHash();
    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/true,
        /*in_memory_chainstate=*/true, [&] {
            SetV2StatePersistDir(fs::PathToString(m_path_root / "empty-native-cache"));
        }));
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_REQUIRE(GetV2BlockStateSnapshot(anchor_hash, root, monetary));
    const auto expected = lotus::v2::StateRoot(GetActiveV2ChainId(), 110,
                                              lotus::v2::SmtRoot(root), monetary);
    BOOST_CHECK(expected == anchor->GetBlockHeader().ToV2Header().state_root);
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return manager.ActiveHeight()), 111);
}

// A valid legacy coin-stat commitment must not authorize a native state that
// disagrees with its trusted anchor header. No native cache may be published.
BOOST_FIXTURE_TEST_CASE(snapshot_rejects_mismatched_native_anchor,
                        TestChain100Setup) {
    auto &manager = *m_node.chainman;
    mineBlocks(10);
    CBlockIndex *anchor = WITH_LOCK(cs_main, return manager.ActiveChain().Tip());
    const auto anchor_hash = anchor->GetBlockHash();
    const auto original_root = anchor->hashStateRoot;
    const bool accepted = CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/true,
        /*in_memory_chainstate=*/true, [&] {
            SetV2StatePersistDir(fs::PathToString(m_path_root / "empty-native-cache"));
            anchor->hashStateRoot.begin()[0] ^= 1;
        });
    anchor->hashStateRoot = original_root;
    BOOST_CHECK(!accepted);
    BOOST_CHECK(!manager.IsSnapshotActive());
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_CHECK(!GetV2BlockStateSnapshot(anchor_hash, root, monetary));
}

BOOST_AUTO_TEST_SUITE_END()
