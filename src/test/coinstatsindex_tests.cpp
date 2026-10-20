// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <config.h>
#include <dbwrapper.h>
#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <lotus_v2/commitment.h>
#include <node/blockstorage.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <undo.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>

// Index component fixture, not natural 131400-block expiry validation. It seeds
// a coherent prior index snapshot and persists protocol-shaped paid Coin undo.
struct CoinStatsIndexTestAccess {
    static void CheckExpiry(TestChain100Setup &fixture, uint64_t fee_atoms) {
        CoinStatsIndex index{interfaces::MakeChain(fixture.m_node, Params()),
                             1 << 20, true};
        BOOST_REQUIRE(index.Init());
        constexpr int height = 131408;
        const std::array<uint8_t, 1> script{0x4e};
        lotus::v2::Output output;
        output.value = 1000;
        output.branches = {lotus::v2::BranchLeaf(script)};
        output.paths = {{0}};
        const Coin expired(CTxOut::FromV2Output(output), 1, false, 7);
        output.value = 2000;
        const Coin live(CTxOut::FromV2Output(output), 1, false, 8);
        BOOST_REQUIRE_EQUAL(expired.GetExpirationHeight(), height);
        BOOST_REQUIRE_EQUAL(live.GetExpirationHeight(), height + 1);
        const COutPoint expired_op(TxId(uint256S("01")), 0);
        const COutPoint live_op(TxId(uint256S("02")), 0);
        const COutPoint funding_op(TxId(uint256S("05")), 0);
        auto seed = [&](const COutPoint &op, const Coin &coin) {
            index.m_muhash.Insert(MakeUCharSpan(kernel::TxOutSer(op, coin)));
            ++index.m_transaction_output_count;
            index.m_total_amount += coin.GetTxOut().nValue;
            index.m_bogo_size +=
                kernel::GetBogoSize(coin.GetTxOut().scriptPubKey);
        };
        seed(expired_op, expired);
        seed(live_op, live);
        CMutableTransaction ordinary;
        CTxUndo txundo;
        if (fee_atoms != 0) {
            output.value = 10000 + fee_atoms;
            const Coin funding(CTxOut::FromV2Output(output), 1, false, 100);
            seed(funding_op, funding);
            txundo.vprevout.push_back(funding);
            ordinary.nVersion = 7;
            ordinary.vin.resize(1);
            ordinary.vin[0].prevout = funding_op;
            ordinary.vin[0].nFlags = 1;
            lotus::v2::BranchWitness witness;
            witness.script.assign(script.begin(), script.end());
            ordinary.vin[0].vWitnesses = {std::move(witness)};
            output.value = 10000;
            ordinary.vout.push_back(CTxOut::FromV2Output(output));
        }
        index.m_total_subsidy = index.m_total_amount;
        index.m_total_new_outputs_ex_coinbase_amount = index.m_total_amount;
        const Amount prior_amount = index.m_total_amount;
        const auto prior_count = index.m_transaction_output_count;
        const auto prior_bogo = index.m_bogo_size;
        uint256 prior_hash;
        index.m_muhash.Finalize(prior_hash);
        const BlockHash parent_hash(uint256S("03"));
        const BlockHash child_hash(uint256S("04"));
        CBlockIndex *parent;
        CBlockIndex *child;
        {
            LOCK(cs_main);
            auto &map = fixture.m_node.chainman->m_blockman.m_block_index;
            auto [p, pins] = map.try_emplace(parent_hash);
            auto [c, cins] = map.try_emplace(child_hash);
            BOOST_REQUIRE(pins && cins);
            parent = &p->second;
            child = &c->second;
            parent->phashBlock = &p->first;
            parent->nHeight = height - 1;
            child->phashBlock = &c->first;
            child->nHeight = height;
            child->pprev = parent;
            child->nFile = 0;
        }
        index.StoreStats(parent);
        CMutableTransaction cb(*fixture.m_coinbase_txns.at(0));
        cb.vin[0].scriptSig = CScript() << height;
        // Independent expected boundary values: no fee, fee/2 cap, base cap.
        const uint64_t bounty = fee_atoms == 0      ? 0
                                : fee_atoms == 1000 ? 500
                                                    : 2000;
        BOOST_REQUIRE_EQUAL(lotus::v2::ComputeCleaningCrewBounty(1, fee_atoms),
                            bounty);
        cb.vout[0].nValue = GetBlockSubsidy(height, Params().GetConsensus()) +
                            static_cast<int64_t>(fee_atoms + bounty) * SATOSHI;
        CBlock block;
        block.vtx = {MakeTransactionRef(cb)};
        CBlockUndo undo;
        if (fee_atoms != 0) {
            block.vtx.push_back(MakeTransactionRef(ordinary));
            undo.vtxundo.push_back(txundo);
        }
        undo.vexpired.push_back({expired_op, expired});
        {
            LOCK(cs_main);
            BlockValidationState state;
            BOOST_REQUIRE(fixture.m_node.chainman->m_blockman.WriteBlockUndo(
                undo, state, *child));
        }
        MuHash3072 expected;
        expected.Insert(MakeUCharSpan(kernel::TxOutSer(live_op, live)));
        const Coin cb_coin(block.vtx[0]->vout[0], height, true);
        expected.Insert(MakeUCharSpan(
            kernel::TxOutSer(COutPoint(block.vtx[0]->GetId(), 0), cb_coin)));
        uint64_t expected_bogo =
            kernel::GetBogoSize(live.GetTxOut().scriptPubKey) +
            kernel::GetBogoSize(cb_coin.GetTxOut().scriptPubKey);
        if (fee_atoms != 0) {
            const Coin created(block.vtx[1]->vout[0], height, false, fee_atoms);
            expected.Insert(MakeUCharSpan(kernel::TxOutSer(
                COutPoint(block.vtx[1]->GetId(), 0), created)));
            expected_bogo +=
                kernel::GetBogoSize(created.GetTxOut().scriptPubKey);
        }
        uint256 expected_hash;
        expected.Finalize(expected_hash);
        auto check_applied = [&] {
            uint256 actual;
            index.m_muhash.Finalize(actual);
            BOOST_CHECK_EQUAL(actual.ToString(), expected_hash.ToString());
            BOOST_CHECK_EQUAL(index.m_transaction_output_count,
                              fee_atoms == 0 ? 2U : 3U);
            BOOST_CHECK_EQUAL(index.m_total_amount / SATOSHI,
                              2000 + (fee_atoms == 0 ? 0 : 10000) +
                                  cb_coin.GetTxOut().nValue / SATOSHI);
            BOOST_CHECK_EQUAL(index.m_bogo_size, expected_bogo);
            BOOST_CHECK_EQUAL(index.m_total_unspendables_expired / SATOSHI,
                              1000);
            BOOST_CHECK_EQUAL(index.m_total_unspendable_amount / SATOSHI, 1000);
            BOOST_CHECK_EQUAL(index.m_total_cleaning_bounty / SATOSHI, bounty);
            BOOST_CHECK_EQUAL(
                index.m_total_unspendables_unclaimed_rewards / SATOSHI, 0);
            BOOST_CHECK(index.m_total_prevout_spent_amount +
                            index.m_total_subsidy +
                            index.m_total_cleaning_bounty +
                            index.m_total_unspendables_expired ==
                        index.m_total_new_outputs_ex_coinbase_amount +
                            index.m_total_coinbase_amount +
                            index.m_total_unspendable_amount);
        };
        BOOST_REQUIRE(index.WriteBlock(block, child));
        check_applied();
        // Persist/reload the exact rolling root and new cumulative counters.
        CDBBatch batch(*index.m_db);
        BOOST_REQUIRE(index.CustomCommit(batch));
        index.m_db->WriteBatch(batch);
        index.m_total_unspendables_expired = Amount::zero();
        index.m_total_cleaning_bounty = Amount::zero();
        index.m_muhash = MuHash3072{};
        BOOST_REQUIRE(
            index.CustomInit(interfaces::BlockKey{child_hash, height}));
        check_applied();
        const auto stats = index.LookUpStats(child);
        BOOST_REQUIRE(stats);
        BOOST_CHECK_EQUAL(stats->total_unspendables_expired / SATOSHI, 1000);
        BOOST_CHECK_EQUAL(stats->total_cleaning_bounty / SATOSHI, bounty);
        BOOST_REQUIRE(index.ReverseBlock(block, child));
        uint256 restored;
        index.m_muhash.Finalize(restored);
        BOOST_CHECK_EQUAL(restored.ToString(), prior_hash.ToString());
        BOOST_CHECK_EQUAL(index.m_transaction_output_count, prior_count);
        BOOST_CHECK(index.m_total_amount == prior_amount);
        BOOST_CHECK_EQUAL(index.m_bogo_size, prior_bogo);
        BOOST_CHECK_EQUAL(index.m_total_unspendables_expired / SATOSHI, 0);
        BOOST_CHECK_EQUAL(index.m_total_cleaning_bounty / SATOSHI, 0);
        // Deterministic replay reads the same durable undo and re-creates
        // stats.
        BOOST_REQUIRE(index.WriteBlock(block, child));
        check_applied();
        // An old/unreadable/unknown DB must not silently supply wrong roots or
        // default newly introduced counters to zero.
        index.m_db->Erase(uint8_t('V'));
        {
            ASSERT_DEBUG_LOG("restart with -reindex to rebuild it");
            BOOST_CHECK(!index.CustomInit(std::nullopt));
        }
        index.m_db->Write(uint8_t('V'), uint32_t(99));
        {
            ASSERT_DEBUG_LOG("restart with -reindex to rebuild it");
            BOOST_CHECK(!index.CustomInit(std::nullopt));
        }
        index.m_db->Write(uint8_t('V'), uint8_t(2)); // Truncated uint32 version.
        {
            ASSERT_DEBUG_LOG("restart with -reindex to rebuild it");
            BOOST_CHECK(!index.CustomInit(std::nullopt));
        }
    }
    template <typename Check>
    static void CheckLoggingFailures(TestingSetup &fixture, Check check) {
        CoinStatsIndex index{interfaces::MakeChain(fixture.m_node, Params()),
                             1 << 20, true};
        BOOST_REQUIRE(index.Init());
        // Real deserialization failure through CustomInit; the unrelated key
        // subsequently ensures an absent V2 format marker is not a new DB.
        index.m_db->Write(uint8_t{'M'}, uint8_t{1});
        check(
            "coinstats_state_read_failed",
            "CustomInit: Cannot read current coinstatsindex state; index may be corrupted",
            [&] { return index.CustomInit(std::nullopt); }, false);
        index.m_db->Erase(uint8_t{'M'});
        index.m_db->Erase(uint8_t{'V'});
        index.m_db->Write(uint8_t{'X'}, uint8_t{1});
        check(
            "coinstats_native_accounting_format_missing",
            "CustomInit: Native coinstats index predates paid-lifetime/expiry accounting; restart with -reindex to rebuild it",
            [&] { return index.CustomInit(std::nullopt); }, false);
        index.m_db->Write(uint8_t{'V'}, uint32_t{0xffffffffU});
        check(
            "coinstats_native_format_unsupported",
            "CustomInit: Unsupported native coinstats index version 4294967295; restart with -reindex to rebuild it",
            [&] { return index.CustomInit(std::nullopt); }, true);
        // Restoring the known format keeps the pre-existing success path.
        index.m_db->Write(uint8_t{'V'}, uint32_t{2});
        BOOST_CHECK(index.CustomInit(std::nullopt));
        index.Stop();
    }
};

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

static void IndexWaitSynced(BaseIndex &index) {
    // Allow the CoinStatsIndex to catch up with the block index that is syncing
    // in a background thread.
    const auto timeout = GetTime<std::chrono::seconds>() + 120s;
    while (!index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(timeout > GetTime<std::chrono::milliseconds>());
        UninterruptibleSleep(100ms);
    }
}

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup) {
    CoinStatsIndex coin_stats_index{interfaces::MakeChain(m_node, Params()),
                                    1 << 20, true};
    BOOST_REQUIRE(coin_stats_index.Init());

    const CBlockIndex *block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveTip();
    }

    // CoinStatsIndex should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookUpStats(block_index));

    // BlockUntilSyncedToCurrentChain should return false before CoinStatsIndex
    // is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(coin_stats_index.StartBackgroundSync());

    IndexWaitSynced(coin_stats_index);

    // Check that CoinStatsIndex works for genesis block.
    const CBlockIndex *genesis_block_index;
    {
        LOCK(cs_main);
        genesis_block_index = m_node.chainman->ActiveChain().Genesis();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(genesis_block_index));

    // Check that CoinStatsIndex updates with new blocks.
    BOOST_CHECK(coin_stats_index.LookUpStats(block_index));

    const CScript script_pub_key{
        CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, script_pub_key);

    // Let the CoinStatsIndex to catch up again.
    BOOST_CHECK(coin_stats_index.BlockUntilSyncedToCurrentChain());

    const CBlockIndex *new_block_index;
    {
        LOCK(cs_main);
        new_block_index = m_node.chainman->ActiveTip();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(new_block_index));

    BOOST_CHECK(block_index != new_block_index);

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The
    // BlockUntilSyncedToCurrentChain() call above is sufficient to ensure this,
    // but the SyncWithValidationInterfaceQueue() call below is also needed to
    // ensure TSAN always sees the test thread waiting for the notification
    // thread, and avoid potential false positive reports.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // Shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();
}

// Test shutdown between BlockConnected and ChainStateFlushed notifications,
// make sure index is not corrupted and is able to reload.
BOOST_FIXTURE_TEST_CASE(coinstatsindex_unclean_shutdown, TestChain100Setup) {
    Chainstate &chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const Config &config = m_node.chainman->GetConfig();
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node, Params()), 1 << 20};
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index);
        std::shared_ptr<const CBlock> new_block;
        CBlockIndex *new_block_index = nullptr;
        {
            const CScript script_pub_key{
                CScript() << ToByteVector(coinbaseKey.GetPubKey())
                          << OP_CHECKSIG};
            const CBlock block =
                this->CreateBlock({}, script_pub_key, chainstate);

            new_block = std::make_shared<CBlock>(block);

            LOCK(cs_main);
            BlockValidationState state;
            BlockValidationOptions options{config};
            BOOST_CHECK(CheckBlock(
                block, state, config.GetChainParams().GetConsensus(), options));
            BOOST_CHECK(m_node.chainman->AcceptBlock(new_block, state, true,
                                                     nullptr, nullptr, true));

            // Get the block index (not returned by AcceptBlock since D2127)
            auto it{m_node.chainman->m_blockman.m_block_index.find(
                new_block->GetHash())};
            if (it != m_node.chainman->m_blockman.m_block_index.end()) {
                new_block_index = &(it->second);
            }

            CCoinsViewCache view(&chainstate.CoinsTip());
            BOOST_CHECK(chainstate.ConnectBlock(block, state, new_block_index,
                                                view, options));
        }
        // Send block connected notification, then stop the index without
        // sending a chainstate flushed notification. Prior to #24138, this
        // would cause the index to be corrupted and fail to reload.
        ValidationInterfaceTest::BlockConnected(ChainstateRole::NORMAL, index,
                                                new_block, new_block_index);
        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(m_node, Params()), 1 << 20};
        BOOST_REQUIRE(index.Init());
        // Make sure the index can be loaded.
        BOOST_REQUIRE(index.StartBackgroundSync());
        index.Stop();
    }
}

BOOST_FIXTURE_TEST_CASE(native_expiry_zero_bounty, TestChain100Setup) {
    CoinStatsIndexTestAccess::CheckExpiry(*this, 0);
}

BOOST_FIXTURE_TEST_CASE(native_expiry_fee_half_bounty, TestChain100Setup) {
    CoinStatsIndexTestAccess::CheckExpiry(*this, 1000);
}

BOOST_FIXTURE_TEST_CASE(native_expiry_base_bounty_boundary, TestChain100Setup) {
    CoinStatsIndexTestAccess::CheckExpiry(*this, 4000);
}

BOOST_FIXTURE_TEST_CASE(native_expiry_base_bounty_cap, TestChain100Setup) {
    CoinStatsIndexTestAccess::CheckExpiry(*this, 8000);
}

BOOST_FIXTURE_TEST_CASE(logging_native_format_and_state_failures,
                        TestingSetup) {
    struct ScopedFormat {
        BCLog::LogFormat previous{LogInstance().m_log_format};
        ScopedFormat() {
            LogInstance().Flush();
            LogInstance().m_log_format = BCLog::LogFormat::JSON;
        }
        ~ScopedFormat() {
            LogInstance().Flush();
            LogInstance().m_log_format = previous;
        }
    } format;
    const auto check = [](const char *event, const char *expected_message,
                          auto operation, bool has_version) {
        std::string captured;
        {
            DebugLogHelper helper(event, [&](const std::string *line) {
                if (line) captured = *line;
                return false; // Inspect JSON only after the logger Flush.
            });
            BOOST_CHECK(!operation());
        }
        UniValue row;
        BOOST_REQUIRE(!captured.empty());
        BOOST_REQUIRE(row.read(captured));
        BOOST_CHECK_EQUAL(row["event"].get_str(), event);
        BOOST_CHECK_EQUAL(row["level"].get_str(), "error");
        BOOST_CHECK_EQUAL(row["source_function"].get_str(), "CustomInit");
        BOOST_CHECK_EQUAL(row["message"].get_str(), expected_message);
        BOOST_CHECK(row["fields_truncated"].isNull());
        if (has_version) {
            BOOST_REQUIRE(row["version"].isNum());
            BOOST_CHECK_EQUAL(row["version"].getInt<int64_t>(),
                              int64_t{4294967295});
        }
        if (std::string{event} == "coinstats_state_read_failed") {
            BOOST_CHECK_EQUAL(row["name"].get_str(), "coinstatsindex");
        }
    };
    CoinStatsIndexTestAccess::CheckLoggingFailures(*this, check);
}

BOOST_AUTO_TEST_SUITE_END()
