// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/txindex.h>

#include <chainparams.h>
#include <dbwrapper.h>
#include <index/disktxpos.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <script/standard.h>
#include <test/util/logging.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(txindex_tests)

BOOST_FIXTURE_TEST_CASE(txindex_initial_sync, TestChain100Setup) {
    TxIndex txindex(interfaces::MakeChain(m_node, Params()), 1 << 20, true);
    BOOST_REQUIRE(txindex.Init());

    CTransactionRef tx_disk;
    BlockHash block_hash;

    // Transaction should not be found in the index before it is started.
    for (const auto &txn : m_coinbase_txns) {
        BOOST_CHECK(!txindex.FindTx(txn->GetId(), block_hash, tx_disk));
    }

    // BlockUntilSyncedToCurrentChain should return false before txindex is
    // started.
    BOOST_CHECK(!txindex.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(txindex.StartBackgroundSync());

    // Allow tx index to catch up with the block index.
    constexpr auto timeout{10s};
    const auto time_start{SteadyClock::now()};
    while (!txindex.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout > SteadyClock::now());
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }

    // Check that txindex excludes genesis block transactions.
    const CBlock &genesis_block = Params().GenesisBlock();
    for (const auto &txn : genesis_block.vtx) {
        BOOST_CHECK(!txindex.FindTx(txn->GetId(), block_hash, tx_disk));
    }

    // Check that txindex has all txs that were in the chain before it started.
    for (const auto &txn : m_coinbase_txns) {
        if (!txindex.FindTx(txn->GetId(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetId() != txn->GetId()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // Check that new transactions in new blocks make it into the index.
    for (int i = 0; i < 10; i++) {
        CScript coinbase_script_pub_key =
            GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        std::vector<CMutableTransaction> no_txns;
        const CBlock &block =
            CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        const CTransactionRef &txn = block.vtx[0];

        BOOST_CHECK(txindex.BlockUntilSyncedToCurrentChain());
        if (!txindex.FindTx(txn->GetId(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetId() != txn->GetId()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The
    // BlockUntilSyncedToCurrentChain() call above is sufficient to ensure this,
    // but the SyncWithValidationInterfaceQueue() call below is also needed to
    // ensure TSAN always sees the test thread waiting for the notification
    // thread, and avoid potential false positive reports.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    txindex.Stop();
}

// Corrupt only this fixture's isolated txindex records. Keep FindTx's failure
// return, existing text, and typed JSON identity observable through its real
// file-reading path; no production API or visibility changes are needed.
BOOST_FIXTURE_TEST_CASE(logging_read_failures, TestChain100Setup) {
    BOOST_REQUIRE(gArgs.GetDataDirNet() == m_args.GetDataDirNet());
    const auto db_path{m_args.GetDataDirNet() / "indexes" / "txindex"};
    const TxId missing_id{uint256S("01")};
    const TxId truncated_id{uint256S("02")};
    const TxId mismatch_id{uint256S("03")};
    const FlatFilePos valid_pos = WITH_LOCK(
        cs_main, return m_node.chainman->ActiveChain()[1]->GetBlockPos());
    {
        CDBWrapper db{DBParams{
            .path = db_path, .cache_bytes = 1 << 20, .wipe_data = true}};
        // This wrapper throws on write failure; Write intentionally returns
        // void.
        db.Write(std::make_pair(uint8_t{'t'}, missing_id),
                 CDiskTxPos{FlatFilePos{99999, 0}, 0});
        db.Write(
            std::make_pair(uint8_t{'t'}, truncated_id),
            CDiskTxPos{FlatFilePos{valid_pos.nFile, 1024U * 1024U * 1024U}, 0});
        db.Write(std::make_pair(uint8_t{'t'}, mismatch_id),
                 CDiskTxPos{valid_pos, GetSizeOfCompactSize(1)});
    }
    TxIndex index(interfaces::MakeChain(m_node, Params()), 1 << 20);
    BOOST_REQUIRE(index.Init());
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
    const auto check = [&](const TxId &id, const char *event,
                           const char *expected_message, bool has_error) {
        std::string captured;
        {
            DebugLogHelper helper(event, [&](const std::string *line) {
                if (line) captured = *line;
                return false; // Assert after Flush on this test's thread.
            });
            CTransactionRef tx;
            BlockHash block_hash;
            BOOST_CHECK(!index.FindTx(id, block_hash, tx));
        }
        UniValue row;
        BOOST_REQUIRE(!captured.empty());
        BOOST_REQUIRE(row.read(captured));
        BOOST_CHECK_EQUAL(row["event"].get_str(), event);
        BOOST_CHECK_EQUAL(row["level"].get_str(), "error");
        BOOST_CHECK_EQUAL(row["source_function"].get_str(), "FindTx");
        if (has_error) {
            BOOST_REQUIRE(row["error"].isStr());
            BOOST_CHECK(!row["error"].get_str().empty());
            BOOST_CHECK_EQUAL(row["message"].get_str(),
                              std::string{expected_message} +
                                  row["error"].get_str());
        } else {
            BOOST_CHECK_EQUAL(row["message"].get_str(), expected_message);
        }
        BOOST_CHECK(row["fields_truncated"].isNull());
    };
    check(missing_id, "transaction_index_block_file_open_failed",
          "FindTx: OpenBlockFile failed", false);
    check(truncated_id, "transaction_index_block_read_failed",
          "FindTx: Deserialize or I/O error - ", true);
    check(mismatch_id, "transaction_index_txid_mismatch",
          "FindTx: txid mismatch", false);
    index.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
