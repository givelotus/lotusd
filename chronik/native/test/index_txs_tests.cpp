// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/txs.rs tests.

#include <chronik/native/index/txs.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::TestDb;
using chronik::native::test::TxIdNum;

namespace {
using Range = std::optional<std::pair<TxNum, TxNum>>;
Range R(TxNum a, TxNum b) {
    return std::make_pair(a, b);
}
} // namespace

BOOST_AUTO_TEST_SUITE(index_txs_tests)

BOOST_AUTO_TEST_CASE(test_insert_txs) {
    TestDb db("txs");
    const TxWriter tx_writer(*db);
    TxsMemData mem_data;
    const TxEntry tx1{TxIdNum(1), 100, 0, 123456, true};
    const index::BlockTx block_tx1{tx1, 0};
    const BlockTxs block1{{tx1}, 0};
    {
        auto rtxn = db->BeginRead();
        const TxReader tx_reader(*db, *rtxn);
        BOOST_CHECK(tx_reader.LastTxNum() == std::nullopt);
        BOOST_CHECK(tx_reader.BlockTxNumRange(0) == std::nullopt);
    }
    {
        // insert genesis tx
        auto txn = db->BeginWrite();
        BOOST_CHECK_EQUAL(tx_writer.Insert(*txn, block1, mem_data), 0U);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const TxReader tx_reader(*db, *rtxn);
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(0) == TxNum(0));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(1) == std::nullopt);
        BOOST_CHECK(tx_reader.LastTxNum() == TxNum(0));
        BOOST_CHECK(tx_reader.BlockTxNumRange(0) == R(0, 1));
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(0)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(0)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(1)) == block_tx1);
        BOOST_CHECK(tx_reader.TxByTxNum(0) == block_tx1);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(1)) == TxNum(0));
    }
    const TxEntry tx2{TxIdNum(2), 200, 20, 234567, false};
    const index::BlockTx block_tx2{tx2, 1};
    const TxEntry tx3{TxIdNum(3), 300, 30, 345678, false};
    const index::BlockTx block_tx3{tx3, 1};
    const BlockTxs block2{{tx2, tx3}, 1};
    {
        // insert 2 more txs
        auto txn = db->BeginWrite();
        BOOST_CHECK_EQUAL(tx_writer.Insert(*txn, block2, mem_data), 1U);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const TxReader tx_reader(*db, *rtxn);
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(0) == TxNum(0));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(1) == TxNum(1));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(2) == std::nullopt);
        BOOST_CHECK(tx_reader.LastTxNum() == TxNum(2));
        BOOST_CHECK(tx_reader.BlockTxNumRange(0) == R(0, 1));
        BOOST_CHECK(tx_reader.BlockTxNumRange(1) == R(1, 3));
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(0)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(0)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(1)) == block_tx1);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(1)) == TxNum(0));
        BOOST_CHECK(tx_reader.TxByTxNum(0) == block_tx1);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(2)) == block_tx2);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(2)) == TxNum(1));
        BOOST_CHECK(tx_reader.TxByTxNum(1) == block_tx2);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(3)) == block_tx3);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(3)) == TxNum(2));
        BOOST_CHECK(tx_reader.TxByTxNum(2) == block_tx3);
        // batched reads
        const auto nums =
            tx_reader.TxNumsByTxids({TxIdNum(3), TxIdNum(9), TxIdNum(1)});
        BOOST_CHECK(nums == (std::vector<std::optional<TxNum>>{2, std::nullopt,
                                                               0}));
        const auto txids = tx_reader.TxidsByTxNums({2, 5});
        BOOST_CHECK(txids ==
                    (std::vector<std::optional<TxId>>{TxIdNum(3),
                                                      std::nullopt}));
    }
    {
        // delete latest block
        auto txn = db->BeginWrite();
        BOOST_CHECK_EQUAL(tx_writer.Delete(*txn, block2, mem_data), 1U);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const TxReader tx_reader(*db, *rtxn);
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(0) == TxNum(0));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(1) == std::nullopt);
        BOOST_CHECK(tx_reader.LastTxNum() == TxNum(0));
        BOOST_CHECK(tx_reader.BlockTxNumRange(0) == R(0, 1));
        BOOST_CHECK(tx_reader.BlockTxNumRange(1) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(0)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(1)) == block_tx1);
        BOOST_CHECK(tx_reader.TxByTxNum(0) == block_tx1);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(2)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxNum(1) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(3)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxNum(2) == std::nullopt);
    }
    const TxEntry tx2b{TxIdNum(102), 200, 20, 234567, false};
    const index::BlockTx block_tx2b{tx2b, 1};
    const TxEntry tx3b{TxIdNum(103), 300, 30, 345678, false};
    const index::BlockTx block_tx3b{tx3b, 1};
    const BlockTxs block3{{tx2b, tx3b}, 1};
    {
        // Add reorg block
        auto txn = db->BeginWrite();
        BOOST_CHECK_EQUAL(tx_writer.Insert(*txn, block3, mem_data), 1U);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const TxReader tx_reader(*db, *rtxn);
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(0) == TxNum(0));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(1) == TxNum(1));
        BOOST_CHECK(tx_reader.FirstTxNumByBlock(2) == std::nullopt);
        BOOST_CHECK(tx_reader.BlockTxNumRange(0) == R(0, 1));
        BOOST_CHECK(tx_reader.BlockTxNumRange(1) == R(1, 3));
        BOOST_CHECK(tx_reader.BlockTxNumRange(2) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(1)) == block_tx1);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(2)) == std::nullopt);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(102)) == block_tx2b);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(102)) == TxNum(1));
        BOOST_CHECK(tx_reader.TxByTxNum(1) == block_tx2b);
        BOOST_CHECK(tx_reader.TxByTxid(TxIdNum(103)) == block_tx3b);
        BOOST_CHECK(tx_reader.TxNumByTxid(TxIdNum(103)) == TxNum(2));
        BOOST_CHECK(tx_reader.TxByTxNum(2) == block_tx3b);
    }
    BOOST_CHECK_EQUAL(mem_data.stats.n_total, 7U);
}

BOOST_AUTO_TEST_SUITE_END()
