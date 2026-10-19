// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/block_stats.rs tests.

#include <chronik/native/index/block_stats.h>
#include <chronik/native/index/txs.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::TestDb;
using chronik::native::test::TxIdNum;

BOOST_AUTO_TEST_SUITE(index_block_stats_tests)

BOOST_AUTO_TEST_CASE(test_block_stats) {
    TestDb db("block_stats");
    const TxWriter tx_writer(*db);
    TxsMemData txs_mem_data;
    const BlockStatsWriter stats_writer(*db);

    std::vector<Tx> block = {
        MakeInputsTx(0x01, {{0x00, UINT32_MAX, 0xffff}}, {50, 20}),
        MakeInputsTx(0x02, {{0x01, 0, 50}}, {40, 10}),
        MakeInputsTx(0x03, {{0x02, 0, 40}, {0x01, 1, 20}, {0x02, 1, 10}},
                     {60, 5}),
    };
    {
        Tx tx = MakeInputsTx(0, {{0x03, 0, 60}}, {});
        tx.txid = TxIdNum(0x05);
        tx.version = 1;
        TxOutput output;
        output.sats = 60;
        output.script = {0x6a, 0x51}; // OP_RETURN OP_1
        tx.outputs.push_back(output);
        block.push_back(std::move(tx));
    }

    std::vector<TxEntry> block_txs;
    for (const Tx &tx : block) {
        TxEntry entry;
        entry.txid = tx.txid;
        block_txs.push_back(entry);
    }
    {
        auto txn = db->BeginWrite();
        const TxNum first_tx_num =
            tx_writer.Insert(*txn, BlockTxs{block_txs, 1}, txs_mem_data);
        const std::vector<IndexTx> index_txs =
            PrepareIndexedTxs(*db, *txn, first_tx_num, block);
        stats_writer.Insert(*txn, 1, 1337, index_txs);
        txn->Commit();
    }
    {
        auto txn = db->BeginRead();
        const BlockStatsReader stats_reader(*db, *txn);
        BOOST_CHECK(stats_reader.ByHeight(1) == (BlockStats{
                                                    1337,
                                                    4,
                                                    6,
                                                    7,
                                                    180,
                                                    70,
                                                    175,
                                                    60,
                                                }));
    }
    {
        auto txn = db->BeginWrite();
        stats_writer.Delete(*txn, 1);
        txn->Commit();
    }
    auto txn = db->BeginRead();
    BOOST_CHECK(BlockStatsReader(*db, *txn).ByHeight(1) == std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
