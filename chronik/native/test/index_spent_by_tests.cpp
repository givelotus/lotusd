// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/spent_by.rs tests.

#include <chronik/native/index/merge.h>
#include <chronik/native/index/spent_by.h>
#include <chronik/native/index/txs.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::TestDb;

namespace {

using Entries = std::optional<std::vector<SpentByEntry>>;

SpentByEntry SB(uint32_t out_idx, TxNum tx_num, uint32_t input_idx) {
    return SpentByEntry{out_idx, tx_num, input_idx};
}

/** connect_block/disconnect_block of the Rust test. */
struct Fixture {
    TestDb db{"spent_by"};
    TxWriter tx_writer{*db};
    SpentByWriter spent_by_writer{*db};
    SpentByMemData mem_data;
    TxsMemData txs_mem_data;
    BlockHeight block_height = -1;

    BlockTxs TxsBatch(const std::vector<Tx> &txs) const {
        BlockTxs batch;
        for (const Tx &tx : txs) {
            TxEntry entry;
            entry.txid = tx.txid;
            batch.txs.push_back(entry);
        }
        batch.block_height = block_height;
        return batch;
    }

    void ConnectBlock(const std::vector<Tx> &txs) {
        std::vector<IndexTx> index_txs;
        {
            auto txn = db->BeginWrite();
            ++block_height;
            const TxNum first_tx_num =
                tx_writer.Insert(*txn, TxsBatch(txs), txs_mem_data);
            index_txs = PrepareIndexedTxs(*db, *txn, first_tx_num, txs);
            spent_by_writer.Insert(*txn, index_txs, mem_data);
            txn->Commit();
        }
        auto rtxn = db->BeginRead();
        const SpentByReader reader(*db, *rtxn);
        for (const IndexTx &tx : index_txs) {
            for (const TxNum input_tx_num : tx.input_nums) {
                reader.ByTxNum(input_tx_num);
                merge::CheckForErrors();
            }
        }
    }

    void DisconnectBlock(const std::vector<Tx> &txs) {
        // On error, the txn is aborted, like the Rust batch never written
        auto txn = db->BeginWrite();
        const TxNum first_tx_num =
            tx_writer.Delete(*txn, TxsBatch(txs), txs_mem_data);
        const std::vector<IndexTx> index_txs =
            PrepareIndexedTxs(*db, *txn, first_tx_num, txs);
        spent_by_writer.Delete(*txn, index_txs, mem_data);
        txn->Commit();
        --block_height;
    }

    Entries ByTxNum(TxNum tx_num) {
        auto txn = db->BeginRead();
        return SpentByReader(*db, *txn).ByTxNum(tx_num);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(index_spent_by_tests)

BOOST_AUTO_TEST_CASE(test_spent_by) {
    ErrorMsg([] { merge::CheckForErrors(); });
    Fixture f;

    const std::vector<Tx> block0 = {
        MakeInputsTx(0, {{0x00, UINT32_MAX, -1}}, {-1, -1, -1, -1})};
    f.ConnectBlock(block0);

    const std::vector<Tx> block1 = {
        MakeInputsTx(1, {{0x00, UINT32_MAX, -1}}, {-1, -1}),
        // spend 3rd output of tx_num=0
        MakeInputsTx(2, {{0, 3, -1}}, {-1, -1, -1}),
    };
    f.ConnectBlock(block1);
    BOOST_CHECK(f.ByTxNum(0) == Entries({SB(3, 2, 0)}));

    // Remove block1
    f.DisconnectBlock(block1);
    BOOST_CHECK(f.ByTxNum(0) == std::nullopt);

    // Add block1 again
    f.ConnectBlock(block1);

    const std::vector<Tx> block2 = {
        MakeInputsTx(3, {{0x00, UINT32_MAX, -1}}, {-1}),
        // spend 2nd output of tx_num=0, and 0th output of tx_num=1
        MakeInputsTx(4, {{0, 2, -1}, {1, 0, -1}}, {-1, -1, -1}),
        // spend 1st output of tx_num=1, and 1st output of tx_num=0
        MakeInputsTx(5, {{1, 1, -1}, {0, 1, -1}}, {-1, -1}),
    };
    f.ConnectBlock(block2);
    BOOST_CHECK(f.ByTxNum(0) ==
                Entries({SB(1, 5, 1), SB(2, 4, 0), SB(3, 2, 0)}));
    BOOST_CHECK(f.ByTxNum(1) == Entries({SB(0, 4, 1), SB(1, 5, 0)}));

    // More complex block
    const std::vector<Tx> block3 = {
        MakeInputsTx(6, {{0x00, UINT32_MAX, -1}}, {-1}),
        MakeInputsTx(7, {{4, 0, -1}, {2, 0, -1}}, {-1, -1}),
        MakeInputsTx(8, {{9, 0, -1}, {5, 1, -1}}, {-1, -1}),
        MakeInputsTx(9, {{7, 1, -1}, {8, 1, -1}}, {-1}),
    };
    f.ConnectBlock(block3);
    BOOST_CHECK(f.ByTxNum(2) == Entries({SB(0, 7, 1)}));
    BOOST_CHECK(f.ByTxNum(4) == Entries({SB(0, 7, 0)}));
    BOOST_CHECK(f.ByTxNum(5) == Entries({SB(1, 8, 1)}));
    BOOST_CHECK(f.ByTxNum(6) == std::nullopt);
    BOOST_CHECK(f.ByTxNum(7) == Entries({SB(1, 9, 0)}));
    BOOST_CHECK(f.ByTxNum(8) == Entries({SB(1, 9, 1)}));
    BOOST_CHECK(f.ByTxNum(9) == Entries({SB(0, 8, 0)}));

    f.DisconnectBlock(block3);
    BOOST_CHECK(f.ByTxNum(0) ==
                Entries({SB(1, 5, 1), SB(2, 4, 0), SB(3, 2, 0)}));
    BOOST_CHECK(f.ByTxNum(1) == Entries({SB(0, 4, 1), SB(1, 5, 0)}));
    for (TxNum tx_num = 2; tx_num <= 9; ++tx_num) {
        if (tx_num == 3) {
            continue;
        }
        BOOST_CHECK(f.ByTxNum(tx_num) == std::nullopt);
    }

    // failed connect: duplicate entry
    const std::vector<Tx> block_duplicate_spend = {
        MakeInputsTx(10, {{0x00, UINT32_MAX, -1}}, {}),
        MakeInputsTx(11, {{0, 1, -1}}, {}),
    };
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.ConnectBlock(block_duplicate_spend); }),
        "Inconsistent DB: Duplicate spend by entry for tx_num = 0: "
        "SpentByEntry { out_idx: 1, tx_num: 5, input_idx: 1 } already exists, "
        "but tried to add SpentByEntry { out_idx: 1, tx_num: 7, input_idx: 0 "
        "}");

    // Ensure failed connect didn't have any side-effects on spent-by data
    BOOST_CHECK(f.ByTxNum(0) ==
                Entries({SB(1, 5, 1), SB(2, 4, 0), SB(3, 2, 0)}));
    BOOST_CHECK(f.ByTxNum(1) == Entries({SB(0, 4, 1), SB(1, 5, 0)}));

    // Undo side effects introduced by failed connect
    f.DisconnectBlock({
        MakeInputsTx(10, {{0x00, UINT32_MAX, -1}}, {}),
        // Note the missing input values
        MakeInputsTx(11, {}, {}),
    });

    // failed disconnect: mismatched entry
    const std::vector<Tx> block_mismatched_spend = {
        MakeInputsTx(3, {{0x00, UINT32_MAX, -1}}, {}),
        MakeInputsTx(4, {{0, 1, -1}}, {}),
    };
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.DisconnectBlock(block_mismatched_spend); }),
        "Inconsistent DB: Mismatched spend by entry for tx_num = 0: Expected "
        "SpentByEntry { out_idx: 1, tx_num: 4, input_idx: 0 } to be present, "
        "but got SpentByEntry { out_idx: 1, tx_num: 5, input_idx: 1 }");

    // failed disconnect: missing entry
    const std::vector<Tx> block_missing_spend = {
        MakeInputsTx(3, {{0x00, UINT32_MAX, -1}}, {}),
        MakeInputsTx(4, {{3, 1, -1}}, {}),
    };
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.DisconnectBlock(block_missing_spend); }),
        "Inconsistent DB: Missing spend by entry for tx_num = 3: Expected "
        "SpentByEntry { out_idx: 1, tx_num: 4, input_idx: 0 } to be present, "
        "but none found");

    // disconnect blocks
    f.DisconnectBlock(block2);
    BOOST_CHECK(f.ByTxNum(0) == Entries({SB(3, 2, 0)}));
    for (TxNum tx_num = 1; tx_num <= 5; ++tx_num) {
        BOOST_CHECK(f.ByTxNum(tx_num) == std::nullopt);
    }

    f.DisconnectBlock(block1);
    for (TxNum tx_num = 0; tx_num <= 3; ++tx_num) {
        BOOST_CHECK(f.ByTxNum(tx_num) == std::nullopt);
    }

    f.DisconnectBlock(block0);
    BOOST_CHECK(f.ByTxNum(0) == std::nullopt);
    BOOST_CHECK(f.ByTxNum(1) == std::nullopt);

    ErrorMsg([] { merge::CheckForErrors(); });
}

BOOST_AUTO_TEST_SUITE_END()
