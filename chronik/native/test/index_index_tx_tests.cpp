// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db index_tx.rs tests.

#include <chronik/native/index/index_tx.h>
#include <chronik/native/index/txs.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::TestDb;
using chronik::native::test::TxIdNum;

namespace {

Tx MakeTx(uint8_t txid_num, const std::vector<uint8_t> &input_txid_nums) {
    Tx tx;
    tx.txid = TxIdNum(txid_num);
    for (const uint8_t input_txid_num : input_txid_nums) {
        TxInput input;
        input.prev_out.txid = TxIdNum(input_txid_num);
        input.prev_out.out_idx = 0;
        tx.inputs.push_back(std::move(input));
    }
    return tx;
}

TxNum At(const TxNumCache::Bucket &bucket, const TxId &txid) {
    return bucket.at(txid);
}

} // namespace

BOOST_AUTO_TEST_SUITE(index_index_tx_tests)

BOOST_AUTO_TEST_CASE(test_prepare_indexed_txs) {
    TestDb db("indexed_txs");
    const TxWriter tx_writer(*db);
    TxsMemData txs_mem_data;
    std::vector<TxEntry> db_txs;
    for (uint8_t txid_num = 100; txid_num < 110; ++txid_num) {
        TxEntry entry;
        entry.txid = TxIdNum(txid_num);
        db_txs.push_back(entry);
    }
    const TxNum first_tx_num = db_txs.size();
    {
        auto txn = db->BeginWrite();
        tx_writer.Insert(*txn, BlockTxs{db_txs, 0}, txs_mem_data);
        txn->Commit();
    }

    const std::vector<Tx> new_txs = {
        MakeTx(110, {0}),
        MakeTx(111, {110, 100, 101}),
        MakeTx(112, {111, 109, 103}),
    };

    auto txn = db->BeginRead();
    const std::vector<IndexTx> index_txs =
        PrepareIndexedTxs(*db, *txn, first_tx_num, new_txs);
    const std::vector<IndexTx> expected = {
        IndexTx{&new_txs[0], 10, true, {}},
        IndexTx{&new_txs[1], 11, false, {10, 0, 1}},
        IndexTx{&new_txs[2], 12, false, {11, 9, 3}},
    };
    BOOST_CHECK(index_txs == expected);

    // An input that is neither in the DB nor in the block
    const std::vector<Tx> bad_txs = {MakeTx(120, {}), MakeTx(121, {99})};
    std::string txid_hex;
    for (int i = 0; i < 32; ++i) {
        txid_hex += "63";
    }
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { PrepareIndexedTxs(*db, *txn, first_tx_num, bad_txs); }),
        "Unknown input spent: OutPoint { txid: TxId(" + txid_hex +
            "), out_idx: 0 }");
}

BOOST_AUTO_TEST_CASE(test_prepare_indexed_txs_cached) {
    TestDb db("indexed_txs_cached");
    TxNumCache cache(TxNumCacheSettings{2, 10});
    const std::vector<Tx> block0 = {MakeTx(1, {}), MakeTx(2, {})};
    auto txn = db->BeginRead();
    const auto index0 = PrepareIndexedTxsCached(
        *db, *txn, 0, test::TxPtrs(block0), cache, PrepareUpdateMode::Add);
    BOOST_CHECK(cache.Get(TxIdNum(2)) == TxNum(1));
    // Inputs resolved from the cache, not the (empty) DB
    const std::vector<Tx> block1 = {MakeTx(3, {}), MakeTx(4, {2, 1})};
    const auto index1 = PrepareIndexedTxsCached(
        *db, *txn, 2, test::TxPtrs(block1), cache, PrepareUpdateMode::Read);
    BOOST_CHECK(index1[1].input_nums == (std::vector<TxNum>{1, 0}));
    BOOST_CHECK(cache.Get(TxIdNum(4)) == std::nullopt);
    // Delete clears the cache
    PrepareIndexedTxsCached(*db, *txn, 0, test::TxPtrs(block0), cache,
                            PrepareUpdateMode::Delete);
    BOOST_CHECK(cache.Get(TxIdNum(1)) == std::nullopt);
}

BOOST_AUTO_TEST_CASE(test_tx_num_cache) {
    std::vector<Tx> txs;
    for (uint8_t tx_num = 0; tx_num <= 10; ++tx_num) {
        txs.push_back(MakeTx(tx_num, {}));
    }
    std::vector<IndexTx> index_txs;
    for (size_t tx_num = 0; tx_num < txs.size(); ++tx_num) {
        index_txs.push_back(IndexTx{&txs[tx_num], tx_num, false, {}});
    }
    auto span = [&](size_t begin, size_t end) {
        return std::span<const IndexTx>(index_txs.data() + begin, end - begin);
    };
    TxNumCache cache(TxNumCacheSettings{2, 3});
    const auto &buckets = cache.Buckets();
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    for (const Tx &tx : txs) {
        BOOST_CHECK(cache.Get(tx.txid) == std::nullopt);
    }

    // Add the first tx
    cache.AddToCache(span(0, 1));
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 1U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[0].txid), 0U);
    BOOST_CHECK(cache.Get(txs[0].txid) == TxNum(0));

    // Add three more, filling the next bucket
    cache.AddToCache(span(1, 4));
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 1U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[3].txid), 3U);
    BOOST_CHECK_EQUAL(buckets[1].size(), 3U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[0].txid), 0U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[1].txid), 1U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[2].txid), 2U);
    for (const IndexTx &tx : span(0, 4)) {
        BOOST_CHECK(cache.Get(tx.tx->txid) == tx.tx_num);
    }

    // Add two more, filling the cache
    cache.AddToCache(span(4, 6));
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 3U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[3].txid), 3U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[4].txid), 4U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[5].txid), 5U);
    BOOST_CHECK_EQUAL(buckets[1].size(), 3U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[0].txid), 0U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[1].txid), 1U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[2].txid), 2U);
    for (const IndexTx &tx : span(0, 6)) {
        BOOST_CHECK(cache.Get(tx.tx->txid) == tx.tx_num);
    }

    // Adding one more empties the last bucket and moves it front
    cache.AddToCache(span(6, 7));
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 1U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[6].txid), 6U);
    BOOST_CHECK_EQUAL(buckets[1].size(), 3U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[3].txid), 3U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[4].txid), 4U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[5].txid), 5U);
    for (size_t i = 0; i < 3; ++i) {
        BOOST_CHECK(cache.Get(txs[i].txid) == std::nullopt);
    }
    for (const IndexTx &tx : span(3, 7)) {
        BOOST_CHECK(cache.Get(tx.tx->txid) == tx.tx_num);
    }

    // Adding three more again empties the last bucket and moves it front
    cache.AddToCache(span(7, 10));
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 1U);
    BOOST_CHECK_EQUAL(At(buckets[0], txs[9].txid), 9U);
    BOOST_CHECK_EQUAL(buckets[1].size(), 3U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[6].txid), 6U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[7].txid), 7U);
    BOOST_CHECK_EQUAL(At(buckets[1], txs[8].txid), 8U);
    for (size_t i = 0; i < 6; ++i) {
        BOOST_CHECK(cache.Get(txs[i].txid) == std::nullopt);
    }
    for (const IndexTx &tx : span(6, 10)) {
        BOOST_CHECK(cache.Get(tx.tx->txid) == tx.tx_num);
    }

    // Clearing the cache leaves the buckets allocated but empty
    // (Rust also checks HashMap::capacity() == 3, which has no
    // std::unordered_map equivalent)
    cache.Clear();
    BOOST_CHECK_EQUAL(buckets.size(), 2U);
    BOOST_CHECK_EQUAL(buckets[0].size(), 0U);
    BOOST_CHECK_EQUAL(buckets[1].size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
