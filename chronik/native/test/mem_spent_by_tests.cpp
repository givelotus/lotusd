// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db mem/spent_by.rs tests.

#include <chronik/native/mem/spent_by.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::mem;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::TxIdNum;

namespace {

/** Rust make_mempool_tx! (test/utxo.rs) */
MempoolTx MakeMempoolTx(uint8_t txid_num,
                        const std::vector<std::pair<uint8_t, uint32_t>> &inputs,
                        size_t num_outputs) {
    std::vector<std::tuple<uint8_t, uint32_t, int64_t>> input_values;
    for (const auto &[input_txid_num, out_idx] : inputs) {
        input_values.emplace_back(input_txid_num, out_idx, -1);
    }
    return MempoolTx{
        std::make_shared<const Tx>(MakeInputsTx(
            txid_num, input_values, std::vector<int64_t>(num_outputs, -1))),
        0};
}

using SB = std::vector<std::tuple<uint32_t, uint8_t, uint32_t>>;

/** spent_by!(out_idx -> (txid_num, input_idx), ...) */
MempoolSpentBy::Entries SpentByMap(const SB &entries) {
    MempoolSpentBy::Entries map;
    for (const auto &[out_idx, txid_num, input_idx] : entries) {
        map[out_idx] = SpentBy{TxIdNum(txid_num), input_idx};
    }
    return map;
}

bool OutputsEq(const MempoolSpentBy &mempool, uint8_t txid_num,
               const SB &entries) {
    const MempoolSpentBy::Entries *got = mempool.OutputsSpent(TxIdNum(txid_num));
    return got && *got == SpentByMap(entries);
}

std::string Hex32(uint8_t num) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 32; ++i) {
        out += digits[num >> 4];
        out += digits[num & 0xf];
    }
    return out;
}

std::string OutPointDebug(uint8_t txid_num, uint32_t out_idx) {
    return "OutPoint { txid: TxId(" + Hex32(txid_num) +
           "), out_idx: " + std::to_string(out_idx) + " }";
}

std::string SpentByDebug(uint8_t txid_num, uint32_t input_idx) {
    return "SpentBy { txid: TxId(" + Hex32(txid_num) +
           "), input_idx: " + std::to_string(input_idx) + " }";
}

} // namespace

BOOST_AUTO_TEST_SUITE(mem_spent_by_tests)

BOOST_AUTO_TEST_CASE(test_mempool_spent_by) {
    MempoolSpentBy mempool;

    // Add tx spending txid_num=10, out_idx=4
    const MempoolTx tx1 = MakeMempoolTx(1, {{10, 4}}, 1);
    mempool.Insert(tx1);
    BOOST_CHECK(OutputsEq(mempool, 10, {{4, 1, 0}}));

    // Remove tx -> no entries in MempoolSpentBy anymore
    mempool.Remove(tx1);
    BOOST_CHECK(mempool.All().empty());

    // Add tx again
    mempool.Insert(tx1);

    // Failed insert: Tx conflicts with existing tx
    const MempoolTx tx_conflict = MakeMempoolTx(2, {{0, 0}, {10, 4}}, 0);
    BOOST_CHECK_EQUAL(ErrorMsg([&] { mempool.Insert(tx_conflict); }),
                      "Inconsistent mempool: Duplicate spend by entry for " +
                          OutPointDebug(10, 4) + ": " + SpentByDebug(1, 0) +
                          " already exists, but tried to add " +
                          SpentByDebug(2, 1));

    // Failed remove: Output never spent in mempool
    const MempoolTx tx_missing = MakeMempoolTx(3, {{10, 3}}, 0);
    BOOST_CHECK_EQUAL(ErrorMsg([&] { mempool.Remove(tx_missing); }),
                      "Inconsistent mempool: Missing spend by entry for " +
                          OutPointDebug(10, 3) + ": Expected " +
                          SpentByDebug(3, 0) +
                          " to be present, but none found");

    // Failed remove: Output spent by a different tx
    const MempoolTx tx_mismatch = MakeMempoolTx(4, {{10, 4}}, 0);
    BOOST_CHECK_EQUAL(ErrorMsg([&] { mempool.Remove(tx_mismatch); }),
                      "Inconsistent mempool: Mismatched spent-by entry for " +
                          OutPointDebug(10, 4) + ": Expected " +
                          SpentByDebug(4, 0) + " to be present, but got " +
                          SpentByDebug(1, 0));

    // Add more spends to existing entries; also spend mempool tx
    const MempoolTx tx2 = MakeMempoolTx(5, {{10, 5}, {10, 3}, {1, 0}}, 0);
    mempool.Insert(tx2);
    BOOST_CHECK(OutputsEq(mempool, 10, {{3, 5, 1}, {4, 1, 0}, {5, 5, 0}}));
    BOOST_CHECK(OutputsEq(mempool, 1, {{0, 5, 2}}));

    // "Mine" first tx
    mempool.Remove(tx1);
    BOOST_CHECK(OutputsEq(mempool, 10, {{3, 5, 1}, {5, 5, 0}}));
    // The now mined tx is still marked as spent in the mempool
    BOOST_CHECK(OutputsEq(mempool, 1, {{0, 5, 2}}));

    // "Mine" dependent tx, now there no entries marked as spent in the
    // mempool anymore.
    mempool.Remove(tx2);
    BOOST_CHECK(mempool.OutputsSpent(TxIdNum(10)) == nullptr);
    BOOST_CHECK(mempool.OutputsSpent(TxIdNum(1)) == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
