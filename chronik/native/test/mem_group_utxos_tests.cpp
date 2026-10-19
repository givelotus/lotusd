// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db mem/group_utxos.rs tests, plus prefix iteration.

#include <chronik/native/mem/group_utxos.h>

#include <test/index_test_util.h>
#include <test/index_value_group.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::mem;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::SerValue;
using chronik::native::test::TxIdNum;
using chronik::native::test::ValueGroup;

namespace {

MempoolTx MakeMempoolTx(
    uint8_t txid_num,
    const std::vector<std::tuple<uint8_t, uint32_t, int64_t>> &input_values,
    const std::vector<int64_t> &output_values) {
    return MempoolTx{std::make_shared<const Tx>(MakeInputsTx(
                         txid_num, input_values, output_values)),
                     0};
}

MempoolGroupUtxos::Utxos
MakeOutpoints(const std::vector<std::pair<uint8_t, uint32_t>> &outpoints) {
    MempoolGroupUtxos::Utxos set;
    for (const auto &[txid_num, out_idx] : outpoints) {
        set.insert(OutPoint{TxIdNum(txid_num), out_idx});
    }
    return set;
}

bool IsMempoolTx(const TxId &txid) {
    return txid.b[0] < 10;
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

} // namespace

BOOST_AUTO_TEST_SUITE(mem_group_utxos_tests)

BOOST_AUTO_TEST_CASE(test_mempool_group_utxos) {
    const ValueGroup value_group;
    MempoolGroupUtxos mempool(value_group);
    auto utxos = [&](int64_t val) { return mempool.GetUtxos(SerValue(val)); };
    auto utxos_eq = [&](int64_t val, const MempoolGroupUtxos::Utxos &exp) {
        const MempoolGroupUtxos::Utxos *got = utxos(val);
        return got && *got == exp;
    };

    // spend a confirmed UTXO
    const MempoolTx tx1 = MakeMempoolTx(1, {{10, 4, 100}}, {101});
    mempool.Insert(tx1, IsMempoolTx, nullptr);
    BOOST_CHECK(utxos(100) == nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{1, 0}})));

    // adding again fails
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { mempool.Insert(tx1, IsMempoolTx, nullptr); }),
        "Inconsistent mempool: UTXO " + OutPointDebug(1, 0) +
            " already exists in mempool");

    // trying to spend a non-existent mempool UTXO fails
    for (const int64_t value : {
             999, // value=999 has no UTXO entries
             101, // value=101 has one entry but for txid=1, out_idx=0
         }) {
        BOOST_CHECK_EQUAL(ErrorMsg([&] {
                              mempool.Insert(
                                  MakeMempoolTx(3, {{2, 4, value}}, {}),
                                  IsMempoolTx, nullptr);
                          }),
                          "Inconsistent mempool: UTXO " +
                              OutPointDebug(2, 4) + " spent by " + Hex32(3) +
                              " doesn't exist in mempool");
    }

    // trying to remove a tx with non-existent outputs fails
    for (const int64_t value : {999, 101}) {
        BOOST_CHECK_EQUAL(
            ErrorMsg([&] {
                mempool.Remove(MakeMempoolTx(3, {}, {value}), IsMempoolTx,
                               nullptr);
            }),
            "Inconsistent mempool when removing tx: UTXO " +
                OutPointDebug(3, 0) + " doesn't exist in mempool");
    }

    // Removing tx1 results in an empty state
    mempool.Remove(tx1, IsMempoolTx, nullptr);
    BOOST_CHECK(mempool.All().empty());

    // Mining tx1 also results in an empty state
    mempool.Insert(tx1, IsMempoolTx, nullptr);
    mempool.RemoveMined(tx1, nullptr);
    BOOST_CHECK(mempool.All().empty());

    // Add back to mempool again
    mempool.Insert(tx1, IsMempoolTx, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{1, 0}})));

    const MempoolTx tx2 = MakeMempoolTx(2, {{1, 0, 101}}, {102, 101});
    mempool.Insert(tx2, IsMempoolTx, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{2, 1}})));
    BOOST_CHECK(utxos_eq(102, MakeOutpoints({{2, 0}})));

    // Removing tx2 restores tx1's outputs, and removes tx2's outputs
    mempool.Remove(tx2, IsMempoolTx, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{1, 0}})));
    BOOST_CHECK(utxos(102) == nullptr);

    // Trying to remove tx2 again fails
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { mempool.Remove(tx2, IsMempoolTx, nullptr); }),
        "Inconsistent mempool: UTXO " + OutPointDebug(1, 0) +
            " already unspent in mempool");

    // Add tx2 again
    mempool.Insert(tx2, IsMempoolTx, nullptr);

    // Add tx3
    const MempoolTx tx3 =
        MakeMempoolTx(3, {{2, 0, 102}, {11, 4, 101}}, {101});
    mempool.Insert(tx3, IsMempoolTx, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{2, 1}, {3, 0}})));
    BOOST_CHECK(utxos(102) == nullptr);

    // Mine tx1: leaves everything unchanged
    mempool.RemoveMined(tx1, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{2, 1}, {3, 0}})));
    BOOST_CHECK(utxos(102) == nullptr);

    // Mine tx2: removes its outputs
    mempool.RemoveMined(tx2, nullptr);
    BOOST_CHECK(utxos_eq(101, MakeOutpoints({{3, 0}})));
    BOOST_CHECK(utxos(102) == nullptr);

    // Mine tx3: results in an empty state
    mempool.RemoveMined(tx3, nullptr);
    BOOST_CHECK(mempool.All().empty());
}

BOOST_AUTO_TEST_CASE(test_mempool_group_utxos_prefix) {
    const ValueGroup value_group;
    MempoolGroupUtxos mempool(value_group);
    mempool.Insert(MakeMempoolTx(1, {}, {0x0101, 0x0102, 0x0201}),
                   IsMempoolTx, nullptr);
    std::vector<Bytes> visited;
    auto collect = [&](const Bytes &member, const MempoolGroupUtxos::Utxos &) {
        visited.push_back(member);
        return true;
    };
    const Bytes prefix = {0, 0, 0, 0, 0, 0, 1};
    mempool.VisitPrefix(prefix, prefix, collect);
    BOOST_CHECK(visited ==
                (std::vector<Bytes>{SerValue(0x0101), SerValue(0x0102)}));
    visited.clear();
    mempool.VisitPrefix(prefix, SerValue(0x0102), collect);
    BOOST_CHECK(visited == (std::vector<Bytes>{SerValue(0x0102)}));
    visited.clear();
    mempool.VisitPrefix({}, {}, [&](const Bytes &member, const auto &) {
        visited.push_back(member);
        return false;
    });
    BOOST_CHECK_EQUAL(visited.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
