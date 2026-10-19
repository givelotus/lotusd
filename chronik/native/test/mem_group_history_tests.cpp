// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db mem/group_history.rs tests, plus the member hash index.

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/mem/group_history.h>

#include <test/index_test_util.h>
#include <test/index_value_group.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::mem;
using chronik::native::test::MakeValueTx;
using chronik::native::test::SerValue;
using chronik::native::test::TxIdNum;
using chronik::native::test::ValueGroup;

namespace {

using HistoryVec = std::optional<std::vector<std::pair<int64_t, TxId>>>;

MempoolTx MakeMempoolTx(uint8_t txid_num,
                        const std::vector<int64_t> &input_values,
                        const std::vector<int64_t> &output_values,
                        int64_t time_first_seen) {
    return MempoolTx{std::make_shared<const Tx>(MakeValueTx(
                         txid_num, input_values, output_values)),
                     time_first_seen};
}

} // namespace

BOOST_AUTO_TEST_SUITE(mem_group_history_tests)

BOOST_AUTO_TEST_CASE(test_mempool_group_history) {
    const ValueGroup value_group;
    MempoolGroupHistory mempool(value_group);
    auto member_history = [&](int64_t val) -> HistoryVec {
        const MempoolGroupHistory::History *history =
            mempool.MemberHistory(SerValue(val));
        if (!history) {
            return std::nullopt;
        }
        return std::vector<std::pair<int64_t, TxId>>(history->begin(),
                                                     history->end());
    };
    using V = std::vector<std::pair<int64_t, TxId>>;

    const MempoolTx tx1 = MakeMempoolTx(1, {10}, {}, 1000);
    mempool.Insert(tx1, nullptr);
    BOOST_CHECK(member_history(10) == V({{1000, TxIdNum(1)}}));

    mempool.Remove(tx1, nullptr);
    BOOST_CHECK(member_history(10) == std::nullopt);

    const MempoolTx tx2 = MakeMempoolTx(2, {}, {10}, 900);
    mempool.Insert(tx1, nullptr);
    mempool.Insert(tx2, nullptr);
    BOOST_CHECK(member_history(10) ==
                V({{900, TxIdNum(2)}, {1000, TxIdNum(1)}}));

    const MempoolTx tx4 = MakeMempoolTx(4, {10}, {10}, 1000);
    mempool.Insert(tx4, nullptr);
    BOOST_CHECK(member_history(10) == V({{900, TxIdNum(2)},
                                         {1000, TxIdNum(1)},
                                         {1000, TxIdNum(4)}}));

    const MempoolTx tx3 = MakeMempoolTx(3, {10, 10}, {10, 20}, 1000);
    mempool.Insert(tx3, nullptr);
    BOOST_CHECK(member_history(10) == V({{900, TxIdNum(2)},
                                         {1000, TxIdNum(1)},
                                         {1000, TxIdNum(3)},
                                         {1000, TxIdNum(4)}}));
    BOOST_CHECK(member_history(20) == V({{1000, TxIdNum(3)}}));

    mempool.Remove(tx4, nullptr);
    mempool.Remove(tx1, nullptr);
    mempool.Remove(tx3, nullptr);
    BOOST_CHECK(member_history(10) == V({{900, TxIdNum(2)}}));
    BOOST_CHECK(member_history(20) == std::nullopt);
}

BOOST_AUTO_TEST_CASE(test_mempool_script_member_hash) {
    const groups::ScriptGroup script_group(
        [](ByteView data, uint8_t out[32]) { test::TestSha256(data, out); });
    MempoolGroupHistory mempool(script_group);
    Tx tx = MakeValueTx(1, {}, {5});
    tx.outputs[0].script = {0x51};
    const MempoolTx mempool_tx{std::make_shared<const Tx>(tx), 0};
    const auto hash = script_group.SerHashMember(Bytes{0x51});

    mempool.Insert(mempool_tx, nullptr);
    const std::optional<ByteView> member_ser =
        mempool.MemberSerByMemberHash(hash);
    BOOST_REQUIRE(member_ser);
    BOOST_CHECK(Bytes(member_ser->begin(), member_ser->end()) ==
                CompressScript(Bytes{0x51}));
    mempool.Remove(mempool_tx, nullptr);
    BOOST_CHECK(!mempool.MemberSerByMemberHash(hash));
    BOOST_CHECK(mempool.All().empty());

    // Non-script groups have no member hash index
    const ValueGroup value_group;
    MempoolGroupHistory value_mempool(value_group);
    value_mempool.Insert(mempool_tx, nullptr);
    BOOST_CHECK(!value_mempool.MemberSerByMemberHash(hash));
}

BOOST_AUTO_TEST_SUITE_END()
