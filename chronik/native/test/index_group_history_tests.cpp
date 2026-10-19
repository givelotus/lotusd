// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/group_history.rs tests, plus member hash index and
// error checks.

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/merge.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/schema.h>

#include <test/index_test_util.h>
#include <test/index_value_group.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeValueTx;
using chronik::native::test::SerValue;
using chronik::native::test::TestDb;
using chronik::native::test::ValueGroup;

namespace {

using Page = std::optional<std::vector<TxNum>>;
using PagesAndTxs = std::pair<size_t, size_t>;

Page P(std::vector<TxNum> tx_nums) {
    return tx_nums;
}

PagesAndTxs PT(size_t num_pages, size_t num_txs) {
    return {num_pages, num_txs};
}

/** connect_block/disconnect_block of the Rust test, for any group. */
struct Fixture {
    TestDb db;
    const GroupDef &group;
    TxWriter tx_writer{*db};
    GroupHistoryWriter group_writer{*db, group};
    GroupHistoryMemData mem_data;
    TxsMemData txs_mem_data;
    BlockHeight block_height = -1;

    Fixture(const std::string &name, const GroupDef &group_)
        : db(name, test::ExtraGroupTables(group_)), group(group_) {}

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
        auto txn = db->BeginWrite();
        ++block_height;
        const TxNum first_tx_num =
            tx_writer.Insert(*txn, TxsBatch(txs), txs_mem_data);
        const std::vector<IndexTx> index_txs =
            PrepareIndexedTxs(*db, *txn, first_tx_num, txs);
        group_writer.Insert(*txn, index_txs, nullptr, mem_data);
        txn->Commit();
    }

    void DisconnectBlock(const std::vector<Tx> &txs) {
        auto txn = db->BeginWrite();
        const TxNum first_tx_num =
            tx_writer.Delete(*txn, TxsBatch(txs), txs_mem_data);
        const std::vector<IndexTx> index_txs =
            PrepareIndexedTxs(*db, *txn, first_tx_num, txs);
        group_writer.Delete(*txn, index_txs, nullptr, mem_data);
        txn->Commit();
        --block_height;
    }

    Page ReadPage(ByteView member_ser, PageNum page_num) {
        auto txn = db->BeginRead();
        return GroupHistoryReader(*db, *txn, group)
            .PageTxs(member_ser, page_num);
    }

    PagesAndTxs ReadNumPagesAndTxs(ByteView member_ser) {
        auto txn = db->BeginRead();
        return GroupHistoryReader(*db, *txn, group)
            .MemberNumPagesAndTxs(member_ser);
    }
};

/** Constructed before Fixture, which uses the group. */
struct ValueGroupHolder {
    ValueGroup value_group;
};

struct ValueFixture : ValueGroupHolder, Fixture {
    ValueFixture() : Fixture("group_history", value_group) {}
    Page ReadPage(int64_t val, PageNum page_num) {
        return Fixture::ReadPage(SerValue(val), page_num);
    }
    PagesAndTxs ReadNumPagesAndTxs(int64_t val) {
        return Fixture::ReadNumPagesAndTxs(SerValue(val));
    }
};

Sha256Fn TestSha() {
    return [](ByteView data, uint8_t out[32]) { test::TestSha256(data, out); };
}

Tx ScriptTx(uint8_t txid_num, const std::vector<Bytes> &input_scripts,
            const std::vector<Bytes> &output_scripts) {
    std::vector<std::tuple<uint8_t, uint32_t, int64_t>> inputs;
    for (size_t i = 0; i < input_scripts.size(); ++i) {
        inputs.emplace_back(txid_num - 1, uint32_t(i), 1);
    }
    Tx tx = test::MakeInputsTx(txid_num, inputs,
                               std::vector<int64_t>(output_scripts.size(), 1));
    for (size_t i = 0; i < input_scripts.size(); ++i) {
        tx.inputs[i].coin->output.script = input_scripts[i];
    }
    for (size_t i = 0; i < output_scripts.size(); ++i) {
        tx.outputs[i].script = output_scripts[i];
    }
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(index_group_history_tests)

BOOST_AUTO_TEST_CASE(test_value_group_history) {
    ValueFixture f;

    // Only adds an entry for value=10 (coinbase inputs are ignored)
    const std::vector<Tx> block0 = {MakeValueTx(0, {0xffff}, {10})};
    f.ConnectBlock(block0);
    BOOST_CHECK(f.ReadPage(0xffff, 0) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(0xffff) == PT(0, 0));

    BOOST_CHECK(f.ReadPage(10, 0) == P({0}));
    BOOST_CHECK(f.ReadNumPagesAndTxs(10) == PT(1, 1));

    // Block that adds a lot of pages to value=10, one entry to value=20
    const std::vector<Tx> block1 = {
        MakeValueTx(1, {0xffff}, {10}),
        MakeValueTx(2, {10}, {}),
        MakeValueTx(3, {20}, {}), // value=20
        MakeValueTx(4, {10}, {}),
        MakeValueTx(5, {10}, {}),
        MakeValueTx(6, {10}, {}),
        MakeValueTx(7, {10}, {}),
        MakeValueTx(8, {10}, {}),
        MakeValueTx(9, {10}, {}),
    };
    f.ConnectBlock(block1);
    BOOST_CHECK(f.ReadPage(0xffff, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0, 1, 2, 4}));
    BOOST_CHECK(f.ReadPage(10, 1) == P({5, 6, 7, 8}));
    BOOST_CHECK(f.ReadPage(10, 2) == P({9}));
    BOOST_CHECK(f.ReadPage(10, 3) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(10) == PT(3, 9));

    BOOST_CHECK(f.ReadPage(20, 0) == P({3}));
    BOOST_CHECK(f.ReadPage(20, 1) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(20) == PT(1, 1));

    // Only tx_num=0 remains
    // The other pages have been removed from the DB entirely
    f.DisconnectBlock(block1);
    BOOST_CHECK(f.ReadPage(0xffff, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0}));
    BOOST_CHECK(f.ReadPage(10, 1) == std::nullopt);
    BOOST_CHECK(f.ReadPage(10, 2) == std::nullopt);
    BOOST_CHECK(f.ReadPage(20, 0) == std::nullopt);

    // Re-org block, with all kinds of input + output values
    const std::vector<Tx> block1b = {
        MakeValueTx(1, {0xffff}, {10}),
        MakeValueTx(2, {10}, {10, 20, 30}),
        MakeValueTx(3, {10, 40}, {10, 10, 40}),
        MakeValueTx(4, {10}, {40, 30, 40}),
    };
    f.ConnectBlock(block1b);
    // all txs add to value=10, with 2 pages
    BOOST_CHECK(f.ReadPage(10, 0) == P({0, 1, 2, 3}));
    BOOST_CHECK(f.ReadPage(10, 1) == P({4}));
    BOOST_CHECK(f.ReadNumPagesAndTxs(10) == PT(2, 5));
    // only tx_num=2 adds to value=20
    BOOST_CHECK(f.ReadPage(20, 0) == P({2}));
    BOOST_CHECK(f.ReadNumPagesAndTxs(20) == PT(1, 1));
    // tx_num=2 and tx_num=4 add to value=30
    BOOST_CHECK(f.ReadPage(30, 0) == P({2, 4}));
    BOOST_CHECK(f.ReadNumPagesAndTxs(30) == PT(1, 2));
    // tx_num=3 and tx_num=4 add to value=40
    BOOST_CHECK(f.ReadPage(40, 0) == P({3, 4}));
    BOOST_CHECK(f.ReadNumPagesAndTxs(40) == PT(1, 2));

    // Delete that block also
    f.DisconnectBlock(block1b);
    BOOST_CHECK(f.ReadPage(0xffff, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0}));
    BOOST_CHECK(f.ReadPage(10, 1) == std::nullopt);
    BOOST_CHECK(f.ReadPage(20, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(30, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(40, 0) == std::nullopt);

    // Add it back in
    f.ConnectBlock(block1b);
    // Add new block, adding 1 tx to 20, 6 txs to 30, 4 txs to 40
    const std::vector<Tx> block2 = {
        MakeValueTx(5, {0xffff}, {40, 30}),
        MakeValueTx(6, {30, 10}, {30}),
        MakeValueTx(7, {10}, {30}),
        MakeValueTx(8, {40}, {30}),
        MakeValueTx(9, {10}, {20}),
    };
    f.ConnectBlock(block2);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0, 1, 2, 3}));
    BOOST_CHECK(f.ReadPage(10, 1) == P({4, 6, 7, 9}));
    BOOST_CHECK(f.ReadPage(10, 2) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(10) == PT(2, 8));

    BOOST_CHECK(f.ReadPage(20, 0) == P({2, 9}));
    BOOST_CHECK(f.ReadPage(20, 1) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(20) == PT(1, 2));

    BOOST_CHECK(f.ReadPage(30, 0) == P({2, 4, 5, 6}));
    BOOST_CHECK(f.ReadPage(30, 1) == P({7, 8}));
    BOOST_CHECK(f.ReadPage(30, 2) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(30) == PT(2, 6));

    BOOST_CHECK(f.ReadPage(40, 0) == P({3, 4, 5, 8}));
    BOOST_CHECK(f.ReadPage(40, 1) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(40) == PT(1, 4));

    // Remove all blocks
    f.DisconnectBlock(block2);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0, 1, 2, 3}));
    BOOST_CHECK(f.ReadPage(10, 1) == P({4}));
    BOOST_CHECK(f.ReadPage(20, 0) == P({2}));
    BOOST_CHECK(f.ReadPage(30, 0) == P({2, 4}));
    BOOST_CHECK(f.ReadPage(30, 1) == std::nullopt);
    BOOST_CHECK(f.ReadPage(40, 0) == P({3, 4}));
    BOOST_CHECK(f.ReadPage(40, 1) == std::nullopt);

    f.DisconnectBlock(block1b);
    BOOST_CHECK(f.ReadPage(10, 0) == P({0}));
    BOOST_CHECK(f.ReadPage(10, 1) == std::nullopt);
    BOOST_CHECK(f.ReadPage(20, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(30, 0) == std::nullopt);
    BOOST_CHECK(f.ReadPage(40, 0) == std::nullopt);

    f.DisconnectBlock(block0);
    BOOST_CHECK(f.ReadPage(10, 0) == std::nullopt);

    ErrorMsg([] { merge::CheckForErrors(); });
}

BOOST_AUTO_TEST_CASE(test_script_member_hash_index) {
    groups::ScriptGroup script_group(TestSha());
    Fixture f("group_history_scripthash", script_group);
    f.mem_data.is_member_hash_index_enabled = true;
    const Bytes script_a{0x51}, script_b{0x52, 0x53};
    const Bytes ser_a = CompressScript(script_a);
    const Bytes ser_b = CompressScript(script_b);

    auto member_ser_by_hash = [&](const Bytes &script) {
        auto txn = f.db->BeginRead();
        return GroupHistoryReader(*f.db, *txn, script_group)
            .MemberSerByMemberHash(script_group.SerHashMember(script));
    };

    const std::vector<Tx> block0 = {
        ScriptTx(0x10, {}, {script_a, Bytes{0x6a, 0x01}, script_b})};
    f.ConnectBlock(block0);
    BOOST_CHECK(f.ReadPage(ser_a, 0) == P({0}));
    BOOST_CHECK(f.ReadPage(ser_b, 0) == P({0}));
    BOOST_CHECK(member_ser_by_hash(script_a) == ser_a);
    BOOST_CHECK(member_ser_by_hash(script_b) == ser_b);
    BOOST_CHECK(member_ser_by_hash(Bytes{0x6a, 0x01}) == std::nullopt);

    // Spend script_a: it gains a tx, its hash entry stays
    const std::vector<Tx> block1 = {ScriptTx(0x20, {}, {}),
                                    ScriptTx(0x11, {script_a}, {})};
    f.ConnectBlock(block1);
    BOOST_CHECK(f.ReadPage(ser_a, 0) == P({0, 2}));
    f.DisconnectBlock(block1);
    BOOST_CHECK(member_ser_by_hash(script_a) == ser_a);

    // Fully removed members lose their hash entry
    f.DisconnectBlock(block0);
    BOOST_CHECK(member_ser_by_hash(script_a) == std::nullopt);
    BOOST_CHECK(member_ser_by_hash(script_b) == std::nullopt);

    // Reindex from num_txs
    f.mem_data.is_member_hash_index_enabled = false;
    f.ConnectBlock(block0);
    BOOST_CHECK(member_ser_by_hash(script_a) == std::nullopt);
    std::vector<std::string> logs;
    f.group_writer.ReindexMemberHash(
        *f.db, [](ByteView compressed) { return *DecompressScript(compressed); },
        [] { return false; },
        [&](const std::string &msg, bool) { logs.push_back(msg); });
    BOOST_CHECK(member_ser_by_hash(script_a) == ser_a);
    BOOST_CHECK(member_ser_by_hash(script_b) == ser_b);
    BOOST_REQUIRE_EQUAL(logs.size(), 3U);
    BOOST_CHECK_EQUAL(logs[0], "Writing Chronik scripthash index.\n");
    BOOST_CHECK_EQUAL(logs[1], "Upgraded 0 of 2 (estimated)\n");

    // Wipe the member hash index
    {
        auto txn = f.db->BeginWrite();
        f.group_writer.WipeMemberHash(*txn);
        txn->Commit();
    }
    BOOST_CHECK(member_ser_by_hash(script_a) == std::nullopt);

    // Shutdown requested: nothing written
    f.group_writer.ReindexMemberHash(
        *f.db, [](ByteView compressed) { return *DecompressScript(compressed); },
        [] { return true; }, [](const std::string &, bool) {});
    BOOST_CHECK(member_ser_by_hash(script_a) == std::nullopt);

    // Wipe the history
    {
        auto txn = f.db->BeginWrite();
        f.group_writer.Wipe(*txn);
        txn->Commit();
    }
    BOOST_CHECK(f.ReadPage(ser_a, 0) == std::nullopt);
    BOOST_CHECK(f.ReadNumPagesAndTxs(ser_a) == PT(0, 0));
}

BOOST_AUTO_TEST_CASE(test_group_history_errors) {
    ValueFixture f;
    {
        auto txn = f.db->BeginWrite();
        txn->Put(f.db->Table("value_history_num_txs"), SerValue(10),
                 Bytes{1, 2, 3});
        txn->Commit();
    }
    BOOST_CHECK_EQUAL(ErrorMsg([&] { f.ReadNumPagesAndTxs(10); }),
                      "Inconsistent DB: Bad num_txs size: [1, 2, 3]");
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.ConnectBlock({MakeValueTx(0, {}, {10})}); }),
        "Inconsistent DB: Bad num_txs size: [1, 2, 3]");

    // Non-script groups have no member hash table
    {
        auto txn = f.db->BeginRead();
        const GroupHistoryReader reader(*f.db, *txn, f.value_group);
        BOOST_CHECK_EQUAL(
            ErrorMsg([&] { reader.MemberSerByMemberHash({}); }),
            "Tried to access member hash db via non-script group");
    }
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.value_group.SerHashMember(SerValue(1)); }),
        "There is no use case for hashing ValueGroup");

    // Undecodable page
    {
        auto txn = f.db->BeginWrite();
        txn->Put(f.db->Table("value_history"),
                 KeyForMemberPage(SerValue(20), 0), Bytes{0x80});
        txn->Commit();
    }
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { f.ReadPage(20, 0); }),
        "Inconsistent DB: Cannot deserialize byte sequence as u64: Hit the "
        "end of buffer, expected more data. Byte sequence: 80");
    ErrorMsg([] { merge::CheckForErrors(); });
}

BOOST_AUTO_TEST_SUITE_END()
