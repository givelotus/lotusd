// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/group_utxos.rs tests, plus the Output dup encoding
// (used by token_id_utxo), prefix iteration and dup batch cancellation.

#include <chronik/native/index/group_utxos.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/schema.h>

#include <core/db/dump.h>

#include <test/index_test_util.h>
#include <test/index_value_group.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::SerValue;
using chronik::native::test::TestDb;
using chronik::native::test::ValueGroup;

namespace {

using Utxos = std::optional<std::vector<UtxoEntry>>;

UtxoEntry U(TxNum tx_num, uint32_t out_idx, int64_t value,
            Bytes script = {}) {
    return UtxoEntry{DbOutpoint{tx_num, out_idx}, value, std::move(script)};
}

/** ValueGroup, but with UtxoDataOutput into a variable-size dup table. */
class OutputValueGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "OutputValueGroup"; }
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override {
        m_value.InputMembers(query, aux, out);
    }
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override {
        m_value.OutputMembers(query, aux, out);
    }
    Bytes SerMember(ByteView member) const override {
        return m_value.SerMember(member);
    }
    std::optional<GroupHistoryConf> TxHistoryConf() const override {
        return std::nullopt;
    }
    std::optional<GroupUtxoConf> UtxoConf() const override {
        return GroupUtxoConf{"value_output_utxo"};
    }
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Output; }

private:
    ValueGroup m_value;
};

struct Fixture {
    TestDb db;
    const GroupDef &group;
    TxWriter tx_writer{*db};
    GroupUtxoWriter group_writer{*db, group};
    GroupUtxoMemData mem_data;
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

    Utxos ReadUtxos(int64_t val) {
        auto txn = db->BeginRead();
        return GroupUtxoReader(*db, *txn, group).Utxos(SerValue(val));
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(index_group_utxos_tests)

BOOST_AUTO_TEST_CASE(test_value_group_utxos) {
    ValueGroup value_group;
    Fixture f("group_utxos", value_group);

    const std::vector<Tx> block0 = {
        MakeInputsTx(0x01, {{0x00, UINT32_MAX, 0xffff}}, {100, 200})};
    f.ConnectBlock(block0);
    BOOST_CHECK(f.ReadUtxos(100) == Utxos({U(0, 0, 100)}));
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(0, 1, 200)}));

    const std::vector<Tx> block1 = {
        MakeInputsTx(0x02, {{0x00, UINT32_MAX, 0xffff}}, {200}),
        MakeInputsTx(0x03, {{0x01, 0, 100}}, {10, 20, 10}),
        MakeInputsTx(0x04, {{0x03, 0, 10}, {0x01, 1, 200}, {0x03, 1, 20}},
                     {200}),
    };
    f.ConnectBlock(block1);
    BOOST_CHECK(f.ReadUtxos(10) == Utxos({U(2, 2, 10)}));
    BOOST_CHECK(f.ReadUtxos(20) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(100) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(1, 0, 200), U(3, 0, 200)}));

    f.DisconnectBlock(block1);
    BOOST_CHECK(f.ReadUtxos(10) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(20) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(100) == Utxos({U(0, 0, 100)}));
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(0, 1, 200)}));

    // Reorg block
    const std::vector<Tx> block1b = {
        MakeInputsTx(0x02, {{0x00, UINT32_MAX, 0xffff}}, {200}),
        MakeInputsTx(0x10, {{0x01, 0, 100}}, {100, 200, 100}),
        MakeInputsTx(0x11, {{0x10, 0, 100}, {0x10, 1, 200}, {0x01, 1, 200}},
                     {200}),
        MakeInputsTx(0x12, {{0x11, 0, 200}}, {200}),
    };

    f.ConnectBlock(block1b);
    BOOST_CHECK(f.ReadUtxos(100) == Utxos({U(2, 2, 100)}));
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(1, 0, 200), U(4, 0, 200)}));

    f.DisconnectBlock(block1b);
    BOOST_CHECK(f.ReadUtxos(100) == Utxos({U(0, 0, 100)}));
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(0, 1, 200)}));

    f.DisconnectBlock(block0);
    BOOST_CHECK(f.ReadUtxos(100) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(200) == std::nullopt);
}

BOOST_AUTO_TEST_CASE(test_output_group_utxos) {
    OutputValueGroup group;
    Fixture f("group_utxos_output", group);

    Tx tx0 = MakeInputsTx(0x01, {{0x00, UINT32_MAX, 0xffff}}, {100, 200});
    tx0.outputs[0].script = {0x51};
    tx0.outputs[1].script = {0x76, 0xa9};
    f.ConnectBlock({tx0});
    BOOST_CHECK(f.ReadUtxos(100) == Utxos({U(0, 0, 100, {0x51})}));
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(0, 1, 200, {0x76, 0xa9})}));
    {
        // tx_num BE8 || out_idx BE4 || sats LE8 || script
        auto txn = f.db->BeginRead();
        const auto lines = db::DumpTableLines(
            *f.db, *txn, GroupTableSpecs(group).at(0));
        BOOST_REQUIRE_EQUAL(lines.size(), 2U);
        BOOST_CHECK_EQUAL(lines[0], "value_output_utxo\t0000000000000064\t"
                                    "0000000000000000000000006400000000000000"
                                    "51");
        BOOST_CHECK_EQUAL(lines[1], "value_output_utxo\t00000000000000c8\t"
                                    "000000000000000000000001c800000000000000"
                                    "76a9");
    }

    // Spend output 1 and re-create value 200 elsewhere; disconnect restores
    // the spent coin's script
    Tx tx1 = MakeInputsTx(0x02, {{0x00, UINT32_MAX, 0xffff}}, {});
    Tx tx2 = MakeInputsTx(0x03, {{0x01, 1, 200}}, {200});
    tx2.inputs[0].coin->output.script = {0x76, 0xa9};
    tx2.outputs[0].script = {0x52};
    f.ConnectBlock({tx1, tx2});
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(2, 0, 200, {0x52})}));
    f.DisconnectBlock({tx1, tx2});
    BOOST_CHECK(f.ReadUtxos(200) == Utxos({U(0, 1, 200, {0x76, 0xa9})}));
}

BOOST_AUTO_TEST_CASE(test_group_utxos_spent_in_same_block) {
    ValueGroup value_group;
    Fixture f("group_utxos_same_block", value_group);
    // Outputs created and spent within the block never reach the table
    const std::vector<Tx> block0 = {
        MakeInputsTx(0x01, {{0x00, UINT32_MAX, 0xffff}}, {100}),
        MakeInputsTx(0x02, {{0x01, 0, 100}}, {50}),
        MakeInputsTx(0x03, {{0x02, 0, 50}}, {25}),
    };
    f.ConnectBlock(block0);
    BOOST_CHECK(f.ReadUtxos(100) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(50) == std::nullopt);
    BOOST_CHECK(f.ReadUtxos(25) == Utxos({U(2, 0, 25)}));
    f.DisconnectBlock(block0);
    for (const int64_t val : {100, 50, 25}) {
        BOOST_CHECK(f.ReadUtxos(val) == std::nullopt);
    }
    auto txn = f.db->BeginRead();
    BOOST_CHECK(db::DumpTableLines(*f.db, *txn, GroupTableSpecs(value_group)
                                                    .back())
                    .empty());
}

BOOST_AUTO_TEST_CASE(test_group_utxos_prefix_and_errors) {
    ValueGroup value_group;
    Fixture f("group_utxos_prefix", value_group);
    f.ConnectBlock({MakeInputsTx(0x01, {{0x00, UINT32_MAX, 0xffff}},
                                 {0x0101, 0x0102, 0x0201, 0x0101})});
    auto txn = f.db->BeginRead();
    const GroupUtxoReader reader(*f.db, *txn, value_group);
    std::vector<std::pair<Bytes, std::vector<UtxoEntry>>> visited;
    auto collect = [&](ByteView member, std::vector<UtxoEntry> &&utxos) {
        visited.emplace_back(Bytes(member.begin(), member.end()),
                             std::move(utxos));
        return true;
    };
    const Bytes prefix = {0, 0, 0, 0, 0, 0, 1};
    reader.VisitPrefix(prefix, prefix, collect);
    BOOST_REQUIRE_EQUAL(visited.size(), 2U);
    BOOST_CHECK(visited[0].first == SerValue(0x0101));
    BOOST_CHECK(visited[0].second ==
                (std::vector<UtxoEntry>{U(0, 0, 0x0101), U(0, 3, 0x0101)}));
    BOOST_CHECK(visited[1].first == SerValue(0x0102));
    // Start after the first member
    visited.clear();
    reader.VisitPrefix(prefix, SerValue(0x0102), collect);
    BOOST_REQUIRE_EQUAL(visited.size(), 1U);
    BOOST_CHECK(visited[0].first == SerValue(0x0102));
    // Empty start begins at the first key
    visited.clear();
    reader.VisitPrefix({}, {}, collect);
    BOOST_CHECK_EQUAL(visited.size(), 3U);

    // Decode errors
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DecodeUtxoDup(UtxoDataKind::Value, Bytes(11, 0)); }),
        "Inconsistent DB: Cannot deserialize byte sequence as "
        "chronik_db::io::group_utxos::UtxoEntry<i64>: Hit the end of buffer, "
        "expected more data. Byte sequence: 0000000000000000000000");
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DecodeUtxoDup(UtxoDataKind::Value, Bytes(13, 0)); }),
        "Inconsistent DB: Cannot deserialize byte sequence as i64: Hit the "
        "end of buffer, expected more data. Byte sequence: "
        "00000000000000000000000000");
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DecodeUtxoDup(UtxoDataKind::Output, Bytes(19, 0)); }),
        "Inconsistent DB: Cannot deserialize byte sequence as (i64, "
        "bytes::bytes::Bytes): Hit the end of buffer, expected more data. "
        "Byte sequence: 00000000000000000000000000000000000000");
    BOOST_CHECK(DecodeUtxoDup(UtxoDataKind::Output, Bytes(20, 0)) ==
                U(0, 0, 0));

    // Groups without UTXOs
    class NoUtxoGroup final : public GroupDef {
    public:
        std::string_view Name() const override { return "NoUtxoGroup"; }
        void InputMembers(const GroupQuery &, const GroupAux *,
                          std::vector<MemberItem> &) const override {}
        void OutputMembers(const GroupQuery &, const GroupAux *,
                           std::vector<MemberItem> &) const override {}
        Bytes SerMember(ByteView m) const override {
            return Bytes(m.begin(), m.end());
        }
        std::optional<GroupHistoryConf> TxHistoryConf() const override {
            return std::nullopt;
        }
        std::optional<GroupUtxoConf> UtxoConf() const override {
            return std::nullopt;
        }
        UtxoDataKind UtxoData() const override {
            return UtxoDataKind::Output;
        }
    } no_utxo;
    BOOST_CHECK_EQUAL(ErrorMsg([&] { GroupUtxoWriter(*f.db, no_utxo); }),
                      "NoUtxoGroup should not be used to group UTXOs");
}

BOOST_AUTO_TEST_SUITE_END()
