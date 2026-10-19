// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the Mempool (mem/mempool.rs has no Rust tests): group indexes,
// errors and the token hook.

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/mem/mempool.h>

#include <test/index_test_util.h>
#include <test/index_value_group.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::mem;
using chronik::native::test::ErrorMsg;
using chronik::native::test::MakeInputsTx;
using chronik::native::test::TestDb;
using chronik::native::test::TxIdNum;

namespace {

std::shared_ptr<const GroupDef> MakeScriptGroup() {
    return std::make_shared<groups::ScriptGroup>(
        [](ByteView data, uint8_t out[32]) { test::TestSha256(data, out); });
}

MempoolTx MakeTx(uint8_t txid_num,
                 const std::vector<std::pair<uint8_t, uint32_t>> &inputs,
                 const std::vector<Bytes> &output_scripts,
                 int64_t time_first_seen = 0,
                 const Bytes &input_script = {0x51}) {
    std::vector<std::tuple<uint8_t, uint32_t, int64_t>> input_values;
    for (const auto &[input_txid_num, out_idx] : inputs) {
        input_values.emplace_back(input_txid_num, out_idx, 1);
    }
    Tx tx = MakeInputsTx(txid_num, input_values,
                         std::vector<int64_t>(output_scripts.size(), 1));
    for (size_t i = 0; i < output_scripts.size(); ++i) {
        tx.outputs[i].script = output_scripts[i];
    }
    for (TxInput &input : tx.inputs) {
        input.coin->output.script = input_script;
    }
    return MempoolTx{std::make_shared<const Tx>(std::move(tx)),
                     time_first_seen};
}

struct TestAux : GroupAux {
    std::vector<int64_t> values;
};

/** Token ID group stand-in: members from TestAux (output values). */
class AuxValueGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "AuxValueGroup"; }
    void InputMembers(const GroupQuery &, const GroupAux *,
                      std::vector<MemberItem> &) const override {}
    void OutputMembers(const GroupQuery &, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override {
        const auto *test_aux = dynamic_cast<const TestAux *>(aux);
        if (!test_aux) {
            return;
        }
        for (size_t idx = 0; idx < test_aux->values.size(); ++idx) {
            out.push_back(
                MemberItem{idx, test::SerValue(test_aux->values[idx])});
        }
    }
    Bytes SerMember(ByteView member) const override {
        return Bytes(member.begin(), member.end());
    }
    std::optional<GroupHistoryConf> TxHistoryConf() const override {
        return GroupHistoryConf{"aux_history", "aux_history_num_txs", 4,
                                std::nullopt};
    }
    std::optional<GroupUtxoConf> UtxoConf() const override {
        return GroupUtxoConf{"aux_utxo"};
    }
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Output; }
};

struct TestTokenHook final : MempoolTokenHook {
    AuxValueGroup group;
    std::vector<std::string> *calls;
    explicit TestTokenHook(std::vector<std::string> *calls_) : calls(calls_) {}

    const GroupDef &TokenIdGroup() const override { return group; }
    void Insert(const KvStore &, const MempoolTx &tx,
                const IsMempoolTxFn &is_mempool_tx) override {
        calls->push_back("insert " + std::to_string(tx.tx->txid.b[0]) +
                         (is_mempool_tx(tx.tx->txid) ? " in" : " out"));
    }
    std::shared_ptr<const GroupAux> AuxFromMempool(const Tx &tx) override {
        calls->push_back("aux " + std::to_string(tx.txid.b[0]));
        auto aux = std::make_shared<TestAux>();
        aux->values = {tx.txid.b[0]};
        return aux;
    }
    void Remove(const TxId &txid) override {
        calls->push_back("remove " + std::to_string(txid.b[0]));
    }
    std::shared_ptr<const GroupAux>
    Probe(const KvStore &, const MempoolTx &tx,
          const IsMempoolTxFn &) const override {
        calls->push_back("probe " + std::to_string(tx.tx->txid.b[0]));
        return nullptr;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(mem_mempool_tests)

BOOST_AUTO_TEST_CASE(test_mempool_insert_remove) {
    TestDb db("mempool");
    Mempool mempool(MakeScriptGroup(), false, true);
    const Bytes p2sh = {0xa9, 0x14};
    const Bytes opreturn = {0x6a, 0x04, 'A', 'B', 'C', 'D'};

    // LOKAD IDs are parsed from the first output
    const MempoolTx tx1 = MakeTx(1, {{20, 0}}, {opreturn, p2sh}, 100);
    const MempoolResult result = mempool.Insert(*db, tx1);
    BOOST_CHECK(result.mempool_tx.tx == tx1.tx);
    BOOST_CHECK(!result.token_id_aux);
    BOOST_CHECK(mempool.GetTx(TxIdNum(1)) != nullptr);
    BOOST_CHECK(mempool.ScriptHistory().MemberHistory(CompressScript(p2sh)));
    BOOST_CHECK(mempool.ScriptHistory().MemberHistory(
        CompressScript(Bytes{0x51})));
    BOOST_CHECK(mempool.ScriptUtxos().GetUtxos(CompressScript(p2sh)));
    BOOST_CHECK(mempool.SpentBy().OutputsSpent(TxIdNum(20)));
    BOOST_CHECK(mempool.LokadIdHistory().MemberHistory(
        Bytes{'A', 'B', 'C', 'D'}));
    BOOST_CHECK(!mempool.TokenIdHistory());

    // Child spending the mempool output
    const MempoolTx tx2 = MakeTx(2, {{1, 1}}, {p2sh}, 200, p2sh);
    mempool.Insert(*db, tx2);
    const auto *utxos = mempool.ScriptUtxos().GetUtxos(CompressScript(p2sh));
    BOOST_REQUIRE(utxos);
    BOOST_CHECK(*utxos == (std::set<OutPoint>{{TxIdNum(2), 0}}));

    // Duplicate tx: the UTXO index fails first, like Rust
    BOOST_CHECK(ErrorMsg([&] { mempool.Insert(*db, tx2); }) !=
                "<no exception>");

    std::string hex1;
    for (int i = 0; i < 32; ++i) {
        hex1 += "07";
    }
    BOOST_CHECK_EQUAL(ErrorMsg([&] { mempool.Remove(TxIdNum(7)); }),
                      "No such mempool tx: " + hex1);

    // Remove child, then mine parent
    mempool.Remove(TxIdNum(2));
    BOOST_CHECK(*mempool.ScriptUtxos().GetUtxos(CompressScript(p2sh)) ==
                (std::set<OutPoint>{{TxIdNum(1), 1}}));
    const std::optional<MempoolTx> mined = mempool.RemoveMined(TxIdNum(1));
    BOOST_REQUIRE(mined);
    BOOST_CHECK(mined->tx == tx1.tx);
    BOOST_CHECK(!mempool.RemoveMined(TxIdNum(1)));
    BOOST_CHECK(mempool.Txs().empty());
    BOOST_CHECK(mempool.ScriptHistory().All().empty());
    BOOST_CHECK(mempool.ScriptUtxos().All().empty());
    BOOST_CHECK(mempool.SpentBy().All().empty());
    BOOST_CHECK(mempool.LokadIdHistory().All().empty());
}

BOOST_AUTO_TEST_CASE(test_mempool_duplicate_tx) {
    TestDb db("mempool_dup");
    Mempool mempool(MakeScriptGroup(), false, false);
    // No inputs, no outputs: only the tx map detects the duplicate
    const MempoolTx tx = MakeTx(3, {}, {});
    mempool.Insert(*db, tx);
    std::string hex;
    for (int i = 0; i < 32; ++i) {
        hex += "03";
    }
    BOOST_CHECK_EQUAL(ErrorMsg([&] { mempool.Insert(*db, tx); }),
                      "Tx " + hex + " already exists in mempool");
    // LOKAD ID index disabled
    const MempoolTx tx_lokad = MakeTx(4, {}, {{0x6a, 0x04, 'A', 'B', 'C', 'D'}});
    mempool.Insert(*db, tx_lokad);
    BOOST_CHECK(mempool.LokadIdHistory().All().empty());
}

BOOST_AUTO_TEST_CASE(test_mempool_token_hook) {
    TestDb db("mempool_tokens");
    std::vector<std::string> calls;
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { Mempool(MakeScriptGroup(), true, false); }),
        "Token index enabled, but no mempool token hook given");
    Mempool mempool(MakeScriptGroup(), true, false,
                    std::make_unique<TestTokenHook>(&calls));
    const MempoolTx tx = MakeTx(5, {}, {{0x51}}, 10);
    const MempoolResult result = mempool.Insert(*db, tx);
    BOOST_CHECK(result.token_id_aux != nullptr);
    BOOST_REQUIRE(mempool.TokenIdHistory());
    BOOST_CHECK(mempool.TokenIdHistory()->MemberHistory(test::SerValue(5)));
    BOOST_CHECK(mempool.TokenIdUtxos()->GetUtxos(test::SerValue(5)));

    mempool.ProbeTx(*db, MakeTx(6, {}, {}));
    mempool.Remove(TxIdNum(5));
    BOOST_CHECK(mempool.TokenIdHistory()->All().empty());
    BOOST_CHECK(mempool.TokenIdUtxos()->All().empty());

    mempool.Insert(*db, tx);
    mempool.RemoveMined(TxIdNum(5));
    BOOST_CHECK(mempool.TokenIdUtxos()->All().empty());
    BOOST_CHECK(calls == (std::vector<std::string>{
                             "insert 5 out", "aux 5", "probe 6", "aux 5",
                             "remove 5", "insert 5 out", "aux 5", "aux 5",
                             "remove 5"}));
}

BOOST_AUTO_TEST_SUITE_END()
