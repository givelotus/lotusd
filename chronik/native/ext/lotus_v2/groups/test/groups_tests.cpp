// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-db groups/v2.rs test and of the legacy-index part of
// chronik-indexer indexer.rs test_v2_three_branch_and_asset_indexing_mdbx
// (the Rust mempool V2 group indexes, read only by Electrum, are not kept).

#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/indexer.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/subs.h>

#include <ext/lotus_v2/groups/groups.h>
#include <test/fake_host.h>
#include <test/index_test_util.h>
#include <test/test_backend.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>

using namespace chronik::native;
using namespace chronik::native::lotus_v2;
namespace th = chronik::native::testhost;
namespace nt = chronik::native::test;

namespace {

Hash32 Fill(uint8_t b) {
    Hash32 h;
    h.b.fill(b);
    return h;
}

Bytes B(const Hash32 &h) { return Bytes(h.b.begin(), h.b.end()); }

std::vector<MemberItem> Inputs(const GroupDef &g, const Tx &tx) {
    std::vector<MemberItem> out;
    g.InputMembers(GroupQuery{false, &tx}, nullptr, out);
    return out;
}

std::vector<MemberItem> Outputs(const GroupDef &g, const Tx &tx) {
    std::vector<MemberItem> out;
    g.OutputMembers(GroupQuery{false, &tx}, nullptr, out);
    return out;
}

const Hash32 kKey = Fill(0x11);
const Hash32 kScript = Fill(0x22);
const Hash32 kData = Fill(0x33);
const Hash32 kAsset = Fill(0xaa);

Bytes ThreeBranch(uint64_t value, bool data, bool burn = false,
                  Hash32 key = kKey) {
    V2ThreeBranchOutput out;
    out.key_branch = key;
    if (key == kKey) {
        out.script_branch = kScript;
    }
    if (data) {
        out.data_branch = kData;
    }
    out.asset_id = kAsset;
    out.value = value;
    out.is_burn = burn;
    auto script = out.ToScript();
    BOOST_REQUIRE(script);
    return *script;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_groups_tests)

BOOST_AUTO_TEST_CASE(test_v2_three_branch_and_asset_groups) {
    Tx tx;
    tx.txid.b.fill(1);
    tx.version = 7;
    TxInput in;
    in.coin = Coin{TxOutput{500, ThreeBranch(500, false)}, 0, false};
    tx.inputs.push_back(in);
    tx.outputs.push_back(TxOutput{300, ThreeBranch(300, true)});
    tx.outputs.push_back(
        TxOutput{200, ThreeBranch(200, false, true, Fill(0x99))});

    const V2BranchGroup branch;
    BOOST_CHECK(Inputs(branch, tx) ==
                (std::vector<MemberItem>{{0, B(kKey)}, {0, B(kScript)}}));
    BOOST_CHECK(Outputs(branch, tx) ==
                (std::vector<MemberItem>{
                    {0, B(kKey)}, {0, B(kScript)}, {0, B(kData)}}));
    BOOST_CHECK(TxMembersForGroup(branch, GroupQuery{false, &tx}, nullptr) ==
                (std::vector<Bytes>{B(kKey), B(kScript), B(kKey), B(kScript),
                                    B(kData)}));

    const V2AssetGroup asset;
    BOOST_CHECK(Inputs(asset, tx) ==
                (std::vector<MemberItem>{{0, B(kAsset)}}));
    BOOST_CHECK(Outputs(asset, tx) ==
                (std::vector<MemberItem>{{0, B(kAsset)}}));

    Tx legacy = tx;
    legacy.version = 2;
    legacy.inputs[0].coin->is_legacy = true;
    BOOST_CHECK(Inputs(branch, legacy).empty());
    BOOST_CHECK(Outputs(branch, legacy).empty());
    BOOST_CHECK(Inputs(asset, legacy).empty());
    BOOST_CHECK(Outputs(asset, legacy).empty());
    legacy.version = 7;
    BOOST_CHECK(Inputs(branch, legacy).empty());
    BOOST_CHECK(Inputs(asset, legacy).empty());
    BOOST_CHECK(!Outputs(branch, legacy).empty());

    // Coinbase txs have no input members
    std::vector<MemberItem> cb;
    branch.InputMembers(GroupQuery{true, &tx}, nullptr, cb);
    asset.InputMembers(GroupQuery{true, &tx}, nullptr, cb);
    BOOST_CHECK(cb.empty());
}

BOOST_AUTO_TEST_CASE(three_branch_output_shape) {
    V2ThreeBranchOutput out;
    out.key_branch = kKey;
    out.script_branch = kKey; // duplicates collapse
    out.data_branch = kData;
    out.asset_id = Hash32{}; // a zero asset ID is no token
    out.value = 7;
    Output v2 = out.ToV2Output();
    BOOST_CHECK(v2.branches == (std::vector<Hash32>{kKey, kData}));
    BOOST_CHECK(v2.paths == (std::vector<std::vector<uint8_t>>{{0}, {1}}));
    BOOST_CHECK_EQUAL(v2.flags, 0);
    out.is_burn = true;
    v2 = out.ToV2Output();
    BOOST_CHECK_EQUAL(v2.flags, 2);
    BOOST_CHECK(v2.paths.empty());
    BOOST_CHECK(out.ToScript());
}

BOOST_AUTO_TEST_CASE(decode_v2_output_script) {
    const Bytes frame = ThreeBranch(5, false);
    BOOST_CHECK(DecodeV2OutputScript(frame));
    Bytes op_return = {0x6a};
    op_return.insert(op_return.end(), frame.begin(), frame.end());
    BOOST_CHECK(DecodeV2OutputScript(op_return) ==
                DecodeV2OutputScript(frame));
    // Short or non-frame scripts are not V2 outputs
    Output tiny;
    tiny.branches = {kKey};
    tiny.paths = {{0}};
    const Bytes tiny_frame = *tiny.Encode();
    BOOST_REQUIRE_EQUAL(tiny_frame.size(), 45u);
    Bytes tiny_op_return = {0x6a};
    tiny_op_return.insert(tiny_op_return.end(), tiny_frame.begin(),
                          tiny_frame.end());
    BOOST_CHECK(DecodeV2OutputScript(tiny_op_return));
    tiny_op_return.resize(43);
    BOOST_CHECK(!DecodeV2OutputScript(tiny_op_return));
    BOOST_CHECK(!DecodeV2OutputScript(th::P2pkh(1)));
    BOOST_CHECK(!DecodeV2OutputScript({}));
    Bytes trailing = frame;
    trailing.push_back(0);
    BOOST_CHECK(!DecodeV2OutputScript(trailing));
}

BOOST_AUTO_TEST_CASE(test_v2_three_branch_and_asset_indexing) {
    nt::RegisterTestStores();
    th::FakeHost host;
    nt::IndexTempDir dir("lotus-v2-groups");
    std::filesystem::create_directories(dir.path);
    const Block genesis = host.MakeBlock(-1, {});
    host.Extend(genesis);
    const Tx &genesis_cb = *genesis.txs[0].tx;

    const Bytes v2_script = ThreeBranch(5000, true);
    Tx tx1;
    tx1.version = 7;
    TxInput in;
    in.prev_out.txid = genesis_cb.txid;
    in.coin = Coin{genesis_cb.outputs[0], 0, true};
    tx1.inputs.push_back(in);
    tx1.outputs = {TxOutput{5000, v2_script},
                   TxOutput{100, ThreeBranch(100, false, true, Fill(0x99))}};
    tx1.txid.b.fill(0x01);
    tx1.wire_size = 400;

    IndexerParams params;
    params.datadir_net = dir.path;
    params.backend = nt::TestBackend();
    params.token_index = false;
    std::vector<std::unique_ptr<Extension>> exts;
    auto owned = std::make_unique<LegacyGroupsExtension>();
    const LegacyGroupsExtension &ext = *owned;
    exts.push_back(std::move(owned));
    auto ix = Indexer::Open(host, params, std::move(exts));
    ix->Resync();

    SubsHub &hub = ix->Impl().Subs();
    BOOST_CHECK_EQUAL(hub.WsScriptTypes().size(), 3u);
    BOOST_REQUIRE(hub.FindWsScriptType("taproot", 32));
    BOOST_CHECK_EQUAL(hub.FindWsScriptType("taproot", 32)->group,
                      hub.FindWsScriptType("v2-branch", 32)->group);
    BOOST_CHECK(!hub.FindWsScriptType("v2-asset", 33));
    auto rx_branch =
        hub.Write()->SubsExt(hub.FindWsScriptType("v2-branch", 32)->group)
            .SubscribeToMember(B(kData));
    auto rx_asset =
        hub.Write()->SubsExt(hub.FindWsScriptType("v2-asset", 32)->group)
            .SubscribeToMember(B(kAsset));
    ix->OnTxAddedToMempool(std::make_shared<const Tx>(tx1), 1234);
    BOOST_CHECK_EQUAL(rx_branch.Len(), 1u);
    BOOST_CHECK_EQUAL(rx_asset.Len(), 1u);

    // Block 1: coinbase (tx_num 1), tx1 (tx_num 2)
    const Block block1 = host.MakeBlock(0, {tx1});
    host.Extend(block1);
    ix->OnBlockConnected(block1);
    // Block 2: coinbase (tx_num 3), spend of tx1:0 (tx_num 4)
    Tx tx2 = host.MakeSpend({{chronik::native::OutPoint{tx1.txid, 0},
                              Coin{TxOutput{5000, v2_script}, 1, false}}},
                            {TxOutput{4000, th::P2pkh(9)}});
    const Block block2 = host.MakeBlock(1, {tx2});
    host.Extend(block2);
    ix->OnBlockConnected(block2);

    const index::UtxoEntry utxo{{2, 0}, 5000, {}};
    {
        auto snap = ix->Impl().Snapshot();
        index::GroupHistoryReader branches(snap.Store(), snap.Txn(),
                                           ext.BranchGroup());
        index::GroupUtxoReader branch_utxos(snap.Store(), snap.Txn(),
                                            ext.BranchGroup());
        for (const Hash32 &branch : {kKey, kScript, kData}) {
            BOOST_CHECK(branches.PageTxs(B(branch), 0) ==
                        (std::vector<index::TxNum>{2, 4}));
            BOOST_CHECK(!branch_utxos.Utxos(B(branch)));
        }
        // The burn's root is not indexed
        BOOST_CHECK(!branches.PageTxs(B(Fill(0x99)), 0));
        index::GroupHistoryReader assets(snap.Store(), snap.Txn(),
                                         ext.AssetGroup());
        BOOST_CHECK(assets.PageTxs(B(kAsset), 0) ==
                    (std::vector<index::TxNum>{2, 4}));
    }

    // Disconnecting block 2 restores the UTXOs
    host.TruncateActive(1);
    ix->OnBlockDisconnected(block2);
    {
        auto snap = ix->Impl().Snapshot();
        index::GroupHistoryReader branches(snap.Store(), snap.Txn(),
                                           ext.BranchGroup());
        index::GroupUtxoReader branch_utxos(snap.Store(), snap.Txn(),
                                            ext.BranchGroup());
        index::GroupUtxoReader asset_utxos(snap.Store(), snap.Txn(),
                                           ext.AssetGroup());
        for (const Hash32 &branch : {kKey, kScript, kData}) {
            BOOST_CHECK(branches.PageTxs(B(branch), 0) ==
                        (std::vector<index::TxNum>{2}));
            BOOST_CHECK(branch_utxos.Utxos(B(branch)) ==
                        (std::vector<index::UtxoEntry>{utxo}));
        }
        BOOST_CHECK(asset_utxos.Utxos(B(kAsset)) ==
                    (std::vector<index::UtxoEntry>{utxo}));
    }
    ix->Close();
}

BOOST_AUTO_TEST_SUITE_END()
