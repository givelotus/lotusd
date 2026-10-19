// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Lotus V2 node input of the native V2 service (V2 tier): the node block
// conversion (port of bridge_v2_native_block) and the service's chain
// lifecycle (port of the V2 parts of chronik-lib bridge.rs).

#include <hosts/abc/abc_host.h>
#include <hosts/abc/abc_v2.h>

#include <chronik/native/http.h>
#include <chronik/native/types.h>
#include <ext/lotus_v2/service/service.h>

#include <chainparams.h>
#include <lotus_v2/header.h>
#include <node/blockstorage.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <filesystem>

namespace cn = chronik::native;
namespace ffi = chronik::native::lotus_v2::ffi;

namespace {

ffi::Bytes32 Bytes(const uint256 &h) {
    ffi::Bytes32 out;
    std::memcpy(out.data(), h.begin(), 32);
    return out;
}

ffi::Anchor AnchorOf(const CBlockIndex &bindex) {
    return ffi::Anchor{.block_id = Bytes(bindex.GetBlockHash()),
                       .height = uint64_t(bindex.nHeight)};
}

const CBlockIndex &Tip(ChainstateManager &chainman) {
    return *WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
}

/** The core's Block of an index: only its info drives the V2 extension. */
cn::Block InfoBlock(const CBlockIndex &bindex) {
    cn::Block block;
    std::memcpy(block.info.hash.b.data(), bindex.GetBlockHash().begin(), 32);
    block.info.height = bindex.nHeight;
    return block;
}

} // namespace

BOOST_AUTO_TEST_SUITE(chronik_native_abc_v2_tests)

BOOST_FIXTURE_TEST_CASE(test_v2_native_block_conversion, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex &tip = Tip(chainman);
    for (const CBlockIndex *bindex : {&tip, tip.GetAncestor(0)}) {
        CBlock block;
        BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block, *bindex));
        const ffi::NativeBlock native =
            cn::abc::ConvertV2NativeBlock(block, *bindex);
        BOOST_CHECK(native.anchor == AnchorOf(*bindex));
        if (bindex->nHeight == 0) {
            BOOST_CHECK(native.parent == native.anchor);
            BOOST_CHECK(std::all_of(native.header_wire.begin(),
                                    native.header_wire.begin() + 32,
                                    [](uint8_t b) { return b == 0; }));
        } else {
            BOOST_CHECK(native.parent == AnchorOf(*bindex->pprev));
            BOOST_CHECK(std::equal(native.parent.block_id.begin(),
                                   native.parent.block_id.end(),
                                   native.header_wire.begin()));
        }
        uint64_t height = 0;
        for (size_t i = 0; i < 8; ++i) {
            height |= uint64_t(native.header_wire[62 + i]) << (8 * i);
        }
        BOOST_CHECK_EQUAL(height, uint64_t(bindex->nHeight));
        BOOST_REQUIRE_EQUAL(native.transactions.size(), block.vtx.size());
        for (size_t n = 0; n < block.vtx.size(); ++n) {
            const ffi::NativeTx &tx = native.transactions[n];
            BOOST_CHECK(tx.txid == Bytes(block.vtx[n]->GetId()));
            BOOST_CHECK(tx.txhash == Bytes(block.vtx[n]->GetHash()));
            BOOST_CHECK_EQUAL(tx.index, n);
            BOOST_CHECK_EQUAL(tx.outputs.size(), block.vtx[n]->vout.size());
            BOOST_CHECK(!tx.wire.empty());
        }
        // The normalized coinbase input spends nothing.
        const ffi::NativeTx &cb = native.transactions[0];
        BOOST_REQUIRE_EQUAL(cb.full_inputs.size(), 1u);
        BOOST_CHECK_EQUAL(cb.full_inputs[0].flags, 2);
        BOOST_CHECK(cb.inputs.empty());
        BOOST_CHECK_EQUAL(cb.lock, 0u);
    }
}

BOOST_FIXTURE_TEST_CASE(test_v2_service_lifecycle, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const cn::abc::AbcHost host(m_node, cn::HostCapabilities{});
    const std::filesystem::path indexes = m_path_root / "indexes";
    const std::filesystem::path v2_dir = indexes / "chronik" / "v2_index";

    cn::abc::AbcV2ServiceExtension ext(m_node, host);
    BOOST_CHECK(ext.TxnMode() == cn::Extension::Txn::OwnEnv);
    ext.Open(indexes, /*wipe=*/false);
    BOOST_CHECK(std::filesystem::is_regular_file(v2_dir / "mdbx.dat"));
    BOOST_REQUIRE(ext.Service());
    BOOST_CHECK(!ext.Service()->Checkpoint());

    // Resync replays the active chain from genesis.
    ext.Resync();
    const CBlockIndex &tip100 = Tip(chainman);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip100));

    // Disconnect expects the checkpoint's block; Connect reads it back.
    ext.Disconnect(InfoBlock(tip100), nullptr);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(*tip100.pprev));
    ext.Connect(InfoBlock(tip100), nullptr);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip100));
    // A disconnect of a block that is not the checkpoint is ignored.
    ext.Disconnect(InfoBlock(*tip100.pprev), nullptr);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip100));

    // Reopening keeps the env; resync connects only the new block.
    ext.Close();
    BOOST_CHECK(!ext.Service());
    CreateAndProcessBlock({}, CScript() << OP_TRUE);
    const CBlockIndex &tip101 = Tip(chainman);
    BOOST_REQUIRE_EQUAL(tip101.nHeight, 101);
    ext.Open(indexes, /*wipe=*/false);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip100));
    ext.Resync();
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip101));

    // Resync rolls back checkpoints that left the active chain.
    ext.Disconnect(InfoBlock(tip101), nullptr);
    ext.Disconnect(InfoBlock(tip100), nullptr);
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(*tip100.pprev));
    ext.Resync();
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip101));

    // A wipe starts a fresh env.
    ext.Close();
    ext.Open(indexes, /*wipe=*/true);
    BOOST_CHECK(!ext.Service()->Checkpoint());
    ext.Resync();
    BOOST_CHECK(ext.Service()->Checkpoint() == AnchorOf(tip101));

    // An unreadable env is replaced by a fresh one.
    ext.Close();
    std::filesystem::resize_file(v2_dir / "mdbx.dat", 16);
    ext.Open(indexes, /*wipe=*/false);
    BOOST_CHECK(!ext.Service()->Checkpoint());
    ext.Close();
}

// The extension serves /v2 and /v2/explorer/v1 over its current service.
BOOST_FIXTURE_TEST_CASE(test_v2_service_routes, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const cn::abc::AbcHost host(m_node, cn::HostCapabilities{});
    cn::abc::AbcV2ServiceExtension ext(m_node, host);
    cn::Router router;
    ext.RegisterRoutes(router);
    auto get = [&](const std::string &path) {
        cn::HttpRequest req;
        req.method = "GET";
        req.path = path;
        return router.Handle(req);
    };
    auto body = [](const cn::HttpResponse &r) {
        return std::string(r.body.begin(), r.body.end());
    };
    // Not opened yet: unavailable.
    BOOST_CHECK_EQUAL(get("/v2/status").status, 503);
    BOOST_CHECK_EQUAL(get("/v2/explorer/v1/status").status, 503);

    ext.Open(m_path_root / "indexes", /*wipe=*/false);
    ext.Resync();
    const CBlockIndex &tip = Tip(chainman);
    const cn::HttpResponse status = get("/v2/status");
    BOOST_CHECK_EQUAL(status.status, 200);
    BOOST_CHECK(body(status).find("\"ready\":true") != std::string::npos);
    const cn::HttpResponse block =
        get("/v2/explorer/v1/blocks/by-height/" + std::to_string(tip.nHeight));
    BOOST_CHECK_EQUAL(block.status, 200);
    BOOST_CHECK(body(block).find("\"height\":\"100\"") != std::string::npos);
    BOOST_CHECK(body(block).find("\"tx_count\":\"1\"") != std::string::npos);
    const std::string explorer_status = body(get("/v2/explorer/v1/status"));
    BOOST_CHECK(explorer_status.find("\"reason\":\"ready\"") !=
                std::string::npos);

    ext.Close();
    BOOST_CHECK_EQUAL(get("/v2/status").status, 503);
}

BOOST_FIXTURE_TEST_CASE(test_v2_decode_raw_tx, TestChain100Setup) {
    // validate-tx and broadcast checks decode a native V2 (v7) tx with the
    // node's decoding: its own inputs, outputs and txid, which differ per
    // tx (the legacy decoder sees no inputs or outputs in v7 bytes).
    const cn::abc::AbcHost host(m_node, cn::HostCapabilities{});
    std::vector<uint256> txids;
    for (const int64_t sats : {1000, 2000}) {
        CMutableTransaction mtx;
        mtx.vin = {CTxIn(COutPoint(m_coinbase_txns[0]->GetId(), 1),
                         CScript(), 0xffffffff)};
        mtx.vout = {CTxOut(sats * SATOSHI, CScript() << OP_TRUE)};
        AdaptLegacyTxToV7(mtx);
        const CTransaction tx(mtx);
        BOOST_REQUIRE_EQUAL(tx.nVersion, 7);
        DataStream ss{};
        ss << tx;
        const auto span = MakeUCharSpan(ss);
        const cn::Bytes raw(span.begin(), span.end());

        const cn::DecodedTx decoded = host.DecodeRawTx(raw);
        BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.error);
        const cn::Tx expected = cn::abc::ConvertTx(
            false, tx, {::Coin(CTxOut(sats * SATOSHI, CScript()), 1, true)});
        BOOST_CHECK(std::equal(decoded.tx.txid.b.begin(),
                               decoded.tx.txid.b.end(), tx.GetId().begin()));
        BOOST_CHECK_EQUAL(decoded.tx.version, 7);
        BOOST_REQUIRE_EQUAL(decoded.tx.inputs.size(), 1u);
        BOOST_CHECK(decoded.tx.inputs[0].prev_out.txid ==
                    expected.inputs[0].prev_out.txid);
        BOOST_CHECK_EQUAL(decoded.tx.inputs[0].prev_out.out_idx, 1u);
        BOOST_CHECK(decoded.tx.inputs[0].script == expected.inputs[0].script);
        BOOST_CHECK_EQUAL(decoded.tx.inputs[0].sequence, 0xffffffffu);
        BOOST_CHECK(!decoded.tx.inputs[0].coin);
        BOOST_REQUIRE_EQUAL(decoded.tx.outputs.size(), 1u);
        BOOST_CHECK_EQUAL(decoded.tx.outputs[0].sats, sats);
        BOOST_CHECK(decoded.tx.outputs[0].script ==
                    expected.outputs[0].script);
        BOOST_CHECK_EQUAL(decoded.tx.locktime, tx.nLockTime);
        BOOST_CHECK_EQUAL(decoded.tx.wire_size, expected.wire_size);
        BOOST_CHECK(decoded.tx.raw == raw);

        // Looking up the spent coins keeps the txid.
        cn::Tx looked_up = decoded.tx;
        (void)host.LookupSpentCoins(looked_up);
        BOOST_CHECK(looked_up.txid == decoded.tx.txid);
        txids.push_back(tx.GetId());
    }
    BOOST_CHECK(txids[0] != txids[1]);
}

BOOST_AUTO_TEST_SUITE_END()
