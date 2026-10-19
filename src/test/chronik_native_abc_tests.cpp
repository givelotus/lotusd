// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the native Chronik ABC host adapter (chronik/native/hosts/abc),
// porting the expectations of the Rust bridge tests
// chronik/test/bridgeprimitives_tests.cpp, chronik/test/chronikbridge_tests.cpp
// and chronik/test/bridgecompression_tests.cpp to chronik::native::abc.
//
// Differences from the bridge tests, by API design of chronik::native::Host:
//  - Missing blocks are std::nullopt instead of a thrown
//    block_index_not_found; invalid header ranges return an empty vector
//    instead of throwing invalid_block_range.
//  - Broadcast returns a BroadcastResult with the error text instead of
//    throwing it.
//  - get_block_ancestor(index, height) has no host equivalent; the host
//    exposes ActiveAtHeight(height) on the active chain instead.
//  - LoadBlock returns the converted chronik::native::Block, not a CBlock.
//  - calc_fee(size, rate) is folded into CalcMaxFee(size), which always uses
//    the node's default max raw tx fee rate.
//  - Script compression is not a host function: it lives in the core codec
//    (chronik/native/codec/script_compress.h). Its output is checked against
//    the node's ScriptCompression, which is what the bridge exposed.

#include <hosts/abc/abc_host.h>

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/host.h>
#include <chronik/native/tx/legacy_tx.h>
#include <chronik/native/types.h>

#include <chainparams.h>
#include <clientversion.h>
#include <compressor.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <feerate.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/output.h>
#include <lotus_v2/transaction.h>
#include <primitives/v2_outputs.h>
#include <node/blockstorage.h>
#include <node/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <txmempool.h>
#include <undo.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace cn = chronik::native;
using cn::abc::AbcHost;
using node::BlockManager;

namespace {

cn::Hash32 ToHash(const uint256 &h) {
    cn::Hash32 out;
    std::memcpy(out.b.data(), h.begin(), 32);
    return out;
}

cn::Bytes ToBytes(const CScript &script) {
    return cn::Bytes(script.begin(), script.end());
}

cn::Bytes Serialized(const CTransaction &tx) {
    DataStream ss{};
    ss << tx;
    const auto span = MakeUCharSpan(ss);
    return cn::Bytes(span.begin(), span.end());
}

AbcHost MakeHost(const node::NodeContext &node) {
    return AbcHost(node, cn::HostCapabilities{});
}

// Lotus V2 nodes give miner-built coinbase outputs native-output branches
// (CTxOut::vBranches) and store such outputs as a native-output frame in the
// script field, so a block read back from disk differs from the in-memory
// CBlock the test miner returns, and undo coins of such outputs have an empty
// script. The eCash tier has no such outputs. On V2, the tests convert the
// stored block, and expect the adapter to index native outputs (such as those
// undo coins) as the native output frame, checked against the node's own
// lotus::v2::EncodeOutput.
template <typename T>
constexpr bool HasV2Branches = requires(const T &o) { o.vBranches; };
constexpr bool kV2Outputs = HasV2Branches<CTxOut>;

/** The script the adapter must index for a node output. */
template <typename TxOutT> cn::Bytes ExpectedScript(const TxOutT &output) {
    if constexpr (HasV2Branches<TxOutT>) {
        if (output.scriptPubKey.size() <= 1 && !output.vBranches.empty()) {
            lotus::v2::Output native;
            native.flags = output.nFlags & 0x03;
            if (!output.tokenId.IsNull()) {
                native.flags |= 1;
                std::memcpy(native.token_id.data(), output.tokenId.begin(),
                            32);
            }
            native.value = uint64_t(output.nValue / SATOSHI);
            native.branches = output.vBranches;
            if (!native.IsBurn()) {
                // Without explicit paths, each branch is its own path.
                native.paths = output.vPaths;
                for (size_t idx = 0; output.vPaths.empty() &&
                                     idx < output.vBranches.size();
                     ++idx) {
                    native.paths.push_back({uint8_t(idx)});
                }
            }
            std::vector<uint8_t> frame;
            std::string error;
            BOOST_REQUIRE_MESSAGE(
                lotus::v2::EncodeOutput(native, frame, error), error);
            return cn::Bytes(frame.begin(), frame.end());
        }
    }
    return cn::Bytes(output.scriptPubKey.begin(), output.scriptPubKey.end());
}

/**
 * Expected Tx::wire_size: the node's serialization size, except on V2 where
 * the adapter keeps the Rust Chronik's size of the legacy-shaped
 * serialization of the converted tx.
 */
uint32_t ExpectedWireSize(const CTransaction &tx, const cn::Tx &expected) {
    if constexpr (kV2Outputs) {
        return uint32_t(cn::SerializeLegacyTx(expected).size());
    }
    return uint32_t(::GetSerializeSize(tx));
}

CBlock AsStored(const BlockManager &blockman, const CBlockIndex &index,
                const CBlock &block) {
    if constexpr (!kV2Outputs) {
        return block;
    }
    CBlock stored;
    BOOST_REQUIRE(blockman.ReadBlock(stored, index));
    BOOST_REQUIRE(stored.GetHash() == block.GetHash());
    return stored;
}

uint32_t HeaderSize() {
    return uint32_t(::GetSerializeSize(CBlockHeader()));
}

const CBlockIndex &Tip(ChainstateManager &chainman) {
    return *WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
}

void CheckCoinsEqual(const std::optional<cn::Coin> &left,
                     const std::optional<cn::Coin> &right) {
    BOOST_CHECK_EQUAL(left.has_value(), right.has_value());
    if (!left || !right) {
        return;
    }
    BOOST_CHECK_EQUAL(left->output.sats, right->output.sats);
    BOOST_CHECK_EQUAL(HexStr(left->output.script),
                      HexStr(right->output.script));
    BOOST_CHECK_EQUAL(left->height, right->height);
    BOOST_CHECK_EQUAL(left->is_coinbase, right->is_coinbase);
}

void CheckTxsEqual(const cn::Tx &left, const cn::Tx &right) {
    BOOST_CHECK_EQUAL(HexStr(left.txid.b), HexStr(right.txid.b));
    BOOST_CHECK_EQUAL(left.version, right.version);
    BOOST_CHECK_EQUAL(left.locktime, right.locktime);
    BOOST_CHECK_EQUAL(left.wire_size, right.wire_size);
    BOOST_CHECK_EQUAL(left.inputs.size(), right.inputs.size());
    for (size_t inputIdx = 0; inputIdx < left.inputs.size(); ++inputIdx) {
        const cn::TxInput &inLeft = left.inputs[inputIdx];
        const cn::TxInput &inRight = right.inputs.at(inputIdx);
        BOOST_CHECK_EQUAL(HexStr(inLeft.prev_out.txid.b),
                          HexStr(inRight.prev_out.txid.b));
        BOOST_CHECK_EQUAL(inLeft.prev_out.out_idx, inRight.prev_out.out_idx);
        BOOST_CHECK_EQUAL(HexStr(inLeft.script), HexStr(inRight.script));
        BOOST_CHECK_EQUAL(inLeft.sequence, inRight.sequence);
        CheckCoinsEqual(inLeft.coin, inRight.coin);
    }
    BOOST_CHECK_EQUAL(left.outputs.size(), right.outputs.size());
    for (size_t outputIdx = 0; outputIdx < left.outputs.size(); ++outputIdx) {
        const cn::TxOutput &outLeft = left.outputs[outputIdx];
        const cn::TxOutput &outRight = right.outputs.at(outputIdx);
        BOOST_CHECK_EQUAL(outLeft.sats, outRight.sats);
        BOOST_CHECK_EQUAL(HexStr(outLeft.script), HexStr(outRight.script));
    }
}

void CheckBlockInfosEqual(const cn::BlockInfo &left,
                          const cn::BlockInfo &right) {
    BOOST_CHECK_EQUAL(HexStr(left.hash.b), HexStr(right.hash.b));
    BOOST_CHECK_EQUAL(HexStr(left.prev_hash.b), HexStr(right.prev_hash.b));
    BOOST_CHECK_EQUAL(left.n_bits, right.n_bits);
    BOOST_CHECK_EQUAL(left.timestamp, right.timestamp);
    BOOST_CHECK_EQUAL(left.height, right.height);
    BOOST_CHECK_EQUAL(left.file_num, right.file_num);
    BOOST_CHECK_EQUAL(left.data_pos, right.data_pos);
    BOOST_CHECK_EQUAL(left.undo_pos, right.undo_pos);
    BOOST_CHECK_EQUAL(left.size, right.size);
}

void CheckBlocksEqual(const cn::Block &left, const cn::Block &right) {
    CheckBlockInfosEqual(left.info, right.info);
    BOOST_CHECK_EQUAL(left.txs.size(), right.txs.size());
    for (size_t txIdx = 0; txIdx < left.txs.size(); ++txIdx) {
        const cn::BlockTx &txLeft = left.txs[txIdx];
        const cn::BlockTx &txRight = right.txs.at(txIdx);
        BOOST_CHECK_EQUAL(txLeft.data_pos, txRight.data_pos);
        BOOST_CHECK_EQUAL(txLeft.undo_pos, txRight.undo_pos);
        BOOST_REQUIRE(txLeft.tx && txRight.tx);
        CheckTxsEqual(*txLeft.tx, *txRight.tx);
    }
}

void CheckMatchesDisk(const BlockManager &blockman, const CBlock &block,
                      const cn::Block &convertedBlock) {
    BOOST_REQUIRE_EQUAL(convertedBlock.txs.size(), block.vtx.size());
    for (size_t idx = 0; idx < block.vtx.size(); ++idx) {
        const cn::BlockTx &blockTx = convertedBlock.txs[idx];
        CMutableTransaction txFromDisk;
        BOOST_CHECK(blockman.ReadTxFromDisk(
            txFromDisk,
            FlatFilePos(convertedBlock.info.file_num, blockTx.data_pos)));
        BOOST_CHECK(txFromDisk.GetHash() == block.vtx[idx]->GetHash());

        if (idx == 0) {
            continue;
        }

        CTxUndo txundo;
        BOOST_CHECK(blockman.ReadTxUndoFromDisk(
            txundo,
            FlatFilePos(convertedBlock.info.file_num, blockTx.undo_pos)));
        BOOST_CHECK_EQUAL(txundo.vprevout.size(), txFromDisk.vin.size());
        for (size_t inputIdx = 0; inputIdx < blockTx.tx->inputs.size();
             ++inputIdx) {
            const ::Coin &coin = txundo.vprevout[inputIdx];
            const std::optional<cn::Coin> &nativeCoin =
                blockTx.tx->inputs[inputIdx].coin;
            BOOST_REQUIRE(nativeCoin);
            BOOST_CHECK_EQUAL(coin.GetTxOut().nValue / SATOSHI,
                              nativeCoin->output.sats);
            BOOST_CHECK_EQUAL(HexStr(ExpectedScript(coin.GetTxOut())),
                              HexStr(nativeCoin->output.script));
            BOOST_CHECK_EQUAL(coin.GetHeight(), nativeCoin->height);
            BOOST_CHECK_EQUAL(coin.IsCoinBase(), nativeCoin->is_coinbase);
        }
    }
}

template <typename F>
void CheckRuntimeError(F &&f, const std::string &expected) {
    BOOST_CHECK_EXCEPTION(f(), std::runtime_error,
                          [&](const std::runtime_error &ex) {
                              BOOST_CHECK_EQUAL(ex.what(), expected);
                              return true;
                          });
}

} // namespace

BOOST_AUTO_TEST_SUITE(chronik_native_abc_tests)

// ---- bridgeprimitives_tests ----

BOOST_FIXTURE_TEST_CASE(test_bridge_genesis, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    const CBlockIndex *pgenesis = WITH_LOCK(
        chainman.GetMutex(), return chainman.ActiveTip()->GetAncestor(0));
    const CBlock &genesisBlock = chainman.GetParams().GenesisBlock();

    // Loading genesis undo data returns an empty undo
    std::unique_ptr<CBlockUndo> genesisBlockUndo =
        host.LoadBlockUndo(*pgenesis);
    BOOST_REQUIRE(genesisBlockUndo);
    BOOST_CHECK(genesisBlockUndo->vtxundo.empty());

    cn::Block convertedGenesisBlock =
        cn::abc::ConvertBlock(genesisBlock, *genesisBlockUndo, *pgenesis);

    cn::Tx expectedGenesisTx;
    expectedGenesisTx.txid = ToHash(genesisBlock.vtx[0]->GetId());
    expectedGenesisTx.version = int32_t(genesisBlock.vtx[0]->nVersion);
    expectedGenesisTx.inputs = {{
        .prev_out = {.txid = {}, .out_idx = 0xffff'ffff},
        .script = ToBytes(genesisBlock.vtx[0]->vin[0].scriptSig),
        .sequence = 0xffff'ffff,
        // Like the bridge: an empty (not absent) coin for coinbase inputs
        .coin = cn::Coin{},
    }};
    expectedGenesisTx.outputs = {{
        .sats = 5000000000,
        .script = ToBytes(genesisBlock.vtx[0]->vout[0].scriptPubKey),
    }};
    expectedGenesisTx.locktime = 0;
    expectedGenesisTx.wire_size =
        ExpectedWireSize(*genesisBlock.vtx[0], expectedGenesisTx);

    // 8 magic bytes in block file, +header +1 compact size
    const uint32_t genesisTxDataPos = 8 + HeaderSize() + 1;
    cn::Block expectedGenesisBlock;
    expectedGenesisBlock.info = {
        .hash = ToHash(genesisBlock.GetHash()),
        .prev_hash = {},
        .height = 0,
        .n_bits = 0x207fffff,
        .timestamp = 1296688602,
        .file_num = 0,
        .data_pos = 8,
        .undo_pos = 0, // genesis has no undo data
        .size = ::GetSerializeSize(genesisBlock),
    };
    expectedGenesisBlock.txs = {{
        .tx = std::make_shared<const cn::Tx>(expectedGenesisTx),
        .data_pos = genesisTxDataPos,
        .undo_pos = 0, // coinbase has no undo data
    }};

    CheckBlocksEqual(convertedGenesisBlock, expectedGenesisBlock);

    const cn::BlockTx &convertedGenesisTx = convertedGenesisBlock.txs[0];
    CMutableTransaction genesisTxFromDisk;
    BOOST_CHECK(chainman.m_blockman.ReadTxFromDisk(
        genesisTxFromDisk, FlatFilePos(convertedGenesisBlock.info.file_num,
                                       convertedGenesisTx.data_pos)));
    BOOST_CHECK(genesisTxFromDisk.GetHash() == genesisBlock.vtx[0]->GetHash());

    CheckTxsEqual(host.LoadTx(convertedGenesisBlock.info.file_num,
                              convertedGenesisTx.data_pos,
                              convertedGenesisTx.undo_pos),
                  *convertedGenesisTx.tx);

    BOOST_CHECK_EQUAL(HexStr(Serialized(*genesisBlock.vtx[0])),
                      HexStr(host.LoadRawTx(convertedGenesisBlock.info.file_num,
                                            convertedGenesisTx.data_pos)));

    // Native: LoadBlock(BlockInfo) loads + converts in one go
    CheckBlocksEqual(host.LoadBlock(cn::abc::ConvertBlockInfo(*pgenesis)),
                     expectedGenesisBlock);
}

BOOST_FIXTURE_TEST_CASE(test_bridge_detailled, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    ChainstateManager &chainman = *Assert(m_node.chainman);

    CBlock coinsBlock = CreateAndProcessBlock({}, CScript() << OP_1,
                                              &chainman.ActiveChainstate());
    mineBlocks(100);

    CScript scriptPad = CScript() << OP_RETURN << std::vector<uint8_t>(100);
    CMutableTransaction tx1;
    tx1.nVersion = 1;
    tx1.vin = {CTxIn(coinsBlock.vtx[0]->GetId(), 0)};
    tx1.vout = {
        CTxOut(50 * COIN - 10000 * SATOSHI, CScript() << OP_3),
        CTxOut(1000 * SATOSHI, CScript() << OP_4),
        CTxOut(Amount::zero(), scriptPad),
    };
    tx1.nLockTime = 123;

    CMutableTransaction tx2;
    tx2.nVersion = 1;
    tx2.vin = {CTxIn(tx1.GetId(), 0), CTxIn(tx1.GetId(), 1)};
    tx2.vout = {
        CTxOut(50 * COIN - 30000 * SATOSHI, CScript() << OP_5),
        CTxOut(Amount::zero(), scriptPad),
    };

    while (!(tx1.GetId() < tx2.GetId())) {
        ++tx2.nLockTime;
    }
    BOOST_CHECK(tx1.GetId() < tx2.GetId());

    CBlock testBlock = CreateAndProcessBlock({tx1, tx2}, CScript() << OP_2,
                                             &chainman.ActiveChainstate());
    const CBlockIndex &tip = Tip(chainman);
    std::unique_ptr<CBlockUndo> testBlockUndo = host.LoadBlockUndo(tip);
    BOOST_REQUIRE(testBlockUndo);

    BOOST_CHECK_EQUAL(tip.GetBlockHash(), testBlock.GetHash());
    const CBlock storedTestBlock =
        AsStored(chainman.m_blockman, tip, testBlock);
    cn::Block convertedTestBlock =
        cn::abc::ConvertBlock(storedTestBlock, *testBlockUndo, tip);

    cn::Tx expectedTestTx0;
    expectedTestTx0.txid = ToHash(testBlock.vtx[0]->GetId());
    expectedTestTx0.version = int32_t(testBlock.vtx[0]->nVersion);
    expectedTestTx0.inputs = {{
        .prev_out = {.txid = ToHash(testBlock.vtx[0]->vin[0].prevout.GetTxId()),
                     .out_idx = testBlock.vtx[0]->vin[0].prevout.GetN()},
        .script = ToBytes(testBlock.vtx[0]->vin[0].scriptSig),
        .sequence = 0xffff'ffff,
        .coin = cn::Coin{}, // null coin
    }};
    expectedTestTx0.outputs = {{
        .sats = 2500000000,
        .script = kV2Outputs
                      ? ToBytes(storedTestBlock.vtx[0]->vout[0].scriptPubKey)
                      : cn::Bytes{0x52},
    }};
    expectedTestTx0.locktime = 0;
    expectedTestTx0.wire_size =
        ExpectedWireSize(*testBlock.vtx[0], expectedTestTx0);

    cn::Tx expectedTestTx1;
    expectedTestTx1.txid = ToHash(tx1.GetId());
    expectedTestTx1.version = 1;
    expectedTestTx1.inputs = {{
        .prev_out = {.txid = ToHash(coinsBlock.vtx[0]->GetId()), .out_idx = 0},
        .script = {},
        .sequence = 0xffff'ffff,
        .coin = cn::Coin{.output = {5000000000,
                                    kV2Outputs
                                        ? ExpectedScript(testBlockUndo
                                                             ->vtxundo[0]
                                                             .vprevout[0]
                                                             .GetTxOut())
                                        : cn::Bytes{0x51}},
                         .height = 101,
                         .is_coinbase = true},
    }};
    expectedTestTx1.outputs = {
        {4999990000, {0x53}}, {1000, {0x54}}, {0, ToBytes(scriptPad)}};
    expectedTestTx1.locktime = 123;
    expectedTestTx1.wire_size = ExpectedWireSize(CTransaction(tx1), expectedTestTx1);

    cn::Tx expectedTestTx2;
    expectedTestTx2.txid = ToHash(tx2.GetId());
    expectedTestTx2.version = 1;
    expectedTestTx2.inputs = {
        {
            .prev_out = {.txid = ToHash(tx1.GetId()), .out_idx = 0},
            .script = {},
            .sequence = 0xffff'ffff,
            .coin = cn::Coin{.output = {4999990000, {0x53}},
                             .height = 202,
                             .is_coinbase = false},
        },
        {
            .prev_out = {.txid = ToHash(tx1.GetId()), .out_idx = 1},
            .script = {},
            .sequence = 0xffff'ffff,
            .coin = cn::Coin{.output = {1000, {0x54}},
                             .height = 202,
                             .is_coinbase = false},
        },
    };
    expectedTestTx2.outputs = {{4999970000, {0x55}}, {0, ToBytes(scriptPad)}};
    expectedTestTx2.locktime = tx2.nLockTime;
    expectedTestTx2.wire_size = ExpectedWireSize(CTransaction(tx2), expectedTestTx2);

    const uint32_t expectedDataPos =
        WITH_LOCK(::cs_main, return tip.nDataPos);
    const uint32_t expectedUndoPos =
        WITH_LOCK(::cs_main, return tip.nUndoPos);
    const uint32_t tx0DataPos = expectedDataPos + HeaderSize() + 1;
    const uint32_t tx1DataPos =
        uint32_t(tx0DataPos + ::GetSerializeSize(*testBlock.vtx[0]));
    const uint32_t tx2DataPos =
        uint32_t(tx1DataPos + ::GetSerializeSize(*testBlock.vtx[1]));
    const uint32_t tx1UndoPos = expectedUndoPos + 1;
    const uint32_t tx2UndoPos =
        uint32_t(tx1UndoPos + ::GetSerializeSize(testBlockUndo->vtxundo[0]));

    cn::Block expectedTestBlock;
    expectedTestBlock.info = {
        .hash = ToHash(testBlock.GetHash()),
        .prev_hash = ToHash(testBlock.hashPrevBlock),
        .height = 202,
        .n_bits = 0x207fffff,
        .timestamp = 1598888152,
        .file_num = 0,
        .data_pos = expectedDataPos,
        .undo_pos = expectedUndoPos,
        .size = ::GetSerializeSize(testBlock),
    };
    expectedTestBlock.txs = {
        {.tx = std::make_shared<const cn::Tx>(expectedTestTx0),
         .data_pos = tx0DataPos,
         .undo_pos = 0},
        {.tx = std::make_shared<const cn::Tx>(expectedTestTx1),
         .data_pos = tx1DataPos,
         .undo_pos = tx1UndoPos},
        {.tx = std::make_shared<const cn::Tx>(expectedTestTx2),
         .data_pos = tx2DataPos,
         .undo_pos = tx2UndoPos},
    };

    CheckBlocksEqual(convertedTestBlock, expectedTestBlock);

    CheckMatchesDisk(chainman.m_blockman, testBlock, convertedTestBlock);

    for (const cn::BlockTx &convertedTx : convertedTestBlock.txs) {
        CheckTxsEqual(host.LoadTx(convertedTestBlock.info.file_num,
                                  convertedTx.data_pos, convertedTx.undo_pos),
                      *convertedTx.tx);
    }

    for (size_t i = 0; i < testBlock.vtx.size(); ++i) {
        BOOST_CHECK_EQUAL(HexStr(Serialized(*testBlock.vtx[i])),
                          HexStr(host.LoadRawTx(
                              convertedTestBlock.info.file_num,
                              convertedTestBlock.txs[i].data_pos)));
    }

    // Native: LoadBlock gives the same result as ConvertBlock
    const std::optional<cn::BlockInfo> tipInfo = host.ActiveTip();
    BOOST_REQUIRE(tipInfo);
    CheckBlocksEqual(host.LoadBlock(*tipInfo), expectedTestBlock);
}

BOOST_FIXTURE_TEST_CASE(test_bridge_bad, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    // Incompatible CBlock and CBlockUndo:
    // CBlock has a tx that the CBlockUndo doesn't have.
    CBlock badBlock1 = CreateBlock({CMutableTransaction()}, CScript() << OP_1,
                                   chainman.ActiveChainstate());
    CBlockUndo badBlockUndo1;
    CheckRuntimeError(
        [&] {
            cn::abc::ConvertBlock(badBlock1, badBlockUndo1, Tip(chainman));
        },
        "Missing undo data for tx");

    CBlock coinsBlock = CreateAndProcessBlock({}, CScript() << OP_1,
                                              &chainman.ActiveChainstate());
    mineBlocks(100);

    // Create block with some undo data
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.vin = {CTxIn(coinsBlock.vtx[0]->GetId(), 0)};
    tx.vout = {CTxOut(50 * COIN - 10000 * SATOSHI,
                      CScript() << OP_RETURN << std::vector<uint8_t>(100))};
    CreateAndProcessBlock({tx}, CScript() << OP_1,
                          &chainman.ActiveChainstate());
    std::unique_ptr<CBlockUndo> blockUndo = host.LoadBlockUndo(Tip(chainman));
    BOOST_REQUIRE(blockUndo);

    // This time, bad CBlock has two inputs whereas the disk has only one.
    CMutableTransaction badTx;
    badTx.vin.resize(2);
    CBlock badBlock2 =
        CreateBlock({badTx}, CScript() << OP_1, chainman.ActiveChainstate());
    CheckRuntimeError(
        [&] { cn::abc::ConvertBlock(badBlock2, *blockUndo, Tip(chainman)); },
        "Missing coin for input");

    // Native: ConvertTx raises the same error directly
    CheckRuntimeError(
        [&] {
            cn::abc::ConvertTx(/*is_coinbase=*/false, CTransaction(badTx),
                               blockUndo->vtxundo[0].vprevout);
        },
        "Missing coin for input");
}

// It's easy to make a hard to detect off-by-one error when using
// GetSizeOfCompactSize, therefore we test blocks with "dangerous" number of
// txs, which cover the cases where GetSizeOfCompactSize goes from 1 -> 3 -> 5.
BOOST_FIXTURE_TEST_CASE(test_bridge_big, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    std::vector<size_t> testNumTxsCases = {
        0,   1,   2,   3,   10,  62,  63,  64,  65,  126, 127, 128,
        129, 130, 250, 251, 252, 253, 254, 255, 256, 257, 258, 65536};

    std::vector<CBlock> coinblocks;
    for (size_t idx = 0; idx < testNumTxsCases.size(); ++idx) {
        CBlock coinblock = CreateAndProcessBlock({}, CScript() << OP_1,
                                                 &chainman.ActiveChainstate());
        coinblocks.push_back(coinblock);
        BOOST_CHECK_EQUAL(Tip(chainman).GetBlockHash(), coinblock.GetHash());
    }
    mineBlocks(100);

    CScript scriptPad = CScript() << OP_RETURN << std::vector<uint8_t>(100);

    for (size_t idx = 0; idx < testNumTxsCases.size(); ++idx) {
        size_t numTxs = testNumTxsCases[idx];
        std::vector<CMutableTransaction> txs;
        txs.reserve(numTxs);
        const CTransactionRef &coinbase = coinblocks[idx].vtx[0];
        Amount available = coinbase->vout[0].nValue;
        TxId coinTxId = coinbase->GetId();
        for (size_t txIdx = 0; txIdx < numTxs; ++txIdx) {
            CMutableTransaction tx;
            tx.nVersion = 1;
            tx.vin = {CTxIn(coinTxId, 0)};
            available -= 10000 * SATOSHI;
            tx.vout = {
                CTxOut(available, CScript() << OP_2),
                CTxOut(Amount::zero(), scriptPad),
            };
            coinTxId = tx.GetId();
            txs.push_back(tx);
        }
        CBlock testBlock = CreateAndProcessBlock(txs, CScript() << OP_1,
                                                 &chainman.ActiveChainstate());
        const CBlockIndex &tip = Tip(chainman);
        BOOST_CHECK_EQUAL(tip.GetBlockHash(), testBlock.GetHash());

        std::unique_ptr<CBlockUndo> testBlockUndo = host.LoadBlockUndo(tip);
        BOOST_REQUIRE(testBlockUndo);

        // test matches disk
        cn::Block convertedBlock = cn::abc::ConvertBlock(
            AsStored(chainman.m_blockman, tip, testBlock), *testBlockUndo, tip);
        CheckMatchesDisk(chainman.m_blockman, testBlock, convertedBlock);

        for (const cn::BlockTx &convertedTx : convertedBlock.txs) {
            CheckTxsEqual(host.LoadTx(convertedBlock.info.file_num,
                                      convertedTx.data_pos,
                                      convertedTx.undo_pos),
                          *convertedTx.tx);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(test_load_tx_bad, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);

    CheckRuntimeError([&] { host.LoadTx(0x7fffffff, 0, 0); },
                      "Reading tx data from disk failed");
    CheckRuntimeError([&] { host.LoadTx(0, 0x7fffffff, 0); },
                      "Reading tx data from disk failed");
    const uint32_t genesisCbDataPos = 8 + HeaderSize() + 1;
    CheckRuntimeError([&] { host.LoadTx(0, genesisCbDataPos, 0x7fffffff); },
                      "Reading tx undo data from disk failed");
    // sanity check
    host.LoadTx(0, genesisCbDataPos, 0);

    // Native: LoadRawTx has the same error text
    CheckRuntimeError([&] { host.LoadRawTx(0x7fffffff, 0); },
                      "Reading tx data from disk failed");
    CheckRuntimeError([&] { host.LoadRawTx(0, 0x7fffffff); },
                      "Reading tx data from disk failed");

    // Native: LoadBlock of an unknown block
    cn::BlockInfo unknown;
    unknown.hash.b.fill(0x42);
    CheckRuntimeError([&] { host.LoadBlock(unknown); },
                      "Block index not found");
    CheckRuntimeError([&] { host.RawHeader(unknown); },
                      "Block index not found");
}

// ---- chronikbridge_tests ----

BOOST_FIXTURE_TEST_CASE(test_get_chain_tip_empty, ChainTestingSetup) {
    // Setup chainstate
    {
        LOCK(::cs_main);
        m_node.chainman->InitializeChainstate(m_node.mempool.get());
    }
    // Chain has no blocks yet: ActiveTip is nullopt (the bridge threw
    // block_index_not_found).
    const AbcHost host = MakeHost(m_node);
    BOOST_CHECK(!host.ActiveTip());
    BOOST_CHECK(!host.ActiveAtHeight(0));
    BOOST_CHECK(host.RawHeadersByRange(0, 10).empty());
}

BOOST_FIXTURE_TEST_CASE(test_get_chain_tip_genesis, TestingSetup) {
    const AbcHost host = MakeHost(m_node);
    // Check for genesis block
    const std::optional<cn::BlockInfo> tip = host.ActiveTip();
    BOOST_REQUIRE(tip);
    const BlockHash genesisHash =
        m_node.chainman->GetParams().GenesisBlock().GetHash();
    BOOST_CHECK_EQUAL(HexStr(tip->hash.b), HexStr(ToHash(genesisHash).b));
    BOOST_CHECK_EQUAL(tip->height, 0);
    BOOST_CHECK_EQUAL(HexStr(host.GenesisHash().b),
                      HexStr(ToHash(genesisHash).b));
}

BOOST_FIXTURE_TEST_CASE(test_get_chain_tip_100, TestChain100Setup) {
    // Generate new block (at height 101)
    CBlock tip_block = CreateAndProcessBlock(
        {}, CScript() << std::vector<uint8_t>(33) << OP_CHECKSIG);
    const AbcHost host = MakeHost(m_node);
    // Check if block is 101th
    const std::optional<cn::BlockInfo> tip = host.ActiveTip();
    BOOST_REQUIRE(tip);
    BOOST_CHECK_EQUAL(HexStr(tip->hash.b),
                      HexStr(ToHash(tip_block.GetHash()).b));
    BOOST_CHECK_EQUAL(tip->height, 101);
}

BOOST_FIXTURE_TEST_CASE(test_lookup_block_index, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    BlockHash genesis_hash =
        m_node.chainman->GetParams().GenesisBlock().GetHash();
    const std::optional<cn::BlockInfo> info_genesis =
        host.LookupBlock(ToHash(genesis_hash));
    BOOST_REQUIRE(info_genesis);
    BOOST_CHECK_EQUAL(HexStr(info_genesis->hash.b),
                      HexStr(ToHash(genesis_hash).b));
    const CBlockIndex *pindex_genesis = host.LookupIndex(ToHash(genesis_hash));
    BOOST_REQUIRE(pindex_genesis);
    BOOST_CHECK_EQUAL(pindex_genesis->GetBlockHash(), genesis_hash);

    // Generate new block (at height 101)
    CBlock tip_block = CreateAndProcessBlock(
        {}, CScript() << std::vector<uint8_t>(33) << OP_CHECKSIG);
    // Query block
    const std::optional<cn::BlockInfo> info_tip =
        host.LookupBlock(ToHash(tip_block.GetHash()));
    BOOST_REQUIRE(info_tip);
    BOOST_CHECK_EQUAL(HexStr(info_tip->hash.b),
                      HexStr(ToHash(tip_block.GetHash()).b));

    // Block 000...000 doesn't exist
    BOOST_CHECK(!host.LookupBlock(cn::BlockHash{}));
    BOOST_CHECK(!host.LookupIndex(cn::BlockHash{}));
}

BOOST_FIXTURE_TEST_CASE(test_find_fork, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    CBlockIndex *tip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    auto fork_hash = [&](const uint256 &hash) {
        std::optional<cn::BlockInfo> fork = host.FindFork(ToHash(hash));
        BOOST_REQUIRE(fork);
        return HexStr(fork->hash.b);
    };

    // Fork of the tip is the tip
    BOOST_CHECK_EQUAL(fork_hash(tip->GetBlockHash()),
                      HexStr(ToHash(tip->GetBlockHash()).b));
    // Fork of the genesis block is the genesis block
    BOOST_CHECK_EQUAL(
        fork_hash(tip->GetAncestor(0)->GetBlockHash()),
        HexStr(ToHash(chainman.GetParams().GenesisBlock().GetHash()).b));

    // Invalidate block in the middle of the chain
    BlockValidationState state;
    chainman.ActiveChainstate().InvalidateBlock(state, tip->GetAncestor(50));

    // Mine 100 blocks, up to height 150
    mineBlocks(100);

    // Fork of old tip is block 49
    auto new_tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    BOOST_REQUIRE(new_tip);
    BOOST_CHECK_EQUAL(fork_hash(tip->GetBlockHash()),
                      HexStr(ToHash(new_tip->GetAncestor(49)->GetBlockHash()).b));

    // Native: unknown blocks have no fork
    BOOST_CHECK(!host.FindFork(cn::BlockHash{}));
}

BOOST_FIXTURE_TEST_CASE(test_lookup_spent_coin, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    CScript anyoneScript = CScript() << OP_1;
    CScript anyoneP2sh = GetScriptForDestination(ScriptHash(anyoneScript));
    CBlock coinsBlock =
        CreateAndProcessBlock({}, anyoneP2sh, &chainman.ActiveChainstate());
    mineBlocks(100);

    const CTransactionRef coinTx = coinsBlock.vtx[0];

    CMutableTransaction tx;
    tx.vin = {CTxIn(
        coinTx->GetId(), 0,
        CScript() << std::vector(anyoneScript.begin(), anyoneScript.end()))};
    tx.vout = {
        CTxOut(1000 * SATOSHI, anyoneP2sh),
        CTxOut(coinTx->vout[0].nValue - 10000 * SATOSHI, anyoneP2sh),
    };
    const MempoolAcceptResult result =
        WITH_LOCK(chainman.GetMutex(),
                  return chainman.ProcessTransaction(MakeTransactionRef(tx)));
    BOOST_CHECK_EQUAL(result.m_result_type,
                      MempoolAcceptResult::ResultType::VALID);
    TxId txid = tx.GetId();

    // Tx we look up coins for. Only the prev_out field is relevant so the other
    // ones are default
    cn::Tx query_tx;
    query_tx.version = 2;
    query_tx.inputs = {
        {.prev_out = {ToHash(txid), 0}},
        {.prev_out = {ToHash(txid), 1}},
        {.prev_out = {{}, 0x12345678}},
    };

    // Keep direct cache inspection protected, but release the lock when mining.
    WAIT_LOCK(chainman.GetMutex(), lock);
    CCoinsViewCache &coins_cache = chainman.ActiveChainstate().CoinsTip();

    // Do lookup
    cn::SpentCoinLookup lookup = host.LookupSpentCoins(query_tx);

    // One of the coins was not found
    BOOST_CHECK_EQUAL(lookup.not_found.size(), 1);
    BOOST_CHECK(lookup.not_found[0] == query_tx.inputs[2].prev_out);
    BOOST_CHECK(!query_tx.inputs[2].coin);

    // Mempool UTXOs aren't in the cache, so LookupSpentCoins thinks they need
    // to be uncached, which seems weird but is intended behavior.
    BOOST_CHECK_EQUAL(lookup.to_uncache.size(), 2);
    BOOST_CHECK(lookup.to_uncache[0] == query_tx.inputs[0].prev_out);
    BOOST_CHECK(lookup.to_uncache[1] == query_tx.inputs[1].prev_out);
    BOOST_CHECK(!coins_cache.HaveCoinInCache(COutPoint(txid, 0)));
    BOOST_CHECK(!coins_cache.HaveCoinInCache(COutPoint(txid, 1)));

    // LookupSpentCoins mutates our query_tx to set the queried coins
    BOOST_REQUIRE(query_tx.inputs[0].coin);
    BOOST_REQUIRE(query_tx.inputs[1].coin);
    const cn::Bytes &script0 = query_tx.inputs[0].coin->output.script;
    const cn::Bytes &script1 = query_tx.inputs[1].coin->output.script;
    BOOST_CHECK_EQUAL(query_tx.inputs[0].coin->output.sats, 1000);
    BOOST_CHECK(CScript(script0.begin(), script0.end()) == anyoneP2sh);
    BOOST_CHECK_EQUAL(query_tx.inputs[1].coin->output.sats,
                      coinTx->vout[0].nValue / SATOSHI - 10000);
    BOOST_CHECK(CScript(script1.begin(), script1.end()) == anyoneP2sh);
    // Native: mempool coins have MEMPOOL_HEIGHT, which converts to -1
    BOOST_CHECK_EQUAL(query_tx.inputs[0].coin->height, -1);
    BOOST_CHECK_EQUAL(query_tx.inputs[0].coin->is_coinbase, false);
    BOOST_CHECK_EQUAL(query_tx.inputs[1].coin->height, -1);

    // ProcessNewBlock requires the caller not to hold cs_main.
    {
        REVERSE_LOCK(lock);
        CreateAndProcessBlock({tx}, CScript() << OP_1,
                              &chainman.ActiveChainstate());
    }
    // Coins are now in the cache
    BOOST_CHECK(coins_cache.HaveCoinInCache(COutPoint(txid, 0)));
    BOOST_CHECK(coins_cache.HaveCoinInCache(COutPoint(txid, 1)));

    // Write cache to DB & clear cache
    coins_cache.Flush();
    BOOST_CHECK(!coins_cache.HaveCoinInCache(COutPoint(txid, 0)));
    BOOST_CHECK(!coins_cache.HaveCoinInCache(COutPoint(txid, 1)));

    // lookup puts the coins back into the cache
    lookup = host.LookupSpentCoins(query_tx);
    BOOST_CHECK_EQUAL(lookup.to_uncache.size(), 2);
    BOOST_CHECK(lookup.to_uncache[0] == query_tx.inputs[0].prev_out);
    BOOST_CHECK(lookup.to_uncache[1] == query_tx.inputs[1].prev_out);
    BOOST_CHECK(coins_cache.HaveCoinInCache(COutPoint(txid, 0)));
    BOOST_CHECK(coins_cache.HaveCoinInCache(COutPoint(txid, 1)));
    // Native: confirmed coins carry their block height (coins block 101, 100
    // more blocks, tx mined at 202)
    BOOST_REQUIRE(query_tx.inputs[0].coin);
    BOOST_CHECK_EQUAL(query_tx.inputs[0].coin->height, 202);
    BOOST_CHECK_EQUAL(query_tx.inputs[0].coin->is_coinbase, false);

    // Now, we don't get any to_uncache (because the call didn't add
    // anything to it)
    lookup = host.LookupSpentCoins(query_tx);
    BOOST_CHECK_EQUAL(lookup.to_uncache.size(), 0);

    // Call UncacheCoins to uncache the 1st coin
    const std::vector<cn::OutPoint> uncache_outpoints{
        query_tx.inputs[0].prev_out};
    host.UncacheCoins(uncache_outpoints);
    // Only the 2nd coin is now in cache
    BOOST_CHECK(!coins_cache.HaveCoinInCache(COutPoint(txid, 0)));
    BOOST_CHECK(coins_cache.HaveCoinInCache(COutPoint(txid, 1)));
}

BOOST_FIXTURE_TEST_CASE(test_load_block, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex &tip = Tip(chainman);

    const cn::Block tipBlock = host.LoadBlock(cn::abc::ConvertBlockInfo(tip));
    BOOST_CHECK_EQUAL(HexStr(tipBlock.info.hash.b),
                      HexStr(ToHash(tip.GetBlockHash()).b));

    {
        // The bridge compared the loaded genesis CBlock's serialization; the
        // native LoadBlock returns the converted block, so compare that
        // conversion and its raw txs.
        const CBlock &genesis = chainman.GetParams().GenesisBlock();
        const cn::Block loaded =
            host.LoadBlock(cn::abc::ConvertBlockInfo(*tip.GetAncestor(0)));
        CheckBlocksEqual(loaded, cn::abc::ConvertBlock(genesis, CBlockUndo{},
                                                       *tip.GetAncestor(0)));
        BOOST_CHECK_EQUAL(loaded.info.size, ::GetSerializeSize(genesis));
        BOOST_REQUIRE_EQUAL(loaded.txs.size(), genesis.vtx.size());
        BOOST_CHECK_EQUAL(
            HexStr(host.LoadRawTx(loaded.info.file_num, loaded.txs[0].data_pos)),
            HexStr(Serialized(*genesis.vtx[0])));
    }
}

BOOST_FIXTURE_TEST_CASE(test_get_block_ancestor, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex &tip = Tip(chainman);

    auto at_height = [&](int32_t height) {
        std::optional<cn::BlockInfo> info = host.ActiveAtHeight(height);
        BOOST_REQUIRE(info);
        return HexStr(info->hash.b);
    };

    // Block 100 is the tip
    BOOST_CHECK_EQUAL(at_height(100), HexStr(ToHash(tip.GetBlockHash()).b));

    // Block 99 is the prev of the tip
    BOOST_CHECK_EQUAL(at_height(99),
                      HexStr(ToHash(tip.GetBlockHeader().hashPrevBlock).b));

    // Genesis block is block 0
    BOOST_CHECK_EQUAL(
        at_height(0),
        HexStr(ToHash(chainman.GetParams().GenesisBlock().GetHash()).b));

    // Block -1 doesn't exist
    BOOST_CHECK(!host.ActiveAtHeight(-1));

    // Block 101 doesn't exist
    BOOST_CHECK(!host.ActiveAtHeight(tip.nHeight + 1));
}

BOOST_FIXTURE_TEST_CASE(test_get_block_info, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);
    const CBlockIndex &tip = Tip(chainman);

    const CBlock &genesis = chainman.GetParams().GenesisBlock();
    cn::BlockInfo expected_genesis_info{
        .hash = ToHash(genesis.GetHash()),
        .prev_hash = {},
        .height = 0,
        .n_bits = genesis.nBits,
        .timestamp = genesis.GetBlockTime(),
        .file_num = 0,
        .data_pos = 8,
        .undo_pos = 0,
        .size = 0, // not known from the index alone
    };
    CheckBlockInfosEqual(cn::abc::ConvertBlockInfo(*tip.GetAncestor(0)),
                         expected_genesis_info);

    const auto [tip_file, tip_data_pos, tip_undo_pos] = WITH_LOCK(
        ::cs_main, return std::make_tuple(tip.nFile, tip.nDataPos,
                                          tip.nUndoPos));
    cn::BlockInfo expected_tip_info{
        .hash = ToHash(tip.GetBlockHash()),
        .prev_hash = ToHash(tip.pprev->GetBlockHash()),
        .height = tip.nHeight,
        .n_bits = tip.nBits,
        .timestamp = tip.GetBlockTime(),
        .file_num = uint32_t(tip_file),
        .data_pos = tip_data_pos,
        .undo_pos = tip_undo_pos,
        .size = 0,
    };
    CheckBlockInfosEqual(cn::abc::ConvertBlockInfo(tip), expected_tip_info);
    const std::optional<cn::BlockInfo> active_tip = host.ActiveTip();
    BOOST_REQUIRE(active_tip);
    CheckBlockInfosEqual(*active_tip, expected_tip_info);
}

BOOST_FIXTURE_TEST_CASE(test_get_block_header, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);
    const CBlockIndex &tip = Tip(chainman);
    const CBlockIndex &genesis = *tip.GetAncestor(0);

    DataStream ser_genesis{};
    ser_genesis << genesis.GetBlockHeader();
    DataStream ser_tip{};
    ser_tip << tip.GetBlockHeader();

    BOOST_CHECK_EQUAL(HexStr(cn::abc::SerializeHeader(genesis)),
                      HexStr(ser_genesis));
    BOOST_CHECK_EQUAL(HexStr(cn::abc::SerializeHeader(tip)), HexStr(ser_tip));
    BOOST_CHECK_EQUAL(cn::abc::SerializeHeader(tip).size(), HeaderSize());
    BOOST_CHECK_EQUAL(
        HexStr(host.RawHeader(cn::abc::ConvertBlockInfo(genesis))),
        HexStr(ser_genesis));
    BOOST_CHECK_EQUAL(HexStr(host.RawHeader(cn::abc::ConvertBlockInfo(tip))),
                      HexStr(ser_tip));
    if (HeaderSize() == 80) {
        BOOST_CHECK_EQUAL(
            HexStr(cn::abc::SerializeHeader(genesis)),
            "010000000000000000000000000000000000000000000000000000000000000000"
            "0000"
            "003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
            "dae5"
            "494dffff7f2002000000");
        BOOST_CHECK_EQUAL(
            HexStr(cn::abc::SerializeHeader(tip)),
            "00000020e0d8e43b1b228a5e07415ea057c06b3a8caf4e9d82c9af6c"
            "f04aa87229fa3e507c4ada19c5746e61699678baa1edc97f3258c613"
            "64d4f8614e6a0801896ee66773184d5fffff7f2000000000");
    }

    // Native: the batch form (bridge get_block_headers_by_range)
    const std::vector<cn::Bytes> headers = host.RawHeadersByRange(0, 100);
    BOOST_REQUIRE_EQUAL(headers.size(), 101);
    BOOST_CHECK_EQUAL(HexStr(headers[0]), HexStr(ser_genesis));
    BOOST_CHECK_EQUAL(HexStr(headers[100]), HexStr(ser_tip));
    for (int32_t height = 0; height <= 100; ++height) {
        BOOST_CHECK_EQUAL(
            HexStr(headers[height]),
            HexStr(cn::abc::SerializeHeader(*tip.GetAncestor(height))));
    }
    // Partial result past the tip
    const std::vector<cn::Bytes> partial = host.RawHeadersByRange(99, 200);
    BOOST_REQUIRE_EQUAL(partial.size(), 2);
    BOOST_CHECK_EQUAL(HexStr(partial[1]), HexStr(ser_tip));
    BOOST_CHECK(host.RawHeadersByRange(101, 200).empty());
    // Invalid ranges (the bridge threw invalid_block_range)
    BOOST_CHECK(host.RawHeadersByRange(-1, 10).empty());
    BOOST_CHECK(host.RawHeadersByRange(10, 9).empty());
}

BOOST_FIXTURE_TEST_CASE(test_bridge_broadcast_tx, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    CScript anyoneScript = CScript() << OP_1;
    CScript anyoneP2sh = GetScriptForDestination(ScriptHash(anyoneScript));
    CBlock coinsBlock =
        CreateAndProcessBlock({}, anyoneP2sh, &chainman.ActiveChainstate());
    mineBlocks(100);

    const CTransactionRef coinTx = coinsBlock.vtx[0];

    CScript scriptPad = CScript() << OP_RETURN << std::vector<uint8_t>(100);
    CMutableTransaction tx;
    tx.vin = {CTxIn(coinTx->GetId(), 0)};
    tx.vout = {
        CTxOut(coinTx->vout[0].nValue - 10000 * SATOSHI, scriptPad),
    };

    {
        // Failed broadcast: mempool rejected tx
        const cn::BroadcastResult result =
            host.Broadcast(Serialized(CTransaction(tx)), 10000);
        BOOST_CHECK(!result.ok);
        BOOST_CHECK(result.error.starts_with(
            "Transaction rejected by mempool: "
            "mandatory-script-verify-flag-failed (Operation "
            "not valid with the current stack size)"));
    }

    tx.vin[0].scriptSig =
        CScript() << std::vector(anyoneScript.begin(), anyoneScript.end());

    {
        // Failed broadcast from excessive fee (10000 > 9999).
        const cn::BroadcastResult result =
            host.Broadcast(Serialized(CTransaction(tx)), 9999);
        BOOST_CHECK(!result.ok);
        BOOST_CHECK_EQUAL(result.error,
                          "Fee exceeds maximum configured by user "
                          "(e.g. -maxtxfee, maxfeerate)");
    }

    {
        // Successful broadcast
        const cn::Bytes raw_tx = Serialized(CTransaction(tx));
        cn::BroadcastResult result = host.Broadcast(raw_tx, 10000);
        BOOST_CHECK(result.ok);
        BOOST_CHECK_EQUAL(result.error, "");
        BOOST_CHECK_EQUAL(HexStr(result.txid.b), HexStr(ToHash(tx.GetId()).b));
        // Broadcast again simply returns the hash (fee check skipped here)
        result = host.Broadcast(raw_tx, 9999);
        BOOST_CHECK(result.ok);
        BOOST_CHECK_EQUAL(HexStr(result.txid.b), HexStr(ToHash(tx.GetId()).b));
    }

    {
        // Native: undecodable bytes are an error result, not an exception
        const cn::BroadcastResult result = host.Broadcast(cn::Bytes{}, 10000);
        BOOST_CHECK(!result.ok);
        BOOST_CHECK(result.error.starts_with("DataStream::read(): end of data"));
    }
}

BOOST_FIXTURE_TEST_CASE(test_calc_fee, BasicTestingSetup) {
    // The bridge's default_max_raw_tx_fee_rate_per_kb(): 0.1 BCHA/kB or
    // 100'000 XEC/kB. Its calc_fee(size, rate) is CFeeRate(rate).GetFee(size);
    // with this default rate it is the host's CalcMaxFee(size)
    // (test_host_fees).
    BOOST_CHECK_EQUAL(node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK() / SATOSHI,
                      10'000'000);
    auto calc_fee = [](size_t num_bytes, int64_t sats_fee_per_kb) {
        return CFeeRate(sats_fee_per_kb * SATOSHI).GetFee(num_bytes) / SATOSHI;
    };
    BOOST_CHECK_EQUAL(calc_fee(1000, 1000), 1000);
    BOOST_CHECK_EQUAL(calc_fee(1000'000, 1000'000), 1000'000'000);
    BOOST_CHECK_EQUAL(calc_fee(123456789, 100), 12345678);
    BOOST_CHECK_EQUAL(calc_fee(2, 1), 1);
    BOOST_CHECK_EQUAL(calc_fee(0xdeadbeef, 0xcafe),
                      0xdeadbeefll * 0xcafell / 1000);
}

BOOST_FIXTURE_TEST_CASE(test_host_fees, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const AbcHost host = MakeHost(m_node);

    // CalcMaxFee == bridge calc_fee(size, default_max_raw_tx_fee_rate_per_kb)
    BOOST_CHECK_EQUAL(host.CalcMaxFee(1000), 10'000'000);
    BOOST_CHECK_EQUAL(host.CalcMaxFee(100), 1'000'000);
    BOOST_CHECK_EQUAL(host.CalcMaxFee(123), 1'230'000);
    BOOST_CHECK_EQUAL(host.CalcMaxFee(0xcafe), 0xcafell * 10'000'000 / 1000);
    for (size_t size : {0, 1, 2, 999, 1001, 100'000}) {
        BOOST_CHECK_EQUAL(
            host.CalcMaxFee(size),
            node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFee(size) / SATOSHI);
    }

    // EstimateFeeRateSatsPerKb / MinRelayFeeRateSatsPerKb: same formulas as
    // ChronikBridge::estimate_fee_rate_sats_per_kb / min_relay_fee...; time is
    // frozen so the hysteresis controller is queried at the same instant.
    SetMockTime(GetTime() + 1);
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const lotus::v2::FeeRateInfo fee_info =
        lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(now_ms);
    const int64_t hysteresis_rate =
        fee_info.rpc_admission_feerate_per_kcu >
                fee_info.consensus_floor_per_kcu
            ? static_cast<int64_t>(std::min<uint64_t>(
                  fee_info.recommended_sdk_feerate_per_kcu, INT64_MAX))
            : static_cast<int64_t>(std::min<uint64_t>(
                  fee_info.rpc_admission_feerate_per_kcu, INT64_MAX));
    const int64_t mempool_estimate =
        m_node.mempool->estimateFee().GetFeePerK() / SATOSHI;
    BOOST_CHECK_EQUAL(host.EstimateFeeRateSatsPerKb(),
                      std::max(mempool_estimate, hysteresis_rate));
    const int64_t base_relay =
        m_node.mempool->m_opts.min_relay_feerate.GetFeePerK() / SATOSHI;
    const int64_t rpc_rate = static_cast<int64_t>(std::min<uint64_t>(
        lotus::v2::GetGlobalFeeHysteresisController()
            .GetRpcAdmissionRatePerKCu(now_ms),
        INT64_MAX));
    BOOST_CHECK_EQUAL(host.MinRelayFeeRateSatsPerKb(),
                      std::max(base_relay, rpc_rate));
    BOOST_CHECK_GE(host.MinRelayFeeRateSatsPerKb(), base_relay);
    SetMockTime(0);

    // MempoolFeeRate: modified fee rate and virtual size of a mempool tx
    CScript anyoneScript = CScript() << OP_1;
    CScript anyoneP2sh = GetScriptForDestination(ScriptHash(anyoneScript));
    CBlock coinsBlock =
        CreateAndProcessBlock({}, anyoneP2sh, &chainman.ActiveChainstate());
    mineBlocks(100);
    const CTransactionRef coinTx = coinsBlock.vtx[0];
    CMutableTransaction tx;
    tx.vin = {CTxIn(
        coinTx->GetId(), 0,
        CScript() << std::vector(anyoneScript.begin(), anyoneScript.end()))};
    tx.vout = {
        CTxOut(coinTx->vout[0].nValue - 10000 * SATOSHI,
               CScript() << OP_RETURN << std::vector<uint8_t>(100)),
    };
    const cn::BroadcastResult result =
        host.Broadcast(Serialized(CTransaction(tx)), 10000);
    BOOST_REQUIRE_MESSAGE(result.ok, result.error);

    const std::optional<cn::FeeRateInfo> fee_rate =
        host.MempoolFeeRate(ToHash(tx.GetId()));
    BOOST_REQUIRE(fee_rate);
    {
        LOCK(m_node.mempool->cs);
        auto iter = m_node.mempool->GetIter(tx.GetId());
        BOOST_REQUIRE(iter);
        BOOST_CHECK_EQUAL(fee_rate->sats_per_kb,
                          (**iter)->GetModifiedFeeRate().GetFeePerK() /
                              SATOSHI);
        BOOST_CHECK_EQUAL(fee_rate->vsize,
                          uint32_t((**iter)->GetTxVirtualSize()));
        BOOST_CHECK_EQUAL(fee_rate->sats_per_kb,
                          CFeeRate(10000 * SATOSHI, fee_rate->vsize)
                                  .GetFeePerK() /
                              SATOSHI);
    }
    BOOST_CHECK(!host.MempoolFeeRate(cn::TxId{}));

    // Avalanche is disabled in tests: never finalized pre-consensus
    BOOST_CHECK(host.IsFinalizedPreConsensus(ToHash(tx.GetId())) ==
                std::optional<bool>(false));
    BOOST_CHECK(host.IsFinalizedPreConsensus(cn::TxId{}) ==
                std::optional<bool>(false));
}

BOOST_FIXTURE_TEST_CASE(test_decode_raw_tx, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin = {CTxIn(COutPoint(TxId(uint256S("0123456789abcdef0123456789abcdef"
                                             "0123456789abcdef0123456789abcdef")),
                               7),
                     CScript() << OP_1 << OP_2, 0x12345678)};
    mtx.vout = {CTxOut(1234 * SATOSHI, CScript() << OP_3),
                CTxOut(Amount::zero(), CScript() << OP_RETURN)};
    mtx.nLockTime = 456;
    const CTransaction tx(mtx);
    const cn::Bytes raw = Serialized(tx);

    const cn::DecodedTx decoded = host.DecodeRawTx(raw);
    BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.error);
    BOOST_CHECK_EQUAL(decoded.error, "");
    cn::Tx expected;
    expected.txid = ToHash(tx.GetId());
    expected.version = 2;
    expected.inputs = {{
        .prev_out = {ToHash(mtx.vin[0].prevout.GetTxId()), 7},
        .script = ToBytes(mtx.vin[0].scriptSig),
        .sequence = 0x12345678,
        .coin = std::nullopt, // spent coins are not resolved
    }};
    expected.outputs = {{1234, {0x53}}, {0, {0x6a}}};
    expected.locktime = 456;
    expected.wire_size = uint32_t(raw.size());
    CheckTxsEqual(decoded.tx, expected);
    BOOST_CHECK_EQUAL(HexStr(decoded.tx.raw), HexStr(raw));

    // Like the Rust TxMut::deser, trailing bytes are not an error; the txid
    // and wire_size are those of the decoded tx.
    cn::Bytes trailing = raw;
    trailing.push_back(0xff);
    const cn::DecodedTx decoded_trailing = host.DecodeRawTx(trailing);
    BOOST_REQUIRE(decoded_trailing.ok);
    CheckTxsEqual(decoded_trailing.tx, expected);
    BOOST_CHECK_EQUAL(HexStr(decoded_trailing.tx.raw), HexStr(trailing));

    // Errors carry the Rust DataError texts
    auto decode_error = [&](const cn::Bytes &bytes) {
        const cn::DecodedTx result = host.DecodeRawTx(bytes);
        BOOST_CHECK(!result.ok);
        return result.error;
    };
    BOOST_CHECK_EQUAL(decode_error({}),
                      "Invalid length, expected 4 bytes but got 0 bytes");
    BOOST_CHECK_EQUAL(decode_error({1, 0, 0}),
                      "Invalid length, expected 4 bytes but got 3 bytes");
    BOOST_CHECK_EQUAL(decode_error({1, 0, 0, 0}),
                      "Invalid length, expected 1 bytes but got 0 bytes");
    BOOST_CHECK_EQUAL(decode_error({1, 0, 0, 0, 1, 0xaa}),
                      "Invalid length, expected 32 bytes but got 1 bytes");
    cn::Bytes truncated(raw.begin(), raw.end() - 1);
    BOOST_CHECK_EQUAL(decode_error(truncated),
                      "Invalid length, expected 4 bytes but got 3 bytes");
}

BOOST_FIXTURE_TEST_CASE(test_host_process, TestChain100Setup) {
    const AbcHost host = MakeHost(m_node);
    BOOST_CHECK(!host.ShutdownRequested());
    BOOST_CHECK_EQUAL(host.FormatFullVersion(), FormatFullVersion());
    // SHA256("abc")
    const std::string abc = "abc";
    uint8_t out[32];
    host.Sha256(MakeUCharSpan(abc), out);
    BOOST_CHECK_EQUAL(
        HexStr(out),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // Doesn't deadlock or throw with an empty queue
    host.SyncWithIndexer();
    host.Log(cn::LogLevel::Info, "chronik_native_abc_tests log line");
    host.Log(cn::LogLevel::Debug, "chronik_native_abc_tests debug line");
}

// ---- bridgecompression_tests ----
// The host has no compression functions; the core codec owns them. Check the
// codec against the node's ScriptCompression (what the bridge exposed) and
// round trip it, using the node's secp256k1 for the uncompressed-P2PK hook.

static void CheckRoundtrip(const CScript &script, bool isSmaller) {
    const cn::Bytes compressed = cn::CompressScript(ToBytes(script));
    DataStream nodeCompressed{};
    nodeCompressed << Using<ScriptCompression>(script);
    BOOST_CHECK_EQUAL(HexStr(compressed), HexStr(nodeCompressed));
    if (isSmaller) {
        BOOST_CHECK(compressed.size() < script.size());
    } else {
        BOOST_CHECK(compressed.size() > script.size());
    }
    const cn::DecompressPubKeyFn decompress =
        [](cn::ByteView form) -> std::optional<cn::Bytes> {
        if (form.size() != 33 || (form[0] != 4 && form[0] != 5)) {
            return std::nullopt;
        }
        std::vector<uint8_t> vch(form.begin(), form.end());
        vch[0] = form[0] - 2;
        CPubKey pubkey(vch);
        if (!pubkey.Decompress()) {
            return std::nullopt;
        }
        return cn::Bytes(pubkey.begin(), pubkey.end());
    };
    const std::optional<cn::Bytes> decompressed =
        cn::DecompressScript(compressed, decompress);
    BOOST_REQUIRE(decompressed);
    BOOST_CHECK_EQUAL(HexStr(*decompressed), HexStr(script));
}

BOOST_FIXTURE_TEST_CASE(test_compression, BasicTestingSetup) {
    CheckRoundtrip(CScript()
                       << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x56)
                       << OP_EQUALVERIFY << OP_CHECKSIG,
                   true);

    CheckRoundtrip(CScript() << OP_HASH160 << std::vector<uint8_t>(20, 0x23)
                             << OP_EQUAL,
                   true);

    CheckRoundtrip(CScript() << std::vector<uint8_t>(33, 0x02) << OP_CHECKSIG,
                   true);

    CPubKey pubkey(std::vector<uint8_t>(33, 0x02));
    assert(pubkey.Decompress());
    CheckRoundtrip(CScript() << std::vector(pubkey.begin(), pubkey.end())
                             << OP_CHECKSIG,
                   true);

    CheckRoundtrip(CScript(), false);
    CheckRoundtrip(CScript() << OP_EQUAL << OP_VERIFY, false);
}

// Lotus V2 native outputs are indexed by their V2 encoding (the scriptPubKey
// a version 7 output carries, CTxOut::V2ScriptPubKey): the node's own
// EncodeOutput of the same fields, or `0x6a || frame` for a burn. Legacy
// outputs, which only a legacy (version 1 or 2) transaction carries, keep
// their script.
BOOST_AUTO_TEST_CASE(test_v2_native_output_frames) {
    auto fill = [](uint8_t b) {
        lotus::v2::Hash32 h;
        h.fill(b);
        return h;
    };
    // A version 7 transaction paying `out` (a spend: a coinbase pays no
    // token output); its V2 outputs get their V2 encoding as scriptPubKey at
    // construction.
    auto frame = [](const CTxOut &out) {
        CMutableTransaction mtx;
        mtx.nVersion = 7;
        mtx.vin = {CTxIn(TxId(uint256::ONE), 0)};
        mtx.vin[0].nFlags = 1;
        lotus::v2::BranchWitness witness;
        witness.script = {V2_OP_TRUE};
        mtx.vin[0].vWitnesses = {witness};
        mtx.vout = {out};
        return cn::abc::ConvertTx(/*is_coinbase=*/true, CTransaction(mtx), {})
            .outputs.at(0);
    };
    auto legacyFrame = [](const CTxOut &out) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin = {CTxIn(COutPoint(), CScript() << OP_0 << OP_0)};
        mtx.vout = {out};
        return cn::abc::ConvertTx(/*is_coinbase=*/true, CTransaction(mtx), {})
            .outputs.at(0);
    };
    auto encode = [](const lotus::v2::Output &o) {
        std::vector<uint8_t> bytes;
        std::string error;
        BOOST_REQUIRE_MESSAGE(lotus::v2::EncodeOutput(o, bytes, error), error);
        return HexStr(bytes);
    };

    // Token output with three branches, one path per branch.
    CTxOut token(1234 * SATOSHI, CScript());
    token.nFlags = 1;
    std::memset(token.tokenId.begin(), 0xaa, 32);
    token.vBranches = {fill(0x11), fill(0x22), fill(0x33)};
    token.vPaths = {{0}, {1}, {2}};
    lotus::v2::Output expected;
    expected.flags = 1;
    expected.value = 1234;
    expected.token_id = fill(0xaa);
    expected.branches = token.vBranches;
    expected.paths = {{0}, {1}, {2}};
    const cn::TxOutput tokenOut = frame(token);
    BOOST_CHECK_EQUAL(tokenOut.script.size(), 145u);
    BOOST_CHECK_EQUAL(HexStr(tokenOut.script), encode(expected));
    BOOST_CHECK_EQUAL(tokenOut.sats, 1234);

    // Native output with explicit paths.
    CTxOut native(5 * SATOSHI, CScript());
    native.vBranches = {fill(0x01), fill(0x02)};
    native.vPaths = {{0, 1}, {1}};
    expected = {};
    expected.value = 5;
    expected.branches = native.vBranches;
    expected.paths = native.vPaths;
    BOOST_CHECK_EQUAL(HexStr(frame(native).script), encode(expected));

    // Burns carry their public roots but no paths, behind OP_RETURN.
    CTxOut burn(7 * SATOSHI, CScript());
    burn.nFlags = 2;
    burn.vBranches = {fill(0x05)};
    expected = {};
    expected.flags = 2;
    expected.value = 7;
    expected.branches = burn.vBranches;
    BOOST_CHECK_EQUAL(HexStr(frame(burn).script), "6a" + encode(expected));

    // Legacy outputs keep their script, also an empty one.
    const CScript p2pkh = CScript() << OP_DUP << OP_HASH160
                                    << std::vector<uint8_t>(20, 3)
                                    << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(HexStr(legacyFrame(CTxOut(SATOSHI, p2pkh)).script),
                      HexStr(p2pkh));
    CTxOut empty(SATOSHI, CScript());
    BOOST_CHECK(legacyFrame(empty).script.empty());
}

// V2 inputs show their coinbase data or first branch witness script; mint
// inputs spend no coin and are not indexed. Legacy inputs show their
// scriptSig.
BOOST_AUTO_TEST_CASE(test_v2_input_scripts_and_mints) {
    CMutableTransaction coinbase;
    coinbase.nVersion = 7;
    coinbase.vin = {CTxIn()};
    coinbase.vin[0].nFlags = 2;
    coinbase.vin[0].fHasCoinbaseData = true;
    coinbase.vin[0].vCoinbaseData = {0x51, 0x52, 0x53};
    coinbase.vout = {V0LeafOutput(SATOSHI, CScript() << OP_1)};
    const cn::Tx cbTx =
        cn::abc::ConvertTx(/*is_coinbase=*/true, CTransaction(coinbase), {});
    BOOST_REQUIRE_EQUAL(cbTx.inputs.size(), 1u);
    BOOST_CHECK_EQUAL(HexStr(cbTx.inputs[0].script), "515253");

    CMutableTransaction tx;
    tx.nVersion = 7;
    // A mint input names a pseudo-outpoint with index 0.
    tx.vin = {CTxIn(TxId(uint256::ONE), 0),
              CTxIn(TxId(uint256S("02")), 0),
              CTxIn(TxId(uint256::ONE), 2)};
    lotus::v2::BranchWitness witness;
    witness.script = {0xac, 0x51};
    tx.vin[0].nFlags = 1;
    tx.vin[0].vWitnesses = {witness};
    lotus::v2::BranchWitness mintWitness;
    mintWitness.script = {V2_OP_TRUE};
    tx.vin[1].nFlags = 3; // mint
    tx.vin[1].vWitnesses = {mintWitness};
    lotus::v2::BranchWitness opTwo;
    opTwo.script = {0x52};
    tx.vin[2].nFlags = 1;
    tx.vin[2].vWitnesses = {opTwo};
    tx.vout = {V0LeafOutput(SATOSHI, CScript() << OP_1)};
    const std::vector<::Coin> coins = {
        ::Coin(CTxOut(10 * SATOSHI, CScript() << OP_3), 5, false),
        ::Coin(),
        ::Coin(CTxOut(20 * SATOSHI, CScript() << OP_4), 6, true),
    };
    const cn::Tx out =
        cn::abc::ConvertTx(/*is_coinbase=*/false, CTransaction(tx), coins);
    BOOST_REQUIRE_EQUAL(out.inputs.size(), 2u);
    BOOST_CHECK_EQUAL(HexStr(out.inputs[0].script), "ac51");
    BOOST_CHECK_EQUAL(out.inputs[0].prev_out.out_idx, 0u);
    BOOST_CHECK_EQUAL(out.inputs[0].coin->output.sats, 10);
    // The mint input is skipped; spent coins stay indexed by vin index.
    BOOST_CHECK_EQUAL(HexStr(out.inputs[1].script), "52");
    BOOST_CHECK_EQUAL(out.inputs[1].prev_out.out_idx, 2u);
    BOOST_CHECK_EQUAL(out.inputs[1].coin->output.sats, 20);
    BOOST_CHECK(out.inputs[1].coin->is_coinbase);

    // A legacy transaction's input shows its scriptSig.
    CMutableTransaction legacy;
    legacy.nVersion = 2;
    legacy.vin = {CTxIn(TxId(uint256::ONE), 3, CScript() << OP_2)};
    legacy.vout = {CTxOut(SATOSHI, CScript() << OP_1)};
    const cn::Tx legacyOut = cn::abc::ConvertTx(
        /*is_coinbase=*/false, CTransaction(legacy),
        {::Coin(CTxOut(30 * SATOSHI, CScript() << OP_5), 7, false)});
    BOOST_REQUIRE_EQUAL(legacyOut.inputs.size(), 1u);
    BOOST_CHECK_EQUAL(HexStr(legacyOut.inputs[0].script),
                      HexStr(CScript() << OP_2));
    BOOST_CHECK_EQUAL(legacyOut.inputs[0].coin->output.sats, 30);
}

BOOST_AUTO_TEST_SUITE_END()
