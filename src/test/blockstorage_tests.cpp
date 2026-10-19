// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <config.h>
#include <lotus_v2/commitment.h>
#include <node/blockstorage.h>
#include <streams.h>
#include <undo.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using node::BlockManager;

BOOST_FIXTURE_TEST_SUITE(blockstorage_tests, TestChain100Setup)

static void CheckReadTx(const BlockManager &blockman, FlatFilePos pos,
                        const CTransaction &expected) {
    CMutableTransaction tx;
    BOOST_REQUIRE(blockman.ReadTxFromDisk(tx, pos));
    BOOST_CHECK_EQUAL(tx.GetId(), expected.GetId());
    BOOST_CHECK_EQUAL(tx.GetHash(), expected.GetHash());
    DataStream actual_bytes, expected_bytes;
    actual_bytes << tx;
    expected_bytes << expected;
    BOOST_CHECK_EQUAL_COLLECTIONS(actual_bytes.begin(), actual_bytes.end(),
                                  expected_bytes.begin(), expected_bytes.end());
}

static void CheckReadTxUndo(const BlockManager &blockman, FlatFilePos pos,
                            const std::vector<Coin> &expected) {
    CTxUndo txundo;
    BOOST_REQUIRE(blockman.ReadTxUndoFromDisk(txundo, pos));
    BOOST_REQUIRE_EQUAL(txundo.vprevout.size(), expected.size());
    for (size_t idx = 0; idx < expected.size(); ++idx) {
        const Coin &expectedCoin = expected[idx];
        const Coin &actualCoin = txundo.vprevout.at(idx);
        BOOST_CHECK(actualCoin.GetTxOut() == expectedCoin.GetTxOut());
        BOOST_CHECK_EQUAL(actualCoin.GetHeight(), expectedCoin.GetHeight());
        BOOST_CHECK_EQUAL(actualCoin.IsCoinBase(), expectedCoin.IsCoinBase());
        // Compare the complete codec, including any native lifetime/fee
        // metadata, without assuming a legacy Coin layout.
        DataStream actual_bytes, expected_bytes;
        actual_bytes << actualCoin;
        expected_bytes << expectedCoin;
        BOOST_CHECK_EQUAL_COLLECTIONS(actual_bytes.begin(), actual_bytes.end(),
                                      expected_bytes.begin(), expected_bytes.end());
    }
}

BOOST_AUTO_TEST_CASE(read_tx_data_from_disk) {
    ChainstateManager &chainman = *Assert(m_node.chainman);

    // Read 100 existing coinbase txs
    auto active_tip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    for (int32_t height = 0; height < 100; ++height) {
        CBlockIndex *pindex = active_tip->GetAncestor(height);
        CBlock block;
        BOOST_CHECK(chainman.m_blockman.ReadBlock(block, *pindex));
        const uint32_t header_and_count =
            uint32_t(::GetSerializeSize(block.GetBlockHeader()) +
                     GetSizeOfCompactSize(block.vtx.size()));
        CheckReadTx(
            chainman.m_blockman,
            WITH_LOCK(cs_main, return FlatFilePos(pindex->nFile,
                                                  pindex->nDataPos +
                                                      header_and_count)),
            *block.vtx[0]);
    }

    // Test with undo data
    const std::vector<uint8_t> program{0x4e}; // Native OP_1.
    const CScript destination(program.begin(), program.end());
    // A native spend needs a V2 coinbase; this fixture mines legacy ones by
    // default.
    m_coinbase_version = 7;
    CBlock coinsBlock = CreateAndProcessBlock({}, destination,
                                              &chainman.ActiveChainstate());
    const COutPoint prevout(coinsBlock.vtx[0]->GetId(), 0);
    const auto spent_coin = WITH_LOCK(cs_main,
        return chainman.ActiveChainstate().CoinsTip().GetCoin(prevout));
    BOOST_REQUIRE(spent_coin.has_value());
    BOOST_REQUIRE_EQUAL(spent_coin->GetHeight(), 101U);
    BOOST_REQUIRE(spent_coin->GetTxOut() == coinsBlock.vtx[0]->vout[0]);
    BOOST_REQUIRE(spent_coin->IsCoinBase());
    mineBlocks(100);
    CMutableTransaction tx;
    tx.nVersion = 7;
    tx.fHasV2Lock = true;
    tx.nV2Lock = 0;
    CTxIn input(prevout);
    input.nFlags = 1;
    input.nPathIndex = 0;
    lotus::v2::BranchWitness witness;
    witness.script = program;
    input.vWitnesses = {witness};
    tx.vin.push_back(std::move(input));
    lotus::v2::Output output;
    output.value = (spent_coin->GetTxOut().nValue - 10000 * SATOSHI) / SATOSHI;
    output.branches = {lotus::v2::BranchLeaf(program)};
    output.paths = {{0}};
    tx.vout.push_back(CTxOut::FromV2Output(output));
    CBlock testBlock = CreateAndProcessBlock({tx}, destination,
                                             &chainman.ActiveChainstate());

    CBlockIndex *ptest =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    BOOST_REQUIRE_EQUAL(ptest->GetBlockHash(), testBlock.GetHash());

    const uint32_t header_and_count =
        uint32_t(::GetSerializeSize(testBlock.GetBlockHeader()) +
                 GetSizeOfCompactSize(testBlock.vtx.size()));
    BOOST_CHECK_EQUAL(::GetSerializeSize(testBlock.GetBlockHeader()), 134U);
    BOOST_REQUIRE_EQUAL(testBlock.vtx.size(), 2U);
    // Check coinbase tx
    CheckReadTx(chainman.m_blockman,
                WITH_LOCK(cs_main,
                          return FlatFilePos(ptest->nFile,
                                             ptest->nDataPos + header_and_count)),
                *testBlock.vtx[0]);
    // Check 2nd tx
    CheckReadTx(
        chainman.m_blockman,
        WITH_LOCK(cs_main,
                  return FlatFilePos(ptest->nFile,
                                     ptest->nDataPos + header_and_count +
                                         ::GetSerializeSize(testBlock.vtx[0]))),
        *testBlock.vtx[1]);
    // Check undo data of 2nd tx
    // + 1 = CompactSize
    CheckReadTxUndo(chainman.m_blockman,
                    WITH_LOCK(cs_main, return FlatFilePos(ptest->nFile,
                                                          ptest->nUndoPos + 1)),
                    {*spent_coin});
}

BOOST_AUTO_TEST_CASE(read_tx_data_from_disk_bad) {
    CMutableTransaction tx;
    CTxUndo txundo;
    ChainstateManager &chainman = *Assert(m_node.chainman);
    BOOST_CHECK(
        !chainman.m_blockman.ReadTxFromDisk(tx, FlatFilePos(0x7fffffff, 0)));
    BOOST_CHECK(
        !chainman.m_blockman.ReadTxFromDisk(tx, FlatFilePos(0, 0x7fffffff)));
    BOOST_CHECK(!chainman.m_blockman.ReadTxUndoFromDisk(
        txundo, FlatFilePos(0x7fffffff, 0)));
    BOOST_CHECK(!chainman.m_blockman.ReadTxUndoFromDisk(
        txundo, FlatFilePos(0, 0x7fffffff)));
}

BOOST_AUTO_TEST_SUITE_END()
