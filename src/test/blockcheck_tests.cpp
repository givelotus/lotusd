// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blockcheck_tests, BasicTestingSetup)

static void RunCheckOnBlockImpl(const GlobalConfig &config, const CBlock &block,
                                BlockValidationState &state, bool expected) {
    block.fChecked = false;
    bool fValid = CheckBlock(
        block, state, config.GetChainParams().GetConsensus(),
        BlockValidationOptions(config).withCheckPoW(false).withCheckMerkleRoot(
            false));

    BOOST_CHECK_EQUAL(fValid, expected);
    BOOST_CHECK_EQUAL(fValid, state.IsValid());
}

static void RunCheckOnBlock(const GlobalConfig &config, const CBlock &block) {
    BlockValidationState state;
    RunCheckOnBlockImpl(config, block, state, true);
}

static void RunCheckOnBlock(const GlobalConfig &config, const CBlock &block,
                            const std::string &reason) {
    BlockValidationState state;
    RunCheckOnBlockImpl(config, block, state, false);

    BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
}

static COutPoint InsecureRandOutPoint() {
    return COutPoint(TxId(InsecureRand256()), 0);
}

BOOST_AUTO_TEST_CASE(blockfail) {
    SelectParams(CBaseChainParams::MAIN);

    // Set max blocksize to default in case other tests left it dirty
    GlobalConfig config;
    config.SetMaxBlockSize(DEFAULT_MAX_BLOCK_SIZE);

    CBlock block;
    // nHeaderVersion 0 invalid, must be 1
    RunCheckOnBlock(config, block, "bad-blk-version");

    // nReserved must be 0
    block.nReserved = 1;
    RunCheckOnBlock(config, block, "bad-blk-reserved");

    // hashExtendedMetadata doesn't match
    block.nReserved = 0;
    block.nHeaderVersion = 1;
    RunCheckOnBlock(config, block, "bad-metadata-hash");

    // Excessive block size in header
    block.SetSize(config.GetMaxBlockSize() + 1);
    RunCheckOnBlock(config, block, "bad-blk-size");

    // Reset size to valid
    block.SetSize(0);

    // Block must have at least a coinbase tx
    block.vMetadata.clear();
    block.hashExtendedMetadata = SerializeHash(block.vMetadata);
    RunCheckOnBlock(config, block, "bad-cb-missing");

    CMutableTransaction tx;

    // Coinbase only.
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42 * SATOSHI;
    auto coinbaseTx = CTransaction(tx);

    block.vtx.resize(1);
    block.vtx[0] = MakeTransactionRef(tx);
    RunCheckOnBlock(config, block, "bad-blk-size-mismatch");

    block.SetSize(GetSerializeSize(block));
    RunCheckOnBlock(config, block);

    // No coinbase
    tx.vin[0].prevout = InsecureRandOutPoint();
    block.vtx[0] = MakeTransactionRef(tx);
    block.SetSize(GetSerializeSize(block));
    RunCheckOnBlock(config, block, "bad-cb-missing");

    // Invalid coinbase
    tx = CMutableTransaction(coinbaseTx);
    tx.vin[0].scriptSig.resize(0);
    block.vtx[0] = MakeTransactionRef(tx);
    block.SetSize(GetSerializeSize(block));
    RunCheckOnBlock(config, block, "bad-cb-length");

    // Oversize block.
    tx = CMutableTransaction(coinbaseTx);
    block.vtx[0] = MakeTransactionRef(tx);
    auto txSize = ::GetSerializeSize(tx, PROTOCOL_VERSION);
    auto emptySize = ::GetSerializeSize(CBlock());
    auto maxTxCount = ((DEFAULT_MAX_BLOCK_SIZE - emptySize) / txSize);

    for (size_t i = 1; i < maxTxCount; i++) {
        tx.vin[0].prevout = InsecureRandOutPoint();
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    block.SetSize(GetSerializeSize(block));

    // Check that at this point, we still accept the block.
    RunCheckOnBlock(config, block);

    // But reject it with one more transaction as it goes over the maximum
    // allowed block size.
    tx.vin[0].prevout = InsecureRandOutPoint();
    block.vtx.push_back(MakeTransactionRef(tx));
    block.SetSize(GetSerializeSize(block));
    RunCheckOnBlock(config, block, "bad-blk-size");
}

BOOST_AUTO_TEST_SUITE_END()
