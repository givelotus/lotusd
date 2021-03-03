// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

#include <minerfund.h>
#include <pow/pow.h>

namespace miner_tests {
struct MinerTestingSetup : public TestingSetup {
    void TestPackageSelection(const CChainParams &chainparams,
                              const CScript &scriptPubKey,
                              const std::vector<CTransactionRef> &txFirst)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    bool TestSequenceLocks(const CTransaction &tx, int flags)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs) {
        return CheckSequenceLocks(*m_node.mempool, tx, flags);
    }
    BlockAssembler AssemblerForTest(const CChainParams &params);
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);

BlockAssembler MinerTestingSetup::AssemblerForTest(const CChainParams &params) {
    BlockAssembler::Options options;
    options.blockMinFeeRate = blockMinFeeRate;
    return BlockAssembler(params, *m_node.mempool, options);
}

constexpr static struct {
    uint8_t extranonce;
    uint32_t nonce;
} blockinfo[] = {
    {1,  0x628b1e49}, {2,  0xac068108}, {11, 0x719c2619}, {2, 0x91559120},
    {5,  0xf5037f52}, {9,  0xa98a3c5a}, {4,  0x8816f72d}, {3, 0xe0e9b66e},
    {2,  0x8611e5e9}, {5,  0x8a36a2ae}, {5,  0x7ea8d188}, {2, 0x6aa0e1c6},
    {5,  0x0062430b}, {2,  0xf03f169f}, {2,  0x4eba97db}, {4, 0xc35b347f},
    {2,  0x52c5b0f0}, {5,  0x4e3c227d}, {2,  0x36f34401}, {5, 0x0a52608c},
    {6,  0x66967a24}, {2,  0xa5a0b36b}, {2,  0x9349f573}, {4, 0x5dddf692},
    {8,  0x944547b4}, {8,  0x435da16c}, {2,  0x77f07522}, {3, 0xaf9c007a},
    {2,  0xa434d282}, {2,  0x7d93d231}, {8,  0x9a7c414e}, {9, 0x6c69144d},
    {13, 0x8eb7cb31}, {5,  0x7e224d22}, {3,  0x701fa359}, {2, 0xb7dbf21f},
    {5,  0x2945ae64}, {10, 0xfb2dbf18}, {2,  0xe581e82a}, {2, 0xa6573b53},
    {8,  0x03e5075f}, {2,  0x65c9a263}, {3,  0xccb0a913}, {3, 0x38f3b43a},
    {7,  0x1b946e22}, {6,  0x68ef7276}, {5,  0x8606b322}, {3, 0x5e73626c},
    {2,  0xd7d91958}, {4,  0x2339a18e}, {2,  0x361c1145}, {2, 0xbd968835},
    {3,  0x79499e34}, {2,  0xf4ba55bb}, {2,  0xfe638677}, {2, 0x19840618},
    {2,  0x1ae4974c}, {3,  0xe35a03c},  {3,  0xaa03f5d6}, {2, 0x7f6cd731},
    {3,  0x6f7c1755}, {9,  0x6250786b}, {3,  0x93ddc561}, {8, 0xf4fff27c},
    {7,  0xae1ee12a}, {6,  0xe94b411f}, {10, 0x5e5db777}, {2, 0xef97a20b},
    {3,  0x52dda1ae}, {2,  0x6a51e635}, {4,  0xe601b236}, {2, 0x541cdcd0},
    {2,  0x53e3a77b}, {2,  0xd6b3b644}, {2,  0x7636046d}, {4, 0xdf3fa0d0},
    {2,  0x38c940e3}, {5,  0xdbfca258}, {3,  0xf613aaa5}, {8, 0xa98a7a13},
    {5,  0x2bf7a509}, {2,  0x31b5c0b8}, {2,  0xd052cc03}, {2, 0x3b48dc21},
    {4,  0x51c76898}, {2,  0x753def12}, {4,  0x17436513}, {2, 0xac80fb6d},
    {2,  0xc102c921}, {3,  0x55ce221b}, {3,  0xea4d7949}, {2, 0xc5b5fdb3},
    {2,  0xc9b382e4}, {2,  0x1dff5208}, {2,  0xae27e31f}, {5, 0x8ff6b4ca},
    {6,  0xe488427f}, {4,  0xa54a73cf}, {2,  0xac55b7b9}, {3, 0x39eff568},
    {3,  0x39cbf2b9}, {20, 0x9735c689}, {2,  0x638102bf}, {4, 0xe8acaf83},
    {7,  0x658828b7}, {2,  0xc0017647}, {2,  0x617a518b}, {6, 0x3f87930e},
    {3,  0x38bc5102}, {2,  0x31a480d5},
};

const Amount BLOCKSUBSIDY = 50 * COIN;
const Amount MINERREWARD = BLOCKSUBSIDY - GetMinerFundAmount(BLOCKSUBSIDY);
const uint64_t MINERREWARD_INT = MINERREWARD / SATOSHI;
const Amount LOWFEE = CENT;
const Amount HIGHFEE = COIN;
const Amount HIGHERFEE = 4 * COIN;

static CBlockIndex CreateBlockIndex(int nHeight)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = ::ChainActive().Tip();
    return index;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(
    const CChainParams &chainparams, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000) * SATOSHI;
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(true)
                                     .FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 10000) * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(10000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(true)
                                     .FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(50000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(false)
                                     .FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == parentTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == mediumFeeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == highFeeTxId);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI;
    TxId freeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(Amount::zero()).FromTx(tx));
    size_t freeTxSize = GetSerializeSize(tx, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee (assuming 1 child tx of the same size).
    Amount feeToUse = blockMinFeeRate.GetFee(2 * freeTxSize) - SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue =
        int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI - feeToUse;
    TxId lowFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    // Verify that the free tx and the low fee tx didn't get selected.
    for (const auto &txn : pblocktemplate->block.vtx) {
        BOOST_CHECK(txn->GetId() != freeTxId);
        BOOST_CHECK(txn->GetId() != lowFeeTxId);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee. Remove the low fee
    // transaction and replace with a higher fee transaction
    m_node.mempool->removeRecursive(CTransaction(tx),
                                    MemPoolRemovalReason::REPLACED);
    // Now we should be just over the min relay fee.
    tx.vout[0].nValue -= 2 * SATOSHI;
    lowFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(feeToUse + 2 * SATOSHI).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == parentTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == lowFeeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == mediumFeeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[4]->GetId() == freeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[5]->GetId() == highFeeTxId);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block. Add a
    // 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 0);
    tx.vout.resize(2);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 100000000) * SATOSHI;
    // 1BCC output.
    tx.vout[1].nValue = 100000000 * SATOSHI;
    TxId freeTxId2 = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(Amount::zero()).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself.
    tx.vin[0].prevout = COutPoint(freeTxId2, 0);
    tx.vout.resize(1);
    feeToUse = blockMinFeeRate.GetFee(freeTxSize);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 100000000) * SATOSHI - feeToUse;
    TxId lowFeeTxId2 = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);

    // Verify that this tx isn't selected.
    for (const auto &txn : pblocktemplate->block.vtx) {
        BOOST_CHECK(txn->GetId() != freeTxId2);
        BOOST_CHECK(txn->GetId() != lowFeeTxId2);
    }

    // This tx will be mineable, and should cause lowFeeTxId2 to be selected as
    // well.
    tx.vin[0].prevout = COutPoint(freeTxId2, 1);
    // 10k satoshi fee.
    tx.vout[0].nValue = (100000000 - 10000) * SATOSHI;
    m_node.mempool->addUnchecked(entry.Fee(10000 * SATOSHI).FromTx(tx));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == lowFeeTxId2);
}

void TestCoinbaseMessageEB(uint64_t eb, std::string cbmsg,
                           const CTxMemPool &mempool) {
    GlobalConfig config;
    config.SetMaxBlockSize(eb);

    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        BlockAssembler(config, mempool).CreateNewBlock(scriptPubKey);

    CBlock *pblock = &pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(pblock, ::ChainActive().Tip(), config.GetMaxBlockSize(),
                        extraNonce);
    unsigned int nHeight = ::ChainActive().Tip()->nHeight + 1;
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig ==
                (CScript() << nHeight << CScriptNum(extraNonce) << vec));
}

// Coinbase scriptSig has to contains the correct EB value
// converted to MB, rounded down to the first decimal
BOOST_AUTO_TEST_CASE(CheckCoinbase_EB) {
    TestCoinbaseMessageEB(1000001, "/EB1.0/", *m_node.mempool);
    TestCoinbaseMessageEB(2000000, "/EB2.0/", *m_node.mempool);
    TestCoinbaseMessageEB(8000000, "/EB8.0/", *m_node.mempool);
    TestCoinbaseMessageEB(8320000, "/EB8.3/", *m_node.mempool);
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity) {
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    CMutableTransaction tx;
    CScript script;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11 * SATOSHI;
    entry.nHeight = 11;

    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 110 blocks :)
    static_assert(sizeof(blockinfo) / sizeof(*blockinfo) == 110,
                  "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (size_t i = 0; i < sizeof(blockinfo) / sizeof(*blockinfo); ++i) {
        // pointer for convenience.
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            pblock->nVersion = 1;
            pblock->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            int nHeight = ::ChainActive().Height() + 1;
            // Make sure coinbase is BIP34 compliant
            txCoinbase.vin[0].scriptSig = CScript() << nHeight << OP_0;
            txCoinbase.vin[0].scriptSig.push_back(blockinfo[i].extranonce);
            txCoinbase.vout[0].scriptPubKey = CScript();
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0) {
                baseheight = ::ChainActive().Height();
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(pblock->vtx[0]);
            }
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->nNonce = blockinfo[i].nonce;
            CBlockHeader header = pblock->GetBlockHeader();
            pblock->nBits = GetNextWorkRequired(::ChainActive().Tip(), &header, chainparams);
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlock(config, shared_pblock, true, nullptr));
        pblock->hashPrevBlock = pblock->GetHash();
    }

    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    // Just to make sure we can still make simple blocks.
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // block size > limit
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);

    tx.vout.resize(1);
    tx.vout[0].nValue = MINERREWARD;
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<uint8_t> vchData(520);
    for (unsigned int i = 0; i < 18; ++i) {
        tx.vout[0].scriptPubKey << vchData << OP_DROP;
    }

    for (unsigned int i = 0; i < 128; ++i) {
        tx.vout[0].nValue -= LOWFEE;
        const TxId txid = tx.GetId();
        // Only first tx spends coinbase.
        bool spendsCoinbase = i == 0;
        m_node.mempool->addUnchecked(entry.Fee(LOWFEE)
                                         .Time(GetTime())
                                         .SpendsCoinbase(spendsCoinbase)
                                         .FromTx(tx));
        tx.vin[0].prevout = COutPoint(txid, 0);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear();

    // Orphan in mempool, template creation fails.
    m_node.mempool->addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear();

    // Child with higher priority than parent.
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    TxId txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 0);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue = tx.vout[0].nValue + MINERREWARD - HIGHERFEE;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear();

    // Coinbase in mempool, template creation fails.
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = Amount::zero();
    txid = tx.GetId();
    // Give it a fee so it'll get mined.
    m_node.mempool->addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-tx-coinbase
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-tx-coinbase"));
    m_node.mempool->clear();

    // Double spend txn pair in mempool, template creation fails.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear();

    // Subsidy changing.
    int nHeight = ::ChainActive().Height();
    // Create an actual 209999-long block chain (without valid blocks).
    while (::ChainActive().Tip()->nHeight < 209999) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (::ChainActive().Tip()->nHeight < 210000) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = MINERREWARD - LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript()
                          << std::vector<uint8_t>(script.begin(), script.end());
    tx.vout[0].nValue -= LOWFEE;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw blk-bad-inputs
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("blk-bad-inputs"));
    m_node.mempool->clear();

    // Delete the dummy blocks again.
    while (::ChainActive().Tip()->nHeight > nHeight) {
        CBlockIndex *del = ::ChainActive().Tip();
        ::ChainActive().SetTip(del->pprev);
        ::ChainstateActive().CoinsTip().SetBestBlock(
            del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);
    uint32_t flags = 0;
    // height map
    std::vector<int> prevheights;

    // Relative height locked.
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    // Only 1 transaction.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    // TODO: These tests seem to be broken regarding MTP, enforcing BIP68 from
    // genesis makes relative locktime fail when creating a block.
    // Now, we just make the tx sequence BIP68 compliant before adding it to
    // the mempool and rely only on TestSequenceLocks for now.
    // This test is a mess, we're using tx to both do tests on the tx itself
    // and for adding txs to the mempool.
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight - 1;
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    // txFirst[0] is the 2nd block
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight + 1;
    txid = tx.GetId();

    const Consensus::Params &params = chainparams.GetConsensus();

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    // Sequence locks pass on 2nd block.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, prevheights,
                      CreateBlockIndex(::ChainActive().Tip()->nHeight + 2)));

    // Relative time locked.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    // TODO: These tests seem to be broken, enforcing BIP68 from genesis
    // makes relative locktime fail when creating a block.
    // We only rely on TestSequenceLocks for now.
    tx.vin[0].nSequence = 0;
    prevheights[0] = baseheight + 2;
    m_node.mempool->addUnchecked(entry.Time(GetTime()).FromTx(tx));
    // txFirst[1] is the 3rd block.
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
                          (((::ChainActive().Tip()->GetMedianTimePast() + 1 -
                             ::ChainActive()[1]->GetMedianTimePast()) >>
                            CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
                           1);
    txid = tx.GetId();

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Trick the MedianTimePast.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime += 512;
    }
    // Sequence locks pass 512 seconds later.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, prevheights,
                      CreateBlockIndex(::ChainActive().Tip()->nHeight + 1)));
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Undo tricked MTP.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime -= 512;
    }

    // Absolute height locked.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = ::ChainActive().Tip()->nHeight + 1;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        TxValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes on 2nd block.
        TxValidationState state;
        int64_t nMedianTimePast = ::ChainActive().Tip()->GetMedianTimePast();
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 2,
            nMedianTimePast, nMedianTimePast));
    }

    // Absolute time locked.
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 0);
    tx.nLockTime = ::ChainActive().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        TxValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes 1 second later.
        TxValidationState state;
        int64_t nMedianTimePast =
            ::ChainActive().Tip()->GetMedianTimePast() + 1;
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 1,
            nMedianTimePast, nMedianTimePast));
    }

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout = COutPoint(txid, 0);
    prevheights[0] = ::ChainActive().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

    // None of the of the absolute height/time locked tx should have made it
    // into the template because we still check IsFinalTx in CreateNewBlock, but
    // relative locked txs will if inconsistently added to g_mempool. For now
    // these will still generate a valid template until BIP68 soft fork.
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3UL);
    // However if we advance height by 1 and time by 512, all of them should be
    // mined.
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Trick the MedianTimePast.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime += 512;
    }
    ::ChainActive().Tip()->nHeight++;
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);

    ::ChainActive().Tip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear();

    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    fCheckpointsEnabled = true;
}

void CheckBlockMaxSize(const Config &config, const CTxMemPool &mempool,
                       uint64_t size, uint64_t expected) {
    gArgs.ForceSetArg("-blockmaxsize", ToString(size));

    BlockAssembler ba(config, mempool);
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), expected);
}

BOOST_AUTO_TEST_CASE(BlockAssembler_construction) {
    GlobalConfig config;

    // We are working on a fake chain and need to protect ourselves.
    LOCK(cs_main);

    // Test around historical 1MB (plus one byte because that's mandatory)
    config.SetMaxBlockSize(ONE_MEGABYTE + 1);
    CheckBlockMaxSize(config, *m_node.mempool, 0, 1000);
    CheckBlockMaxSize(config, *m_node.mempool, 1000, 1000);
    CheckBlockMaxSize(config, *m_node.mempool, 1001, 1001);
    CheckBlockMaxSize(config, *m_node.mempool, 12345, 12345);

    CheckBlockMaxSize(config, *m_node.mempool, ONE_MEGABYTE - 1001,
                      ONE_MEGABYTE - 1001);
    CheckBlockMaxSize(config, *m_node.mempool, ONE_MEGABYTE - 1000,
                      ONE_MEGABYTE - 1000);
    CheckBlockMaxSize(config, *m_node.mempool, ONE_MEGABYTE - 999,
                      ONE_MEGABYTE - 999);
    CheckBlockMaxSize(config, *m_node.mempool, ONE_MEGABYTE,
                      ONE_MEGABYTE - 999);

    // Test around default cap
    config.SetMaxBlockSize(DEFAULT_MAX_BLOCK_SIZE);

    // Now we can use the default max block size.
    CheckBlockMaxSize(config, *m_node.mempool, DEFAULT_MAX_BLOCK_SIZE - 1001,
                      DEFAULT_MAX_BLOCK_SIZE - 1001);
    CheckBlockMaxSize(config, *m_node.mempool, DEFAULT_MAX_BLOCK_SIZE - 1000,
                      DEFAULT_MAX_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, *m_node.mempool, DEFAULT_MAX_BLOCK_SIZE - 999,
                      DEFAULT_MAX_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, *m_node.mempool, DEFAULT_MAX_BLOCK_SIZE,
                      DEFAULT_MAX_BLOCK_SIZE - 1000);

    // If the parameter is not specified, we use
    // DEFAULT_MAX_GENERATED_BLOCK_SIZE
    {
        gArgs.ClearForcedArg("-blockmaxsize");
        BlockAssembler ba(config, *m_node.mempool);
        BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(),
                          DEFAULT_MAX_GENERATED_BLOCK_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(TestCBlockTemplateEntry) {
    const CTransaction tx;
    CTransactionRef txRef = MakeTransactionRef(tx);
    CBlockTemplateEntry txEntry(txRef, 1 * SATOSHI, 10);
    BOOST_CHECK_MESSAGE(txEntry.tx == txRef, "Transactions did not match");
    BOOST_CHECK_EQUAL(txEntry.fees, 1 * SATOSHI);
    BOOST_CHECK_EQUAL(txEntry.sigOpCount, 10);
}

BOOST_AUTO_TEST_SUITE_END()
