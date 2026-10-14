// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/system.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <minerfund.h>
#include <node/blockfitter.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <script/standard.h>
#include <timedata.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

using node::BlockAssembler;
using node::BlockFitter;
using node::CBlockTemplate;
using node::CBlockTemplateEntry;

namespace miner_tests {
struct MinerTestingSetup : public AvalancheTestingSetup {
    bool m_preconsensus{false};

    MinerTestingSetup(const std::vector<const char *> &extra_args = {})
        : AvalancheTestingSetup(ChainType::MAIN, extra_args) {}

    void TestPackageSelection(const CChainParams &chainparams,
                              const CScript &scriptPubKey,
                              const std::vector<CTransactionRef> &txFirst)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    void TestBasicMining(const CChainParams &chainparams,
                         const CScript &scriptPubKey,
                         const std::vector<CTransactionRef> &txFirst,
                         int baseheight)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    void TestPrioritisedMining(const CChainParams &chainparams,
                               const CScript &scriptPubKey,
                               const std::vector<CTransactionRef> &txFirst)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    void CreateNewBlock_validity();
    bool TestSequenceLocks(const CTransaction &tx)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs) {
        CCoinsViewMemPool view_mempool(
            &m_node.chainman->ActiveChainstate().CoinsTip(), *m_node.mempool);
        CBlockIndex *tip{m_node.chainman->ActiveChain().Tip()};
        const std::optional<LockPoints> lock_points{
            CalculateLockPointsAtTip(tip, view_mempool, tx)};
        return lock_points.has_value() &&
               CheckSequenceLocksAtTip(tip, *lock_points);
    }
    BlockAssembler AssemblerForTest(const CChainParams &params);

    void AddUnchecked(CTxMemPoolEntryRef entry)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_node.mempool->cs) {
        AssertLockHeld(cs_main);
        AssertLockHeld(m_node.mempool->cs);

        ChainstateManager &chainman = *Assert(m_node.chainman);
        const Consensus::Params &params = chainman.GetConsensus();
        const CBlockIndex &tip = *Assert(chainman.ActiveTip());

        m_node.mempool->addUnchecked(entry);
        if (m_preconsensus) {
            std::vector<TxId> dummy;
            m_node.mempool->setAvalancheFinalized(entry, params, tip, dummy);
        }
    }
};

struct MinerTestingSetupNoCheckpoints : public MinerTestingSetup {
    MinerTestingSetupNoCheckpoints() : MinerTestingSetup({"-checkpoints=0"}) {}
};

struct PreconsensusMinerTestingSetupNoCheckpoints : public MinerTestingSetup {
    PreconsensusMinerTestingSetupNoCheckpoints()
        : MinerTestingSetup({"-checkpoints=0"}) {
        m_preconsensus = true;
    }
};

} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);

BlockAssembler MinerTestingSetup::AssemblerForTest(const CChainParams &params) {
    BlockFitter::Options fitter_options;
    fitter_options.blockMinFeeRate = blockMinFeeRate;
    BlockAssembler::Options assembler_options;
    assembler_options.add_finalized_txs = m_preconsensus;
    return BlockAssembler{
        BlockFitter(fitter_options), m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(), assembler_options, m_node.avalanche.get()};
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
// Miner reward after 8% fund deduction (LEGACY_MINER_FUND_RATIO, before Cowperthwaite activation)
const Amount MINERREWARD = BLOCKSUBSIDY - 8 * BLOCKSUBSIDY / 100;
const uint64_t MINERREWARD_INT = MINERREWARD / SATOSHI;
const Amount LOWFEE = CENT;
const Amount HIGHFEE = COIN;
const Amount HIGHERFEE = 4 * COIN;

static CBlockIndex CreateBlockIndex(int nHeight, CBlockIndex *active_chain_tip)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = active_chain_tip;
    return index;
}

// Test suite for feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(
    const CChainParams &chainparams, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected before a higher fee
    // transaction when the high-fee tx has a low fee parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000) * SATOSHI;
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    AddUnchecked(entry.Fee(1000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 10000) * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    AddUnchecked(entry.Fee(10000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    AddUnchecked(entry.Fee(50000 * SATOSHI).Time(GetTime()).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);

    // Since we use the mainnet for the test, the ordering is not enforced by
    // CTOR.
    // But using preconsensus, CTOR is always enforced.
    std::vector<TxId> txids = {mediumFeeTxId, parentTxId, highFeeTxId};
    if (m_preconsensus) {
        std::sort(txids.begin(), txids.end());
    }
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == txids[0]);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == txids[1]);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == txids[2]);

    // Test that a tranactions with ancestor below the block min tx fee doesn't
    // get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI;
    TxId freeTxId = tx.GetId();
    AddUnchecked(entry.Fee(Amount::zero()).FromTx(tx));
    BOOST_CHECK(!m_node.mempool->isAvalancheFinalizedPreConsensus(freeTxId));

    // Add a child transaction with high fee.
    Amount feeToUse = 50000 * SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue =
        int64_t(MINERREWARD_INT - 1000 - 50000) * SATOSHI - feeToUse;
    TxId highFeeDecendantTxId = tx.GetId();
    AddUnchecked(entry.Fee(feeToUse).FromTx(tx));
    BOOST_CHECK(!m_node.mempool->isAvalancheFinalizedPreConsensus(
        highFeeDecendantTxId));
    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);

    // Verify that the free tx and its high fee descendant tx didn't get
    // selected.
    for (const auto &txn : pblocktemplate->block.vtx) {
        BOOST_CHECK(txn->GetId() != freeTxId);
        BOOST_CHECK(txn->GetId() != highFeeDecendantTxId);
    }
}

static void TestCoinbaseMessageEB(uint64_t eb, std::string cbmsg,
                                  const CTxMemPool &mempool,
                                  const ChainstateManager &chainman) {
    GlobalConfig config;
    config.SetMaxBlockSize(eb);

    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        BlockAssembler{config, chainman.ActiveChainstate(), &mempool}
            .CreateNewBlock(scriptPubKey);

    CBlock *pblock = &pblocktemplate->block;

    CBlockIndex *active_chain_tip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    createCoinbaseAndMerkleRoot(pblock, active_chain_tip,
                                config.GetMaxBlockSize());

    unsigned int nHeight = active_chain_tip->nHeight + 1;
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig ==
                (CScript() << nHeight << vec));
}

// Coinbase scriptSig has to contains the correct EB value
// converted to MB, rounded down to the first decimal
BOOST_AUTO_TEST_CASE(CheckCoinbase_EB) {
    TestCoinbaseMessageEB(1000001, "/EB1.0/", *m_node.mempool,
                          *m_node.chainman);
    TestCoinbaseMessageEB(2000000, "/EB2.0/", *m_node.mempool,
                          *m_node.chainman);
    TestCoinbaseMessageEB(8000000, "/EB8.0/", *m_node.mempool,
                          *m_node.chainman);
    TestCoinbaseMessageEB(8320000, "/EB8.3/", *m_node.mempool,
                          *m_node.chainman);
}

void MinerTestingSetup::TestBasicMining(
    const CChainParams &chainparams, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst, int baseheight) {
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11 * SATOSHI;
    entry.nHeight = 11;

    // Just to make sure we can still make simple blocks.
    auto pblocktemplate =
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

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
        AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
        tx.vin[0].prevout = COutPoint(txid, 0);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Orphan in mempool, template creation fails. Note that finalizing it will
    // finalize the parent, so we skip this test when preconsensus is enabled
    if (!m_preconsensus) {
        AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
        BOOST_CHECK_EXCEPTION(
            AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
            std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Child with higher priority than parent.
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    TxId txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 0);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue = tx.vout[0].nValue + MINERREWARD - HIGHERFEE;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHERFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Coinbase in mempool, template creation fails.
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = Amount::zero();
    txid = tx.GetId();
    // Give it a fee so it'll get mined.
    AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    // Should throw bad-tx-coinbase
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-tx-coinbase"));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Double spend txn pair in mempool, template creation fails.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Subsidy changing.
    int nHeight = m_node.chainman->ActiveHeight();
    // Create an actual 209999-long block chain (without valid blocks).
    while (m_node.chainman->ActiveHeight() < 209999) {
        CBlockIndex *prev = m_node.chainman->ActiveTip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(m_rng.rand256());
        m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(
            next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        m_node.chainman->ActiveChain().SetTip(*next);
    }
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (m_node.chainman->ActiveHeight() < 210000) {
        CBlockIndex *prev = m_node.chainman->ActiveTip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(m_rng.rand256());
        m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(
            next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        m_node.chainman->ActiveChain().SetTip(*next);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = MINERREWARD - LOWFEE;
    CScript script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
    txid = tx.GetId();
    AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript()
                          << std::vector<uint8_t>(script.begin(), script.end());
    tx.vout[0].nValue -= LOWFEE;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    // Should throw blk-bad-inputs
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error,
        HasReason(
            "mandatory-script-verify-flag-failed (Script evaluated without "
            "error but finished with a false/empty top stack element)"));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Delete the dummy blocks again.
    while (m_node.chainman->ActiveHeight() > nHeight) {
        CBlockIndex *del = m_node.chainman->ActiveTip();
        m_node.chainman->ActiveChain().SetTip(*Assert(del->pprev));
        m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(
            del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(m_node.chainman->ActiveTip()->GetMedianTimePast() + 1);
    const uint32_t flags{0};
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
    tx.vin[0].nSequence = m_node.chainman->ActiveHeight() - 1;
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = MINERREWARD - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    // txFirst[0] is the 2nd block
    tx.vin[0].nSequence = m_node.chainman->ActiveHeight() + 1;
    txid = tx.GetId();

    const Consensus::Params &params = chainparams.GetConsensus();

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            *Assert(m_node.chainman->ActiveTip()), params, CTransaction{tx},
            state));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}));

    // Sequence locks pass on 2nd block.
    BOOST_CHECK(
        SequenceLocks(CTransaction{tx}, flags, prevheights,
                      CreateBlockIndex(m_node.chainman->ActiveHeight() + 2,
                                       m_node.chainman->ActiveTip())));

    // Relative time locked.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    // TODO: These tests seem to be broken, enforcing BIP68 from genesis
    // makes relative locktime fail when creating a block.
    // We only rely on TestSequenceLocks for now.
    tx.vin[0].nSequence = 0;
    prevheights[0] = baseheight + 2;
    AddUnchecked(entry.Time(GetTime()).FromTx(tx));
    // txFirst[1] is the 3rd block.
    tx.vin[0].nSequence =
        CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
        (((m_node.chainman->ActiveTip()->GetMedianTimePast() + 1 -
           m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >>
          CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
         1);
    txid = tx.GetId();

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            *Assert(m_node.chainman->ActiveTip()), params, CTransaction{tx},
            state));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}));

    // Sequence locks pass 512 seconds later
    const int SEQUENCE_LOCK_TIME = 512;
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        // Trick the MedianTimePast
        m_node.chainman->ActiveTip()
            ->GetAncestor(m_node.chainman->ActiveHeight() - i)
            ->nTime += SEQUENCE_LOCK_TIME;
    }

    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, prevheights,
                      CreateBlockIndex(m_node.chainman->ActiveHeight() + 1,
                                       m_node.chainman->ActiveTip())));

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        CBlockIndex *ancestor{
            Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(
                m_node.chainman->ActiveHeight() - i))};
        // Undo tricked MTP.
        ancestor->nTime -= SEQUENCE_LOCK_TIME;
    }

    // Absolute height locked.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = m_node.chainman->ActiveHeight() + 1;
    txid = tx.GetId();
    auto height_locked_entry = entry.Time(GetTime()).FromTx(tx);
    AddUnchecked(height_locked_entry);

    {
        // Locktime fails.
        TxValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            *Assert(m_node.chainman->ActiveTip()), params, CTransaction{tx},
            state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}));

    {
        // Locktime passes on 2nd block.
        TxValidationState state;
        int64_t nMedianTimePast =
            m_node.chainman->ActiveTip()->GetMedianTimePast();
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction{tx}, state,
            m_node.chainman->ActiveHeight() + 2, nMedianTimePast));
    }

    // Absolute time locked.
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 0);
    tx.nLockTime = m_node.chainman->ActiveTip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    txid = tx.GetId();
    auto time_locked_entry = entry.Time(GetTime()).FromTx(tx);
    AddUnchecked(time_locked_entry);

    {
        // Locktime fails.
        TxValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            *Assert(m_node.chainman->ActiveTip()), params, CTransaction{tx},
            state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}));

    {
        // Locktime passes 1 second later.
        TxValidationState state;
        int64_t nMedianTimePast =
            m_node.chainman->ActiveTip()->GetMedianTimePast() + 1;
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction{tx}, state,
            m_node.chainman->ActiveHeight() + 1, nMedianTimePast));
    }

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout = COutPoint(txid, 0);
    prevheights[0] = m_node.chainman->ActiveHeight() + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;

    {
        // Locktime passes.
        TxValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            *Assert(m_node.chainman->ActiveTip()), params, CTransaction{tx},
            state));
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}));
    tx.vin[0].nSequence = 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}));

    pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

    // None of the of the absolute height/time locked tx should have made it
    // into the template because we still check IsFinalTx in CreateNewBlock, but
    // relative locked txs will if inconsistently added to g_mempool. For now
    // these will still generate a valid template until BIP68 soft fork.
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3UL);
    // However if we advance height by 1 and time by SEQUENCE_LOCK_TIME, all of
    // them should be mined.
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        CBlockIndex *ancestor{
            Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(
                m_node.chainman->ActiveHeight() - i))};
        // Trick the MedianTimePast.
        ancestor->nTime += SEQUENCE_LOCK_TIME;
    }
    m_node.chainman->ActiveTip()->nHeight++;
    SetMockTime(m_node.chainman->ActiveTip()->GetMedianTimePast() + 1);

    for (auto &mempool_entry : {height_locked_entry, time_locked_entry}) {
        std::vector<TxId> dummy;
        BOOST_CHECK(m_node.mempool->setAvalancheFinalized(
            mempool_entry, chainparams.GetConsensus(),
            *Assert(m_node.chainman->ActiveTip()), dummy));
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);
}

void MinerTestingSetup::TestPrioritisedMining(
    const CChainParams &chainparams, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    TestMemPoolEntryHelper entry;

    auto finalizePrioritizedTx =
        [&](const CMutableTransaction &tx, const Amount &fee,
            const Amount &delta) NO_THREAD_SAFETY_ANALYSIS {
            const TxId txid = tx.GetId();
            auto pool_entry = entry.Fee(fee).Time(GetTime()).FromTx(tx);

            m_node.mempool->addUnchecked(pool_entry);
            m_node.mempool->PrioritiseTransaction(txid, delta);

            ChainstateManager &chainman = *Assert(m_node.chainman);
            const CBlockIndex &tip = *Assert(chainman.ActiveTip());

            if (m_preconsensus) {
                std::vector<TxId> dummy;
                m_node.mempool->setAvalancheFinalized(
                    pool_entry, chainparams.GetConsensus(), tip, dummy);
            }

            return txid;
        };

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{txFirst[0]->GetId(), 0};
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout.resize(1);
    const int64_t fiveBillion = 5000000000;
    // 0 fee
    tx.vout[0].nValue = fiveBillion * SATOSHI;
    const TxId hashFreePrioritisedTx =
        finalizePrioritizedTx(tx, Amount::zero(), 5 * COIN);

    // This tx has a low fee: 1000 satoshis
    tx.vin[0].prevout = COutPoint{txFirst[1]->GetId(), 0};
    tx.vout[0].nValue = (fiveBillion - 1000) * SATOSHI;
    // save this txid for later use
    const TxId hashParentTx =
        finalizePrioritizedTx(tx, 1000 * SATOSHI, Amount::zero());

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout = COutPoint{txFirst[2]->GetId(), 0};
    tx.vout[0].nValue = (fiveBillion - 10000) * SATOSHI;
    const TxId hashMediumFeeTx =
        finalizePrioritizedTx(tx, 10000 * SATOSHI, -5 * COIN);
    BOOST_CHECK(
        !m_node.mempool->isAvalancheFinalizedPreConsensus(hashMediumFeeTx));

    // This tx also has a low fee, but is prioritised
    tx.vin[0].prevout = COutPoint{hashParentTx, 0};
    // 1000 satoshi fee
    tx.vout[0].nValue = (fiveBillion - 1000 - 1000) * SATOSHI;
    const TxId hashPrioritisedChild =
        finalizePrioritizedTx(tx, 1000 * SATOSHI, 2 * COIN);

    // Test that transaction selection properly updates ancestor fee
    // calculations as prioritised parents get included in a block. Create a
    // transaction with two prioritised ancestors, each included by itself:
    // FreeParent <- FreeChild <- FreeGrandchild. When FreeParent is added, a
    // modified entry will be created for FreeChild + FreeGrandchild
    // FreeParent's prioritisation should not be included in that entry.
    // When FreeChild is included, FreeChild's prioritisation should also not be
    // included.
    tx.vin[0].prevout = COutPoint{txFirst[3]->GetId(), 0};
    // 0 fee
    tx.vout[0].nValue = fiveBillion * SATOSHI;
    const TxId hashFreeParent =
        finalizePrioritizedTx(tx, Amount::zero(), 10 * COIN);

    tx.vin[0].prevout = COutPoint{hashFreeParent, 0};
    // 0 fee
    tx.vout[0].nValue = fiveBillion * SATOSHI;
    const TxId hashFreeChild =
        finalizePrioritizedTx(tx, Amount::zero(), 1 * COIN);

    tx.vin[0].prevout = COutPoint{hashFreeChild, 0};
    // 0 fee
    tx.vout[0].nValue = fiveBillion * SATOSHI;
    const TxId hashFreeGrandchild =
        finalizePrioritizedTx(tx, Amount::zero(), Amount::zero());
    BOOST_CHECK(
        !m_node.mempool->isAvalancheFinalizedPreConsensus(hashFreeGrandchild));

    auto pblocktemplate =
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 6U);
    std::vector<TxId> txids = {hashFreeParent, hashFreePrioritisedTx,
                               hashFreeChild, hashParentTx,
                               hashPrioritisedChild};
    if (m_preconsensus) {
        std::sort(txids.begin(), txids.end());
    }
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == txids[0]);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == txids[1]);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == txids[2]);
    BOOST_CHECK(pblocktemplate->block.vtx[4]->GetId() == txids[3]);
    BOOST_CHECK(pblocktemplate->block.vtx[5]->GetId() == txids[4]);
    for (size_t i = 0; i < pblocktemplate->block.vtx.size(); ++i) {
        // The FreeParent and FreeChild's prioritisations should not impact the
        // child.
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetId() !=
                    hashFreeGrandchild);
        // De-prioritised transaction should not be included.
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetId() != hashMediumFeeTx);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
void MinerTestingSetup::CreateNewBlock_validity() {
    // FIXME Update the below blocks to create a valid miner fund coinbase.
    // This requires to update the blockinfo nonces.
    gArgs.ForceSetArg("-enableminerfund", "0");
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 110 blocks :)
    static_assert(std::size(blockinfo) == 110,
                  "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (const auto &bi : blockinfo) {
        // pointer for convenience
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            pblock->nVersion = 1;
            pblock->nTime =
                m_node.chainman->ActiveTip()->GetMedianTimePast() + 1;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            int nHeight = m_node.chainman->ActiveHeight() + 1;
            // Make sure coinbase is BIP34 compliant
            txCoinbase.vin[0].scriptSig = CScript() << nHeight << OP_0;
            txCoinbase.vin[0].scriptSig.push_back(bi.extranonce);
            txCoinbase.vout[0].scriptPubKey = CScript();
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0) {
                baseheight = m_node.chainman->ActiveHeight();
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(pblock->vtx[0]);
            }
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->nBits = GetNextWorkRequired(
                m_node.chainman->ActiveTip(), pblock, chainparams);
            pblock->nNonce = bi.nonce;
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(Assert(m_node.chainman)
                        ->ProcessNewBlock(shared_pblock, true, true, nullptr));
        pblock->hashPrevBlock = pblock->GetHash();
    }

    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    TestBasicMining(chainparams, scriptPubKey, txFirst, baseheight);

    m_node.chainman->ActiveTip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPrioritisedMining(chainparams, scriptPubKey, txFirst);

    gArgs.ClearForcedArg("-enableminerfund");
}

BOOST_FIXTURE_TEST_CASE(CreateNewBlock_validity_no_preconsensus,
                        MinerTestingSetupNoCheckpoints) {
    CreateNewBlock_validity();
}
BOOST_FIXTURE_TEST_CASE(CreateNewBlock_validity_preconsensus,
                        PreconsensusMinerTestingSetupNoCheckpoints) {
    CreateNewBlock_validity();
}

static void CheckBlockMaxSize(const Config &config, const CTxMemPool &mempool,
                              Chainstate &active_chainstate, uint64_t size,
                              uint64_t expected) {
    gArgs.ForceSetArg("-blockmaxsize", ToString(size));

    BlockAssembler ba{config, active_chainstate, &mempool};
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), expected);
}

BOOST_AUTO_TEST_CASE(BlockAssembler_construction) {
    GlobalConfig config;

    // We are working on a fake chain and need to protect ourselves.
    LOCK(cs_main);

    const CTxMemPool &mempool = *m_node.mempool;
    Chainstate &active_chainstate = m_node.chainman->ActiveChainstate();

    // Test around historical 1MB (plus one byte because that's mandatory)
    config.SetMaxBlockSize(ONE_MEGABYTE + 1);
    CheckBlockMaxSize(config, mempool, active_chainstate, 0, 1000);
    CheckBlockMaxSize(config, mempool, active_chainstate, 1000, 1000);
    CheckBlockMaxSize(config, mempool, active_chainstate, 1001, 1001);
    CheckBlockMaxSize(config, mempool, active_chainstate, 12345, 12345);

    CheckBlockMaxSize(config, mempool, active_chainstate, ONE_MEGABYTE - 1001,
                      ONE_MEGABYTE - 1001);
    CheckBlockMaxSize(config, mempool, active_chainstate, ONE_MEGABYTE - 1000,
                      ONE_MEGABYTE - 1000);
    CheckBlockMaxSize(config, mempool, active_chainstate, ONE_MEGABYTE - 999,
                      ONE_MEGABYTE - 999);
    CheckBlockMaxSize(config, mempool, active_chainstate, ONE_MEGABYTE,
                      ONE_MEGABYTE - 999);

    // Test around default cap
    config.SetMaxBlockSize(DEFAULT_MAX_BLOCK_SIZE);

    // Now we can use the default max block size.
    CheckBlockMaxSize(config, mempool, active_chainstate,
                      DEFAULT_MAX_BLOCK_SIZE - 1001,
                      DEFAULT_MAX_BLOCK_SIZE - 1001);
    CheckBlockMaxSize(config, mempool, active_chainstate,
                      DEFAULT_MAX_BLOCK_SIZE - 1000,
                      DEFAULT_MAX_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, mempool, active_chainstate,
                      DEFAULT_MAX_BLOCK_SIZE - 999,
                      DEFAULT_MAX_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, mempool, active_chainstate,
                      DEFAULT_MAX_BLOCK_SIZE, DEFAULT_MAX_BLOCK_SIZE - 1000);

    // If the parameter is not specified, we use
    // DEFAULT_MAX_GENERATED_BLOCK_SIZE
    {
        gArgs.ClearForcedArg("-blockmaxsize");
        BlockAssembler ba{config, m_node.chainman->ActiveChainstate(),
                          m_node.mempool.get()};
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
    BOOST_CHECK_EQUAL(txEntry.sigChecks, 10);
}

BOOST_AUTO_TEST_SUITE_END()
