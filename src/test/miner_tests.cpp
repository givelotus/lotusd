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

    void TestPackageSelection(const Config &config,
                              const CScript &scriptPubKey,
                              const std::vector<CTransactionRef> &txFirst)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    void TestBasicMining(const Config &config,
                         const CScript &scriptPubKey,
                         const std::vector<CTransactionRef> &txFirst,
                         int baseheight)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    void TestPrioritisedMining(const Config &config,
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
    BlockAssembler AssemblerForTest(const Config &config);

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

BlockAssembler MinerTestingSetup::AssemblerForTest(const Config &config) {
    BlockFitter::Options fitter_options;
    fitter_options.blockMinFeeRate = blockMinFeeRate;
    BlockAssembler::Options assembler_options;
    assembler_options.add_finalized_txs = m_preconsensus;
    assembler_options.enableMinerFund = config.EnableMinerFund();
    return BlockAssembler{
        BlockFitter(fitter_options), m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(), assembler_options, m_node.avalanche.get()};
}

constexpr uint64_t blockinfo[] = {
    138489447073, 2000123001,   35192735278,  30743516887,  90270421301,
    4746156542,   269517074003, 50530474709,  201348804349, 131694823915,
    96838508997,  54292234081,  146777944833, 194579551989, 17459672428,
    239463286493, 35972158971,  131229981500, 288173081779, 8271781121,
    14054617812,  1168893791,   67365635174,  196656931529, 35800309163,
    17851574064,  26749261103,  14953015794,  22247598424,  16778982303,
    119328830052, 19182627651,  133744171463, 161386696561, 5583120677,
    37193104054,  74777620295,  240886925522, 202169284734, 37158187173,
    180572907622, 34681770166,  218161288478, 5698624760,   123626801781,
    8494330929,   134180517818, 380634240428, 1112112668,   19262695841,
    727120508,    65255482113,  90905170725,  45882969013,  112934652766,
    15470497544,  89665853312,  4833940537,   70579955079,  131318555366,
    51087976648,  18737029675,  112319798991, 154404109467, 164492077002,
    26800008678,  8462192695,   35955108190,  70609431501,  141973644757,
    171937771431, 27571969114,  175359612626, 9514202569,   144770109340,
    18542728507,  67998505071,  274075528823, 202967048402, 18535319865,
    937791320,    60483413889,  43840334254,  38996608745,  135126199815,
    136500720625, 3691630528,   85448072763,  75537584241,  205777394006,
    22255213872,  170642741506, 130688629769, 219159895699, 97098261172,
    118269396602, 87328266489,  185378645008, 10623915215,  7452183400,
    14890598267,  671249038,    97235700784,  35390245092,  144350615945,
    67256243540,  71934634370,  12275123663,  151449715016, 8967451371,
};

// In Logos, half of the block subsidy goes to the miner.
const Amount MINERREWARD = SUBSIDY / 2;
const Amount LOWFEE = 10'000 * SATOSHI;
const Amount HIGHFEE = 10 * LOTUS;
const Amount HIGHERFEE = 4 * LOTUS;

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
    const Config &config, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    CScript scriptSig = CScript() << std::vector<uint8_t>{OP_1};

    // Padding so txs are not undersize
    std::vector<uint8_t> padData(100);

    // Test that a medium fee transaction will be selected before a higher fee
    // transaction when the high-fee tx has a low fee parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    // vout 0 = OP_RETURN, vout 1 = miner reward
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vout.resize(2);
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - 1000 * SATOSHI;
    tx.vout[1].nValue = Amount::zero();
    tx.vout[1].scriptPubKey = CScript() << OP_RETURN << padData;
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    Amount parentTxAmount = tx.vout[0].nValue;
    AddUnchecked(entry.Fee(1000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - 10000 * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    AddUnchecked(entry.Fee(10000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = parentTxAmount - 50000 * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    Amount highFeeTxAmount = tx.vout[0].nValue;
    AddUnchecked(entry.Fee(50000 * SATOSHI).Time(GetTime()).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(config).CreateNewBlock(scriptPubKey);

    // CTOR is always enforced from genesis in Lotus.
    std::vector<TxId> txids = {mediumFeeTxId, parentTxId, highFeeTxId};
    std::sort(txids.begin(), txids.end());
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 4U);
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == txids[0]);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == txids[1]);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == txids[2]);

    // Test that a tranactions with ancestor below the block min tx fee doesn't
    // get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = highFeeTxAmount;
    TxId freeTxId = tx.GetId();
    Amount freeTxAmount = tx.vout[0].nValue;
    AddUnchecked(entry.Fee(Amount::zero()).FromTx(tx));
    BOOST_CHECK(!m_node.mempool->isAvalancheFinalizedPreConsensus(freeTxId));

    // Add a child transaction with high fee.
    Amount feeToUse = 50000 * SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue = freeTxAmount - feeToUse;
    TxId highFeeDecendantTxId = tx.GetId();
    AddUnchecked(entry.Fee(feeToUse).FromTx(tx));
    BOOST_CHECK(!m_node.mempool->isAvalancheFinalizedPreConsensus(
        highFeeDecendantTxId));
    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);

    // Under preconsensus (addFinalizedTxs), the free tx and its high fee
    // descendant tx don't get finalized/selected. Under addTxs (001 nlogn
    // package accumulation), their package fee rate exceeds blockMinFeeRate so
    // they are selected.
    if (m_preconsensus) {
        for (const auto &txn : pblocktemplate->block.vtx) {
            BOOST_CHECK(txn->GetId() != freeTxId);
            BOOST_CHECK(txn->GetId() != highFeeDecendantTxId);
        }
    } else {
        BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 6U);
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

    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig == (CScript() << vec));
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
    const Config &config, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst, int baseheight) {
    const CChainParams &chainparams = config.GetChainParams();
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11 * SATOSHI;
    entry.nHeight = 11;

    // Just to make sure we can still make simple blocks.
    auto pblocktemplate =
        AssemblerForTest(config).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

    CScript scriptSig = CScript() << std::vector<uint8_t>{OP_1};
    // block size > limit
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);

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
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Orphan in mempool, template creation fails. Note that finalizing it will
    // finalize the parent, so we skip this test when preconsensus is enabled
    if (!m_preconsensus) {
        AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
        BOOST_CHECK_EXCEPTION(
            AssemblerForTest(config).CreateNewBlock(scriptPubKey),
            std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Child with higher priority than parent.
    tx.vin[0].scriptSig = scriptSig;
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - HIGHFEE;
    TxId txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    tx.vin[1].scriptSig = scriptSig;
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 1);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue =
        tx.vout[0].nValue + txFirst[0]->vout[1].nValue - HIGHERFEE;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHERFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
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
        AssemblerForTest(config).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-tx-coinbase"));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Double spend txn pair in mempool, template creation fails.
    std::vector<uint8_t> padData(100);
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(2);
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.vout[1].nValue = Amount::zero();
    tx.vout[1].scriptPubKey = CScript() << OP_RETURN << padData;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(config).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    // Subsidy changing.
    int nHeight = m_node.chainman->ActiveHeight();
    // Create an actual 209999-long block chain (without valid blocks).
    BlockHash epochBlockHash;
    while (m_node.chainman->ActiveHeight() < 209999) {
        CBlockIndex *prev = m_node.chainman->ActiveTip();
        if ((prev->nHeight + 1) % EPOCH_NUM_BLOCKS == 0) {
            epochBlockHash = *prev->phashBlock;
        }
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(m_rng.rand256());
        m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(
            next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->hashEpochBlock = epochBlockHash;
        next->BuildSkip();
        m_node.chainman->ActiveChain().SetTip(*next);
    }
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (m_node.chainman->ActiveHeight() < 210000) {
        CBlockIndex *prev = m_node.chainman->ActiveTip();
        if ((prev->nHeight + 1) % EPOCH_NUM_BLOCKS == 0) {
            epochBlockHash = *prev->phashBlock;
        }
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(m_rng.rand256());
        m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(
            next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->hashEpochBlock = epochBlockHash;
        next->BuildSkip();
        m_node.chainman->ActiveChain().SetTip(*next);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - LOWFEE;
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
        AssemblerForTest(config).CreateNewBlock(scriptPubKey),
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
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    // TODO: These tests seem to be broken regarding MTP, enforcing BIP68 from
    // genesis makes relative locktime fail when creating a block.
    // Now, we just make the tx sequence BIP68 compliant before adding it to
    // the mempool and rely only on TestSequenceLocks for now.
    // This test is a mess, we're using tx to both do tests on the tx itself
    // and for adding txs to the mempool.
    tx.vin[0].nSequence = m_node.chainman->ActiveHeight() - 1;
    prevheights[0] = baseheight + 1;
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - HIGHFEE;
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
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    // TODO: These tests seem to be broken, enforcing BIP68 from genesis
    // makes relative locktime fail when creating a block.
    // We only rely on TestSequenceLocks for now.
    tx.vin[0].nSequence = 0;
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - entry.nFee;
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
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 1);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    tx.vout[0].nValue = txFirst[2]->vout[1].nValue - entry.nFee;
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
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 1);
    tx.vout[0].nValue = txFirst[3]->vout[1].nValue - entry.nFee;
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

    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);
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
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);
}

void MinerTestingSetup::TestPrioritisedMining(
    const Config &config, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    const CChainParams &chainparams = config.GetChainParams();
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

    // Padding so txs are not undersize
    std::vector<uint8_t> padData(100);

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{txFirst[0]->GetId(), 1};
    tx.vin[0].scriptSig = CScript() << std::vector<uint8_t>{OP_1};
    tx.vout.resize(2);
    // 0 fee
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue;
    tx.vout[1].nValue = Amount::zero();
    tx.vout[1].scriptPubKey = CScript() << OP_RETURN << padData;
    const TxId hashFreePrioritisedTx =
        finalizePrioritizedTx(tx, Amount::zero(), 5 * COIN);

    // This tx has a low fee: 1000 satoshis
    tx.vin[0].prevout = COutPoint{txFirst[1]->GetId(), 1};
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - 1000 * SATOSHI;
    // save this txid for later use
    const TxId hashParentTx =
        finalizePrioritizedTx(tx, 1000 * SATOSHI, Amount::zero());

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout = COutPoint{txFirst[2]->GetId(), 1};
    tx.vout[0].nValue = txFirst[2]->vout[1].nValue - 10000 * SATOSHI;
    const TxId hashMediumFeeTx =
        finalizePrioritizedTx(tx, 10000 * SATOSHI, -5 * COIN);
    BOOST_CHECK(
        !m_node.mempool->isAvalancheFinalizedPreConsensus(hashMediumFeeTx));

    // This tx also has a low fee, but is prioritised
    tx.vin[0].prevout = COutPoint{hashParentTx, 0};
    // 1000 satoshi fee
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - 1000 * SATOSHI - 1000 * SATOSHI;
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
    tx.vin[0].prevout = COutPoint{txFirst[3]->GetId(), 1};
    // 0 fee
    tx.vout[0].nValue = txFirst[3]->vout[1].nValue;
    const TxId hashFreeParent =
        finalizePrioritizedTx(tx, Amount::zero(), 10 * COIN);

    tx.vin[0].prevout = COutPoint{hashFreeParent, 0};
    // 0 fee
    tx.vout[0].nValue = txFirst[3]->vout[1].nValue;
    const TxId hashFreeChild =
        finalizePrioritizedTx(tx, Amount::zero(), 1 * COIN);

    tx.vin[0].prevout = COutPoint{hashFreeChild, 0};
    // 0 fee
    tx.vout[0].nValue = txFirst[3]->vout[1].nValue;
    const TxId hashFreeGrandchild =
        finalizePrioritizedTx(tx, Amount::zero(), Amount::zero());
    BOOST_CHECK(
        !m_node.mempool->isAvalancheFinalizedPreConsensus(hashFreeGrandchild));

    auto pblocktemplate =
        AssemblerForTest(config).CreateNewBlock(scriptPubKey);
    std::vector<TxId> txids = {hashFreeParent, hashFreePrioritisedTx,
                               hashFreeChild, hashParentTx,
                               hashPrioritisedChild};
    if (!m_preconsensus) {
        txids.push_back(hashFreeGrandchild);
    }
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), txids.size() + 1);
    std::sort(txids.begin(), txids.end());
    for (size_t i = 0; i < txids.size(); ++i) {
        BOOST_CHECK(pblocktemplate->block.vtx[i + 1]->GetId() == txids[i]);
    }
    for (size_t i = 0; i < pblocktemplate->block.vtx.size(); ++i) {
        if (m_preconsensus) {
            // The FreeParent and FreeChild's prioritisations should not impact
            // the child under preconsensus finalization.
            BOOST_CHECK(pblocktemplate->block.vtx[i]->GetId() !=
                        hashFreeGrandchild);
        }
        // De-prioritised transaction should not be included.
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetId() != hashMediumFeeTx);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
void MinerTestingSetup::CreateNewBlock_validity() {
    // Note that by default, these tests run with size accounting enabled.
    Config &config = const_cast<Config &>(GetConfig());
    // Don't check this functionality in this test.
    config.SetEnableMinerFund(false);
    const CChainParams &chainparams = config.GetChainParams();
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 110 blocks :)
    static_assert(std::size(blockinfo) == 110,
                  "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    int nHeight = WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight() + 1);
    int64_t nTime = WITH_LOCK(
        cs_main, return m_node.chainman->ActiveTip()->GetMedianTimePast() + 1);
    for (size_t i = 0; i < std::size(blockinfo); ++i) {
        // pointer for convenience
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            // Fill in header
            pblock->SetBlockTime(nTime);
            pblock->nNonce = blockinfo[i];
            pblock->nHeaderVersion = 1;
            pblock->nHeight = nHeight;
            pblock->hashEpochBlock.SetNull();
            pblock->hashExtendedMetadata = SerializeHash(uint8_t(0));
            CBlockHeader header = pblock->GetBlockHeader();
            pblock->nBits = GetNextWorkRequired(
                m_node.chainman->ActiveTip(), &header, chainparams);
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            // Add padding to prevent undersize
            txCoinbase.vin[0].scriptSig = CScript();
            txCoinbase.vin[0].scriptSig.resize(100);
            // First output is OP_RETURN "logos" <height>
            txCoinbase.vout[0].scriptPubKey =
                CScript() << OP_RETURN << COINBASE_PREFIX << nHeight;
            // Block subsidy adjustst with difficulty, so we have to update the
            // miner fund outputs
            Amount minerReward =
                GetBlockSubsidy(pblock->nBits, chainparams.GetConsensus());
            std::vector<CTxOut> requiredOutputs = GetMinerFundRequiredOutputs(
                chainparams.GetConsensus(), config.EnableMinerFund(),
                m_node.chainman->ActiveTip(), minerReward);
            for (size_t j = 0; j < requiredOutputs.size(); ++j) {
                txCoinbase.vout[j + 2] = requiredOutputs[j];
                minerReward -= requiredOutputs[j].nValue;
            }
            txCoinbase.vout[1].nValue = minerReward;
            txCoinbase.vout[1].scriptPubKey =
                GetScriptForDestination(ScriptHash(CScript() << OP_1));
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0) {
                baseheight = nHeight - 1;
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(pblock->vtx[0]);
            }
            pblock->SetSize(::GetSerializeSize(*pblock));
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(Assert(m_node.chainman)
                        ->ProcessNewBlock(shared_pblock, true, true, nullptr));
        ++nHeight;
        ++nTime;
        pblock->hashPrevBlock = pblock->GetHash();
    }

    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    TestBasicMining(config, scriptPubKey, txFirst, baseheight);

    m_node.chainman->ActiveTip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPackageSelection(config, scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPrioritisedMining(config, scriptPubKey, txFirst);
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
