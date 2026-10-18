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
#include <node/blockfitter.h>
#include <pow/pow.h>
#include <policy/policy.h>
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
using util::ToString;

namespace avalanche {
namespace {
    struct AvalancheTest {
        static void setFinalizationTip(Processor &p,
                                       const CBlockIndex *pindex) {
            LOCK(p.cs_finalizationTip);
            p.finalizationTip = pindex;
        }
    };
} // namespace
} // namespace avalanche

namespace miner_tests {
struct MinerTestingSetup : public AvalancheTestingSetup {
    bool m_preconsensus{false};

    MinerTestingSetup(const std::vector<const char *> &extra_args = {})
        : AvalancheTestingSetup(ChainType::REGTEST, extra_args) {}

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
            m_node.mempool->setAvalancheFinalized(
                entry, params, tip, chainman.ActiveChainstate(), dummy);
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

constexpr int MINER_FIXTURE_BLOCKS = 110;

static CBlockIndex CreateBlockIndex(int nHeight, CBlockIndex *active_chain_tip)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = active_chain_tip;
    return index;
}

// Raw Lotus VM opcodes differ from the legacy CScript numeric constants.
static CScript NativeMinerScript(uint8_t opcode) {
    CScript script;
    script.push_back(opcode);
    return script;
}

static void SetNativeMinerWitness(CTxIn &input, const CScript &script) {
    input.nFlags = 1;
    input.nPathIndex = 0;
    input.scriptSig = script;
    lotus::v2::BranchWitness witness;
    witness.script.assign(script.begin(), script.end());
    input.vWitnesses = {std::move(witness)};
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
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4e);
    tx.vout[0].nValue = int64_t(5000000000LL - 1000) * SATOSHI;
    tx.vout.emplace_back(Amount::zero(),
                         CScript() << OP_RETURN << std::vector<uint8_t>(80));
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    AddUnchecked(entry.Fee(1000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = int64_t(5000000000LL - 10000) * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    AddUnchecked(entry.Fee(10000 * SATOSHI).Time(GetTime()).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = int64_t(5000000000LL - 1000 - 50000) * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    AddUnchecked(entry.Fee(50000 * SATOSHI).Time(GetTime()).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);

    // CTOR applies from genesis in this development chain.
    std::vector<TxId> txids = {mediumFeeTxId, parentTxId, highFeeTxId};
    std::sort(txids.begin(), txids.end());
    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == txids[0]);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == txids[1]);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == txids[2]);

    // Test that a tranactions with ancestor below the block min tx fee doesn't
    // get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = int64_t(5000000000LL - 1000 - 50000) * SATOSHI;
    TxId freeTxId = tx.GetId();
    AddUnchecked(entry.Fee(Amount::zero()).FromTx(tx));
    BOOST_CHECK(!m_node.mempool->isAvalancheFinalizedPreConsensus(freeTxId));

    // Add a child transaction with high fee.
    Amount feeToUse = 50000 * SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue =
        int64_t(5000000000LL - 1000 - 50000) * SATOSHI - feeToUse;
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

    const Amount BLOCKSUBSIDY = 50 * COIN;
    const Amount LOWFEE = CENT;
    const Amount HIGHFEE = COIN;
    const Amount HIGHERFEE = 4 * COIN;

    // block size > limit
    tx.vin.resize(1);
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4e);
    tx.vout[0].nValue = BLOCKSUBSIDY;
    tx.vout.emplace_back(Amount::zero(),
                         CScript() << OP_RETURN << std::vector<uint8_t>(9000));
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
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    TxId txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    SetNativeMinerWitness(tx.vin[1], NativeMinerScript(0x4e));
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 0);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE;
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
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4e);
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4f);
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

    // A committed false native branch must fail template self-validation
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
    CScript script = NativeMinerScript(0x00);
    tx.vout[0].scriptPubKey = script;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    SetNativeMinerWitness(tx.vin[0], script);
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
    const uint32_t flags{LOCKTIME_VERIFY_SEQUENCE};
    // height map
    std::vector<int> prevheights;

    // Relative height locked.
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    // Only 1 transaction.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    // txFirst[0] is the 2nd block
    tx.vin[0].nSequence = m_node.chainman->ActiveHeight() + 1;
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4e);
    tx.vout.emplace_back(Amount::zero(),
                         CScript() << OP_RETURN << std::vector<uint8_t>(80));
    tx.nLockTime = 0;
    txid = tx.GetId();
    AddUnchecked(entry.Fee(HIGHFEE).Time(GetTime()).FromTx(tx));

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
    // txFirst[1] is the 3rd block.
    tx.vin[0].nSequence =
        CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
        (((m_node.chainman->ActiveTip()->GetMedianTimePast() + 1 -
           m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >>
          CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
         1);
    prevheights[0] = baseheight + 2;
    txid = tx.GetId();
    AddUnchecked(entry.Time(GetTime()).FromTx(tx));

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

    // BIP68 applies from genesis in this development chain. The deliberately
    // unchecked mempool entries must fail template self-validation here.
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-nonfinal"));
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
            *Assert(m_node.chainman->ActiveTip()),
            m_node.chainman->ActiveChainstate(), dummy));
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
                    pool_entry, chainparams.GetConsensus(), tip,
                    chainman.ActiveChainstate(), dummy);
            }

            return txid;
        };

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{txFirst[0]->GetId(), 0};
    SetNativeMinerWitness(tx.vin[0], NativeMinerScript(0x4e));
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = NativeMinerScript(0x4e);
    const int64_t fiveBillion = 5000000000;
    tx.vout.emplace_back(Amount::zero(),
                         CScript() << OP_RETURN << std::vector<uint8_t>(80));
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
    std::sort(txids.begin(), txids.end());
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
    struct RestoreMinerFundArg {
        bool was_set = gArgs.IsArgSet("-enableminerfund");
        std::string value = gArgs.GetArg("-enableminerfund", "");
        ~RestoreMinerFundArg() {
            if (was_set) {
                gArgs.ForceSetArg("-enableminerfund", value);
            } else {
                gArgs.ClearForcedArg("-enableminerfund");
            }
        }
    } restore_miner_fund;
    gArgs.ForceSetArg("-enableminerfund", "0");
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    const CScript scriptPubKey = NativeMinerScript(0x4e); // Native OP_1.
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey));

    // Build a spendable chain under the current development consensus rules.
    // Historical mainnet nonces no longer satisfy the 120-second ASERT target.
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (int i = 0; i < MINER_FIXTURE_BLOCKS; ++i) {
        pblocktemplate = AssemblerForTest(chainparams).CreateNewBlock(scriptPubKey);
        CBlock &block = pblocktemplate->block;
        {
            LOCK(cs_main);
            createCoinbaseAndMerkleRoot(&block, m_node.chainman->ActiveTip(),
                                        config.GetMaxBlockSize());
            if (i == 0) {
                baseheight = m_node.chainman->ActiveHeight();
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(block.vtx[0]);
            }
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits,
                                 chainparams.GetConsensus())) {
            ++block.nNonce;
        }
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(
            CheckBlock(block, state, chainparams.GetConsensus(),
                       BlockValidationOptions(config)),
            state.ToString());
        BOOST_REQUIRE(Assert(m_node.chainman)
                          ->ProcessNewBlock(std::make_shared<const CBlock>(block),
                                            true, true, nullptr));
    }

    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    // Finalize tip->pprev rather than the tip to avoid transient state:
    // TestBasicMining mutates tip->nHeight, which would break GetAncestor on
    // the finalized index.
    CBlockIndex *finalized = m_node.chainman->ActiveTip()->pprev;
    BOOST_CHECK(m_node.chainman->ActiveChainstate().AvalancheFinalizeBlock(
        finalized, *Assert(m_node.avalanche)));
    avalanche::AvalancheTest::setFinalizationTip(*m_node.avalanche, finalized);

    TestBasicMining(chainparams, scriptPubKey, txFirst, baseheight);

    m_node.chainman->ActiveTip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear(/*include_finalized_txs=*/true);

    TestPrioritisedMining(chainparams, scriptPubKey, txFirst);
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
    CTransactionRef txRef = MakeTransactionRef();
    CBlockTemplateEntry txEntry(txRef, 1 * SATOSHI, 10);
    BOOST_CHECK_MESSAGE(txEntry.tx == txRef, "Transactions did not match");
    BOOST_CHECK_EQUAL(txEntry.fees, 1 * SATOSHI);
    BOOST_CHECK_EQUAL(txEntry.sigChecks, 10);
}


BOOST_FIXTURE_TEST_CASE(speculative_overlay_does_not_validate_unchecked_scripts, TestChain100Setup) {
    CMutableTransaction bad;
    bad.nVersion = 2;
    bad.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetId(), 0), CScript() << OP_FALSE);
    bad.vout.emplace_back(m_coinbase_txns[0]->vout[0].nValue - 1000 * SATOSHI,
                          CScript() << OP_TRUE);
    while (::GetSerializeSize(bad) < MIN_TX_SIZE) bad.vout[0].scriptPubKey << OP_NOP;
    const auto unchecked = MakeTransactionRef(bad);
    {
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->SyncMerklixOverlayToTip(m_node.chainman->ActiveTip()->GetBlockHash(),
            101, m_node.chainman->ActiveTip()->GetMedianTimePast());
        m_node.mempool->addUnchecked(TestMemPoolEntryHelper().Fee(1000 * SATOSHI).FromTx(unchecked));
    }
    auto block = CreateBlock({bad}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()),
                             m_node.chainman->ActiveChainstate());
    block.vtx[1] = unchecked; // Compact reconstruction can reuse the exact mempool object.
    m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr);
    { LOCK(cs_main);
      const auto *index = m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash());
      BOOST_REQUIRE(index);
      BOOST_CHECK(index->nStatus.isInvalid()); }
    BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 100);
}

BOOST_FIXTURE_TEST_CASE(template_root_is_checked_from_selected_transactions, TestChain100Setup) {
    node::BlockAssembler::Options options;
    options.test_block_validity = false;
    const auto block_template = node::BlockAssembler(
        node::BlockFitter(GetConfig()), m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(), options).CreateNewBlock(CScript() << OP_TRUE);
    BOOST_REQUIRE(block_template);
    BOOST_CHECK(block_template->block.hashMerkleRoot == BlockMerkleRoot(block_template->block));
    BOOST_CHECK(!block_template->block.m_checked_merkle_root);
}

// A coinbase output must be the same after a wire round trip as in the
// miner's memory: legacy inputs spending it are verified against its
// scriptPubKey, so a script known only to the miner splits the miner from
// every peer.
BOOST_FIXTURE_TEST_CASE(coinbase_outputs_survive_wire_round_trip,
                        TestChain100Setup) {
    node::BlockAssembler::Options options;
    options.test_block_validity = false;
    const CScript payout =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    const auto block_template = node::BlockAssembler(
        node::BlockFitter(GetConfig()), m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(), options).CreateNewBlock(payout);
    BOOST_REQUIRE(block_template);
    const CTransaction &coinbase = *block_template->block.vtx[0];

    DataStream ss{};
    ss << coinbase;
    const CTransaction decoded(deserialize, ss);
    BOOST_CHECK_EQUAL(decoded.GetId(), coinbase.GetId());
    BOOST_CHECK_EQUAL(decoded.GetHash(), coinbase.GetHash());
    BOOST_REQUIRE_EQUAL(decoded.vout.size(), coinbase.vout.size());
    BOOST_CHECK(coinbase.vout[0].scriptPubKey == payout);
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        BOOST_CHECK(decoded.vout[i].scriptPubKey ==
                    coinbase.vout[i].scriptPubKey);
        BOOST_CHECK(decoded.vout[i] == coinbase.vout[i]);
    }
}

BOOST_FIXTURE_TEST_CASE(finalized_template_after_deferred_remove_readd_matches_own_root, AvalancheTestChain100Setup) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    auto *tip = m_node.chainman->ActiveTip();
    avalanche::AvalancheTest::setFinalizationTip(*m_node.avalanche, tip);
    BOOST_REQUIRE(m_node.avalanche->isPreconsensusActivated(tip));
    TestMemPoolEntryHelper helper;
    std::vector<CTransactionRef> txs;
    pool.SyncMerklixOverlayToTip(tip->GetBlockHash(), tip->nHeight + 1,
                                tip->GetMedianTimePast());
    for (uint32_t i = 0; i < 3; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(TxId{uint256{uint8_t(i + 1)}}, 0);
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        while (::GetSerializeSize(tx) < MIN_TX_SIZE) tx.vout[0].scriptPubKey << OP_NOP;
        txs.push_back(MakeTransactionRef(tx));
        pool.addUnchecked(helper.Fee(1000 * SATOSHI).FromTx(txs.back()));
    }
    (void)pool.GetMerklixOverlay();
    {
        CTxMemPool::ScopedSnapshotDefer defer(pool);
        pool.removeRecursive(*txs[0], MemPoolRemovalReason::MANUAL);
        pool.addUnchecked(helper.Fee(1000 * SATOSHI).FromTx(txs[0]));
    }
    for (size_t i = 0; i < 2; ++i) {
        std::vector<TxId> finalized;
        BOOST_REQUIRE(pool.setAvalancheFinalized(*pool.mapTx.find(txs[i]->GetId()),
            m_node.chainman->GetConsensus(), *tip,
            m_node.chainman->ActiveChainstate(), finalized));
    }
    node::BlockAssembler::Options options;
    options.add_finalized_txs = true;
    options.test_block_validity = false;
    const auto block_template = node::BlockAssembler(
        node::BlockFitter(config), m_node.chainman->ActiveChainstate(),
        &pool, options, m_node.avalanche.get()).CreateNewBlock(CScript() << OP_TRUE);
    BOOST_REQUIRE(block_template);
    BOOST_CHECK_EQUAL(block_template->block.vtx.size(), 3U);
    BOOST_CHECK(block_template->block.hashMerkleRoot == BlockMerkleRoot(block_template->block));
}

BOOST_AUTO_TEST_CASE(CreateNewBlock_1000tx_MerklixOverlay) {
    LOCK2(cs_main, m_node.mempool->cs);
    m_node.mempool->clear(/*include_finalized_txs=*/true);
    TestMemPoolEntryHelper entry;

    CBlockIndex *tip = m_node.chainman->ActiveTip();
    BOOST_REQUIRE(tip != nullptr);

    // Create a funding transaction with 800 spendable outputs in CoinsTip()
    // and in the tip's V2 block state snapshot.
    CMutableTransaction fundTx;
    fundTx.nVersion = 2;
    fundTx.vin.resize(1);
    fundTx.vin[0].prevout = COutPoint(TxId{FastRandomContext().rand256()}, 0);
    fundTx.vin[0].scriptSig = CScript() << int64_t(1) << OP_TRUE;
    fundTx.vout.resize(800);
    for (size_t i = 0; i < 800; ++i) {
        fundTx.vout[i].nValue = 100000 * SATOSHI;
        fundTx.vout[i].scriptPubKey = CScript() << OP_TRUE;
    }
    CTransactionRef fundRef = MakeTransactionRef(std::move(fundTx));
    AddCoins(m_node.chainman->ActiveChainstate().CoinsTip(), *fundRef, 1);

    CBlock syntheticTipBlock;
    syntheticTipBlock.nHeaderVersion = lotus::v2::kHeaderVersion;
    syntheticTipBlock.nHeight = tip->nHeight;
    syntheticTipBlock.nBits = tip->nBits;
    syntheticTipBlock.SetBlockTime(tip->GetBlockTime());
    CMutableTransaction dummyCb;
    dummyCb.nVersion = 2;
    dummyCb.vin.resize(1);
    dummyCb.vin[0].nFlags = 2;
    dummyCb.vin[0].scriptSig = CScript() << int64_t(tip->nHeight) << OP_0;
    dummyCb.vout.emplace_back(200 * SATOSHI, CScript() << OP_TRUE);
    syntheticTipBlock.vtx.push_back(MakeTransactionRef(std::move(dummyCb)));
    syntheticTipBlock.vtx.push_back(fundRef);
    RecordV2BlockState(syntheticTipBlock, tip->GetBlockHash(), BlockHash{},
                       uint64_t(tip->nHeight), 0);

    const uint64_t nextHeight = uint64_t(tip->nHeight + 1);
    const uint64_t nextMtp = uint64_t(tip->GetMedianTimePast());
    m_node.mempool->ConnectBlockReset(tip->GetBlockHash(), nextHeight, nextMtp);

    // Add 800 root transactions + 200 child transactions = 1,000 mempool txs
    std::vector<CTransactionRef> rootTxs;
    rootTxs.reserve(800);
    for (uint32_t i = 0; i < 800; ++i) {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(fundRef->GetId(), i);
        tx.vin[0].scriptSig =
            CScript() << int64_t(i + 1) << std::vector<uint8_t>(48, 0x42);
        tx.vout.emplace_back(90000 * SATOSHI, CScript() << OP_TRUE);
        CTransactionRef txRef = MakeTransactionRef(std::move(tx));
        AddUnchecked(entry.Fee(10000 * SATOSHI).FromTx(txRef));
        rootTxs.push_back(txRef);
    }
    for (uint32_t i = 0; i < 200; ++i) {
        CMutableTransaction child;
        child.nVersion = 2;
        child.vin.resize(1);
        child.vin[0].prevout = COutPoint(rootTxs[i]->GetId(), 0);
        child.vin[0].scriptSig =
            CScript() << int64_t(1000 + i) << std::vector<uint8_t>(48, 0x43);
        child.vout.emplace_back(80000 * SATOSHI, CScript() << OP_TRUE);
        CTransactionRef childRef = MakeTransactionRef(std::move(child));
        AddUnchecked(entry.Fee(10000 * SATOSHI).FromTx(childRef));
    }

    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 1000U);
    BOOST_REQUIRE_EQUAL(
        m_node.mempool->GetMerklixOverlay().GetSpeculativeOverlay().GetTxCount(),
        1000U);

    BlockFitter::Options fitterOpts;
    fitterOpts.blockMinFeeRate = blockMinFeeRate;
    BlockAssembler::Options asmOpts;
    asmOpts.test_block_validity = false;
    asmOpts.add_finalized_txs = false;

    const auto t0 = SteadyClock::now();
    auto pblocktemplate =
        BlockAssembler{BlockFitter(fitterOpts),
                       m_node.chainman->ActiveChainstate(),
                       m_node.mempool.get(), asmOpts}
            .CreateNewBlock(CScript() << OP_TRUE);
    const auto t1 = SteadyClock::now();
    const double create_new_block_ms = Ticks<MillisecondsDouble>(t1 - t0);

    BOOST_REQUIRE(pblocktemplate != nullptr);
    const CBlock &block = pblocktemplate->block;
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1001U);

    // Verify strict CTOR ordering on block.vtx[1..1000]
    for (size_t i = 2; i < block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i - 1]->GetId() < block.vtx[i]->GetId());
    }

    // Time O(1) overlay root extraction vs O(N log N) from-scratch computation
    const auto &spec =
        m_node.mempool->GetMerklixOverlay().GetSpeculativeOverlay();
    const auto t_ov0 = SteadyClock::now();
    const uint256 ov_merkle =
        ComputeV2TxRootFromSubtreeA(*block.vtx[0], spec.GetSubtreeARoot());
    const uint256 ov_state = ComputeV2StateRootFromOverlay(
        *block.vtx[0], spec, block.nBits, nextHeight, nextMtp, false);
    const auto t_ov1 = SteadyClock::now();
    const double overlay_roots_ms = Ticks<MillisecondsDouble>(t_ov1 - t_ov0);

    const auto t_full0 = SteadyClock::now();
    const uint256 expected_merkle = BlockMerkleRoot(block);
    const uint256 expected_state = ComputeV2BlockStateRoot(
        block, tip->GetBlockHash(), nextHeight, nextMtp, false);
    const auto t_full1 = SteadyClock::now();
    const double full_roots_ms = Ticks<MillisecondsDouble>(t_full1 - t_full0);

    BOOST_CHECK_EQUAL(block.hashMerkleRoot, expected_merkle);
    BOOST_CHECK_EQUAL(block.hashStateRoot, expected_state);
    BOOST_CHECK_EQUAL(ov_merkle, expected_merkle);
    BOOST_CHECK_EQUAL(ov_state, expected_state);

    BOOST_TEST_MESSAGE(strprintf(
        "1000-tx CreateNewBlock: %.3f ms | O(1) Overlay Roots: %.4f ms vs "
        "From-Scratch Roots: %.3f ms (%.1fx speedup)",
        create_new_block_ms, overlay_roots_ms, full_roots_ms,
        overlay_roots_ms > 0.0 ? (full_roots_ms / overlay_roots_ms) : 0.0));
}

BOOST_AUTO_TEST_SUITE_END()
