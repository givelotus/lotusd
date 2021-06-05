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
#include <pow/aserti32d.h>
#include <pow/pow.h>
#include <streams.h>
#include <util/strencodings.h>

// Set this to 1 to make the CreateNewBlock_validity test print block headers
// and then terminate instead of running the actual test.
#define GENERATE_BLOCK_HEADERS 0

namespace miner_tests {
struct MinerTestingSetup : public TestingSetup {
    void TestPackageSelection(const Config &config, const CScript &scriptPubKey,
                              const std::vector<CTransactionRef> &txFirst)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs);
    bool TestSequenceLocks(const CTransaction &tx, int flags)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_node.mempool->cs) {
        return CheckSequenceLocks(*m_node.mempool, tx, flags);
    }
    BlockAssembler AssemblerForTest(const Config &config);
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);

BlockAssembler MinerTestingSetup::AssemblerForTest(const Config &config) {
    const CChainParams &params = config.GetChainParams();
    BlockAssembler::Options options;
    options.blockMinFeeRate = blockMinFeeRate;
    options.enableMinerFund = config.EnableMinerFund();
    return BlockAssembler(params, *m_node.mempool, options);
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
    const Config &config, const CScript &scriptPubKey,
    const std::vector<CTransactionRef> &txFirst) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    CScript scriptSig = CScript() << std::vector<uint8_t>{OP_1};

    // Padding so txs are not undersize
    std::vector<uint8_t> padData(100);

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
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
    m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(true)
                                     .FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - 10000 * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(10000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(true)
                                     .FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = parentTxAmount - 50000 * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    Amount highFeeTxAmount = tx.vout[0].nValue;
    m_node.mempool->addUnchecked(entry.Fee(50000 * SATOSHI)
                                     .Time(GetTime())
                                     .SpendsCoinbase(false)
                                     .FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(config).CreateNewBlock(scriptPubKey);
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 4);
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx[1]->GetId(), parentTxId);
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx[2]->GetId(), highFeeTxId);
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx[3]->GetId(), mediumFeeTxId);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = highFeeTxAmount;
    TxId freeTxId = tx.GetId();
    Amount freeTxAmount = tx.vout[0].nValue;
    m_node.mempool->addUnchecked(entry.Fee(Amount::zero()).FromTx(tx));
    size_t freeTxSize = GetSerializeSize(tx, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee (assuming 1 child tx of the same size).
    Amount feeToUse = blockMinFeeRate.GetFee(2 * freeTxSize) - SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue = freeTxAmount - feeToUse;
    TxId lowFeeTxId = tx.GetId();
    m_node.mempool->addUnchecked(entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);
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
    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 6);
    // Need pointers to be able to swap entries
    const std::vector<TxId> txIds = {freeTxId, lowFeeTxId, parentTxId,
                                     highFeeTxId, mediumFeeTxId};
    // std::sort(std::begin(txIds), std::end(txIds));
    for (const auto &txn : std::vector(pblocktemplate->block.vtx.begin() + 1,
                                       pblocktemplate->block.vtx.end())) {
        const auto found = std::find(txIds.begin(), txIds.end(), txn->GetId());
        BOOST_CHECK_MESSAGE(found != txIds.end(),
                            "Could not find: " << txn->GetId());
    }

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block. Add a
    // 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 1);
    tx.vout[0].nValue = txFirst[2]->vout[1].nValue - 100000000 * SATOSHI;
    tx.vout[0].scriptPubKey = CScript() << padData << OP_DROP;
    // 1BCC output.
    tx.vout[1].nValue = 100000000 * SATOSHI;
    tx.vout[1].scriptPubKey = CScript();
    TxId freeTxId2 = tx.GetId();
    Amount freeTxAmount2 = tx.vout[0].nValue;
    m_node.mempool->addUnchecked(
        entry.Fee(Amount::zero()).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself.
    tx.vin[0].prevout = COutPoint(freeTxId2, 0);
    tx.vout.resize(1);
    feeToUse = blockMinFeeRate.GetFee(freeTxSize);
    tx.vout[0].nValue = freeTxAmount2 - feeToUse;
    TxId lowFeeTxId2 = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);

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
    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);
    const auto foundTx = std::find_if(
        pblocktemplate->block.vtx.begin(), pblocktemplate->block.vtx.end(),
        [lowFeeTxId2](const CTransactionRef &a) -> bool {
            return a->GetId() == lowFeeTxId2;
        });

    BOOST_CHECK_MESSAGE(foundTx != pblocktemplate->block.vtx.end(),
                        "Did not find lowFeeTxId2");
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
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig ==
                (CScript() << CScriptNum(extraNonce) << vec));
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
    // Don't check this functionality in this test.
    config.SetEnableMinerFund(false);
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
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 110 blocks :)
    static_assert(sizeof(blockinfo) / sizeof(*blockinfo) == 110,
                  "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
#if GENERATE_BLOCK_HEADERS
    const int64_t anchorTime = ::ChainActive().Tip()->nTime;
    const int32_t anchorHeight = ::ChainActive().Tip()->nHeight + 1;
    int64_t nTimePrev = ::ChainActive().Tip()->GetMedianTimePast();
#endif
    int nHeight = ::ChainActive().Height() + 1;
    int64_t nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
    for (size_t i = 0; i < sizeof(blockinfo) / sizeof(*blockinfo); ++i) {
        // pointer for convenience.
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            // Fill in header
            pblock->SetBlockTime(nTime);
            pblock->nNonce = blockinfo[i];
            pblock->nHeaderVersion = 1;
            pblock->nHeight = nHeight;
            pblock->hashEpochBlock.SetNull();
            pblock->hashExtendedMetadata = SerializeHash('\0');
            CBlockHeader header = pblock->GetBlockHeader();
            pblock->nBits = GetNextWorkRequired(::ChainActive().Tip(), &header,
                                                chainparams);
#if GENERATE_BLOCK_HEADERS
            if (nHeight > 1) {
                pblock->nBits =
                    CalculateASERT(
                        UintToArith256(chainparams.GetConsensus().powLimit),
                        chainparams.GetConsensus().nPowTargetSpacing,
                        nTimePrev - anchorTime, (nHeight - 1) - anchorHeight,
                        UintToArith256(chainparams.GetConsensus().powLimit),
                        chainparams.GetConsensus().nDAAHalfLife)
                        .GetCompact();
            }
#endif
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
                ::ChainActive().Tip(), minerReward);
            for (size_t i = 0; i < requiredOutputs.size(); ++i) {
                txCoinbase.vout[i + 2] = requiredOutputs[i];
                minerReward -= requiredOutputs[i].nValue;
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
            pblock->SetSize(GetSerializeSize(*pblock));
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
#if GENERATE_BLOCK_HEADERS
        CDataStream writer(SER_NETWORK, PROTOCOL_VERSION);
        writer << pblock->GetBlockHeader();
        std::cout << HexStr(std::vector(writer.begin(), writer.end()))
                  << std::endl;
        nTimePrev = nTime;
#else
        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlock(config, shared_pblock, true, nullptr));
#endif
        ++nHeight;
        ++nTime;
        pblock->hashPrevBlock = pblock->GetHash();
    }
#if GENERATE_BLOCK_HEADERS
    return;
#endif
    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    // Just to make sure we can still make simple blocks.
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));

    std::vector<uint8_t> padData(100);

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
        // Only first tx spends coinbase.
        bool spendsCoinbase = i == 0;
        m_node.mempool->addUnchecked(entry.Fee(LOWFEE)
                                         .Time(GetTime())
                                         .SpendsCoinbase(spendsCoinbase)
                                         .FromTx(tx));
        tx.vin[0].prevout = COutPoint(txid, 0);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    m_node.mempool->clear();

    // Orphan in mempool, template creation fails.
    m_node.mempool->addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(AssemblerForTest(config).CreateNewBlock(scriptPubKey),
                          std::runtime_error,
                          HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear();

    // Child with higher priority than parent.
    tx.vin[0].scriptSig = scriptSig;
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - HIGHFEE;
    TxId txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    tx.vin[1].scriptSig = scriptSig;
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 1);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue =
        tx.vout[0].nValue + txFirst[0]->vout[1].nValue - HIGHERFEE;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
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
    BOOST_CHECK_EXCEPTION(AssemblerForTest(config).CreateNewBlock(scriptPubKey),
                          std::runtime_error, HasReason("bad-tx-coinbase"));
    m_node.mempool->clear();

    // Double spend txn pair in mempool, template creation fails.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(2);
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.vout[1].nValue = Amount::zero();
    tx.vout[1].scriptPubKey = CScript() << OP_RETURN << padData;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    m_node.mempool->addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(AssemblerForTest(config).CreateNewBlock(scriptPubKey),
                          std::runtime_error,
                          HasReason("bad-txns-inputs-missingorspent"));
    m_node.mempool->clear();

    // Subsidy changing.
    nHeight = ::ChainActive().Height();
    // Create an actual 209999-long block chain (without valid blocks).
    BlockHash epochBlockHash;
    while (::ChainActive().Tip()->nHeight < 209999) {
        CBlockIndex *prev = ::ChainActive().Tip();
        if ((prev->nHeight + 1) % EPOCH_NUM_BLOCKS == 0) {
            epochBlockHash = *prev->phashBlock;
        }
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->hashEpochBlock = epochBlockHash;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (::ChainActive().Tip()->nHeight < 210000) {
        CBlockIndex *prev = ::ChainActive().Tip();
        if ((prev->nHeight + 1) % EPOCH_NUM_BLOCKS == 0) {
            epochBlockHash = *prev->phashBlock;
        }
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        ::ChainstateActive().CoinsTip().SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->hashEpochBlock = epochBlockHash;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }

    BOOST_CHECK(pblocktemplate =
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - LOWFEE;
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
    BOOST_CHECK_EXCEPTION(AssemblerForTest(config).CreateNewBlock(scriptPubKey),
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
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 1);
    tx.vin[0].scriptSig = scriptSig;
    // TODO: These tests seem to be broken regarding MTP, enforcing BIP68 from
    // genesis makes relative locktime fail when creating a block.
    // Now, we just make the tx sequence BIP68 compliant before adding it to
    // the mempool and rely only on TestSequenceLocks for now.
    // This test is a mess, we're using tx to both do tests on the tx itself
    // and for adding txs to the mempool.
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight - 1;
    prevheights[0] = baseheight + 1;
    tx.vout[0].nValue = txFirst[0]->vout[1].nValue - HIGHFEE;
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
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 1);
    // TODO: These tests seem to be broken, enforcing BIP68 from genesis
    // makes relative locktime fail when creating a block.
    // We only rely on TestSequenceLocks for now.
    tx.vin[0].nSequence = 0;
    tx.vout[0].nValue = txFirst[1]->vout[1].nValue - entry.nFee;
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
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 1);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    tx.vout[0].nValue = txFirst[2]->vout[1].nValue - entry.nFee;
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
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 1);
    tx.vout[0].nValue = txFirst[3]->vout[1].nValue - entry.nFee;
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

    pblocktemplate = AssemblerForTest(config).CreateNewBlock(scriptPubKey);
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
                    AssemblerForTest(config).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);

    ::ChainActive().Tip()->nHeight--;
    SetMockTime(0);
    m_node.mempool->clear();

    TestPackageSelection(config, scriptPubKey, txFirst);

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
