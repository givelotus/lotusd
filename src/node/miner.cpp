// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <minerfund.h>
#include <policy/block/stakingrewards.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow/pow.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <validation.h>

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <utility>

namespace node {
int64_t UpdateTime(CBlockHeader *pblock, const CChainParams &chainParams,
                   const CBlockIndex *pindexPrev, int64_t adjustedTime) {
    int64_t nOldTime = pblock->GetBlockTime();
    int64_t nNewTime{
        std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, adjustedTime)};

    if (nOldTime < nNewTime) {
        pblock->SetBlockTime(nNewTime);
    }

    // Updating time can change work required on testnet:
    if (chainParams.GetConsensus().fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainParams);
    }

    return nNewTime - nOldTime;
}

Amount GetBlockRewardFromFees(Amount nFees) {
    // 50% of fees get burned.
    return nFees / 2;
}

void ApplyArgsManOptions(const ArgsManager &args,
                         BlockAssembler::Options &options) {
    options.fPrintPriority =
        args.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    options.add_finalized_txs = args.GetBoolArg(
        "-avalanchepreconsensusmining", DEFAULT_AVALANCHE_MINING_PRECONSENSUS);
}

static BlockAssembler::Options ConfiguredOptions() {
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    return options;
}

BlockAssembler::BlockAssembler(const BlockFitter &fitter,
                               Chainstate &chainstate,
                               const CTxMemPool *mempool,
                               const Options &options,
                               const avalanche::Processor *avalanche)
    : blockFitter(fitter), chainParams(chainstate.m_chainman.GetParams()),
      m_mempool(mempool), m_chainstate(chainstate), m_avalanche(avalanche),
      fPrintPriority{options.fPrintPriority},
      test_block_validity{options.test_block_validity},
      add_finalized_txs{avalanche && options.add_finalized_txs} {}

BlockAssembler::BlockAssembler(const BlockFitter &fitter,
                               Chainstate &chainstate,
                               const CTxMemPool *mempool,
                               const avalanche::Processor *avalanche)
    : BlockAssembler(fitter, chainstate, mempool, ConfiguredOptions(),
                     avalanche) {}

BlockAssembler::BlockAssembler(const Config &config, Chainstate &chainstate,
                               const CTxMemPool *mempool,
                               const avalanche::Processor *avalanche)
    : BlockAssembler(BlockFitter(config), chainstate, mempool, avalanche) {}

std::optional<int64_t> BlockAssembler::m_last_block_num_txs{std::nullopt};
std::optional<int64_t> BlockAssembler::m_last_block_size{std::nullopt};

std::unique_ptr<CBlockTemplate>
BlockAssembler::CreateNewBlock(const CScript &scriptPubKeyIn) {
    const auto time_start{SteadyClock::now()};

    blockFitter.resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    if (!pblocktemplate.get()) {
        return nullptr;
    }

    // Pointer for convenience.
    CBlock *const pblock = &pblocktemplate->block;

    // Add dummy coinbase tx as first transaction.  It is updated at the end.
    pblocktemplate->entries.emplace_back(CTransactionRef(), -SATOSHI, -1);

    LOCK(::cs_main);
    CBlockIndex *pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    const Consensus::Params &consensusParams = chainParams.GetConsensus();

    // Version must always be 1
    pblock->nHeaderVersion = 1;
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainParams.MineBlocksOnDemand()) {
        pblock->nHeaderVersion =
            gArgs.GetIntArg("-blockversion", pblock->nHeaderVersion);
    }

    // Fill in header.
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->SetBlockTime(TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
    UpdateTime(pblock, chainParams, pindexPrev,
               TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainParams);
    pblock->nNonce = 0;
    pblock->nHeight = nHeight;
    if (nHeight % EPOCH_NUM_BLOCKS == 0) { // new epoch started
        pblock->hashEpochBlock = pblock->hashPrevBlock;
    } else {
        pblock->hashEpochBlock = pindexPrev->hashEpochBlock;
    }
    pblock->hashExtendedMetadata = SerializeHash(pblock->vMetadata);
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    bool shouldAddFinalizedTxs =
        m_avalanche && add_finalized_txs &&
        m_avalanche->isPreconsensusActivated(pindexPrev);

    if (m_mempool) {
        LOCK(m_mempool->cs);
        if (shouldAddFinalizedTxs) {
            addFinalizedTxs(*m_mempool);
        } else {
            addTxs(*m_mempool);
        }
    }

    // Canonical ordering is naturally enforced when using the radix tree
    if (!shouldAddFinalizedTxs) {
        // We make sure transaction are canonically ordered.
        std::sort(std::begin(pblocktemplate->entries) + 1,
                  std::end(pblocktemplate->entries),
                  [](const CBlockTemplateEntry &a, const CBlockTemplateEntry &b)
                      -> bool { return a.tx->GetId() < b.tx->GetId(); });
    }

    // Copy all the transactions refs into the block
    pblock->vtx.reserve(pblocktemplate->entries.size());
    for (const CBlockTemplateEntry &entry : pblocktemplate->entries) {
        pblock->vtx.push_back(entry.tx);
    }

    const auto time_1{SteadyClock::now()};
    const Amount amountFeeReward = GetBlockRewardFromFees(blockFitter.nFees);

    m_last_block_num_txs = blockFitter.nBlockTx;
    m_last_block_size = blockFitter.nBlockSize;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout = COutPoint();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue =
        amountFeeReward + GetBlockSubsidy(pblock->nBits, consensusParams);
    coinbaseTx.vin[0].scriptSig = CScript()
                                  << COINBASE_PREFIX << nHeight << OP_0;

    const Amount blockReward = coinbaseTx.vout[0].nValue;
    const std::vector<CTxOut> requiredOutputs =
        GetMinerFundRequiredOutputs(consensusParams, pindexPrev, blockReward);
    for (const CTxOut &requiredOutput : requiredOutputs) {
        coinbaseTx.vout[0].nValue -= requiredOutput.nValue;
        coinbaseTx.vout.push_back(requiredOutput);
    }

    std::vector<CScript> stakingRewardsPayoutScripts;
    if (m_avalanche && IsStakingRewardsActivated(consensusParams, pindexPrev) &&
        m_avalanche->getStakingRewardWinners(pindexPrev->GetBlockHash(),
                                             stakingRewardsPayoutScripts)) {
        const Amount stakingRewards = GetStakingRewardsAmount(blockReward);
        coinbaseTx.vout[0].nValue -= stakingRewards;
        coinbaseTx.vout.emplace_back(stakingRewards,
                                     stakingRewardsPayoutScripts[0]);
    }

    // Make sure the coinbase is big enough.
    uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx);
    if (coinbaseSize < MIN_TX_SIZE) {
        coinbaseTx.vin[0].scriptSig
            << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
    }

    pblocktemplate->entries[0].tx = MakeTransactionRef(coinbaseTx);
    pblocktemplate->entries[0].fees = -1 * blockFitter.nFees;
    pblock->vtx[0] = pblocktemplate->entries[0].tx;

    uint64_t nSerializeSize = GetSerializeSize(*pblock);

    LogPrintf(
        "CreateNewBlock(): total size: %u txs: %u fees: %ld sigChecks %d\n",
        nSerializeSize, blockFitter.nBlockTx, blockFitter.nFees,
        blockFitter.nBlockSigChecks);

    // Fill in size
    pblock->SetSize(nSerializeSize);
    pblocktemplate->entries[0].sigChecks = 0;

    BlockValidationState state;
    if (test_block_validity &&
        !TestBlockValidity(
            state, chainParams, m_chainstate, *pblock, pindexPrev,
            GetAdjustedTime,
            BlockValidationOptions(blockFitter.getMaxGeneratedBlockSize())
                .withCheckPoW(false)
                .withCheckMerkleRoot(false))) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s",
                                           __func__, state.ToString()));
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(
        BCLog::BENCH,
        "CreateNewBlock() addTxs: %.2fms, validity: %.2fms (total %.2fms)\n",
        Ticks<MillisecondsDouble>(time_1 - time_start),
        Ticks<MillisecondsDouble>(time_2 - time_1),
        Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

void BlockAssembler::AddToBlock(const CTxMemPoolEntryRef &entry) {
    pblocktemplate->entries.emplace_back(entry->GetSharedTx(), entry->GetFee(),
                                         entry->GetSigChecks());

    blockFitter.addTx(entry->GetTxSize(), entry->GetSigChecks(),
                      entry->GetFee());

    if (fPrintPriority) {
        LogPrintf(
            "fee rate %s txid %s\n",
            CFeeRate(entry->GetModifiedFee(), entry->GetTxSize()).ToString(),
            entry->GetTx().GetId().ToString());
    }
}

bool BlockAssembler::CheckTx(const CTransaction &tx) const {
    TxValidationState state;
    return ContextualCheckTransaction(chainParams.GetConsensus(), tx, state,
                                      nHeight, m_lock_time_cutoff);
}

/**
 * Build a dependency snapshot and select the highest-feerate ready transaction.
 * Each transaction is queued at most once and each direct-parent edge is
 * updated once: expected O(n + m + n log n) time and O(n + m) space for n
 * entries and m dependency edges. Hash lookups use the salted transaction ID
 * hasher. This is not an assertion of a speedup over upstream's assembler.
 */
void BlockAssembler::addTxs(const CTxMemPool &mempool) {
    struct SnapshotEntry {
        CTxMemPoolEntryRef entry;
        size_t missingParents;
        std::vector<size_t> children;
    };
    std::vector<SnapshotEntry> snapshot;
    snapshot.reserve(mempool.mapTx.size());
    std::unordered_map<TxId, size_t, SaltedTxIdHasher> locations;
    locations.reserve(mempool.mapTx.size());
    for (const auto &entry : mempool.mapTx.get<entry_id>()) {
        locations.emplace(entry->GetTx().GetId(), snapshot.size());
        snapshot.push_back({entry, entry->GetMemPoolParentsConst().size(), {}});
    }
    // Parent sets deduplicate multiple inputs spending one parent, and a
    // shared ancestor is represented only by its direct dependency edges.
    for (size_t child = 0; child < snapshot.size(); ++child) {
        for (const auto &parent : snapshot[child].entry->GetMemPoolParentsConst()) {
            const auto position = locations.find(parent.get()->GetTx().GetId());
            assert(position != locations.end());
            snapshot[position->second].children.push_back(child);
        }
    }
    auto lowerPriority = [&snapshot](size_t a, size_t b) {
        return CompareTxMemPoolEntryByModifiedFeeRate{}(snapshot[b].entry,
                                                       snapshot[a].entry);
    };
    std::priority_queue<size_t, std::vector<size_t>, decltype(lowerPriority)>
        ready(lowerPriority);
    for (size_t i = 0; i < snapshot.size(); ++i) {
        if (snapshot[i].missingParents == 0) {
            ready.push(i);
        }
    }

    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t consecutiveFailures = 0;
    while (!ready.empty()) {
        const size_t index = ready.top();
        ready.pop();
        const auto &entry = snapshot[index].entry;
        // Individual modified fees preserve the existing no-CPFP policy:
        // already selected ancestors cannot subsidize a free descendant.
        if (blockFitter.isBelowBlockMinFeeRate(entry->GetModifiedFeeRate())) {
            // All remaining ready entries have no higher fee rate, and their
            // descendants cannot become ready without including them.
            break;
        }
        // Recheck this transaction's actual resources against the live block;
        // ancestors are already included and must not be charged twice.
        if (!blockFitter.testTxFits(entry->GetTxSize(), entry->GetSigChecks())) {
            ++consecutiveFailures;
            if (consecutiveFailures > MAX_CONSECUTIVE_FAILURES &&
                blockFitter.nBlockSize >
                    blockFitter.getMaxGeneratedBlockSize() - 1000) {
                break;
            }
            continue;
        }
        if (!CheckTx(entry->GetTx())) {
            continue;
        }
        consecutiveFailures = 0;
        AddToBlock(entry);
        // Only successful inclusion releases children. A nonfinal, low-fee,
        // or non-fitting ancestor therefore also excludes its descendants.
        for (const size_t child : snapshot[index].children) {
            assert(snapshot[child].missingParents > 0);
            if (--snapshot[child].missingParents == 0) {
                ready.push(child);
            }
        }
    }
}

/**
 * addFinalizedTxs fills the template with the finalized transactons. The radix
 * tree is making sure it's all ready to go and already sorted so there is no
 * check to do anymore.
 */
void BlockAssembler::addFinalizedTxs(const CTxMemPool &mempool) {
    AssertLockHeld(mempool.cs);

    mempool.finalizedTxs.forEachLeaf(
        [this, &mempool](const CTxMemPoolEntryRef &entry) {
            // A tx can be added if it exists in the mempool. Otherwise this
            // means that a block connected but is not yet finalized containing
            // this tx.
            if (mempool.exists(entry->GetTx().GetId())) {
                AddToBlock(entry);
            }
            return true;
        });
}
} // namespace node
