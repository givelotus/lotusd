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
#include <feerate.h>
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
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace node {
int64_t UpdateTime(CBlockHeader *pblock, const CChainParams &chainParams,
                   const CBlockIndex *pindexPrev, int64_t adjustedTime) {
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{
        std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, adjustedTime)};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (chainParams.GetConsensus().fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainParams);
    }

    return nNewTime - nOldTime;
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

    // Always mine version 1
    pblock->nVersion = 1;
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainParams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    // Fill in header.
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    UpdateTime(pblock, chainParams, pindexPrev,
               TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainParams);
    pblock->nNonce = 0;
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
    // 50% of fees get burned.
    const Amount amountFeeReward = blockFitter.nFees / 2;

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

    LogPrint(
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
 * addTxs selects transactions from the mempool for inclusion in a block.
 *
 * Algorithm overview (O(n log n) total):
 *  1. Snapshot all mempool transactions in topological order (entry_id order —
 *     parents always precede children).  O(n)
 *  2. Forward-walk the snapshot to accumulate package fee/size/sigchecks for
 *     each transaction from its in-mempool ancestors.  O(n + m)
 *  3. Assign each transaction a scheduling "order":
 *       order=0  → mine-first tier (package fee rate beats all ancestors)
 *       order>0  → deeper ancestor chain must go in first
 *     Sort ascending by order, then descending by fee rate.  O(n log n)
 *  4. Visit transactions in sorted order; for each, DFS to add all
 *     unconfirmed ancestors before the transaction itself.  O(n + m)
 *
 * This eliminates the O(n²) ancestor-score update loop of the legacy
 * implementation and removes the need for any pre-computed mempool
 * ancestor/descendant bookkeeping fields.
 */
void BlockAssembler::addTxs(const CTxMemPool &mempool) {
    // ── 1. Snapshot mempool in topological (entry_id) order ──────────────────
    std::vector<CBlockTemplateEntry> txPool;
    txPool.reserve(mempool.mapTx.size());
    std::unordered_map<TxId, size_t, SaltedTxIdHasher> txLocations;
    size_t idx = 0;
    for (const auto &entry : mempool.mapTx.get<entry_id>()) {
        txPool.emplace_back(entry->GetSharedTx(),
                            entry->GetFee(),
                            entry->GetModifiedFee(),
                            entry->GetTxSize(),
                            entry->GetSigChecks());
        txLocations[txPool.back().tx->GetId()] = idx++;
    }

    // ── 2. Accumulate package stats from parents ──────────────────────────────
    // Single forward pass suffices because parents always appear before
    // children in entry_id order. Diamond patterns are double-counted
    // (acceptable: avoiding it isn't worth the extra complexity).
    std::unordered_set<TxId, SaltedTxIdHasher> seen;
    for (auto &entry : txPool) {
        seen.clear();
        for (const auto &txIn : entry.tx->vin) {
            const TxId &parentId = txIn.prevout.GetTxId();
            if (!seen.insert(parentId).second) {
                continue; // skip duplicate direct parents
            }
            auto it = txLocations.find(parentId);
            if (it == txLocations.end()) {
                continue; // confirmed (not in mempool)
            }
            entry.AccountForParent(txPool[it->second]);
        }
    }

    // ── 3. Sort: ascending order depth, descending fee rate within each tier ──
    std::sort(txPool.begin(), txPool.end(),
              [](const CBlockTemplateEntry &a, const CBlockTemplateEntry &b) {
                  return a.GetOrder() == b.GetOrder()
                             ? a.FeeRate() > b.FeeRate()
                             : a.GetOrder() < b.GetOrder();
              });

    // Rebuild location index after sort.
    idx = 0;
    for (const auto &e : txPool) {
        txLocations[e.tx->GetId()] = idx++;
    }

    // ── 4. Include transactions in sorted order via ancestor DFS ──────────────
    // txIdsInBlock tracks added TxIds for O(1) membership tests inside DFS.
    std::unordered_set<TxId, SaltedTxIdHasher> txIdsInBlock;
    std::unordered_set<TxId, SaltedTxIdHasher> txnsInvalid;

    for (const auto &entry : txPool) {
        const TxId txId = entry.tx->GetId();

        if (txIdsInBlock.count(txId) || txnsInvalid.count(txId)) {
            continue;
        }

        // Skip packages below the min fee rate.
        if (blockFitter.isBelowBlockMinFeeRate(
                CFeeRate(entry.packageFees, entry.packageSize))) {
            txnsInvalid.insert(txId);
            continue;
        }

        // Quick package-level size/sigchecks check before the DFS.
        if (!blockFitter.testTxFits(entry.packageSize, entry.packageSigChecks)) {
            continue;
        }

        // DFS: push ancestors onto addStack in reverse-topological order so
        // that popping the stack yields topological (parents-first) order.
        std::stack<std::reference_wrapper<const CBlockTemplateEntry>>
            ancestorStack;
        std::stack<std::reference_wrapper<const CBlockTemplateEntry>> addStack;
        bool packageInvalid = false;

        ancestorStack.push(std::cref(entry));
        while (!ancestorStack.empty() && !packageInvalid) {
            const CBlockTemplateEntry &ancestor = ancestorStack.top();
            const TxId &ancestorId = ancestor.tx->GetId();
            ancestorStack.pop();
            addStack.push(std::cref(ancestor));

            // Contextual check (locktime / finality).
            if (!CheckTx(*ancestor.tx)) {
                txnsInvalid.insert(ancestorId);
                packageInvalid = true;
                break;
            }

            for (const auto &txIn : ancestor.tx->vin) {
                const TxId &parentId = txIn.prevout.GetTxId();
                if (txIdsInBlock.count(parentId)) {
                    continue; // already in block
                }
                if (txnsInvalid.count(parentId)) {
                    txnsInvalid.insert(ancestorId);
                    packageInvalid = true;
                    break;
                }
                auto it = txLocations.find(parentId);
                if (it == txLocations.end()) {
                    continue; // confirmed parent
                }
                ancestorStack.push(std::cref(txPool[it->second]));
            }
        }

        if (packageInvalid) {
            // Propagate invalidity through addStack items.
            while (!addStack.empty()) {
                const CBlockTemplateEntry &child = addStack.top();
                addStack.pop();
                for (const auto &txIn : child.tx->vin) {
                    if (txnsInvalid.count(txIn.prevout.GetTxId())) {
                        txnsInvalid.insert(child.tx->GetId());
                        break;
                    }
                }
            }
            continue;
        }

        // All ancestors passed — commit to block in topological order.
        while (!addStack.empty()) {
            const CBlockTemplateEntry &toAdd = addStack.top();
            const TxId &addId = toAdd.tx->GetId();
            addStack.pop();
            if (txIdsInBlock.count(addId)) {
                continue; // addStack can contain duplicates from DFS
            }
            auto optIter = mempool.GetIter(addId);
            if (optIter) {
                AddToBlock(**optIter);
                txIdsInBlock.insert(addId);
            }
        }
    }
}

/**
 * accuratelyAddTxs: legacy O(n²) implementation.
 * Kept for reference and benchmarking. Not called in production.
 */
void BlockAssembler::accuratelyAddTxs(const CTxMemPool &mempool) {
    // mapped_value is the number of mempool parents that are still needed for
    // the entry. We decrement this count each time we add a parent of the entry
    // to the block.
    std::unordered_map<CTxMemPoolEntryRef, size_t> missingParentCount;
    missingParentCount.reserve(mempool.size() / 2);

    // set of children we skipped because we have not yet added their parents
    std::unordered_set<CTxMemPoolEntryRef> skippedChildren;

    auto hasMissingParents =
        [&missingParentCount](const CTxMemPoolEntryRef &entry)
            EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
                // If we've added any of this tx's parents already, then
                // missingParentCount will have the current count
                if (auto pcIt = missingParentCount.find(entry);
                    pcIt != missingParentCount.end()) {
                    // when pcIt->second reaches 0, we have added all of this
                    // tx's parents
                    return pcIt->second != 0;
                }
                return !entry->GetMemPoolParentsConst().empty();
            };

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    // Transactions where a parent has been added and need to be checked for
    // inclusion.
    std::queue<CTxMemPoolEntryRef> backlog;
    auto mi = mempool.mapTx.get<modified_feerate>().begin();

    auto nextEntry = [&backlog, &mi](bool &isFromBacklog) {
        if (backlog.empty()) {
            return *mi++;
        }

        auto &entry = backlog.front();
        backlog.pop();

        isFromBacklog = true;

        return entry;
    };

    while (!backlog.empty() ||
           mi != mempool.mapTx.get<modified_feerate>().end()) {
        // Get a new or old transaction in mapTx to evaluate.
        bool isFromBacklog = false;
        const CTxMemPoolEntryRef &entry = nextEntry(isFromBacklog);

        if (blockFitter.isBelowBlockMinFeeRate(entry->GetModifiedFeeRate())) {
            // Since the txs are sorted by fee, bail early if there is none that
            // can be included in the block anymore.
            break;
        }

        // Check whether all of this tx's parents are already in the block. If
        // not, pass on it until later.
        //
        // If it's from the backlog, then we know all parents are already in
        // the block.
        if (!isFromBacklog && hasMissingParents(entry)) {
            skippedChildren.insert(entry);
            continue;
        }

        // Check whether the tx will exceed the block limits.
        if (!blockFitter.testTxFits(entry->GetTxSize(),
                                    entry->GetSigChecks())) {
            ++nConsecutiveFailed;
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                blockFitter.nBlockSize >
                    blockFitter.getMaxGeneratedBlockSize() - 1000) {
                // Give up if we're close to full and haven't succeeded in a
                // while.
                break;
            }
            continue;
        }

        // Test transaction finality (locktime)
        if (!CheckTx(entry->GetTx())) {
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Tx can be added.
        AddToBlock(entry);

        // This tx's children may now be candidates for addition if they have
        // higher scores than the tx at the cursor. We can only process a
        // child once all of that tx's parents have been added, though. To
        // avoid O(n^2) checking of dependencies, we store and decrement the
        // number of mempool parents for each child. Although this code
        // ends up taking O(n) time to process a single tx with n children,
        // that's okay because the amount of time taken is proportional to the
        // tx's byte size and fee paid.
        for (const auto &child : entry->GetMemPoolChildrenConst()) {
            // Remember this tx has missing parents.
            // Create the map entry if it doesn't exist already, and init with
            // the number of parents.
            const auto &[parentCount, _] = missingParentCount.try_emplace(
                child, child.get()->GetMemPoolParentsConst().size());
            // We just added one parent, so decrement the counter and check if
            // we have any missing parent remaining.
            const bool allParentsAdded = --parentCount->second == 0;

            // If all parents have been added to the block, and if this child
            // has been previously skipped due to missing parents, enqueue it
            // (if it hasn't been skipped it will come up in a later iteration)
            if (allParentsAdded && skippedChildren.count(child) > 0) {
                backlog.push(child);
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
