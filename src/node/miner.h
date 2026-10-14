// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINER_H
#define BITCOIN_NODE_MINER_H

#include <common/args.h>
#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <node/blockfitter.h>
#include <primitives/block.h>
#include <txmempool.h>

#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <cstdint>
#include <memory>
#include <optional>

class CBlockIndex;
class CChainParams;
class Config;
class CScript;

namespace Consensus {
struct Params;
}

namespace avalanche {
class Processor;
}

namespace node {
static const bool DEFAULT_PRINTPRIORITY = false;

/**
 * Calculate the additional block reward in the coinbase from fees.
 * Currenty, 50% of fees are burned.
 */
Amount GetBlockRewardFromFees(Amount nFees);

struct CBlockTemplateEntry {
    CTransactionRef tx;
    Amount fees;
    int64_t sigChecks;

    // Internal fields used during block assembly — not meaningful in final
    // pblocktemplate->entries after CreateNewBlock returns.
    Amount modifiedFee;
    size_t txSize;
    // Accumulated package totals (this tx + all unconfirmed ancestors).
    size_t packageSize;
    Amount packageFees;
    int64_t packageSigChecks;
    // Maximum fee rate seen across any ancestor package (used for ordering).
    double maxPackageFeeRate;
    // Scheduling depth: 0 means "mine me first", higher = deeper ancestor chain.
    int order;

    // Constructor for final block entries (backward compatible).
    CBlockTemplateEntry(CTransactionRef _tx, Amount _fees, int64_t _sigChecks)
        : tx(_tx), fees(_fees), sigChecks(_sigChecks),
          modifiedFee(_fees), txSize(0),
          packageSize(0), packageFees(Amount::zero()), packageSigChecks(0),
          maxPackageFeeRate(0.0), order(0) {}

    // Constructor used internally by addTxs.
    CBlockTemplateEntry(CTransactionRef _tx, Amount _fees, Amount _modFee,
                        size_t _size, int64_t _sigChecks)
        : tx(std::move(_tx)), fees(_fees), sigChecks(_sigChecks),
          modifiedFee(_modFee), txSize(_size),
          packageSize(_size), packageFees(_modFee), packageSigChecks(_sigChecks),
          maxPackageFeeRate(_size > 0
                                ? double(_modFee / SATOSHI) / double(_size)
                                : 0.0),
          order(0) {}

    double FeeRate() const {
        return packageSize > 0
                   ? double(packageFees / SATOSHI) / double(packageSize)
                   : 0.0;
    }

    int GetOrder() const { return order; }

    /**
     * Fold a parent's package totals into this entry's accumulators.
     * If our effective package fee rate exceeds the best seen so far among
     * ancestors, reset order to 0 so we sort to the front of our tier.
     */
    void AccountForParent(const CBlockTemplateEntry &parent) {
        packageSize += parent.packageSize;
        packageFees += parent.packageFees;
        packageSigChecks += parent.packageSigChecks;

        int parentOrder = parent.order + 1;
        if (parentOrder > order) {
            order = parentOrder;
        }

        double parentFeeRate = parent.FeeRate();
        if (parentFeeRate > maxPackageFeeRate) {
            maxPackageFeeRate = parentFeeRate;
        }
        // If our package is now the best, pull it to the front (order=0).
        if (FeeRate() > maxPackageFeeRate) {
            order = 0;
            maxPackageFeeRate = FeeRate();
        }
    }
};

struct CBlockTemplate {
    CBlock block;

    std::vector<CBlockTemplateEntry> entries;
};

/** Generate a new block, without valid proof-of-work */
class BlockAssembler {
private:
    BlockFitter blockFitter;

    // Chain context for the block
    int nHeight;
    int64_t m_lock_time_cutoff;
    const CChainParams &chainParams;

    const CTxMemPool *const m_mempool;
    Chainstate &m_chainstate;
    const avalanche::Processor *const m_avalanche;

    const bool fPrintPriority;

    // Whether to call TestBlockValidity() at the end of CreateNewBlock().
    const bool test_block_validity;

    const bool add_finalized_txs;
    const bool enableMinerFund;

public:
    struct Options {
        bool fPrintPriority{DEFAULT_PRINTPRIORITY};
        bool test_block_validity{true};
        bool add_finalized_txs{false};
        bool enableMinerFund{false};
    };

    BlockAssembler(const Config &config, Chainstate &chainstate,
                   const CTxMemPool *mempool,
                   const avalanche::Processor *avalanche = nullptr);
    BlockAssembler(const node::BlockFitter &fitter, Chainstate &chainstate,
                   const CTxMemPool *mempool,
                   const avalanche::Processor *avalanche = nullptr);
    BlockAssembler(const node::BlockFitter &fitter, Chainstate &chainstate,
                   const CTxMemPool *mempool, const Options &options,
                   const avalanche::Processor *avalanche = nullptr);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate>
    CreateNewBlock(const CScript &scriptPubKeyIn);

    uint64_t GetMaxGeneratedBlockSize() const {
        return blockFitter.getMaxGeneratedBlockSize();
    }

    /**
     * Add transactions from the mempool based on individual tx feerate.
     */
    void addTxs(const CTxMemPool &mempool) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs);

    /**
     * Add the finalized transactions to the block template
     */
    void addFinalizedTxs(const CTxMemPool &mempool)
        EXCLUSIVE_LOCKS_REQUIRED(mempool.cs);

    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    static std::optional<int64_t> m_last_block_num_txs;
    static std::optional<int64_t> m_last_block_size;

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(const CTxMemPoolEntryRef &entry);

    // Methods for how to add transactions to a block.

    /// Check the transaction for finality, etc before adding to block
    bool CheckTx(const CTransaction &tx) const;

    // Legacy O(n²) implementation kept for comparison; not called in production.
    void accuratelyAddTxs(const CTxMemPool &mempool)
        EXCLUSIVE_LOCKS_REQUIRED(mempool.cs);
};

int64_t UpdateTime(CBlockHeader *pblock, const CChainParams &chainParams,
                   const CBlockIndex *pindexPrev, int64_t adjustedTime);
/** Apply options from ArgsManager to BlockAssembler options. */
void ApplyArgsManOptions(const ArgsManager &args,
                         BlockAssembler::Options &options);
} // namespace node

#endif // BITCOIN_NODE_MINER_H
