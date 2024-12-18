// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_POW_H
#define BITCOIN_POW_POW_H

#include <cstdint>

struct BlockHash;
class CBlockHeader;
class CBlockIndex;
class CChainParams;
class uint256;

namespace Consensus {
struct Params;
}

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev,
                             const CBlockHeader *pblock,
                             const CChainParams &chainParams);

/**
 * Check whether a block hash satisfies the proof-of-work requirement specified
 * by nBits
 */
bool CheckProofOfWork(const BlockHash &hash, uint32_t nBits,
                      const Consensus::Params &params);

/**
 * Check if proof of work is sufficient to be an epoch block.
 * A block is considered an epoch block if the hash is EPOCH_NUM_BLOCKS times
 * below the target of the *next* block.
 */
bool IsEpochBlockHash(const BlockHash &hash, const uint32_t nBits);

/**
 * Check if the block has sufficient proof of work to be an epoch block.
 */
bool IsEpochBlock(const Consensus::Params &params, const CBlockIndex *pindex);

/**
 * Return the epoch block hash for the next block.
 * Before the July 21st 2022 hardfork, epochs roll over every
 * EPOCH_NUM_BLOCKS blocks, after, they roll over if the previous block hash is
 * EPOCH_NUM_BLOCKS times below the target of the block.
 */
uint256 GetNextEpochBlockHash(const Consensus::Params &params,
                              const CBlockIndex *pindex);

#endif // BITCOIN_POW_POW_H
