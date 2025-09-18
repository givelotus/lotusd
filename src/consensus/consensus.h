// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdint>
#include <vector>

/** 1MB */
static const uint64_t ONE_MEGABYTE = 1000000;
/** The maximum allowed size for a transaction, in bytes */
static const uint64_t MAX_TX_SIZE = ONE_MEGABYTE;
/** The minimum allowed size for a transaction, in bytes */
static const uint64_t MIN_TX_SIZE = 100;
/** The maximum allowed size for a block, before the UAHF */
static const uint64_t LEGACY_MAX_BLOCK_SIZE = ONE_MEGABYTE;
/** Default setting for maximum allowed size for a block, in bytes */
static const uint64_t DEFAULT_MAX_BLOCK_SIZE = 32 * ONE_MEGABYTE;
/** Allowed number of signature check operations per transaction. */
static const uint64_t MAX_TX_SIGCHECKS = 3000;

/** Enforced prefix for all coinbase strings.
 * This prevents duplicate transactions on other Bitcoin derived chains
 * for approx. 9'664'528 years.
 */
static const std::vector<uint8_t> COINBASE_PREFIX =
    {0x6c, 0x6f, 0x67, 0x6f, 0x73};
    //6672627463 ?

/**
 * The ratio between the maximum allowable block size and the maximum allowable
 * SigChecks (executed signature check operations) in the block. (network rule).
 */
static const int BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO = 141;
/**
 * Coinbase transaction outputs can only be spent after this number of new
 * blocks (network rule).
 */
static const int COINBASE_MATURITY = 100;
/** Coinbase scripts have their own script size limit. */
static const int MAX_COINBASE_SCRIPTSIG_SIZE = 100;

/**
 * Compute the maximum number of sigchecks that can be contained in a block
 * given the MAXIMUM block size as parameter. The maximum sigchecks scale
 * linearly with the maximum block size and do not depend on the actual
 * block size. The returned value is rounded down (there are no fractional
 * sigchecks so the fractional part is meaningless).
 */
inline uint64_t GetMaxBlockSigChecksCount(uint64_t maxBlockSize) {
    return maxBlockSize / BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO;
}

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
