// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <primitives/blockhash.h>
#include <script/script.h>
#include <uint256.h>

#include <limits>

namespace Consensus {

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    BlockHash hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Unix time used for MTP activation of 15 Nov 2021 12:00:00 UTC upgrade */
    int selectronActivationTime;

    /**
     * Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations.
     */
    int MinBIP9WarningHeight;
    uint32_t nMinerConfirmationWindow;

    /** Enable or disable the miner fund by default */
    bool enableMinerFund;
    std::vector<std::vector<std::string>> payoutAddressSets;

    bool enableDifficultyBasedSubsidy;

    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nDAAHalfLife;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const {
        return nPowTargetTimespan / nPowTargetSpacing;
    }
    uint256 nMinimumChainWork;
    BlockHash defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
