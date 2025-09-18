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

struct CoinbaseAddresses {
    std::vector<std::string> genesis;
    std::vector<std::string> exodus;
    std::vector<std::string> leviticus;
    std::vector<std::string> numbers;
    std::vector<std::string> deuteronomy;
    std::vector<std::string> joshua;
    std::vector<std::string> judges;
    std::vector<std::string> ruth;
    std::vector<std::string> firstSamuel;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    BlockHash hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Unix time used for MTP activation of 2021-12-21T15:59:00.000Z protocol
     * upgrade */
    int exodusActivationTime;
    /** Unix time used for MTP activation of 2022-06-21T09:14:00.000Z protocol
     * upgrade */
    int leviticusActivationTime;
    /** Unix time used for MTP activation of 2022-12-12T21:48:00.000Z protocol
     * upgrade */
    int numbersActivationTime;
    /** Unix time used for MTP activation of 2023-06-21T14:58:00.000Z protocol
     * upgrade */
    int deuteronomyActivationTime;
    /** Unix time used for MTP activation of 2023-12-22T03:27:00.000Z protocol
     * upgrade */
    int joshuaActivationTime;
    /** Unix time used for MTP activation of 2024-06-20T20:51:00.000Z protocol
     * upgrade */
    int judgesActivationTime;
    /** Unit time used for MTP activation of 2024-12-21T09:20:00.000Z protocol
     * upgrade */
    int ruthActivationTime;
    /** Unit time used for MTP activation of 2025-06-21T02:42:00.000Z protocol
     * upgrade */
    int firstSamuelActivationTime;
    /** Unit time used for MTP activation of 2025-12-21T15:03:00.000Z protocol
     * upgrade */
    int secondSamuelActivationTime;

    /**
     * Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations.
     */
    int MinBIP9WarningHeight;
    uint32_t nMinerConfirmationWindow;

    /** Enable or disable the miner fund by default */
    bool enableMinerFund;
    CoinbaseAddresses coinbasePayoutAddresses;

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
