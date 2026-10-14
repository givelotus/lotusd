// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <primitives/blockhash.h>
#include <script/script.h>
#include <uint256.h>

#include <chrono>
#include <limits>
#include <string>
#include <vector>

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
    std::vector<std::string> secondSamuel;
    std::vector<std::string> firstKings;
    std::vector<std::string> secondKings;
};

enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with
    // DeploymentPos
    DEPLOYMENT_P2SH = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_HEIGHTINCB,
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
};

constexpr bool ValidDeployment(BuriedDeployment dep) {
    return dep <= DEPLOYMENT_CSV;
}

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    BlockHash hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Unix time used for MTP activation of 2021-12-21T15:59:00.000Z protocol upgrade */
    int exodusActivationTime;
    /** Unix time used for MTP activation of 2022-06-21T09:14:00.000Z protocol upgrade */
    int leviticusActivationTime;
    /** Unix time used for MTP activation of 2022-12-21T21:48:00.000Z protocol
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
    /** Unix time used for MTP activation of 2025-06-21T02:42:00.000Z protocol
     * upgrade */
    int firstSamuelActivationTime;
    /** Unix time used for MTP activation of 2025-12-21T15:03:00.000Z protocol
     * upgrade */
    int secondSamuelActivationTime;
    /** Unix time used for MTP activation of 2026-06-21T08:24:00.000Z protocol
     * upgrade */
    int firstKingsActivationTime;
    /** Unix time used for MTP activation of 2026-12-21T20:50:00.000Z protocol
     * upgrade */
    int secondKingsActivationTime;
    /** Block height at which BIP16 becomes active */
    int BIP16Height;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    BlockHash BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which the wellington activation becomes active */
    int wellingtonHeight;
    /** Block height at which the Cowperthwaite activation becomes active */
    int cowperthwaiteHeight;
    /** Unix time used for MTP activation of 15 May 2025 12:00:00 UTC upgrade */
    int schumpeterActivationTime;
    /** Unix time used for MTP activation of 15 May 2026 12:00:00 UTC upgrade */
    int obolenskyActivationTime;

    /** Enable or disable the miner fund by default */
    bool enableMinerFund;
    CoinbaseAddresses coinbasePayoutAddresses;

    bool enableDifficultyBasedSubsidy;

    /** Enable or disable the staking rewards by default */
    bool enableStakingRewards;

    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nDAAHalfLife;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const {
        return nPowTargetTimespan / nPowTargetSpacing;
    }
    uint256 nMinimumChainWork;
    BlockHash defaultAssumeValid;

    int DeploymentHeight(BuriedDeployment dep) const {
        switch (dep) {
            case DEPLOYMENT_P2SH:
                return BIP16Height;
            case DEPLOYMENT_HEIGHTINCB:
                return BIP34Height;
            case DEPLOYMENT_CLTV:
                return BIP65Height;
            case DEPLOYMENT_DERSIG:
                return BIP66Height;
            case DEPLOYMENT_CSV:
                return CSVHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
