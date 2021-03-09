// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <util/system.h>

static CCheckpointData mainNetCheckpointData = {
    .mapCheckpoints = {
        /* Fill in checkpoints once there are any */
    }};

static CCheckpointData testNetCheckpointData = {
    .mapCheckpoints = {
        /* Fill in checkpoints once there are any */
    }};

static CCheckpointData regTestCheckpointData = {
    .mapCheckpoints = {
        {0, BlockHash::fromHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb4"
                               "36012afca590b1a11466e2206")},
    }};

const CCheckpointData &CheckpointData(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return mainNetCheckpointData;
    }
    if (chain == CBaseChainParams::TESTNET) {
        return testNetCheckpointData;
    }
    if (chain == CBaseChainParams::REGTEST) {
        return regTestCheckpointData;
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}
