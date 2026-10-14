// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/system.h>
#include <util/chaintype.h>

static CCheckpointData mainNetCheckpointData = {
    .mapCheckpoints = {
        // Exodus activation
        {143509, BlockHash::fromHex("00000000000df2347fd05d10e9ce5846f3089ef7e6"
                                    "0b650a2725f9c462c5b601")},
        // Leviticus activation
        {273561, BlockHash::fromHex("000000000006a214caf1b62fdc5fa9746aa90d2887"
                                    "8868561dcc1741da19eade")},
        // Joshua activation
        {663736, BlockHash::fromHex("0000000000985d7295c59ee8b1a7cb941c4ab1e309"
                                    "0baa13fed0bea2096198ca")},
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

const CCheckpointData &CheckpointData(const ChainType chain) {
    switch (chain) {
        case ChainType::MAIN:
            return mainNetCheckpointData;
        case ChainType::TESTNET:
            return testNetCheckpointData;
        case ChainType::REGTEST:
            return regTestCheckpointData;
    }
    throw std::invalid_argument(
        strprintf("%s: Invalid ChainType value", __func__));
}
