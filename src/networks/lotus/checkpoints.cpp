// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/system.h>
#include <util/chaintype.h>

// The Lotus V2 networks have no history yet, so mainnet and testnet have no
// checkpoints. Regtest checkpoints its genesis block.
static CCheckpointData mainNetCheckpointData = {.mapCheckpoints = {}};

static CCheckpointData testNetCheckpointData = {.mapCheckpoints = {}};

static CCheckpointData regTestCheckpointData = {
    .mapCheckpoints = {
        {0, *BlockHash::FromHex("5297d8c90656af6365bd4c2280f100b13b6fee2e9d9"
                                "09cd29eb509fa3feb7605")},
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
