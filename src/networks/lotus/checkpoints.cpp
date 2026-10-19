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
        {0, *BlockHash::FromHex("720da0e6627eb824fb69ad12fd5162fd02ea91775c4"
                                "a04e7561c99b7e50723e4")},
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
