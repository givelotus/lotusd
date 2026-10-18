// Copyright (c) 2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AVALANCHE_AVALANCHE_H
#define BITCOIN_AVALANCHE_AVALANCHE_H

#include <cstddef>

#include <consensus/amount.h>

/**
 * Is avalanche enabled by default.
 */
static constexpr bool AVALANCHE_DEFAULT_ENABLED = true;

/**
 * Conflicting proofs cooldown time default value in seconds.
 * Minimal delay between two proofs with at least a common UTXO.
 */
static constexpr size_t AVALANCHE_DEFAULT_CONFLICTING_PROOF_COOLDOWN = 60;

/**
 * Peer replacement cooldown time default value in seconds.
 * Minimal delay before a peer can be replaced due to a conflicting proof.
 */
static constexpr size_t AVALANCHE_DEFAULT_PEER_REPLACEMENT_COOLDOWN =
    24 * 60 * 60;

/**
 * Avalanche default cooldown in milliseconds.
 */
static constexpr size_t AVALANCHE_DEFAULT_COOLDOWN = 100;

/**
 * Default minimum cumulative stake of all known peers that constitutes a usable
 * quorum.
 */
static constexpr Amount AVALANCHE_DEFAULT_MIN_QUORUM_STAKE =
    int64_t(1'000'000'000'000) * SATOSHI; // 10B XEC

/**
 * Default minimum percentage of stake-weighted peers we must have a node for to
 * constitute a usable quorum.
 */
static constexpr double AVALANCHE_DEFAULT_MIN_QUORUM_CONNECTED_STAKE_RATIO =
    0.8;

/**
 * Default minimum number of nodes that sent us an avaproofs message before we
 * can consider our quorum suitable for polling.
 */
static constexpr double AVALANCHE_DEFAULT_MIN_AVAPROOFS_NODE_COUNT = 8;

/**
 * Default minimum number of connected Avalanche nodes required for quorum.
 */
static constexpr size_t AVALANCHE_DEFAULT_MIN_QUORUM_NODES = 8;

/**
 * Default minimum staked ratio in permille (1/1000ths) of circulating supply
 * required for quorum (1 permille = 0.1%).
 */
static constexpr uint64_t AVALANCHE_DEFAULT_MIN_QUORUM_SUPPLY_PERMILLE = 1;

/** Default for -persistavapeers */
static constexpr bool DEFAULT_PERSIST_AVAPEERS{true};

/** Default for -avalanchepreconsensus */
static constexpr bool DEFAULT_AVALANCHE_PRECONSENSUS{true};

/** Default for -avalanchestakingpreconsensus */
static constexpr bool DEFAULT_AVALANCHE_STAKING_PRECONSENSUS{true};

/** Default for -avalanchepreconsensusmining */
static constexpr bool DEFAULT_AVALANCHE_MINING_PRECONSENSUS{true};

#endif // BITCOIN_AVALANCHE_AVALANCHE_H
