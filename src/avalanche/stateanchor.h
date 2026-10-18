// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AVALANCHE_STATEANCHOR_H
#define BITCOIN_AVALANCHE_STATEANCHOR_H

#include <hash.h>
#include <primitives/blockhash.h>
#include <uint256.h>

namespace avalanche {

/**
 * StateAnchorId commits to a (BlockHash, UtxoRoot) pair so that Avalanche
 * quorums can poll, vote on, and finalize 256-shard Merklix UTXO state roots
 * for pivot and epoch blocks without requiring a state_root field in the
 * 80-byte CBlockHeader.
 */
struct StateAnchorId : public uint256 {
    explicit StateAnchorId() : uint256() {}
    explicit StateAnchorId(const uint256 &b) : uint256(b) {}
    explicit StateAnchorId(const BlockHash &blockhash, const uint256 &utxo_root)
        : uint256(Hash(blockhash, utxo_root)) {}
};

} // namespace avalanche

#endif // BITCOIN_AVALANCHE_STATEANCHOR_H
