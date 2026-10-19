// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_AVALANCHE_H
#define CHRONIK_NATIVE_AVALANCHE_H

#include <cstdint>
#include <string>

/** Port of chronik-indexer avalanche.rs. */
namespace chronik::native {

/** The indexer's Avalanche state. */
struct Avalanche {
    /** Height of the highest finalized block. Default: -1 */
    int32_t height = -1;

    /**
     * Mark the block height as the highest finalized height in the indexer.
     * Throws ChronikError (DecreasingFinalizedHeight) if `height` is below
     * the current finalized height.
     */
    void FinalizeBlock(int32_t height);

    /**
     * Disconnect the block, may decrease the highest finalized height. The
     * disconnected block must either not be finalized, or be the last
     * finalized block; otherwise the indexer is out of sync with the node and
     * this throws ChronikError (DisconnectBelowLastFinalizedHeight).
     */
    void DisconnectBlock(int32_t height);

    /** Whether the given block height has been finalized by Avalanche. */
    bool IsFinalHeight(int32_t block_height) const {
        return block_height <= height;
    }

    bool operator==(const Avalanche &) const = default;
};

/** AvalancheError::DecreasingFinalizedHeight message */
std::string AvalancheDecreasingFinalizedHeightMessage(int32_t indexer_height,
                                                      int32_t next_height);
/** AvalancheError::DisconnectBelowLastFinalizedHeight message */
std::string
AvalancheDisconnectBelowLastFinalizedHeightMessage(int32_t indexer_height,
                                                   int32_t disconnected_height);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_AVALANCHE_H
