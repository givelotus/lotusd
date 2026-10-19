// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer avalanche.rs.

#include <chronik/native/avalanche.h>

#include <chronik/native/error.h>

namespace chronik::native {

std::string AvalancheDecreasingFinalizedHeightMessage(int32_t indexer_height,
                                                      int32_t next_height) {
    return "Inconsistent DB: Decreasing finalized height: indexer " +
           std::to_string(indexer_height) + " > finalized " +
           std::to_string(next_height);
}

std::string
AvalancheDisconnectBelowLastFinalizedHeightMessage(int32_t indexer_height,
                                                   int32_t disconnected_height) {
    return "Inconsistent DB: Disconnected block " +
           std::to_string(disconnected_height) +
           " that's not the last finalized block in the indexer " +
           std::to_string(indexer_height);
}

void Avalanche::FinalizeBlock(int32_t next_height) {
    if (height > next_height) {
        throw ChronikError(
            AvalancheDecreasingFinalizedHeightMessage(height, next_height));
    }
    height = next_height;
}

void Avalanche::DisconnectBlock(int32_t disconnected_height) {
    if (disconnected_height < height) {
        throw ChronikError(AvalancheDisconnectBelowLastFinalizedHeightMessage(
            height, disconnected_height));
    }
    if (height == disconnected_height) {
        height -= 1;
    }
}

} // namespace chronik::native
