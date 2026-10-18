// Copyright (c) 2026 The Lotus developers
// Development-chain regtest candidate. Not mainnet and not frozen consensus.
#ifndef LOTUS_V2_DEV_GENESIS_H
#define LOTUS_V2_DEV_GENESIS_H

#include "monetary.h"

namespace lotus::v2 {

// Constants are the existing test profile and are not a mainnet genesis.
inline constexpr MonetaryProfile DevelopmentGenesis{
    2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, Hash{9}};

// All-zero id for this development candidate. Not a mainnet chain id.
inline constexpr ChainId kDevelopmentChainId{};

struct DevelopmentGenesisFixture {
    ChainId chain_id{};
    MonetaryState state{};
    Header header{};
};

// Height 0 and a zero previous id only. A nonzero previous id or height is
// rejected and leaves out unchanged. This does not connect a block.
bool MakeDevelopmentGenesis(const Hash &prev_id, uint64_t height,
                            DevelopmentGenesisFixture &out);

} // namespace lotus::v2

#endif
