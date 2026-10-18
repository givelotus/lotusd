// Copyright (c) 2026 The Lotus developers
#include "dev_genesis.h"

#include "commitment.h"

#include <algorithm>

namespace lotus::v2 {
namespace {

// Compact target test_header.cpp accepts. Not a new proof-of-work limit.
constexpr uint32_t kHeaderBits = 0x1d00ffff;
// Timestamp test_header.cpp serializes. It is inside MAX_TIME.
constexpr uint64_t kHeaderTime = 0x010203040506;
static_assert(kHeaderTime <= MAX_TIME, "development header time exceeds MAX_TIME");

bool ZeroHash(const Hash &hash) {
    return std::all_of(hash.begin(), hash.end(),
                       [](uint8_t byte) { return byte == 0; });
}

// test_monetary.cpp initial state: reserve 9, tail 200, work 9, EMA 4.
// Genesis records that state and does not issue.
MonetaryState InitialTestState() {
    MonetaryState state;
    state.bootstrap_reserve = 9;
    state.tail_subsidy = 200;
    state.prev_work[0] = 9;
    state.ema_block_cost = 4;
    return InitializeMonetaryGenesis(DevelopmentGenesis, state, 0);
}

} // namespace

bool MakeDevelopmentGenesis(const Hash &prev_id, uint64_t height,
                            DevelopmentGenesisFixture &out) {
    if (!ZeroHash(prev_id) || height != 0) return false;
    Hash tx_root{};
    if (!TransactionRoot({}, tx_root)) return false;
    const MonetaryState state = InitialTestState();
    const Hash state_root =
        StateRoot(kDevelopmentChainId, 0, EmptyUtxoRoot(), state);
    Header header;
    header.prev_id = {};
    header.bits = kHeaderBits;
    header.time = kHeaderTime;
    header.nonce = 0;
    header.version = kHeaderVersion;
    header.size = HEADER_SIZE; // Header encoding length, not a block-size rule.
    header.height = 0;
    header.tx_root = tx_root;
    header.state_root = state_root;
    DevelopmentGenesisFixture fixture;
    fixture.chain_id = kDevelopmentChainId;
    fixture.state = state;
    fixture.header = header;
    out = fixture;
    return true;
}

} // namespace lotus::v2
