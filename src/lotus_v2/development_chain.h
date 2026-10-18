// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DEVELOPMENT_CHAIN_H
#define LOTUS_V2_DEVELOPMENT_CHAIN_H
#include "disk_block.h"
namespace lotus::v2 {
// Development initializer for a manifest-pinned, single-coinbase genesis.
// No defaults or preloaded UTXO snapshot: coins derive only from genesis bytes.
// Validates before opening storage. A crash before the genesis batch may leave
// an empty, profile-bound store; reopening safely retries that initialization.
// With options.existing_only, absent/empty homes fail without initialization.
// LevelDB still opens exclusively and may maintain its engine files.
// Existing tips are checked against their stored history/state commitment.
// Uses the explicit indexed storage schema; pre-index development homes fail
// closed. Replaying into a new home is separate from this initializer.
// This is not a peer genesis-adoption API, socket runtime or best-chain selector.
bool OpenDevelopmentChain(
    const std::string &directory, const std::vector<uint8_t> &genesis_wire,
    const HeaderChainProfile &hp, const OrdinaryCandidateProfile &op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    const MonetaryState &initial, DiskStateOptions options,
    DiskStateStore &out, std::string &error);
// Chain-aware undo: refuses genesis and validates the exact predecessor's
// history, monetary/root commitment and retained body before publication.
// Caller serializes access and supplies the expected active tip.
bool DisconnectDevelopmentTip(
    const Hash &expected_tip, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, DiskStateStore &store, std::string &error);
// Same predecessor/genesis checks, with progress published atomically by storage.
bool DisconnectRecoveryDevelopmentTip(
    const Hash &expected_tip, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, const DiskRecoveryUpdate &recovery,
    DiskStateStore &store, std::string &error);
} // namespace lotus::v2
#endif
