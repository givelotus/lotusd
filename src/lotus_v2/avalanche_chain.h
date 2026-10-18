// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_CHAIN_H
#define LOTUS_V2_AVALANCHE_CHAIN_H
#include "avalanche_proof.h"
namespace lotus::v2::ava {
enum class Status { Accepted, Rejected, Finalized, Invalid, Stale };
struct BlockUpdate { Hash block{}; Status status{}; Hash expected_tip{}; uint64_t expected_generation{}; };
// Runtime performs mutations/recovery. Poll engine cannot finalize an arbitrary
// caller-supplied block. Invalid is a completed negative poll, not invalid PoW.
// One response is one atomic runtime batch. Rejecting the batch leaves vote
// confidence unchanged; the authenticated request remains consumed.
using ApplyBlockUpdates = std::function<bool(const std::vector<BlockUpdate> &, std::string &)>;
struct BlockObservation { bool known{}, valid{}, active{}, parked{}, finalized{}, conflicting_finalized{}, forks_active{}, has_data{}; };
using ObserveBlock = std::function<bool(const Hash &, BlockObservation &, std::string &)>;
} // namespace lotus::v2::ava
#endif
