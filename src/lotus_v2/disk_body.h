// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DISK_BODY_H
#define LOTUS_V2_DISK_BODY_H
#include "disk_block.h"
namespace lotus::v2 {
enum class RetainedBodyStatus { Available, Missing, CapacityRefused, StorageError };
// Exact retained bytes, authenticated against their stored header and state.
// Caller serializes store access. Available does not prove active-chain membership
// or rerun historical VM execution. Previously connected side branches can remain
// available after disconnect. Missing means no complete body in a directly indexed retained record,
// not proof that the body never existed. No history/service promise is implied.
// max_body_bytes limits decoding/returned bytes, not LevelDB's underlying undo
// record allocation: storage currently reads the full historical delta record.
// On any non-Available result, out remains unchanged. No store writes occur.
RetainedBodyStatus ReadRetainedBlockBody(
    const Hash &id, uint64_t max_body_bytes, const HeaderChainProfile &,
    const OrdinaryCandidateProfile &, const MonetaryProfile &, const BlockCostProfile &,
    const DiskStateStore &, std::vector<uint8_t> &out, std::string &error);
} // namespace lotus::v2
#endif
