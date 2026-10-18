// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_BLOCK_ASSEMBLER_H
#define LOTUS_V2_BLOCK_ASSEMBLER_H
#include "disk_block.h"
#include <optional>
#ifdef LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION
#include <functional>
#endif
namespace lotus::v2 {
// All fields are caller policy, not network defaults. Supplied transactions
// include their actual signed witnesses and are executed in the supplied order.
struct LocalBlockRequest {
    Hash expected_parent{};
    uint64_t time{}, max_claim{};
    Output coinbase_destination; // Value replaced; one native spendable output.
    std::optional<std::vector<uint8_t>> coinbase_data;
    std::vector<Transaction> ordinary;
};
struct LocalBlockLimits {
    uint64_t max_ordinary_transactions{}, max_block_bytes{}, max_coinbase_data_bytes{};
};
struct LocalBlockTemplate {
    BlockPreview preview;
    std::vector<uint8_t> wire;
    std::optional<Hash> mined_id; // Absent until bounded nonce search succeeds.
};
enum class LocalBlockBuildResult {
    Ready, InvalidTransactions, CapacityRefused, StaleParent, Inconclusive, StorageError
};
// Two independently aborted previews: claim zero quotes the authoritative
// monetary entitlement/deduction; final fixed-width claim computes exact roots.
// Never publishes state, admits a header, emits a failure proof, or scans UTXOs.
// Caller serializes store access. Failure leaves out unchanged.
// Allocation failures are CapacityRefused (retry with smaller limits); unexpected
// exceptions are logged and reported as StorageError, never body invalidity.
LocalBlockBuildResult BuildLocalDiskBlockTemplate(
    const LocalBlockRequest &, const LocalBlockLimits &,
    const HeaderChainProfile &, OrdinaryCandidateProfile,
    const MonetaryProfile &, const BlockCostProfile &, DiskStateStore &,
    LocalBlockTemplate &out, std::string &error);
#ifdef LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION
// Test-only exception injection; absent from daemon and library builds.
void SetLocalBlockBuildTestHook(std::function<void()> hook);
#endif
enum class LocalNonceResult { Found, Exhausted, CapacityRefused, InvalidTemplate, Inconclusive };
// Uses existing SearchNonce's <=256 attempts and nonwrapping nonce range.
// Checks header/wire binding, not contextual body validity. The resulting bytes
// still require normal full validation before publication or peer announcement.
// Copies the frozen body only on Found; all other results preserve out.
LocalNonceResult SearchLocalBlockNonce(
    const LocalBlockTemplate &, const ChainId &, const Hash &pow_limit,
    uint64_t start_nonce, uint64_t max_attempts,
    LocalBlockTemplate &out, std::string &error);
} // namespace lotus::v2
#endif
