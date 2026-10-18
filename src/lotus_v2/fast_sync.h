// Copyright (c) 2026 The Lotus developers
// Fast UTXO Shard Sync protocol, cryptographic verification, and pivot eligibility.
#ifndef LOTUS_V2_FAST_SYNC_H
#define LOTUS_V2_FAST_SYNC_H

#include "block_transition.h"
#include "disk_state.h"
#include "header.h"
#include "monetary.h"
#include "sparse_state.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lotus::v2 {

inline constexpr size_t kFastSyncShardCount = 256;
inline constexpr uint8_t kMinUtxoShardPrefixDepth = 8;
inline constexpr uint8_t kMaxUtxoShardPrefixDepth = 16;
inline constexpr size_t kMaxUtxoShardLeaves = 4096;
inline constexpr uint64_t kFastSyncMinBuriedBlocks = 100;
inline constexpr size_t kFastSyncMinNetgroupConfirmations = 3;
inline constexpr uint64_t kFastSyncPivotSafetyCushion = 10;

// Cardinality tag for P02 single-leaf collapse verification (Hole 11 defense):
// 0 = Empty (subtree_root == EmptyUtxoRoot())
// 1 = SingleLeaf (subtree_root == UtxoLeaf(coin), collapsed without UtxoNode hashing)
// 2 = InteriorNode (>= 2 leaves, subtree_root == UtxoNode(depth, left, right))
struct ShardRootEntry {
    uint8_t cardinality_tag = 0;
    Hash subtree_root = EmptyUtxoRoot();
    bool operator==(const ShardRootEntry &) const = default;
};

struct GetUtxoRootsRequest {
    Hash pivot_block_id{};
    bool operator==(const GetUtxoRootsRequest &) const = default;
};

struct UtxoRootsMessage {
    Hash pivot_block_id{};
    uint64_t height = 0;
    std::array<uint8_t, 56> monetary_state{};
    std::array<ShardRootEntry, kFastSyncShardCount> shards{};
    bool operator==(const UtxoRootsMessage &) const = default;
};

struct GetUtxoShardRequest {
    Hash pivot_block_id{};
    uint8_t prefix_depth = kMinUtxoShardPrefixDepth;
    uint16_t prefix_bits = 0;
    bool operator==(const GetUtxoShardRequest &) const = default;
};

struct UtxoShardMessage {
    Hash pivot_block_id{};
    uint8_t prefix_depth = kMinUtxoShardPrefixDepth;
    uint16_t prefix_bits = 0;
    // Ordered from depth (prefix_depth - 1) down to depth 8.
    std::vector<Hash> boundary_siblings;
    // Sorted by OutpointKey(coin.outpoint), max kMaxUtxoShardLeaves (4096).
    std::vector<Coin> coins;
};

// Hole 13 & Hole 14: Dual Pivot Authentication Gate and Pivot Safety Cushion.
struct FastSyncPivotCandidate {
    uint64_t pivot_height = 0;
    uint64_t best_header_height = 0;
    bool has_minimum_chain_work = false;
    bool is_avalanche_finalized = false;
    uint64_t buried_blocks = 0;
    size_t distinct_netgroup_confirmations = 0;
};

bool CheckFastSyncPivotEligibility(const FastSyncPivotCandidate &candidate,
                                   std::string &error);

// Extracts the little-endian prefix bits of outpoint_key for depths [0 .. prefix_depth - 1].
// For prefix_depth == 8, this equals uint16_t(outpoint_key[0]).
uint16_t OutpointPrefixBits(const Hash &outpoint_key, uint8_t prefix_depth);

bool IsValidShardRootEntry(const ShardRootEntry &entry);

// Folds two sibling subtrees at parent `depth` using exact P02 single-leaf collapse rules.
bool FoldShardPair(uint8_t depth, const ShardRootEntry &left,
                   const ShardRootEntry &right, ShardRootEntry &out);

// Folds 256 depth-8 ShardRootEntries from depth d = 7 down to d = 0 (Hole 11 defense).
std::optional<Hash> FoldDepth8ShardRoots(
    const std::array<ShardRootEntry, kFastSyncShardCount> &shards,
    std::string *error = nullptr);

// Verifies UtxoRootsMessage against an authenticated pivot header's state_root.
bool VerifyUtxoRootsAgainstHeader(const Header &pivot_header,
                                  const ChainId &chain_id,
                                  const UtxoRootsMessage &msg,
                                  std::string &error);

// Verifies a UtxoShardMessage (depth k in [8..16], max 4096 leaves, strict prefix
// membership, strict ascending OutpointKey order, no burn outputs, creation_height <= pivot_height,
// and boundary-sibling folding up to depth 8) before any disk write (Holes 11 & 15 defense).
bool VerifyAndBuildUtxoShard(const ShardRootEntry &expected_depth8_entry,
                             uint64_t pivot_height,
                             const UtxoShardMessage &shard,
                             ShardRootEntry *computed_subshard_out,
                             std::string &error);

// Wire serialization for P2P messages (getutxoroots, utxoroots, getutxoshard, utxoshard).
std::vector<uint8_t> EncodeGetUtxoRootsRequest(const GetUtxoRootsRequest &req);
bool DecodeGetUtxoRootsRequest(const std::vector<uint8_t> &bytes,
                               GetUtxoRootsRequest &out,
                               std::string &error);

std::vector<uint8_t> EncodeUtxoRootsMessage(const UtxoRootsMessage &msg);
bool DecodeUtxoRootsMessage(const std::vector<uint8_t> &bytes,
                            UtxoRootsMessage &out,
                            std::string &error);

bool EncodeGetUtxoShardRequest(const GetUtxoShardRequest &req,
                               std::vector<uint8_t> &out,
                               std::string &error);
bool DecodeGetUtxoShardRequest(const std::vector<uint8_t> &bytes,
                               GetUtxoShardRequest &out,
                               std::string &error);

bool EncodeUtxoShardMessage(const UtxoShardMessage &msg,
                            std::vector<uint8_t> &out,
                            std::string &error);
bool DecodeUtxoShardMessage(const std::vector<uint8_t> &bytes,
                            UtxoShardMessage &out,
                            std::string &error);

// Export 256 depth-8 ShardRootEntries and 56-byte MonetaryState from a UtxoSet or DiskStateStore.
bool ExportUtxoRoots(const UtxoSet &utxo, const ChainId &chain_id,
                     const Header &pivot_header, const MonetaryState &monetary,
                     UtxoRootsMessage &out, std::string &error);

bool ExportUtxoShard(const UtxoSet &utxo, const Hash &pivot_block_id,
                     uint8_t prefix_depth, uint16_t prefix_bits,
                     UtxoShardMessage &out, std::string &error,
                     size_t max_shard_leaves = kMaxUtxoShardLeaves);

// Exports all non-empty shards for a pivot UtxoSet, adaptively splitting any shard
// exceeding `max_shard_leaves` down to depth k in [8..16].
bool ExportAdaptiveUtxoShards(const UtxoSet &utxo, const Hash &pivot_block_id,
                              std::vector<UtxoShardMessage> &out,
                              std::string &error,
                              size_t max_shard_leaves = kMaxUtxoShardLeaves);

// Assembles and cryptographically verifies a complete set of UTXO shards against
// the pivot header and UtxoRootsMessage, producing the authenticated UtxoSet and MonetaryState.
bool AssembleAndVerifyFastSyncPivot(
    const Header &pivot_header, const ChainId &chain_id,
    const UtxoRootsMessage &roots_msg,
    const std::vector<UtxoShardMessage> &shards, UtxoSet &out_utxo,
    MonetaryState &out_monetary, std::string &error);

// DiskStateStore helpers for exporting and importing fast-sync pivot state.
bool ExportDiskUtxoRoots(const DiskStateStore &store, const ChainId &chain_id,
                         UtxoRootsMessage &out, std::string &error);

bool ImportVerifiedFastSyncPivotToDisk(
    const Header &pivot_header, const ChainId &chain_id,
    const std::vector<Header> &history, const UtxoRootsMessage &roots_msg,
    const std::vector<UtxoShardMessage> &shards, DiskStateStore &store,
    std::string &error);

// ============================================================================
// Bijective Reverse Block Peeling (Patch 040 & Hole 12 Defense)
// ============================================================================

struct GetBlockUndoRequest {
    Hash block_id{};
    bool operator==(const GetBlockUndoRequest &) const = default;
};

struct BlockUndoMessage {
    Hash block_id{};
    std::array<uint8_t, 56> parent_monetary_state{};
    // Spent coins created strictly prior to height h (I_h^prior), in exact
    // block input order. Intra-block spends (I_h^intra) are omitted and
    // reconstructed locally from B_h.
    std::vector<Coin> prior_spent_coins;
};

std::vector<uint8_t> EncodeGetBlockUndoRequest(const GetBlockUndoRequest &req);
bool DecodeGetBlockUndoRequest(const std::vector<uint8_t> &bytes,
                               GetBlockUndoRequest &out,
                               std::string &error);

bool EncodeBlockUndoMessage(const BlockUndoMessage &msg,
                            std::vector<uint8_t> &out,
                            std::string &error);
bool DecodeBlockUndoMessage(const std::vector<uint8_t> &bytes,
                            BlockUndoMessage &out,
                            std::string &error);

// Constructs a canonical BlockUndoMessage for block B_h from its pre-block
// UtxoSet and parent MonetaryState, partitioning I_h = I_h^prior |_| I_h^intra
// and omitting intra-block spends from prior_spent_coins (Hole 12 defense).
bool BuildBlockUndoMessage(const std::vector<uint8_t> &block_wire,
                           const ChainId &chain_id,
                           const TxProfile &tx_profile,
                           const MonetaryState &parent_monetary,
                           const UtxoSet &pre_block_utxo,
                           BlockUndoMessage &out,
                           std::string &error);

// Cryptographically peels block B_h backwards from authenticated post-block
// state (state_at_h, monetary_at_h) to authenticated parent state at height h - 1:
// 1. Partitions outputs O_h^net = O_h^all \ I_h^intra and inputs I_h = I_h^prior |_| I_h^intra.
// 2. Verifies O_h^net exists in state_at_h with identical canonical bytes and I_h^prior is absent.
// 3. Peels Merklix tree backwards (erase O_h^net, insert I_h^prior) and verifies
//    StateRoot(chain_id, h - 1, UtxoRoot'_{h-1}, parent_monetary) == parent_header.state_root.
// 4. Executes full forward transaction, signature, VM script, and P05/P06 monetary
//    validation of B_h against the peeled parent state via StageCompleteBlock.
bool PeelBlockReverse(const std::vector<uint8_t> &block_wire,
                      const BlockUndoMessage &undo_msg,
                      const Header &parent_header,
                      const std::vector<Header> &history,
                      const HeaderChainProfile &header_profile,
                      OrdinaryCandidateProfile ordinary_profile,
                      const MonetaryProfile &monetary_profile,
                      const BlockCostProfile &cost_profile,
                      UtxoSet &state_at_h,
                      MonetaryState &monetary_at_h,
                      std::string &error);

// Peels DiskStateStore backwards from height h to height h - 1 after full
// cryptographic verification via PeelBlockReverse.
bool PeelDiskBlockReverse(const std::vector<uint8_t> &block_wire,
                          const BlockUndoMessage &undo_msg,
                          const Header &parent_header,
                          const std::vector<Header> &history,
                          const HeaderChainProfile &header_profile,
                          OrdinaryCandidateProfile ordinary_profile,
                          const MonetaryProfile &monetary_profile,
                          const BlockCostProfile &cost_profile,
                          DiskStateStore &store,
                          std::string &error);

struct ReversePeelBlockStep {
    std::vector<uint8_t> block_wire;
    BlockUndoMessage undo_msg;
    Header parent_header{};
    std::vector<Header> history;
};

// Peels a contiguous window of K blocks [h, h - 1, ..., h - K + 1] backwards in
// RAM with full cryptographic verification at every intermediate height,
// cancelling cross-block ephemeral UTXOs in memory and committing the net delta
// to DiskStateStore in a single batch.
bool PeelDiskBlockWindowReverse(const std::vector<ReversePeelBlockStep> &steps,
                                const HeaderChainProfile &header_profile,
                                OrdinaryCandidateProfile ordinary_profile,
                                const MonetaryProfile &monetary_profile,
                                const BlockCostProfile &cost_profile,
                                DiskStateStore &store,
                                std::string &error);

} // namespace lotus::v2

#endif // LOTUS_V2_FAST_SYNC_H
