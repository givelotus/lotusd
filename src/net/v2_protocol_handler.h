// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_V2_PROTOCOL_HANDLER_H
#define BITCOIN_NET_V2_PROTOCOL_HANDLER_H

#include <blockencodings.h>
#include <lotus_v2/blocksnap.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/fast_sync.h>
#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

class ChainstateManager;
class CTxMemPool;
class PeerManager;

namespace avalanche {
class Processor;
} // namespace avalanche

namespace lotus::v2::net {

/**
 * Scope tag for generalized Merklix set reconciliation.
 */
enum class ReconScope : uint8_t {
    LIVE_MEMPOOL = 0x01,
    EPOCH_BATCH = 0x02,
    BLOCK_RECON = 0x03,
    AVA_CONFLICT_SET = 0x04,
};

constexpr bool IsValidReconScope(uint8_t raw) noexcept {
    return raw >= static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL) &&
           raw <= static_cast<uint8_t>(ReconScope::AVA_CONFLICT_SET);
}

/**
 * Deterministically derive the 128-bit SipHash key (k0, k1) for Merklix set
 * reconciliation from (scope, context_id, epoch_or_nonce) using tagged SHA-256.
 */
std::pair<uint64_t, uint64_t>
DeriveReconSipHashKey(ReconScope scope, const uint256 &context_id,
                      uint64_t epoch_or_nonce = 0) noexcept;

/**
 * Check whether (salt_k0, salt_k1) is a valid deterministically derived key
 * for (scope, context_id).
 */
bool IsValidReconSipHashKey(ReconScope scope, const uint256 &context_id,
                            uint64_t salt_k0, uint64_t salt_k1) noexcept;

/**
 * Compute the 256-bit SubtreeA Merklix root over a CTOR-normalized set of
 * non-coinbase transactions.
 */
uint256 ComputeScopedMerklixRoot(const std::vector<CTransactionRef> &txs);

/**
 * Compute the 256-bit block TransactionRoot in O(1) from a coinbase
 * transaction and a precomputed SubtreeA root.
 */
uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const lotus::v2::Hash &subtree_a_root);

/**
 * Precomputed candidate overlay entry storing normalized non-coinbase
 * transactions alongside their precomputed SubtreeA Merklix root and
 * positional SHA-256d null_merkle_root + coinbase_merkle_branch.
 */
struct CandidateOverlayEntry {
    std::vector<CTransactionRef> txs;
    lotus::v2::Hash subtree_a_root{};
    uint256 null_merkle_root{};
    std::vector<uint256> coinbase_merkle_branch{};
};

/**
 * Depth-4 bucket entry in MerklixSyncSummary (12 bytes serialized).
 */
struct MerklixBucketEntry {
    uint32_t count{0};
    uint64_t xor_short_id{0};

    friend bool operator==(const MerklixBucketEntry &a,
                           const MerklixBucketEntry &b) noexcept {
        return a.count == b.count && a.xor_short_id == b.xor_short_id;
    }

    SERIALIZE_METHODS(MerklixBucketEntry, obj) {
        READWRITE(obj.count, obj.xor_short_id);
    }
};

/**
 * Depth-4 Merklix sync summary (merklixsync message).
 * Contains 16 top-level prefix buckets (4-bit nibbles 0x0..0xF) and the
 * 256-bit candidate_root commitment.
 */
struct MerklixSyncSummary {
    uint8_t scope{static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL)};
    uint256 context_id{};
    uint64_t salt_k0{0};
    uint64_t salt_k1{0};
    uint256 candidate_root{};
    std::array<MerklixBucketEntry, 16> buckets{};

    SERIALIZE_METHODS(MerklixSyncSummary, obj) {
        READWRITE(obj.scope, obj.context_id, obj.salt_k0, obj.salt_k1,
                  obj.candidate_root);
        for (auto &b : obj.buckets) {
            READWRITE(b);
        }
    }
};

/**
 * Request for sub-bucket algebraic syndromes (getmerklixbuck message)
 * for the mismatched or overflowing buckets indicated by bucket_mask at
 * prefix depth depth_bits (4, 8, 12, or 16) under parent_prefix.
 */
struct MerklixBucketRequest {
    uint8_t scope{static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL)};
    uint256 context_id{};
    uint64_t salt_k0{0};
    uint64_t salt_k1{0};
    uint16_t bucket_mask{0};
    uint8_t depth_bits{4};
    uint16_t parent_prefix{0};

    SERIALIZE_METHODS(MerklixBucketRequest, obj) {
        READWRITE(obj.scope, obj.context_id, obj.salt_k0, obj.salt_k1,
                  obj.bucket_mask, obj.depth_bits, obj.parent_prefix);
    }
};

/**
 * Sub-bucket entry with 3-power-sum algebraic syndromes over GF(2^64):
 * s1 = XOR_i x_i
 * s3 = XOR_i (x_i)^3 in GF(2^64)
 * s5 = XOR_i (x_i)^5 in GF(2^64) (checksum eliminating d >= 3 false decodes)
 */
struct MerklixSubBucketEntry {
    uint16_t count{0};
    uint64_t s1{0};
    uint64_t s3{0};
    uint64_t s5{0};

    friend bool operator==(const MerklixSubBucketEntry &a,
                           const MerklixSubBucketEntry &b) noexcept {
        return a.count == b.count && a.s1 == b.s1 && a.s3 == b.s3 &&
               a.s5 == b.s5;
    }

    SERIALIZE_METHODS(MerklixSubBucketEntry, obj) {
        READWRITE(obj.count, obj.s1, obj.s3, obj.s5);
    }
};

/**
 * Sub-bucket summary (merklixbuck message) for a prefix at depth_bits
 * (8, 12, or 16) under parent_prefix (4-bit, 8-bit, or 12-bit prefix).
 */
struct MerklixSubBucketSummary {
    uint8_t scope{static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL)};
    uint256 context_id{};
    uint64_t salt_k0{0};
    uint64_t salt_k1{0};
    uint8_t parent_bucket{0};
    uint8_t depth_bits{8};
    uint16_t parent_prefix{0};
    std::array<MerklixSubBucketEntry, 16> sub_buckets{};
    std::vector<uint64_t> overflow_short_ids{};

    SERIALIZE_METHODS(MerklixSubBucketSummary, obj) {
        READWRITE(obj.scope, obj.context_id, obj.salt_k0, obj.salt_k1,
                  obj.parent_bucket, obj.depth_bits, obj.parent_prefix);
        for (auto &sb : obj.sub_buckets) {
            READWRITE(sb);
        }
        READWRITE(obj.overflow_short_ids);
    }
};

/**
 * Request for missing transactions by 64-bit salted short IDs (getshorttx).
 */
struct ShortTxRequest {
    static constexpr size_t MAX_SHORT_IDS = 4096;

    uint8_t scope{static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL)};
    uint256 context_id{};
    uint64_t salt_k0{0};
    uint64_t salt_k1{0};
    std::vector<uint64_t> short_ids;

    SERIALIZE_METHODS(ShortTxRequest, obj) {
        READWRITE(obj.scope, obj.context_id, obj.salt_k0, obj.salt_k1,
                  obj.short_ids);
    }
};

/**
 * Response carrying transactions matching a ShortTxRequest (shorttx).
 */
struct ShortTxResponse {
    static constexpr size_t MAX_TXS = 4096;

    uint8_t scope{static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL)};
    uint256 context_id{};
    std::vector<CTransactionRef> txs;

    SERIALIZE_METHODS(ShortTxResponse, obj) {
        READWRITE(obj.scope, obj.context_id,
                  Using<VectorFormatter<TransactionCompression>>(obj.txs));
    }
};

/**
 * GF(2^64) arithmetic modulo P(z) = z^64 + z^4 + z^3 + z + 1 (0x1b).
 * Used for 2-element syndrome decoding and s5 checksum verification in
 * MerklixSubBucketSummary.
 */
uint64_t GF64Mul(uint64_t a, uint64_t b) noexcept;
uint64_t GF64Square(uint64_t a) noexcept;
uint64_t GF64Cube(uint64_t a) noexcept;
uint64_t GF64Pow5(uint64_t a) noexcept;
uint64_t GF64Inv(uint64_t a) noexcept;

/**
 * Solve y^2 ^ y = c in GF(2^64). Returns true and sets y_out if a solution
 * exists in GF(2^64) (i.e. Tr(c) == 0).
 */
bool GF64SolveQuadratic(uint64_t c, uint64_t &y_out) noexcept;

/**
 * Recover 1 or 2 symmetric-difference elements {x1[, x2]} from GF(2^64)
 * power-sum syndrome deltas delta_s1 = x1 ^ x2, delta_s3 = x1^3 ^ x2^3,
 * and delta_s5 = x1^5 ^ x2^5.
 * Returns empty vector if delta_s1 == 0 && delta_s3 == 0 && delta_s5 == 0,
 * or nullopt if the difference contains > 2 elements (or fails s5 check).
 */
std::optional<std::vector<uint64_t>>
RecoverGF64Syndromes(uint64_t delta_s1, uint64_t delta_s3,
                     uint64_t delta_s5) noexcept;
std::optional<std::vector<uint64_t>>
RecoverGF64Syndromes(uint64_t delta_s1, uint64_t delta_s3) noexcept;

/**
 * Compute non-zero 64-bit SipHash short ID for a transaction ID.
 */
uint64_t ComputeMerklixShortId(uint64_t salt_k0, uint64_t salt_k1,
                               const TxId &txid) noexcept;

/**
 * Extract 4-bit nibble at nibble_idx (0..63) and multi-nibble prefix (4, 8,
 * 12, or 16 bits) from a canonical TxId.
 */
inline uint8_t GetMerklixNibble(const TxId &txid, uint8_t nibble_idx) noexcept {
    const uint8_t byte = txid.begin()[(nibble_idx >> 1) & 0x1f];
    return (nibble_idx & 1U) == 0 ? static_cast<uint8_t>((byte >> 4) & 0x0f)
                                  : static_cast<uint8_t>(byte & 0x0f);
}

inline uint16_t GetMerklixPrefix(const TxId &txid,
                                 uint8_t depth_bits) noexcept {
    const uint8_t num_nibbles = static_cast<uint8_t>((depth_bits >> 2) & 0x07);
    uint16_t prefix = 0;
    for (uint8_t i = 0; i < num_nibbles && i < 4; ++i) {
        prefix =
            static_cast<uint16_t>((prefix << 4) | GetMerklixNibble(txid, i));
    }
    return prefix;
}

inline uint8_t GetMerklixBucketIndex(const TxId &txid) noexcept {
    return GetMerklixNibble(txid, 0);
}

inline uint8_t GetMerklixSubBucketIndex(const TxId &txid) noexcept {
    return GetMerklixNibble(txid, 1);
}

/**
 * Result of comparing a remote MerklixSyncSummary against a local transaction
 * set.
 */
struct MerklixSyncDiffResult {
    //! True iff the 256-bit candidate_root matched our local scoped root.
    bool root_matched{false};
    //! Bitmask of depth-4 buckets (0..15) needing depth-8 sub-bucket syndromes.
    uint16_t mismatched_bucket_mask{0};
    //! Short IDs of single-tx bucket differences immediately identified as
    //! missing locally.
    std::vector<uint64_t> single_missing_short_ids;
};

/**
 * Result of comparing a remote MerklixSubBucketSummary against a local
 * transaction set for parent_bucket.
 */
struct MerklixSubBucketDiffResult {
    //! Short IDs recovered via 1-tx or 2-tx GF(2^64) syndromes that are
    //! missing locally.
    std::vector<uint64_t> missing_short_ids;
    //! Sub-bucket indices (0..15) whose differences exceeded 2 elements.
    std::vector<uint8_t> unresolved_sub_buckets;
};

/**
 * Telemetry / inspection counters for V2PeerProtocolHandler.
 */
struct V2ProtocolHandlerStats {
    uint64_t sealedheader_received{0};
    uint64_t sealedheader_reconstructed{0};
    uint64_t sealedheader_overlay_fastpath{0};
    uint64_t sealedheader_fallback_getdata{0};
    uint64_t sealedheader_invalid{0};
    uint64_t sealedheader_rejected{0};
    uint64_t merklixsync_received{0};
    uint64_t getmerklixbuck_received{0};
    uint64_t merklixbuck_received{0};
    uint64_t getshorttx_received{0};
    uint64_t shorttx_received{0};
    uint64_t unsolicited_shorttx{0};
    uint64_t unsolicited_shorttx_dropped{0};
    uint64_t rate_limited_messages{0};
    uint64_t malformed_messages{0};
    uint64_t getutxoroots_received{0};
    uint64_t utxoroots_received{0};
    uint64_t getutxoshard_received{0};
    uint64_t utxoshard_received{0};
    uint64_t getblockundo_received{0};
    uint64_t blockundo_received{0};
    uint64_t swarm_corrupted_roots_rejected{0};
    uint64_t swarm_corrupted_shards_rejected{0};
    uint64_t swarm_corrupted_undo_rejected{0};
    uint64_t swarm_shards_verified{0};
    uint64_t swarm_blocks_peeled{0};
    //! Relay-epoch reconciliation: short ids found missing and requested
    uint64_t recon_relay_missing{0};
};

enum class FastSyncSwarmState : uint8_t {
    IDLE = 0,
    FETCHING_ROOTS = 1,
    FETCHING_SHARDS = 2,
    PIVOT_ACTIVE_PEELING = 3,
    COMPLETED = 4,
    FAILED = 5,
};

const char *FastSyncSwarmStateToString(FastSyncSwarmState state) noexcept;

struct FastSyncSwarmStatus {
    FastSyncSwarmState state{FastSyncSwarmState::IDLE};
    BlockHash pivot_block_hash{};
    int pivot_height{0};
    std::optional<uint256> avalanche_state_anchor{};
    size_t total_non_empty_shards{0};
    size_t verified_shards{0};
    size_t pending_shards{0};
    size_t in_flight_shards{0};
    size_t active_peers{0};
    size_t banned_swarm_peers{0};
    uint64_t coins_imported{0};
    uint64_t corrupted_roots_rejected{0};
    uint64_t corrupted_shards_rejected{0};
    uint64_t corrupted_undo_rejected{0};
    uint64_t blocks_peeled{0};
};

/**
 * Nucleation relay's view of its short-id epochs (implemented by the peer
 * manager over txrelay::TxRelayIndex). For a LIVE_MEMPOOL context_id that
 * names a relay epoch and is keyed with that epoch's key, the handler
 * resolves short ids through the relay index instead of scanning the
 * mempool, and rate limits the messages separately from reconciliation:
 * relay requests arrive every tick.
 */
class TxRelayEpochProvider {
public:
    virtual ~TxRelayEpochProvider() = default;
    /** The SipHash key of the relay epoch named context_id, if indexed */
    virtual std::optional<std::pair<uint64_t, uint64_t>>
    RelayEpochKey(const uint256 &context_id) const = 0;
    /** Short ids are truncated to this mask (all ones except in tests) */
    virtual uint64_t RelayShortIdMask() const = 0;
    /** The mempool transactions with these short ids in this epoch */
    virtual std::vector<CTransactionRef>
    ResolveRelayShortIds(const uint256 &context_id,
                         const std::vector<uint64_t> &short_ids) const = 0;
    /**
     * The reconciliation set of a relay epoch: transactions admitted within
     * the reconciliation window that are still in the mempool. nullopt if
     * context_id is not a relay epoch.
     */
    virtual std::optional<std::vector<CTransactionRef>>
    RelayReconSet(const uint256 &context_id) const = 0;
    /** Whether we have a transaction with this short id in this epoch */
    virtual bool HaveRelayShortId(const uint256 &context_id,
                                  uint64_t short_id) const = 0;
};

/**
 * Constructor-injected handler for Lotus V2 / Tachyon P2P protocol messages:
 * - SealedHeader ("sealedheader") fast-path O(1) block reconstruction and
 *   automatic getdata fallback.
 * - Generalized Merklix Set Reconciliation ("merklixsync", "getmerklixbuck",
 *   "merklixbuck", "getshorttx", "shorttx") across LIVE_MEMPOOL, EPOCH_BATCH,
 *   BLOCK_RECON, and AVA_CONFLICT_SET scopes.
 * - Tachyon SnapSync 256-Shard UTXO Fast Sync & Bijective Reverse Block Peeling
 *   Swarm Coordinator ("getutxoroots", "utxoroots", "getutxoshard",
 *   "utxoshard", "getblockundo", "blockundo") anchored via Avalanche state-root
 *   quorum polling without requiring a state root in the 80-byte block header.
 */
class V2PeerProtocolHandler {
public:
    static constexpr size_t MAX_SYNC_MESSAGES_PER_WINDOW = 32;
    /**
     * getshorttx/shorttx exchanged for relay-epoch short-id announcements
     * (one per peer per relay tick at most each way, plus slack)
     */
    static constexpr size_t MAX_RELAY_MESSAGES_PER_WINDOW = 1000;
    static constexpr size_t MAX_SHARD_MESSAGES_PER_WINDOW = 512;
    static constexpr std::chrono::milliseconds RATE_LIMIT_WINDOW{1000};
    static constexpr size_t MAX_MINEDHEADER_COINBASE_BYTES = 10000;
    static constexpr size_t MAX_SEALEDHEADER_COINBASE_BYTES =
        MAX_MINEDHEADER_COINBASE_BYTES;
    static constexpr size_t MAX_TRACKED_RECON_SCOPES = 64;
    static constexpr size_t MAX_SCOPED_TXS = 4096;

    V2PeerProtocolHandler(ChainstateManager &chainman, CTxMemPool &mempool,
                          CConnman &connman, PeerManager &peerman);

    void SetAvalancheProcessor(avalanche::Processor *avalanche)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Set once, before any message is handled */
    void SetTxRelayEpochProvider(const TxRelayEpochProvider *provider) {
        m_relay_epochs = provider;
    }
    /** Whether (scope, context_id, k0, k1) is a relay epoch and its key */
    bool IsRelayEpoch(ReconScope scope, const uint256 &context_id, uint64_t k0,
                      uint64_t k1) const;
    /**
     * Short id of txid for a request or summary in (scope, context_id),
     * truncated as relay epochs require
     */
    uint64_t ScopedShortId(ReconScope scope, const uint256 &context_id,
                           uint64_t k0, uint64_t k1, const TxId &txid) const;
    /** Drop short ids of a relay epoch that we already have */
    void FilterRelayHave(CNode &pfrom, ReconScope scope,
                         const uint256 &context_id, uint64_t k0, uint64_t k1,
                         std::vector<uint64_t> &short_ids) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void SetSnapSyncEnabled(std::optional<bool> enabled)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void SetReverseSyncEnabled(std::optional<bool> enabled)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void SetServeUtxoShards(std::optional<bool> enabled)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsSnapSyncEnabled() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsReverseSyncEnabled() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsServeUtxoShardsEnabled() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void SetPeerServices(NodeId peer_id, ServiceFlags services)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ServiceFlags GetPeerServices(NodeId peer_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Dispatch a V2 protocol message if msg_type is handled by this handler.
     * Returns true if msg_type was recognized and handled.
     */
    bool TryHandleMessage(CNode &pfrom, const std::string &msg_type,
                          DataStream &vRecv,
                          std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void HandleMinedHeader(CNode &pfrom, DataStream &vRecv)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        HandleSealedHeader(pfrom, vRecv);
    }
    void HandleSealedHeader(CNode &pfrom, DataStream &vRecv)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleMerklixSync(CNode &pfrom, DataStream &vRecv,
                           std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleGetMerklixBuck(CNode &pfrom, DataStream &vRecv,
                              std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleMerklixBuck(CNode &pfrom, DataStream &vRecv,
                           std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleGetShortTx(CNode &pfrom, DataStream &vRecv,
                          std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleShortTx(CNode &pfrom, DataStream &vRecv,
                       std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void HandleGetUtxoRoots(CNode &pfrom, DataStream &vRecv,
                            std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleUtxoRoots(CNode &pfrom, DataStream &vRecv,
                         std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleGetUtxoShard(CNode &pfrom, DataStream &vRecv,
                            std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleUtxoShard(CNode &pfrom, DataStream &vRecv,
                         std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleGetBlockUndo(CNode &pfrom, DataStream &vRecv,
                            std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void HandleBlockUndo(CNode &pfrom, DataStream &vRecv,
                         std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Register a CNode reference for direct P2P message pushing (also recorded
     * automatically in TryHandleMessage; useful for unit tests using
     * stack-allocated CNode instances).
     */
    void RegisterPeerNode(CNode &pnode) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Start an autonomous multi-peer Fast-Sync UTXO Shard Swarm session for
     * pivot_hash across peer_ids (or all connected peers if peer_ids is empty).
     */
    bool StartFastSyncSwarm(const BlockHash &pivot_hash,
                            const std::vector<NodeId> &peer_ids,
                            bool auto_peel,
                            std::string &err)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Start or resume multi-peer reverse block peeling (GETBLOCKUNDO /
     * BLOCKUNDO) backwards from earliest_verified_height toward genesis.
     */
    bool StartReversePeelSwarm(const std::vector<NodeId> &peer_ids,
                               std::string &err)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Split a pending or in-flight shard (prefix_depth, prefix_bits) into two
     * adaptive sub-shards at prefix_depth + 1 and dispatch them across healthy
     * swarm peers.
     */
    bool SplitSwarmShardToSubShards(uint8_t prefix_depth, uint16_t prefix_bits,
                                    std::string &err)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Requested historical bodies must be accepted by ABC before undo replay. */
    bool IsFastSyncBlockRequested(const BlockHash &hash) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void BlockDataReceived(const BlockHash &hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Called by the normal peer send loop, including while no reply arrives. */
    void CheckFastSyncTimeouts(NodeId peer_id, std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    FastSyncSwarmStatus GetFastSyncSwarmStatus() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Register a candidate transaction overlay for O(1) sealedheader
     * reconstruction keyed by the parent block hash (or block merkle root).
     * Precomputes subtree_a_root and positional SHA-256d null_merkle_root +
     * coinbase_merkle_branch once.
     */
    void RegisterCandidateOverlay(const BlockHash &prev_block_hash,
                                  std::vector<CTransactionRef> txs)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Clear all registered candidate overlays.
     */
    void ClearCandidateOverlays() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Attempt O(1) reconstruction of a full CBlock from a SealedHeader /
     * SealedBlock against registered candidate overlays or the local CTOR
     * mempool overlays.
     */
    std::shared_ptr<const CBlock>
    MatchCandidateOverlay(const CBlockHeader &header,
                          const CTransactionRef &coinbase_tx,
                          const std::vector<uint256> &coinbase_merkle_branch = {},
                          const std::vector<uint256> &epoch_batch_ids = {}) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Register or update the local transaction set for a specific
     * (ReconScope, context_id) pair. For LIVE_MEMPOOL with a null context_id,
     * the handler also reads directly from m_mempool when no explicit set is
     * registered.
     */
    void SetScopedTransactions(ReconScope scope, const uint256 &context_id,
                               std::vector<CTransactionRef> txs)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Retrieve the current local transactions for (scope, context_id).
     */
    std::vector<CTransactionRef>
    GetScopedTransactions(ReconScope scope, const uint256 &context_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Build a depth-4 MerklixSyncSummary over the local transaction set for
     * (scope, context_id) using the given SipHash salt.
     */
    MerklixSyncSummary BuildSyncSummary(ReconScope scope,
                                        const uint256 &context_id,
                                        uint64_t salt_k0 = 0,
                                        uint64_t salt_k1 = 0) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Compare a remote MerklixSyncSummary against our local set.
     */
    MerklixSyncDiffResult
    DiffSyncSummary(const MerklixSyncSummary &remote_summary) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Build a depth-8 MerklixSubBucketSummary for parent_bucket (0..15).
     */
    MerklixSubBucketSummary BuildSubBucketSummary(ReconScope scope,
                                                  const uint256 &context_id,
                                                  uint64_t salt_k0,
                                                  uint64_t salt_k1,
                                                  uint8_t parent_bucket) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Build a MerklixSubBucketSummary at depth_bits (8, 12, or 16) for
     * parent_prefix (4-bit, 8-bit, or 12-bit prefix).
     */
    MerklixSubBucketSummary BuildSubBucketSummary(ReconScope scope,
                                                  const uint256 &context_id,
                                                  uint64_t salt_k0,
                                                  uint64_t salt_k1,
                                                  uint16_t parent_prefix,
                                                  uint8_t depth_bits) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Compare a remote MerklixSubBucketSummary against our local set and
     * recover missing short IDs via 1-tx and 2-tx GF(2^64) syndromes.
     */
    MerklixSubBucketDiffResult
    DiffSubBucketSummary(const MerklixSubBucketSummary &remote_sub) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Resolve a list of short IDs against our local transaction set for
     * (scope, context_id).
     */
    std::vector<CTransactionRef>
    ResolveShortIds(ReconScope scope, const uint256 &context_id,
                    uint64_t salt_k0, uint64_t salt_k1,
                    const std::vector<uint64_t> &short_ids) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Record a pending GETSHORTTX request sent to peer_id so only solicited
     * SHORTTX responses matching requested short_ids are accepted.
     */
    void RecordPendingShortTxRequest(NodeId peer_id, ReconScope scope,
                                     const uint256 &context_id,
                                     uint64_t salt_k0, uint64_t salt_k1,
                                     const std::vector<uint64_t> &short_ids)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool HasPendingShortTxRequests(NodeId peer_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Configure or query whether a peer is opted into BIP152-style
     * High-Bandwidth preemptive SHORTTX and SEALEDHEADER relay.
     */
    void SetHighBandwidthShortTxPeer(NodeId peer_id, bool enabled)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsHighBandwidthShortTxPeer(NodeId peer_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Clean up all per-peer state when a peer disconnects.
     */
    void RemovePeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void RemovePeer(CNode &pnode) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Record and query the last block known to have been announced/sent by a
     * peer via SEALEDHEADER so we do not redundantly re-announce it back.
     */
    void RecordPeerKnownBlock(NodeId peer_id, const BlockHash &block_hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool PeerKnowsBlock(NodeId peer_id, const BlockHash &block_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<BlockHash> GetLastPeerKnownBlock(NodeId peer_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool CheckPeerRateLimit(NodeId peer_id,
                            std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool CheckPeerShardRateLimit(NodeId peer_id,
                                 std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool CheckPeerRelayRateLimit(NodeId peer_id,
                                 std::chrono::microseconds time_received)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    V2ProtocolHandlerStats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<CInv> GetLastFallbackInv() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct ShardKey {
        uint8_t prefix_depth{8};
        uint16_t prefix_bits{0};

        bool operator==(const ShardKey &o) const noexcept {
            return prefix_depth == o.prefix_depth &&
                   prefix_bits == o.prefix_bits;
        }
        bool operator<(const ShardKey &o) const noexcept {
            if (prefix_depth != o.prefix_depth) {
                return prefix_depth < o.prefix_depth;
            }
            return prefix_bits < o.prefix_bits;
        }
    };

    struct FastSyncSwarmCoordinatorState {
        FastSyncSwarmState state{FastSyncSwarmState::IDLE};
        BlockHash pivot_hash{};
        lotus::v2::Hash pivot_v2_id{};
        int pivot_height{0};
        std::optional<lotus::v2::Hash> expected_anchor{};
        bool auto_peel{false};
        std::vector<NodeId> healthy_peers;
        std::unordered_set<NodeId> banned_peers;
        size_t rr_cursor{0};
        std::map<NodeId, std::chrono::microseconds> request_deadlines;
        NodeId roots_in_flight_peer{-1};
        bool has_verified_roots{false};
        lotus::v2::UtxoRootsMessage verified_roots{};
        size_t total_non_empty_shards{0};
        std::deque<ShardKey> pending_shards;
        std::map<ShardKey, NodeId> in_flight_shards;
        std::map<ShardKey, lotus::v2::UtxoShardMessage> verified_shards;
        uint64_t coins_imported{0};
        uint64_t blocks_peeled{0};
        BlockHash undo_in_flight_hash{};
        NodeId undo_in_flight_peer{-1};
        std::optional<lotus::v2::BlockUndoMessage> pending_undo_for_block{};
        NodeId pending_undo_peer{-1};
    };

    bool PeerSupportsUtxoShardsLocked(NodeId peer_id) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void GetScopedTransactionsAndRoot(ReconScope scope,
                                      const uint256 &context_id,
                                      std::vector<CTransactionRef> &out_txs,
                                      uint256 *out_root) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool SendRawPayloadToPeerLocked(NodeId peer_id, const char *msg_type,
                                    Span<const uint8_t> payload)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool RequestSwarmRootsLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void DispatchPendingSwarmShardsLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void HandleSwarmPeerFailureLocked(NodeId peer_id,
                                      std::optional<ShardKey> failed_shard)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool RequestNextReversePeelBlockLocked(int target_height,
                                           const BlockHash &target_hash,
                                           bool need_block_data = false)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    ChainstateManager &m_chainman;
    CTxMemPool &m_mempool;
    CConnman &m_connman;
    PeerManager &m_peerman;
    const TxRelayEpochProvider *m_relay_epochs{nullptr};

    mutable Mutex m_mutex;
    avalanche::Processor *m_avalanche GUARDED_BY(m_mutex){nullptr};
    std::optional<bool> m_snapsync_enabled_override GUARDED_BY(m_mutex);
    std::optional<bool> m_reversesync_enabled_override GUARDED_BY(m_mutex);
    std::optional<bool> m_serve_utxo_shards_override GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, CNode *> m_peer_nodes GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, ServiceFlags> m_peer_services GUARDED_BY(m_mutex);
    FastSyncSwarmCoordinatorState m_swarm GUARDED_BY(m_mutex);
    std::map<BlockHash, std::vector<CandidateOverlayEntry>>
        m_candidate_overlays GUARDED_BY(m_mutex);

    struct ScopeKey {
        ReconScope scope;
        uint256 context_id;

        bool operator<(const ScopeKey &other) const noexcept {
            if (scope != other.scope) {
                return static_cast<uint8_t>(scope) <
                       static_cast<uint8_t>(other.scope);
            }
            return context_id < other.context_id;
        }
    };
    struct ScopedTxSetEntry {
        std::vector<CTransactionRef> txs;
        lotus::v2::Hash subtree_a_root{};
        uint256 null_merkle_root{};
        std::vector<uint256> coinbase_merkle_branch{};
    };
    std::map<ScopeKey, ScopedTxSetEntry>
        m_scoped_txs GUARDED_BY(m_mutex);

    struct PendingShortTxKey {
        NodeId peer_id;
        ReconScope scope;
        uint256 context_id;

        bool operator<(const PendingShortTxKey &other) const noexcept {
            if (peer_id != other.peer_id) {
                return peer_id < other.peer_id;
            }
            if (scope != other.scope) {
                return static_cast<uint8_t>(scope) <
                       static_cast<uint8_t>(other.scope);
            }
            return context_id < other.context_id;
        }
    };
    struct PendingShortTxEntry {
        uint64_t salt_k0{0};
        uint64_t salt_k1{0};
        std::unordered_set<uint64_t> requested_short_ids;
    };
    std::map<PendingShortTxKey, PendingShortTxEntry>
        m_pending_shorttx_requests GUARDED_BY(m_mutex);

    std::unordered_set<NodeId>
        m_high_bandwidth_shorttx_peers GUARDED_BY(m_mutex);

    struct PeerRateState {
        std::chrono::microseconds window_start{0};
        size_t count{0};
    };
    std::unordered_map<NodeId, PeerRateState>
        m_peer_rates GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, PeerRateState>
        m_peer_shorttx_windows GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, PeerRateState>
        m_peer_shard_windows GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, PeerRateState>
        m_peer_relay_windows GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, std::chrono::microseconds>
        m_peer_window_start GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, size_t>
        m_peer_msg_counts GUARDED_BY(m_mutex);
    std::unordered_map<NodeId, BlockHash>
        m_peer_known_blocks GUARDED_BY(m_mutex);

    mutable V2ProtocolHandlerStats m_stats GUARDED_BY(m_mutex);
    std::optional<CInv> m_last_fallback_inv GUARDED_BY(m_mutex);
};

} // namespace lotus::v2::net

#endif // BITCOIN_NET_V2_PROTOCOL_HANDLER_H
