// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/v2_protocol_handler.h>

#include <node/metrics.h>

#include <avalanche/processor.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/siphash.h>
#include <logging.h>
#include <lotus_v2/blocksnap.h>
#include <lotus_v2/set_reconciliation.h>
#include <lotus_v2/tagged_hash.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/metrics.h>
#include <txmempool.h>
#include <validation.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_set>



namespace lotus::v2::net {

namespace {

constexpr size_t MAX_OVERLAYS_PER_PREV = 16;

std::vector<CTransactionRef>
NormalizeCtorTxList(const std::vector<CTransactionRef> &txs) {
    std::vector<CTransactionRef> sorted;
    sorted.reserve(txs.size());
    for (const auto &tx : txs) {
        if (tx && !tx->IsNull() && !tx->IsCoinBase()) {
            sorted.push_back(tx);
        }
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const CTransactionRef &a, const CTransactionRef &b) {
                  return a->GetId() < b->GetId();
              });
    sorted.erase(
        std::unique(sorted.begin(), sorted.end(),
                    [](const CTransactionRef &a, const CTransactionRef &b) {
                        return a->GetId() == b->GetId();
                    }),
        sorted.end());
    if (sorted.size() > V2PeerProtocolHandler::MAX_SCOPED_TXS) {
        sorted.resize(V2PeerProtocolHandler::MAX_SCOPED_TXS);
    }
    return sorted;
}

lotus::v2::TxIdentityPair MakeTxIdentityPair(const CTransaction &tx) noexcept {
    lotus::v2::TxIdentityPair pair{};
    std::memcpy(pair.tx_hash.data(), tx.GetHash().begin(), 32);
    std::memcpy(pair.tx_id.data(), tx.GetId().begin(), 32);
    return pair;
}

lotus::v2::Hash
ComputeSubtreeAHash(const std::vector<CTransactionRef> &normalized_txs) {
    std::vector<lotus::v2::TxIdentityPair> pairs;
    pairs.reserve(normalized_txs.size());
    for (const auto &tx : normalized_txs) {
        if (tx && !tx->IsNull() && !tx->IsCoinBase()) {
            pairs.push_back(MakeTxIdentityPair(*tx));
        }
    }
    return lotus::v2::BuildTxSubtreeA(pairs);
}

CandidateOverlayEntry
BuildCandidateOverlayEntry(const std::vector<CTransactionRef> &raw_txs) {
    CandidateOverlayEntry entry;
    entry.txs = NormalizeCtorTxList(raw_txs);
    entry.subtree_a_root = ComputeSubtreeAHash(entry.txs);
    lotus::v2::ComputeNullMerkleRootAndBranch(entry.txs, entry.null_merkle_root,
                                              entry.coinbase_merkle_branch);
    return entry;
}

} // namespace

std::pair<uint64_t, uint64_t>
DeriveReconSipHashKey(ReconScope scope, const uint256 &context_id,
                      uint64_t epoch_or_nonce) noexcept {
    std::array<uint8_t, 42> payload{};
    payload[0] = 0x52; // domain sub-tag 'R' for reconciliation SipHash key
    payload[1] = static_cast<uint8_t>(scope);
    std::memcpy(payload.data() + 2, context_id.begin(), 32);
    for (unsigned i = 0; i < 8; ++i) {
        payload[34 + i] = static_cast<uint8_t>(epoch_or_nonce >> (8 * i));
    }
    const lotus::v2::Hash digest =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, payload);
    uint64_t k0 = 0;
    uint64_t k1 = 0;
    for (unsigned i = 0; i < 8; ++i) {
        k0 |= uint64_t(digest[i]) << (8 * i);
        k1 |= uint64_t(digest[8 + i]) << (8 * i);
    }
    return {k0, k1};
}

bool IsValidReconSipHashKey(ReconScope scope, const uint256 &context_id,
                            uint64_t salt_k0, uint64_t salt_k1) noexcept {
    const auto [k0_default, k1_default] =
        DeriveReconSipHashKey(scope, context_id, 0);
    if (salt_k0 == k0_default && salt_k1 == k1_default) {
        return true;
    }
    // Also permit salt_k0 as an explicit epoch/nonce if salt_k1 matches the
    // second half of DeriveReconSipHashKey(scope, context_id, salt_k0).
    const auto [_, k1_from_nonce] =
        DeriveReconSipHashKey(scope, context_id, salt_k0);
    return salt_k1 == k1_from_nonce;
}

uint256 ComputeScopedMerklixRoot(const std::vector<CTransactionRef> &txs) {
    const std::vector<CTransactionRef> normalized = NormalizeCtorTxList(txs);
    const lotus::v2::Hash root = ComputeSubtreeAHash(normalized);
    uint256 out{};
    std::memcpy(out.begin(), root.data(), 32);
    return out;
}

uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const lotus::v2::Hash &subtree_a_root) {
    const lotus::v2::TxIdentityPair cb_pair = MakeTxIdentityPair(coinbase_tx);
    const lotus::v2::Hash root =
        lotus::v2::CombineCoinbaseAndSubtreeA(cb_pair, subtree_a_root);
    uint256 out{};
    std::memcpy(out.begin(), root.data(), 32);
    return out;
}

uint64_t GF64Mul(uint64_t a, uint64_t b) noexcept {
    return lotus::v2::GF64Mul(a, b);
}

uint64_t GF64Square(uint64_t a) noexcept {
    return lotus::v2::GF64Sqr(a);
}

uint64_t GF64Cube(uint64_t a) noexcept {
    return lotus::v2::GF64Cube(a);
}

uint64_t GF64Pow5(uint64_t a) noexcept {
    return lotus::v2::GF64Pow5(a);
}

uint64_t GF64Inv(uint64_t a) noexcept {
    return lotus::v2::GF64Inv(a);
}

bool GF64SolveQuadratic(uint64_t c, uint64_t &y_out) noexcept {
    return lotus::v2::GF64SolveQuadratic(c, y_out);
}

std::optional<std::vector<uint64_t>>
RecoverGF64Syndromes(uint64_t delta_s1, uint64_t delta_s3) noexcept {
    if (delta_s1 == 0 && delta_s3 == 0) {
        return std::vector<uint64_t>{};
    }
    if (delta_s1 == 0) {
        return std::nullopt;
    }
    // 1-element difference: delta_s3 == (delta_s1)^3
    const uint64_t s1_cubed = GF64Cube(delta_s1);
    if (s1_cubed == delta_s3) {
        return std::vector<uint64_t>{delta_s1};
    }

    // 2-element difference:
    // (x1 ^ x2)^3 = x1^3 ^ x2^3 ^ x1*x2*(x1 ^ x2)
    // => x1*x2 = (delta_s3 ^ (delta_s1)^3) * (delta_s1)^(-1)
    // Let x1 = delta_s1 * y => y^2 ^ y = (x1*x2) * (delta_s1)^(-2) = c.
    const uint64_t num = delta_s3 ^ s1_cubed;
    const uint64_t inv_s1 = GF64Inv(delta_s1);
    const uint64_t prod = GF64Mul(num, inv_s1);
    const uint64_t c = GF64Mul(prod, GF64Square(inv_s1));

    uint64_t y = 0;
    if (!GF64SolveQuadratic(c, y)) {
        return std::nullopt;
    }
    uint64_t x1 = GF64Mul(delta_s1, y);
    uint64_t x2 = x1 ^ delta_s1;
    if (x1 > x2) {
        std::swap(x1, x2);
    }
    return std::vector<uint64_t>{x1, x2};
}

std::optional<std::vector<uint64_t>>
RecoverGF64Syndromes(uint64_t delta_s1, uint64_t delta_s3,
                     uint64_t delta_s5) noexcept {
    if (delta_s1 == 0 && delta_s3 == 0 && delta_s5 == 0) {
        return std::vector<uint64_t>{};
    }
    auto roots = RecoverGF64Syndromes(delta_s1, delta_s3);
    if (!roots.has_value() || roots->empty()) {
        return std::nullopt;
    }
    uint64_t expected_s5 = 0;
    for (uint64_t r : *roots) {
        expected_s5 ^= GF64Pow5(r);
    }
    if (expected_s5 != delta_s5) {
        return std::nullopt;
    }
    return roots;
}

uint64_t ComputeMerklixShortId(uint64_t salt_k0, uint64_t salt_k1,
                               const TxId &txid) noexcept {
    const uint64_t sid = SipHashUint256(salt_k0, salt_k1, txid);
    return sid != 0 ? sid : 1ULL;
}

const char *FastSyncSwarmStateToString(FastSyncSwarmState state) noexcept {
    switch (state) {
        case FastSyncSwarmState::IDLE:
            return "idle";
        case FastSyncSwarmState::FETCHING_ROOTS:
            return "fetching_roots";
        case FastSyncSwarmState::FETCHING_SHARDS:
            return "fetching_shards";
        case FastSyncSwarmState::PIVOT_ACTIVE_PEELING:
            return "pivot_active_peeling";
        case FastSyncSwarmState::COMPLETED:
            return "completed";
        case FastSyncSwarmState::FAILED:
            return "failed";
    }
    return "unknown";
}

V2PeerProtocolHandler::V2PeerProtocolHandler(ChainstateManager &chainman,
                                             CTxMemPool &mempool,
                                             CConnman &connman,
                                             PeerManager &peerman)
    : m_chainman(chainman), m_mempool(mempool), m_connman(connman),
      m_peerman(peerman) {}

void V2PeerProtocolHandler::SetAvalancheProcessor(
    avalanche::Processor *avalanche) {
    LOCK(m_mutex);
    m_avalanche = avalanche;
}

void V2PeerProtocolHandler::SetSnapSyncEnabled(std::optional<bool> enabled) {
    {
        LOCK(cs_main);
        if (!m_chainman.GetAll().empty()) {
            m_chainman.ActiveChainstate().SetSnapSyncEnabled(enabled);
        }
    }
    LOCK(m_mutex);
    m_snapsync_enabled_override = enabled;
}

void V2PeerProtocolHandler::SetReverseSyncEnabled(std::optional<bool> enabled) {
    {
        LOCK(cs_main);
        if (!m_chainman.GetAll().empty()) {
            m_chainman.ActiveChainstate().SetReverseSyncEnabled(enabled);
        }
    }
    LOCK(m_mutex);
    m_reversesync_enabled_override = enabled;
}

void V2PeerProtocolHandler::SetServeUtxoShards(std::optional<bool> enabled) {
    LOCK(m_mutex);
    m_serve_utxo_shards_override = enabled;
}

bool V2PeerProtocolHandler::IsSnapSyncEnabled() const {
    LOCK(m_mutex);
    const bool snap =
        m_snapsync_enabled_override.value_or(gArgs.GetBoolArg("-snapsync", true));
    const bool rev = m_reversesync_enabled_override.value_or(
        gArgs.GetBoolArg("-reversesync", true));
    return snap && rev;
}

bool V2PeerProtocolHandler::IsReverseSyncEnabled() const {
    return IsSnapSyncEnabled();
}

bool V2PeerProtocolHandler::IsServeUtxoShardsEnabled() const {
    LOCK(m_mutex);
    return m_serve_utxo_shards_override.value_or(
        gArgs.GetBoolArg("-serveutxoshards", true));
}

void V2PeerProtocolHandler::SetPeerServices(NodeId peer_id,
                                            ServiceFlags services) {
    LOCK(m_mutex);
    m_peer_services[peer_id] = services;
}

ServiceFlags V2PeerProtocolHandler::GetPeerServices(NodeId peer_id) const {
    LOCK(m_mutex);
    auto it = m_peer_services.find(peer_id);
    return it != m_peer_services.end() ? it->second : NODE_NONE;
}

bool V2PeerProtocolHandler::PeerSupportsUtxoShardsLocked(NodeId peer_id) const {
    AssertLockHeld(m_mutex);
    auto it = m_peer_services.find(peer_id);
    if (it != m_peer_services.end()) {
        return (it->second & NODE_UTXO_SHARD) != 0;
    }
    return false;
}

void V2PeerProtocolHandler::RegisterPeerNode(CNode &pnode) {
    LOCK(m_mutex);
    m_peer_nodes[pnode.GetId()] = &pnode;
}

bool V2PeerProtocolHandler::TryHandleMessage(
    CNode &pfrom, const std::string &msg_type, DataStream &vRecv,
    std::chrono::microseconds time_received) {
    {
        LOCK(m_mutex);
        m_peer_nodes[pfrom.GetId()] = &pfrom;
    }
    if (msg_type == NetMsgType::MINEDHEADER ||
        msg_type == NetMsgType::SEALEDHEADER ||
        msg_type == NetMsgType::SEALEDBLOCK) {
        HandleSealedHeader(pfrom, vRecv);
        return true;
    }
    if (msg_type == NetMsgType::MERKLIXSYNC) {
        HandleMerklixSync(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::GETMERKLIXBUCK) {
        HandleGetMerklixBuck(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::MERKLIXBUCK) {
        HandleMerklixBuck(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::GETSHORTTX) {
        HandleGetShortTx(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::SHORTTX) {
        HandleShortTx(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::GETUTXOROOTS) {
        HandleGetUtxoRoots(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::UTXOROOTS) {
        HandleUtxoRoots(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::GETUTXOSHARD) {
        HandleGetUtxoShard(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::UTXOSHARD) {
        HandleUtxoShard(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::GETBLOCKUNDO) {
        HandleGetBlockUndo(pfrom, vRecv, time_received);
        return true;
    }
    if (msg_type == NetMsgType::BLOCKUNDO) {
        HandleBlockUndo(pfrom, vRecv, time_received);
        return true;
    }
    return false;
}

bool V2PeerProtocolHandler::CheckPeerRateLimit(
    NodeId peer_id, std::chrono::microseconds time_received) {
    LOCK(m_mutex);
    auto &state = m_peer_rates[peer_id];
    const auto window_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            RATE_LIMIT_WINDOW);
    if (time_received < state.window_start ||
        (time_received - state.window_start) >= window_us) {
        state.window_start = time_received;
        state.count = 1;
        m_peer_window_start[peer_id] = time_received;
        m_peer_msg_counts[peer_id] = 1;
        return true;
    }
    if (state.count >= MAX_SYNC_MESSAGES_PER_WINDOW) {
        ++m_stats.rate_limited_messages;
        return false;
    }
    ++state.count;
    m_peer_msg_counts[peer_id] = state.count;
    return true;
}

bool V2PeerProtocolHandler::CheckPeerRelayRateLimit(
    NodeId peer_id, std::chrono::microseconds time_received) {
    LOCK(m_mutex);
    auto &state = m_peer_relay_windows[peer_id];
    const auto window_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            RATE_LIMIT_WINDOW);
    if (time_received < state.window_start ||
        (time_received - state.window_start) >= window_us) {
        state.window_start = time_received;
        state.count = 1;
        return true;
    }
    if (state.count >= MAX_RELAY_MESSAGES_PER_WINDOW) {
        ++m_stats.rate_limited_messages;
        return false;
    }
    ++state.count;
    return true;
}

bool V2PeerProtocolHandler::IsRelayEpoch(ReconScope scope,
                                         const uint256 &context_id, uint64_t k0,
                                         uint64_t k1) const {
    if (scope != ReconScope::LIVE_MEMPOOL || !m_relay_epochs ||
        context_id.IsNull()) {
        return false;
    }
    const auto key{m_relay_epochs->RelayEpochKey(context_id)};
    return key && key->first == k0 && key->second == k1;
}

void V2PeerProtocolHandler::FilterRelayHave(
    CNode &pfrom, ReconScope scope, const uint256 &context_id, uint64_t k0,
    uint64_t k1, std::vector<uint64_t> &short_ids) const {
    if (short_ids.empty() || !IsRelayEpoch(scope, context_id, k0, k1)) {
        return;
    }
    auto *metrics{node::GetNodeMetrics()};
    if (metrics) {
        metrics->txrelay_recon_diff.Record(short_ids.size());
    }
    // "Missing" from our window may still be in our mempool (admitted
    // before the window, or the peer's window edge differs from ours).
    std::erase_if(short_ids, [&](uint64_t short_id) {
        return m_relay_epochs->HaveRelayShortId(context_id, short_id);
    });
    if (!short_ids.empty()) {
        if (metrics) {
            metrics->txrelay_recon_fetched.Add(0, short_ids.size());
        }
        {
            LOCK(m_mutex);
            m_stats.recon_relay_missing += short_ids.size();
        }
        // Fetch them like announced short ids: one request per transaction
        // across peers, whether reconciliation or an announcement found it.
        m_peerman.AddRelayShortIdAnnouncements(pfrom, context_id, short_ids);
        short_ids.clear();
    }
}

uint64_t V2PeerProtocolHandler::ScopedShortId(ReconScope scope,
                                              const uint256 &context_id,
                                              uint64_t k0, uint64_t k1,
                                              const TxId &txid) const {
    uint64_t short_id{ComputeMerklixShortId(k0, k1, txid)};
    if (IsRelayEpoch(scope, context_id, k0, k1)) {
        short_id &= m_relay_epochs->RelayShortIdMask();
        if (short_id == 0) {
            short_id = 1;
        }
    }
    return short_id;
}

bool V2PeerProtocolHandler::CheckPeerShardRateLimit(
    NodeId peer_id, std::chrono::microseconds time_received) {
    LOCK(m_mutex);
    auto &state = m_peer_shard_windows[peer_id];
    const auto window_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            RATE_LIMIT_WINDOW);
    if (time_received < state.window_start ||
        (time_received - state.window_start) >= window_us) {
        state.window_start = time_received;
        state.count = 1;
        return true;
    }
    if (state.count >= MAX_SHARD_MESSAGES_PER_WINDOW) {
        ++m_stats.rate_limited_messages;
        return false;
    }
    ++state.count;
    return true;
}

void V2PeerProtocolHandler::RegisterCandidateOverlay(
    const BlockHash &prev_block_hash, std::vector<CTransactionRef> txs) {
    CandidateOverlayEntry entry = BuildCandidateOverlayEntry(txs);
    LOCK(m_mutex);
    auto &vec = m_candidate_overlays[prev_block_hash];
    if (vec.size() >= MAX_OVERLAYS_PER_PREV) {
        vec.erase(vec.begin());
    }
    vec.push_back(std::move(entry));
}

void V2PeerProtocolHandler::ClearCandidateOverlays() {
    LOCK(m_mutex);
    m_candidate_overlays.clear();
}

std::shared_ptr<const CBlock> V2PeerProtocolHandler::MatchCandidateOverlay(
    const CBlockHeader &header, const CTransactionRef &coinbase_tx,
    const std::vector<uint256> &coinbase_merkle_branch,
    const std::vector<uint256> &epoch_batch_ids) const {
    if (header.IsNull() || !coinbase_tx || coinbase_tx->IsNull() ||
        !coinbase_tx->IsCoinBase()) {
        return nullptr;
    }

    uint64_t parent_mtp = 0;
    uint64_t next_height = 0;
    {
        LOCK(cs_main);
        const CBlockIndex *pindex_prev =
            m_chainman.m_blockman.LookupBlockIndex(header.hashPrevBlock);
        if (pindex_prev) {
            parent_mtp =
                static_cast<uint64_t>(pindex_prev->GetMedianTimePast());
            next_height = static_cast<uint64_t>(pindex_prev->nHeight + 1);
        }
    }

    const TxId cb_txid_u256 = coinbase_tx->GetId();
    lotus::v2::Hash cb_tx_id{};
    std::memcpy(cb_tx_id.data(), cb_txid_u256.begin(), 32);
    lotus::v2::Hash prev_block_id{};
    std::memcpy(prev_block_id.data(), header.hashPrevBlock.begin(), 32);

    // Check progressive Merklix overlay layers (finalized epoch layers L_k and
    // live speculative layer L_spec) in O(log N) (<= 16 SHA-256d spine hashes)
    // using the precomputed positional null_merkle_root + coinbase_merkle_branch
    // before falling back to explicit candidates.
    std::shared_ptr<const CBlock> overlay_matched;
    bool used_overlay_fastpath = false;
    {
        LOCK(m_mempool.cs);
        if (!header.hashPrevBlock.IsNull() && m_mempool.size() > 0 &&
            next_height > 0) {
            m_mempool.SyncMerklixOverlayToTip(header.hashPrevBlock, next_height,
                                              parent_mtp);
        }

        auto try_match_layer = [&](const lotus::v2::MempoolOverlayLayer &layer)
            -> std::shared_ptr<const CBlock> {
            if (layer.Contains(cb_tx_id) || layer.HasDoubleSpends()) {
                return nullptr;
            }

            // 1. Standard positional SHA-256d Merkle spine verification:
            //    - If caller supplied `coinbase_merkle_branch`, verify both:
            //      ComputeMerkleRootFromBranch(0, branch) == layer.null_merkle_root
            //      ComputeMerkleRootFromBranch(cb_txid, branch) == header.hashMerkleRoot
            //    - Otherwise, verify via layer's cached coinbase_merkle_branch.
            bool merkle_matched = false;
            if (!coinbase_merkle_branch.empty()) {
                const lotus::v2::SealedBlock sealed_blk(
                    header, coinbase_tx, coinbase_merkle_branch,
                    epoch_batch_ids);
                merkle_matched = sealed_blk.VerifyAgainstLayer(layer);
            } else {
                const lotus::v2::Hash pos_root =
                    layer.ComputePositionalMerkleRoot(cb_tx_id);
                merkle_matched =
                    (std::memcmp(pos_root.data(), header.hashMerkleRoot.begin(),
                                 32) == 0);
            }

            // eCash commits only the positional transaction Merkle root.

            if (!merkle_matched) {
                return nullptr;
            }

            auto block = std::make_shared<CBlock>(header);
            block->vtx.reserve(1 + layer.GetTxCount());
            block->vtx.push_back(coinbase_tx);
            for (const auto &[_, oentry] : layer.GetOrderedTxs()) {
                CTransactionRef tx =
                    std::static_pointer_cast<const CTransaction>(oentry.tx_ref);
                if (!tx) {
                    uint256 raw_id;
                    std::memcpy(raw_id.begin(), oentry.tx_id.data(), 32);
                    tx = m_mempool.get(TxId(raw_id));
                }
                if (!tx) {
                    return nullptr;
                }
                block->vtx.push_back(std::move(tx));
            }
            // CheckBlock must still check the Merkle root and duplicate-tail mutation.

            const bool anchored =
                layer.GetParentBlockId() == prev_block_id &&
                (next_height == 0 || layer.GetHeight() == next_height) &&
                layer.GetParentMtp() == parent_mtp;
            if (anchored) {
                used_overlay_fastpath = true;
            }
            return block;
        };

        auto &overlay_mgr = m_mempool.GetOverlayManager();
        const auto &frozen_epochs = overlay_mgr.GetFrozenEpochs();
        for (auto it = frozen_epochs.rbegin(); it != frozen_epochs.rend();
             ++it) {
            if (auto matched = try_match_layer(*it)) {
                overlay_matched = std::move(matched);
                break;
            }
        }
        if (!overlay_matched) {
            overlay_matched =
                try_match_layer(overlay_mgr.GetSpeculativeOverlay());
        }
    }
    if (overlay_matched) {
        if (used_overlay_fastpath) {
            LOCK(m_mutex);
            ++m_stats.sealedheader_overlay_fastpath;
        }
        return overlay_matched;
    }

    std::vector<CandidateOverlayEntry> candidates;
    {
        LOCK(m_mutex);
        auto it_prev = m_candidate_overlays.find(header.hashPrevBlock);
        if (it_prev != m_candidate_overlays.end()) {
            for (const auto &overlay : it_prev->second) {
                candidates.push_back(overlay);
            }
        }
        auto it_merkle =
            m_candidate_overlays.find(BlockHash(header.hashMerkleRoot));
        if (it_merkle != m_candidate_overlays.end()) {
            for (const auto &overlay : it_merkle->second) {
                candidates.push_back(overlay);
            }
        }
        for (const ReconScope scope :
             {ReconScope::BLOCK_RECON, ReconScope::EPOCH_BATCH,
              ReconScope::LIVE_MEMPOOL}) {
            auto it_scope_prev =
                m_scoped_txs.find(ScopeKey{scope, header.hashPrevBlock});
            if (it_scope_prev != m_scoped_txs.end()) {
                candidates.push_back(CandidateOverlayEntry{
                    it_scope_prev->second.txs,
                    it_scope_prev->second.subtree_a_root,
                    it_scope_prev->second.null_merkle_root,
                    it_scope_prev->second.coinbase_merkle_branch});
            }
            auto it_scope_hash =
                m_scoped_txs.find(ScopeKey{scope, header.GetHash()});
            if (it_scope_hash != m_scoped_txs.end()) {
                candidates.push_back(CandidateOverlayEntry{
                    it_scope_hash->second.txs,
                    it_scope_hash->second.subtree_a_root,
                    it_scope_hash->second.null_merkle_root,
                    it_scope_hash->second.coinbase_merkle_branch});
            }
        }
    }

    // Include the live CTOR-ordered mempool transaction set as a candidate.
    {
        std::vector<CTransactionRef> mempool_txs;
        {
            LOCK(m_mempool.cs);
            mempool_txs.reserve(m_mempool.mapTx.size());
            for (const auto &entry : m_mempool.mapTx) {
                mempool_txs.push_back(entry->GetSharedTx());
            }
        }
        candidates.push_back(BuildCandidateOverlayEntry(mempool_txs));
    }

    // Also include the empty non-coinbase candidate set (for coinbase-only
    // blocks).
    candidates.push_back(BuildCandidateOverlayEntry({}));

    for (const auto &candidate : candidates) {
        // Verify coinbase txid does not collide with any candidate transaction.
        const bool cb_dup = std::binary_search(
            candidate.txs.begin(), candidate.txs.end(), coinbase_tx,
            [](const CTransactionRef &a, const CTransactionRef &b) {
                return a->GetId() < b->GetId();
            });
        if (cb_dup) {
            continue;
        }

        // Fast positional SHA-256d Merkle spine verification (<= 16 hashes)
        // before allocating block->vtx!
        bool merkle_matched = false;
        if (!coinbase_merkle_branch.empty()) {
            if (coinbase_merkle_branch.size() ==
                candidate.coinbase_merkle_branch.size()) {
                const lotus::v2::SealedBlock sealed_blk(
                    header, coinbase_tx, coinbase_merkle_branch,
                    epoch_batch_ids);
                merkle_matched =
                    sealed_blk.VerifyMerkleSpine(candidate.null_merkle_root);
            }
        } else {
            const uint256 expected_pos_root =
                lotus::v2::ComputeMerkleRootFromBranch(
                    cb_txid_u256, candidate.coinbase_merkle_branch,
                    /*index=*/0);
            merkle_matched = (expected_pos_root == header.hashMerkleRoot);
        }

        // V2 commitment matching belongs in the explicit V2 protocol adapter.

        if (!merkle_matched) {
            continue;
        }

        auto block = std::make_shared<CBlock>(header);
        block->vtx.reserve(1 + candidate.txs.size());
        block->vtx.push_back(coinbase_tx);
        for (const auto &tx : candidate.txs) {
            block->vtx.push_back(tx);
        }
        // CheckBlock must still check the Merkle root and duplicate-tail mutation.
        return block;
    }

    return nullptr;
}

void V2PeerProtocolHandler::HandleSealedHeader(CNode &pfrom,
                                               DataStream &vRecv) {
    SealedHeader sealed;
    try {
        vRecv >> sealed;
    } catch (const std::exception &) {
        node::CountSealedHeader(node::SealedHeaderOutcome::INVALID);
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.malformed_messages;
        return;
    }

    {
        LOCK(m_mutex);
        ++m_stats.sealedheader_received;
    }

    if (!sealed.IsValid()) {
        node::CountSealedHeader(node::SealedHeaderOutcome::INVALID);
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.malformed_messages;
        return;
    }

    // Defect C1 (Hole 7): Enforce coinbase serialization size cap before any
    // header/overlay processing.
    if (::GetSerializeSize(*sealed.coinbase_tx) >
        MAX_SEALEDHEADER_COINBASE_BYTES) {
        node::CountSealedHeader(node::SealedHeaderOutcome::REJECTED);
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.sealedheader_rejected;
        return;
    }

    // Defect C1 (Hole 7): Validate header PoW and chain context via
    // ProcessNewBlockHeaders (AcceptBlockHeader) BEFORE running
    // MatchCandidateOverlay or emitting fallback GETDATA(MSG_CMPCT_BLOCK).
    BlockValidationState header_state;
    const CBlockIndex *pindex = nullptr;
    if (!m_chainman.ProcessNewBlockHeaders({sealed.header},
                                           /*min_pow_checked=*/true,
                                           header_state, &pindex)) {
        node::CountSealedHeader(node::SealedHeaderOutcome::REJECTED);
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.sealedheader_rejected;
        return;
    }

    const BlockHash block_hash = sealed.header.GetHash();
    RecordPeerKnownBlock(pfrom.GetId(), block_hash);

    if (pindex && WITH_LOCK(cs_main, return pindex->nStatus.hasData())) {
        node::CountSealedHeader(node::SealedHeaderOutcome::ALREADY_HAVE);
        LOCK(m_mutex);
        ++m_stats.sealedheader_reconstructed;
        return;
    }

    std::shared_ptr<const CBlock> reconstructed = MatchCandidateOverlay(
        sealed.header, sealed.coinbase_tx, sealed.coinbase_merkle_branch,
        sealed.epoch_batch_ids);
    if (reconstructed) {
        node::CountSealedHeader(node::SealedHeaderOutcome::REBUILT);
        {
            LOCK(m_mutex);
            ++m_stats.sealedheader_reconstructed;
        }
        bool fNewBlock = false;
        m_chainman.ProcessNewBlock(reconstructed, /*force_processing=*/true,
                                   /*min_pow_checked=*/true, &fNewBlock);
        return;
    }

    // Fast-path candidate overlay missed: fall back to requesting
    // MSG_CMPCT_BLOCK via getdata from pfrom without penalizing the peer.
    const CInv fallback_inv(MSG_CMPCT_BLOCK, block_hash);
    node::CountSealedHeader(node::SealedHeaderOutcome::FALLBACK);
    {
        LOCK(m_mutex);
        ++m_stats.sealedheader_fallback_getdata;
        m_last_fallback_inv = fallback_inv;
    }
    m_connman.PushMessage(
        &pfrom, NetMsg::Make(NetMsgType::GETDATA,
                             std::vector<CInv>{fallback_inv}));
}

void V2PeerProtocolHandler::SetScopedTransactions(
    ReconScope scope, const uint256 &context_id,
    std::vector<CTransactionRef> txs) {
    ScopedTxSetEntry entry;
    entry.txs = NormalizeCtorTxList(txs);
    entry.subtree_a_root = ComputeSubtreeAHash(entry.txs);
    lotus::v2::ComputeNullMerkleRootAndBranch(entry.txs, entry.null_merkle_root,
                                              entry.coinbase_merkle_branch);
    LOCK(m_mutex);
    const ScopeKey key{scope, context_id};
    if (m_scoped_txs.find(key) == m_scoped_txs.end() &&
        m_scoped_txs.size() >= MAX_TRACKED_RECON_SCOPES) {
        m_scoped_txs.erase(m_scoped_txs.begin());
    }
    m_scoped_txs[key] = std::move(entry);
}

void V2PeerProtocolHandler::GetScopedTransactionsAndRoot(
    ReconScope scope, const uint256 &context_id,
    std::vector<CTransactionRef> &out_txs, uint256 *out_root) const {
    {
        LOCK(m_mutex);
        auto it = m_scoped_txs.find(ScopeKey{scope, context_id});
        if (it != m_scoped_txs.end()) {
            out_txs = it->second.txs;
            if (out_root) {
                std::memcpy(out_root->begin(), it->second.subtree_a_root.data(), 32);
            }
            return;
        }
    }
    if (scope == ReconScope::LIVE_MEMPOOL && m_relay_epochs &&
        !context_id.IsNull()) {
        // A relay epoch: the transactions admitted within the
        // reconciliation window, not the whole mempool.
        if (auto window{m_relay_epochs->RelayReconSet(context_id)}) {
            out_txs = NormalizeCtorTxList(*window);
            if (out_root) {
                const lotus::v2::Hash root = ComputeSubtreeAHash(out_txs);
                std::memcpy(out_root->begin(), root.data(), 32);
            }
            return;
        }
    }
    if (scope == ReconScope::LIVE_MEMPOOL) {
        std::vector<CTransactionRef> mempool_txs;
        {
            LOCK(m_mempool.cs);
            if (m_mempool.mapTx.size() <= MAX_SCOPED_TXS) {
                const auto &layer =
                    m_mempool.GetMerklixOverlay().GetSpeculativeOverlay();
                const auto &ordered = layer.GetOrderedTxs();
                out_txs.clear();
                out_txs.reserve(ordered.size());
                for (const auto &[_, oentry] : ordered) {
                    if (oentry.tx_ref) {
                        out_txs.push_back(
                            std::static_pointer_cast<const CTransaction>(
                                oentry.tx_ref));
                    }
                }
                if (out_txs.size() == m_mempool.mapTx.size()) {
                    if (out_root) {
                        const lotus::v2::Hash root = layer.GetSubtreeARoot();
                        std::memcpy(out_root->begin(), root.data(), 32);
                    }
                    return;
                }
            }
            mempool_txs.reserve(m_mempool.mapTx.size());
            for (const auto &entry : m_mempool.mapTx) {
                mempool_txs.push_back(entry->GetSharedTx());
            }
        }
        out_txs = NormalizeCtorTxList(mempool_txs);
        if (out_root) {
            const lotus::v2::Hash root = ComputeSubtreeAHash(out_txs);
            std::memcpy(out_root->begin(), root.data(), 32);
        }
        return;
    }
    out_txs.clear();
    if (out_root) {
        const lotus::v2::Hash empty_root = lotus::v2::EmptyTxRoot();
        std::memcpy(out_root->begin(), empty_root.data(), 32);
    }
}

std::vector<CTransactionRef> V2PeerProtocolHandler::GetScopedTransactions(
    ReconScope scope, const uint256 &context_id) const {
    std::vector<CTransactionRef> txs;
    // Bucket drill-down needs membership only, not a Merklix root.
    GetScopedTransactionsAndRoot(scope, context_id, txs, nullptr);
    return txs;
}

MerklixSyncSummary V2PeerProtocolHandler::BuildSyncSummary(
    ReconScope scope, const uint256 &context_id, uint64_t salt_k0,
    uint64_t salt_k1) const {
    if (salt_k0 == 0 && salt_k1 == 0) {
        std::tie(salt_k0, salt_k1) = DeriveReconSipHashKey(scope, context_id, 0);
    }
    MerklixSyncSummary summary;
    summary.scope = static_cast<uint8_t>(scope);
    summary.context_id = context_id;
    summary.salt_k0 = salt_k0;
    summary.salt_k1 = salt_k1;

    const std::vector<CTransactionRef> txs =
        GetScopedTransactions(scope, context_id);
    summary.candidate_root = ComputeScopedMerklixRoot(txs);
    for (const auto &tx : txs) {
        const TxId &txid = tx->GetId();
        const uint8_t b = GetMerklixBucketIndex(txid);
        const uint64_t sid =
            ScopedShortId(scope, context_id, salt_k0, salt_k1, txid);
        summary.buckets[b].count += 1;
        summary.buckets[b].xor_short_id ^= sid;
    }
    return summary;
}

MerklixSyncDiffResult V2PeerProtocolHandler::DiffSyncSummary(
    const MerklixSyncSummary &remote_summary) const {
    MerklixSyncDiffResult result;
    if (!IsValidReconScope(remote_summary.scope)) {
        return result;
    }
    const ReconScope scope = static_cast<ReconScope>(remote_summary.scope);
    const std::vector<CTransactionRef> local_txs =
        GetScopedTransactions(scope, remote_summary.context_id);

    const uint256 local_root = ComputeScopedMerklixRoot(local_txs);
    result.root_matched = (local_root == remote_summary.candidate_root);
    if (result.root_matched) {
        return result;
    }

    uint64_t k0 = remote_summary.salt_k0;
    uint64_t k1 = remote_summary.salt_k1;
    if (k0 == 0 && k1 == 0) {
        std::tie(k0, k1) =
            DeriveReconSipHashKey(scope, remote_summary.context_id, 0);
    }

    std::array<MerklixBucketEntry, 16> local_buckets{};
    std::array<std::unordered_set<uint64_t>, 16> local_bucket_sids{};
    for (const auto &tx : local_txs) {
        const TxId &txid = tx->GetId();
        const uint8_t b = GetMerklixBucketIndex(txid);
        const uint64_t sid =
            ScopedShortId(scope, remote_summary.context_id, k0, k1, txid);
        local_buckets[b].count += 1;
        local_buckets[b].xor_short_id ^= sid;
        local_bucket_sids[b].insert(sid);
    }

    // A peer can have missing transactions even when its bucket contains no
    // more entries than ours: local extras can balance or exceed those misses.
    // Count direction therefore cannot establish relay-window coverage.
    std::array<uint64_t, 16> local_extra_sids{};
    uint16_t local_extra_mask{0};
    for (uint8_t b = 0; b < 16; ++b) {
        const auto &rem = remote_summary.buckets[b];
        const auto &loc = local_buckets[b];
        const uint64_t diff_xor = rem.xor_short_id ^ loc.xor_short_id;
        const int64_t diff_count =
            static_cast<int64_t>(rem.count) - static_cast<int64_t>(loc.count);

        if (diff_xor == 0 && diff_count == 0) {
            continue;
        }

        // Count and XOR hints do not prove a one-element difference.
        if (diff_count == -1 && diff_xor != 0) {
            const bool in_local =
                local_bucket_sids[b].find(diff_xor) !=
                local_bucket_sids[b].end();
            // A +1 count and one XOR syndrome do not prove a single
            // missing transaction: larger balanced differences can produce
            // the same hint. Recover through the existing three-syndrome
            // sub-bucket exchange instead of terminating on an unowned ID.
            if (diff_count == -1 && in_local) {
                // This is a candidate local extra, not proof that other
                // differences are absent. Authenticate the subset root below.
                local_extra_sids[b] = diff_xor;
                local_extra_mask |= static_cast<uint16_t>(1U << b);
                continue;
            }
        }

        result.mismatched_bucket_mask |= static_cast<uint16_t>(1U << b);
    }

    // Defect D1 (Hole 1): Never treat a scope as converged when the 256-bit
    // candidate_root differs, even if all 16 64-bit bucket XORs/counts match.
    if (!result.root_matched &&
        result.mismatched_bucket_mask == 0 &&
        result.single_missing_short_ids.empty()) {
        // Relay windows can differ only by local extras. Avoid sixteen
        // response frames for that common case only if the captured local set
        // minus those candidates authenticates the peer's complete root.
        // Count/XOR hints alone cannot exclude hidden balanced differences.
        if (local_extra_mask != 0 &&
            IsRelayEpoch(scope, remote_summary.context_id, k0, k1)) {
            std::vector<CTransactionRef> remote_subset;
            remote_subset.reserve(local_txs.size());
            uint16_t removed_mask{0};
            bool ambiguous_short_id{false};
            for (const auto &tx : local_txs) {
                const uint8_t bucket{GetMerklixBucketIndex(tx->GetId())};
                if ((local_extra_mask & (1U << bucket)) != 0 &&
                    ScopedShortId(scope, remote_summary.context_id, k0, k1,
                                  tx->GetId()) == local_extra_sids[bucket]) {
                    const uint16_t bit{static_cast<uint16_t>(1U << bucket)};
                    ambiguous_short_id |= (removed_mask & bit) != 0;
                    removed_mask |= bit;
                    continue;
                }
                remote_subset.push_back(tx);
            }
            if (!ambiguous_short_id &&
                ComputeScopedMerklixRoot(remote_subset) ==
                    remote_summary.candidate_root) {
                return result;
            }
        }
        result.mismatched_bucket_mask = 0xFFFFU;
    }

    return result;
}

MerklixSubBucketSummary V2PeerProtocolHandler::BuildSubBucketSummary(
    ReconScope scope, const uint256 &context_id, uint64_t salt_k0,
    uint64_t salt_k1, uint8_t parent_bucket) const {
    return BuildSubBucketSummary(scope, context_id, salt_k0, salt_k1,
                                 static_cast<uint16_t>(parent_bucket & 0x0f),
                                 /*depth_bits=*/8);
}

MerklixSubBucketSummary V2PeerProtocolHandler::BuildSubBucketSummary(
    ReconScope scope, const uint256 &context_id, uint64_t salt_k0,
    uint64_t salt_k1, uint16_t parent_prefix, uint8_t depth_bits) const {
    if (salt_k0 == 0 && salt_k1 == 0) {
        std::tie(salt_k0, salt_k1) = DeriveReconSipHashKey(scope, context_id, 0);
    }
    if (depth_bits != 8 && depth_bits != 12 && depth_bits != 16) {
        depth_bits = 8;
    }
    const uint8_t parent_bits = static_cast<uint8_t>(depth_bits - 4);
    const uint16_t prefix_mask =
        static_cast<uint16_t>((1U << parent_bits) - 1U);
    const uint16_t masked_prefix = parent_prefix & prefix_mask;
    const uint8_t child_nibble_idx = static_cast<uint8_t>((depth_bits >> 2) - 1);

    MerklixSubBucketSummary sub;
    sub.scope = static_cast<uint8_t>(scope);
    sub.context_id = context_id;
    sub.salt_k0 = salt_k0;
    sub.salt_k1 = salt_k1;
    sub.depth_bits = depth_bits;
    sub.parent_prefix = masked_prefix;
    sub.parent_bucket =
        static_cast<uint8_t>((masked_prefix >> (parent_bits - 4)) & 0x0f);

    const std::vector<CTransactionRef> txs =
        GetScopedTransactions(scope, context_id);
    for (const auto &tx : txs) {
        const TxId &txid = tx->GetId();
        if (GetMerklixPrefix(txid, parent_bits) != masked_prefix) {
            continue;
        }
        const uint8_t sb = GetMerklixNibble(txid, child_nibble_idx);
        const uint64_t sid =
            ScopedShortId(scope, context_id, salt_k0, salt_k1, txid);
        sub.sub_buckets[sb].count += 1;
        sub.sub_buckets[sb].s1 ^= sid;
        sub.sub_buckets[sb].s3 ^= GF64Cube(sid);
        sub.sub_buckets[sb].s5 ^= GF64Pow5(sid);
        if (depth_bits == 16 &&
            sub.overflow_short_ids.size() < ShortTxRequest::MAX_SHORT_IDS) {
            sub.overflow_short_ids.push_back(sid);
        }
    }
    if (!sub.overflow_short_ids.empty()) {
        std::sort(sub.overflow_short_ids.begin(), sub.overflow_short_ids.end());
        sub.overflow_short_ids.erase(std::unique(sub.overflow_short_ids.begin(),
                                                 sub.overflow_short_ids.end()),
                                     sub.overflow_short_ids.end());
    }
    return sub;
}

MerklixSubBucketDiffResult V2PeerProtocolHandler::DiffSubBucketSummary(
    const MerklixSubBucketSummary &remote_sub) const {
    MerklixSubBucketDiffResult result;
    const uint8_t depth_bits =
        remote_sub.depth_bits == 0 ? 8 : remote_sub.depth_bits;
    if (!IsValidReconScope(remote_sub.scope) ||
        remote_sub.parent_bucket >= 16 ||
        (depth_bits != 8 && depth_bits != 12 && depth_bits != 16) ||
        remote_sub.overflow_short_ids.size() > ShortTxRequest::MAX_SHORT_IDS) {
        return result;
    }

    const uint8_t parent_bits = static_cast<uint8_t>(depth_bits - 4);
    const uint16_t max_parent_prefix = static_cast<uint16_t>(1U << parent_bits);
    if (remote_sub.parent_prefix >= max_parent_prefix) {
        return result;
    }
    const uint16_t effective_parent_prefix =
        (depth_bits == 8 &&
         (remote_sub.parent_bucket != 0 || remote_sub.parent_prefix == 0))
            ? static_cast<uint16_t>(remote_sub.parent_bucket)
            : remote_sub.parent_prefix;
    const uint8_t child_nibble_idx = static_cast<uint8_t>((depth_bits >> 2) - 1);

    const ReconScope scope = static_cast<ReconScope>(remote_sub.scope);
    const std::vector<CTransactionRef> local_txs =
        GetScopedTransactions(scope, remote_sub.context_id);

    uint64_t k0 = remote_sub.salt_k0;
    uint64_t k1 = remote_sub.salt_k1;
    if (k0 == 0 && k1 == 0) {
        std::tie(k0, k1) =
            DeriveReconSipHashKey(scope, remote_sub.context_id, 0);
    }

    std::array<MerklixSubBucketEntry, 16> local_subs{};
    std::array<std::unordered_set<uint64_t>, 16> local_sub_sids{};
    std::unordered_set<uint64_t> local_prefix_sids;
    for (const auto &tx : local_txs) {
        const TxId &txid = tx->GetId();
        if (GetMerklixPrefix(txid, parent_bits) != effective_parent_prefix) {
            continue;
        }
        const uint8_t sb = GetMerklixNibble(txid, child_nibble_idx);
        const uint64_t sid =
            ScopedShortId(scope, remote_sub.context_id, k0, k1, txid);
        local_subs[sb].count += 1;
        local_subs[sb].s1 ^= sid;
        local_subs[sb].s3 ^= GF64Cube(sid);
        local_subs[sb].s5 ^= GF64Pow5(sid);
        local_sub_sids[sb].insert(sid);
        local_prefix_sids.insert(sid);
    }

    bool use_terminal_overflow_fallback = false;
    for (uint8_t sb = 0; sb < 16; ++sb) {
        const auto &rem = remote_sub.sub_buckets[sb];
        const auto &loc = local_subs[sb];
        const uint64_t delta_s1 = rem.s1 ^ loc.s1;
        const uint64_t delta_s3 = rem.s3 ^ loc.s3;
        const uint64_t delta_s5 = rem.s5 ^ loc.s5;
        if (delta_s1 == 0 && delta_s3 == 0 && delta_s5 == 0 &&
            rem.count == loc.count) {
            continue;
        }

        auto recovered = RecoverGF64Syndromes(delta_s1, delta_s3, delta_s5);
        if (!recovered.has_value()) {
            if (depth_bits == 16 && !remote_sub.overflow_short_ids.empty()) {
                use_terminal_overflow_fallback = true;
            } else {
                result.unresolved_sub_buckets.push_back(sb);
            }
            continue;
        }

        // Verify recovered symmetric difference is consistent with count delta:
        size_t num_in_local = 0;
        size_t num_missing = 0;
        for (const uint64_t sid : *recovered) {
            if (local_sub_sids[sb].find(sid) != local_sub_sids[sb].end()) {
                ++num_in_local;
            } else {
                ++num_missing;
            }
        }
        const int64_t expected_diff =
            static_cast<int64_t>(num_missing) -
            static_cast<int64_t>(num_in_local);
        const int64_t actual_diff =
            static_cast<int64_t>(rem.count) - static_cast<int64_t>(loc.count);
        if (expected_diff != actual_diff) {
            if (depth_bits == 16 && !remote_sub.overflow_short_ids.empty()) {
                use_terminal_overflow_fallback = true;
            } else {
                result.unresolved_sub_buckets.push_back(sb);
            }
            continue;
        }

        for (const uint64_t sid : *recovered) {
            if (local_sub_sids[sb].find(sid) == local_sub_sids[sb].end()) {
                result.missing_short_ids.push_back(sid);
            }
        }
    }

    if (use_terminal_overflow_fallback) {
        for (const uint64_t sid : remote_sub.overflow_short_ids) {
            if (sid != 0 &&
                local_prefix_sids.find(sid) == local_prefix_sids.end() &&
                std::find(result.missing_short_ids.begin(),
                          result.missing_short_ids.end(),
                          sid) == result.missing_short_ids.end()) {
                result.missing_short_ids.push_back(sid);
            }
        }
    }

    return result;
}

std::vector<CTransactionRef> V2PeerProtocolHandler::ResolveShortIds(
    ReconScope scope, const uint256 &context_id, uint64_t salt_k0,
    uint64_t salt_k1, const std::vector<uint64_t> &short_ids) const {
    if (short_ids.empty()) {
        return {};
    }
    if (salt_k0 == 0 && salt_k1 == 0) {
        std::tie(salt_k0, salt_k1) = DeriveReconSipHashKey(scope, context_id, 0);
    }
    const std::vector<CTransactionRef> local_txs =
        GetScopedTransactions(scope, context_id);
    std::unordered_map<uint64_t, CTransactionRef> by_sid;
    by_sid.reserve(local_txs.size());
    for (const auto &tx : local_txs) {
        const uint64_t sid =
            ComputeMerklixShortId(salt_k0, salt_k1, tx->GetId());
        by_sid.emplace(sid, tx);
    }

    std::vector<CTransactionRef> resolved;
    resolved.reserve(short_ids.size());
    for (const uint64_t sid : short_ids) {
        auto it = by_sid.find(sid);
        if (it != by_sid.end()) {
            resolved.push_back(it->second);
        }
    }
    return resolved;
}

void V2PeerProtocolHandler::RecordPendingShortTxRequest(
    NodeId peer_id, ReconScope scope, const uint256 &context_id,
    uint64_t salt_k0, uint64_t salt_k1,
    const std::vector<uint64_t> &short_ids) {
    if (short_ids.empty()) {
        return;
    }
    if (salt_k0 == 0 && salt_k1 == 0) {
        std::tie(salt_k0, salt_k1) = DeriveReconSipHashKey(scope, context_id, 0);
    }

    LOCK(m_mutex);
    const PendingShortTxKey key{peer_id, scope, context_id};
    if (m_pending_shorttx_requests.find(key) ==
            m_pending_shorttx_requests.end() &&
        m_pending_shorttx_requests.size() >= MAX_TRACKED_RECON_SCOPES) {
        m_pending_shorttx_requests.erase(m_pending_shorttx_requests.begin());
    }
    PendingShortTxEntry &entry = m_pending_shorttx_requests[key];
    entry.salt_k0 = salt_k0;
    entry.salt_k1 = salt_k1;
    for (const uint64_t sid : short_ids) {
        if (entry.requested_short_ids.size() < MAX_SCOPED_TXS) {
            entry.requested_short_ids.insert(sid);
        }
    }
}

bool V2PeerProtocolHandler::HasPendingShortTxRequests(NodeId peer_id) const {
    LOCK(m_mutex);
    for (const auto &[key, entry] : m_pending_shorttx_requests) {
        if (key.peer_id == peer_id && !entry.requested_short_ids.empty()) {
            return true;
        }
    }
    return false;
}

void V2PeerProtocolHandler::SetHighBandwidthShortTxPeer(NodeId peer_id,
                                                        bool enabled) {
    LOCK(m_mutex);
    if (enabled) {
        m_high_bandwidth_shorttx_peers.insert(peer_id);
    } else {
        m_high_bandwidth_shorttx_peers.erase(peer_id);
    }
}

bool V2PeerProtocolHandler::IsHighBandwidthShortTxPeer(NodeId peer_id) const {
    LOCK(m_mutex);
    return m_high_bandwidth_shorttx_peers.count(peer_id) > 0;
}

void V2PeerProtocolHandler::RemovePeer(NodeId peer_id) {
    LOCK(m_mutex);
    for (auto it = m_pending_shorttx_requests.begin();
         it != m_pending_shorttx_requests.end();) {
        if (it->first.peer_id == peer_id) {
            it = m_pending_shorttx_requests.erase(it);
        } else {
            ++it;
        }
    }
    m_high_bandwidth_shorttx_peers.erase(peer_id);
    m_peer_rates.erase(peer_id);
    m_peer_shorttx_windows.erase(peer_id);
    m_peer_shard_windows.erase(peer_id);
    m_peer_relay_windows.erase(peer_id);
    m_peer_window_start.erase(peer_id);
    m_peer_msg_counts.erase(peer_id);
    m_peer_known_blocks.erase(peer_id);
    m_peer_nodes.erase(peer_id);
    m_peer_services.erase(peer_id);
    if (m_swarm.state == FastSyncSwarmState::FETCHING_ROOTS ||
        m_swarm.state == FastSyncSwarmState::FETCHING_SHARDS ||
        m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING) {
        HandleSwarmPeerFailureLocked(peer_id, std::nullopt);
    }
}

void V2PeerProtocolHandler::RemovePeer(CNode &pnode) {
    pnode.m_bip152_highbandwidth_to.store(false);
    pnode.m_bip152_highbandwidth_from.store(false);
    RemovePeer(pnode.GetId());
}

void V2PeerProtocolHandler::RecordPeerKnownBlock(NodeId peer_id,
                                                 const BlockHash &block_hash) {
    LOCK(m_mutex);
    m_peer_known_blocks[peer_id] = block_hash;
}

bool V2PeerProtocolHandler::PeerKnowsBlock(NodeId peer_id,
                                           const BlockHash &block_hash) const {
    LOCK(m_mutex);
    auto it = m_peer_known_blocks.find(peer_id);
    return it != m_peer_known_blocks.end() && it->second == block_hash;
}

std::optional<BlockHash>
V2PeerProtocolHandler::GetLastPeerKnownBlock(NodeId peer_id) const {
    LOCK(m_mutex);
    auto it = m_peer_known_blocks.find(peer_id);
    if (it == m_peer_known_blocks.end()) {
        return std::nullopt;
    }
    return it->second;
}

void V2PeerProtocolHandler::HandleMerklixSync(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
        return;
    }

    MerklixSyncSummary summary;
    try {
        vRecv >> summary;
    } catch (const std::exception &) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    if (!IsValidReconScope(summary.scope)) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const ReconScope scope = static_cast<ReconScope>(summary.scope);
    if ((summary.salt_k0 != 0 || summary.salt_k1 != 0) &&
        !IsValidReconSipHashKey(scope, summary.context_id, summary.salt_k0,
                                summary.salt_k1) &&
        !IsRelayEpoch(scope, summary.context_id, summary.salt_k0,
                      summary.salt_k1)) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }
    if (summary.salt_k0 == 0 && summary.salt_k1 == 0) {
        std::tie(summary.salt_k0, summary.salt_k1) =
            DeriveReconSipHashKey(scope, summary.context_id, 0);
    }

    {
        LOCK(m_mutex);
        ++m_stats.merklixsync_received;
    }

    MerklixSyncDiffResult diff = DiffSyncSummary(summary);
    if (auto *metrics{node::GetNodeMetrics()}) {
        metrics->merklix_rounds.Add(diff.root_matched ? 0 : 1);
        if (!diff.single_missing_short_ids.empty()) {
            metrics->merklix_differences.Record(
                diff.single_missing_short_ids.size(), 0);
        }
    }
    if (diff.root_matched) {
        return;
    }
    FilterRelayHave(pfrom, scope, summary.context_id, summary.salt_k0,
                    summary.salt_k1, diff.single_missing_short_ids);

    if (!diff.single_missing_short_ids.empty()) {
        RecordPendingShortTxRequest(pfrom.GetId(), scope, summary.context_id,
                                    summary.salt_k0, summary.salt_k1,
                                    diff.single_missing_short_ids);
        ShortTxRequest req;
        req.scope = summary.scope;
        req.context_id = summary.context_id;
        req.salt_k0 = summary.salt_k0;
        req.salt_k1 = summary.salt_k1;
        req.short_ids = diff.single_missing_short_ids;
        m_connman.PushMessage(&pfrom,
                              NetMsg::Make(NetMsgType::GETSHORTTX, req));
    }

    if (diff.mismatched_bucket_mask != 0) {
        MerklixBucketRequest buck_req;
        buck_req.scope = summary.scope;
        buck_req.context_id = summary.context_id;
        buck_req.salt_k0 = summary.salt_k0;
        buck_req.salt_k1 = summary.salt_k1;
        buck_req.bucket_mask = diff.mismatched_bucket_mask;
        buck_req.depth_bits = 4;
        buck_req.parent_prefix = 0;
        m_connman.PushMessage(
            &pfrom, NetMsg::Make(NetMsgType::GETMERKLIXBUCK, buck_req));
    }
}

void V2PeerProtocolHandler::HandleGetMerklixBuck(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
        return;
    }

    MerklixBucketRequest req;
    try {
        vRecv >> req;
    } catch (const std::exception &) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const uint8_t req_depth = req.depth_bits == 0 ? 4 : req.depth_bits;
    if (!IsValidReconScope(req.scope) || req.bucket_mask == 0 ||
        (req_depth != 4 && req_depth != 8 && req_depth != 12) ||
        (req_depth == 4 && req.parent_prefix != 0) ||
        (req_depth > 4 && req.parent_prefix >= (1U << (req_depth - 4)))) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const ReconScope scope = static_cast<ReconScope>(req.scope);
    if ((req.salt_k0 != 0 || req.salt_k1 != 0) &&
        !IsValidReconSipHashKey(scope, req.context_id, req.salt_k0,
                                req.salt_k1) &&
        !IsRelayEpoch(scope, req.context_id, req.salt_k0, req.salt_k1)) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }
    if (req.salt_k0 == 0 && req.salt_k1 == 0) {
        std::tie(req.salt_k0, req.salt_k1) =
            DeriveReconSipHashKey(scope, req.context_id, 0);
    }

    {
        LOCK(m_mutex);
        ++m_stats.getmerklixbuck_received;
    }

    const uint8_t child_depth = static_cast<uint8_t>(req_depth + 4);
    for (uint8_t b = 0; b < 16; ++b) {
        if ((req.bucket_mask & (1U << b)) == 0) {
            continue;
        }
        const uint16_t child_parent_prefix =
            req_depth == 4
                ? static_cast<uint16_t>(b)
                : static_cast<uint16_t>((req.parent_prefix << 4) | b);
        MerklixSubBucketSummary sub = BuildSubBucketSummary(
            scope, req.context_id, req.salt_k0, req.salt_k1,
            child_parent_prefix, child_depth);
        m_connman.PushMessage(&pfrom,
                              NetMsg::Make(NetMsgType::MERKLIXBUCK, sub));
    }
}

void V2PeerProtocolHandler::HandleMerklixBuck(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
        return;
    }

    MerklixSubBucketSummary sub;
    try {
        vRecv >> sub;
    } catch (const std::exception &) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const uint8_t depth_bits = sub.depth_bits == 0 ? 8 : sub.depth_bits;
    if (!IsValidReconScope(sub.scope) || sub.parent_bucket >= 16 ||
        (depth_bits != 8 && depth_bits != 12 && depth_bits != 16) ||
        sub.parent_prefix >= (1U << (depth_bits - 4)) ||
        sub.overflow_short_ids.size() > ShortTxRequest::MAX_SHORT_IDS) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const ReconScope scope = static_cast<ReconScope>(sub.scope);
    if ((sub.salt_k0 != 0 || sub.salt_k1 != 0) &&
        !IsValidReconSipHashKey(scope, sub.context_id, sub.salt_k0,
                                sub.salt_k1) &&
        !IsRelayEpoch(scope, sub.context_id, sub.salt_k0, sub.salt_k1)) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }
    if (sub.salt_k0 == 0 && sub.salt_k1 == 0) {
        std::tie(sub.salt_k0, sub.salt_k1) =
            DeriveReconSipHashKey(scope, sub.context_id, 0);
    }

    {
        LOCK(m_mutex);
        ++m_stats.merklixbuck_received;
    }

    MerklixSubBucketDiffResult diff = DiffSubBucketSummary(sub);
    if (auto *metrics{node::GetNodeMetrics()}) {
        const bool matched{diff.missing_short_ids.empty() &&
                           diff.unresolved_sub_buckets.empty()};
        metrics->merklix_rounds.Add(2 + (matched ? 0 : 1));
        if (!diff.missing_short_ids.empty()) {
            metrics->merklix_differences.Record(diff.missing_short_ids.size(),
                                                1);
        }
        if (!diff.unresolved_sub_buckets.empty()) {
            metrics->merklix_overflows.Add(0,
                                           diff.unresolved_sub_buckets.size());
        }
    }
    FilterRelayHave(pfrom, scope, sub.context_id, sub.salt_k0, sub.salt_k1,
                    diff.missing_short_ids);
    if (!diff.missing_short_ids.empty()) {
        RecordPendingShortTxRequest(pfrom.GetId(), scope, sub.context_id,
                                    sub.salt_k0, sub.salt_k1,
                                    diff.missing_short_ids);
        ShortTxRequest req;
        req.scope = sub.scope;
        req.context_id = sub.context_id;
        req.salt_k0 = sub.salt_k0;
        req.salt_k1 = sub.salt_k1;
        req.short_ids = diff.missing_short_ids;
        m_connman.PushMessage(&pfrom,
                              NetMsg::Make(NetMsgType::GETSHORTTX, req));
    }

    if (!diff.unresolved_sub_buckets.empty() &&
        IsRelayEpoch(scope, sub.context_id, sub.salt_k0, sub.salt_k1)) {
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->txrelay_recon_overflow.Add(
                0, diff.unresolved_sub_buckets.size());
        }
    }

    // Multi-depth prefix bisection for d >= 3 sub-bucket overflows:
    // depth 8 -> request depth 12; depth 12 -> request depth 16.
    if (!diff.unresolved_sub_buckets.empty() && depth_bits < 16) {
        uint16_t unresolved_mask = 0;
        for (const uint8_t sb : diff.unresolved_sub_buckets) {
            if (sb < 16) {
                unresolved_mask |= static_cast<uint16_t>(1U << sb);
            }
        }
        if (unresolved_mask != 0) {
            const uint16_t effective_parent_prefix =
                (depth_bits == 8 &&
                 (sub.parent_bucket != 0 || sub.parent_prefix == 0))
                    ? static_cast<uint16_t>(sub.parent_bucket)
                    : sub.parent_prefix;
            MerklixBucketRequest bisected_req;
            bisected_req.scope = sub.scope;
            bisected_req.context_id = sub.context_id;
            bisected_req.salt_k0 = sub.salt_k0;
            bisected_req.salt_k1 = sub.salt_k1;
            bisected_req.bucket_mask = unresolved_mask;
            bisected_req.depth_bits = depth_bits;
            bisected_req.parent_prefix = effective_parent_prefix;
            m_connman.PushMessage(
                &pfrom,
                NetMsg::Make(NetMsgType::GETMERKLIXBUCK, bisected_req));
        }
    }
}

void V2PeerProtocolHandler::HandleGetShortTx(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    ShortTxRequest req;
    try {
        vRecv >> req;
    } catch (const std::exception &) {
        if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
            return;
        }
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    const bool relay_epoch{IsValidReconScope(req.scope) &&
                           IsRelayEpoch(static_cast<ReconScope>(req.scope),
                                        req.context_id, req.salt_k0,
                                        req.salt_k1)};
    if (!(relay_epoch ? CheckPeerRelayRateLimit(pfrom.GetId(), time_received)
                      : CheckPeerRateLimit(pfrom.GetId(), time_received))) {
        return;
    }

    if (!IsValidReconScope(req.scope) || req.short_ids.empty() ||
        req.short_ids.size() > ShortTxRequest::MAX_SHORT_IDS) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    if (relay_epoch) {
        // Nucleation relay: answer from the relay index (O(request)).
        {
            LOCK(m_mutex);
            ++m_stats.getshorttx_received;
        }
        std::vector<CTransactionRef> resolved{
            m_relay_epochs->ResolveRelayShortIds(req.context_id,
                                                 req.short_ids)};
        if (!resolved.empty()) {
            ShortTxResponse resp;
            resp.scope = req.scope;
            resp.context_id = req.context_id;
            resp.txs = std::move(resolved);
            m_connman.PushMessage(&pfrom,
                                  NetMsg::Make(NetMsgType::SHORTTX, resp));
        }
        return;
    }

    const ReconScope scope = static_cast<ReconScope>(req.scope);
    if ((req.salt_k0 != 0 || req.salt_k1 != 0) &&
        !IsValidReconSipHashKey(scope, req.context_id, req.salt_k0,
                                req.salt_k1)) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }
    if (req.salt_k0 == 0 && req.salt_k1 == 0) {
        std::tie(req.salt_k0, req.salt_k1) =
            DeriveReconSipHashKey(scope, req.context_id, 0);
    }

    {
        LOCK(m_mutex);
        ++m_stats.getshorttx_received;
    }

    std::vector<CTransactionRef> resolved = ResolveShortIds(
        scope, req.context_id, req.salt_k0, req.salt_k1, req.short_ids);
    if (!resolved.empty()) {
        ShortTxResponse resp;
        resp.scope = req.scope;
        resp.context_id = req.context_id;
        resp.txs = std::move(resolved);
        m_connman.PushMessage(&pfrom, NetMsg::Make(NetMsgType::SHORTTX, resp));
    }
}

void V2PeerProtocolHandler::HandleShortTx(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    ShortTxResponse resp;
    try {
        vRecv >> resp;
    } catch (const std::exception &) {
        if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
            return;
        }
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    // Responses to relay-epoch requests come every tick: their own limit.
    const bool relay_epoch{
        resp.scope == static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL) &&
        m_relay_epochs && !resp.context_id.IsNull() &&
        m_relay_epochs->RelayEpochKey(resp.context_id).has_value()};
    if (!(relay_epoch ? CheckPeerRelayRateLimit(pfrom.GetId(), time_received)
                      : CheckPeerRateLimit(pfrom.GetId(), time_received))) {
        return;
    }

    if (!IsValidReconScope(resp.scope) || resp.txs.empty() ||
        resp.txs.size() > ShortTxResponse::MAX_TXS) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    for (const auto &tx : resp.txs) {
        if (!tx || tx->IsNull() || tx->IsCoinBase()) {
            LOCK(m_mutex);
            ++m_stats.malformed_messages;
            return;
        }
    }

    const ReconScope scope = static_cast<ReconScope>(resp.scope);
    const bool high_bandwidth_opt_in = WITH_LOCK(
        m_mutex,
        return pfrom.m_bip152_highbandwidth_to.load() ||
               pfrom.m_bip152_highbandwidth_from.load() ||
               m_high_bandwidth_shorttx_peers.count(pfrom.GetId()) > 0 ||
               pfrom.HasPermission(NetPermissionFlags::Relay) ||
               gArgs.GetBoolArg("-highbandwidthtx", false));
    if (relay_epoch) {
        // Relay requests already live in the ordinary request tracker. A
        // second 4096-ID set cannot represent all requests outstanding in it.
        auto selected{m_peerman.FilterRequestedShortTxResponse(
            pfrom.GetId(), resp.context_id, resp.txs, high_bandwidth_opt_in)};
        {
            LOCK(m_mutex);
            if (selected.empty()) {
                ++m_stats.unsolicited_shorttx;
                ++m_stats.unsolicited_shorttx_dropped;
                return;
            }
            ++m_stats.shorttx_received;
        }
        m_peerman.ProcessShortTxResponse(pfrom, selected);
        return;
    }

    std::vector<CTransactionRef> solicited_txs;
    {
        LOCK(m_mutex);
        const PendingShortTxKey key{pfrom.GetId(), scope, resp.context_id};
        auto it = m_pending_shorttx_requests.find(key);
        if (it != m_pending_shorttx_requests.end() &&
            !it->second.requested_short_ids.empty()) {
            solicited_txs.reserve(resp.txs.size());
            for (const auto &tx : resp.txs) {
                const uint64_t sid =
                    ScopedShortId(scope, resp.context_id, it->second.salt_k0,
                                  it->second.salt_k1, tx->GetId());
                // Receiving one requested body does not revoke opt-in for
                // the other bodies in the same high-bandwidth response.
                if (it->second.requested_short_ids.erase(sid) > 0 ||
                    high_bandwidth_opt_in) {
                    solicited_txs.push_back(tx);
                }
            }
            if (it->second.requested_short_ids.empty()) {
                m_pending_shorttx_requests.erase(it);
            }
            if (solicited_txs.empty() && !high_bandwidth_opt_in) {
                ++m_stats.unsolicited_shorttx;
                ++m_stats.unsolicited_shorttx_dropped;
                return;
            }
        } else if (high_bandwidth_opt_in) {
            solicited_txs = resp.txs;
        } else {
            ++m_stats.unsolicited_shorttx;
            ++m_stats.unsolicited_shorttx_dropped;
            return;
        }

        if (solicited_txs.empty()) {
            solicited_txs = resp.txs;
        }
        ++m_stats.shorttx_received;
    }

    // Defect D2: Validate each transaction via ProcessRawTxBatch /
    // ProcessTransaction (or check m_mempool) BEFORE inserting into
    // m_scoped_txs so invalid transactions never pollute reconciliation state!
    std::vector<CTransactionRef> valid_txs;
    std::vector<CTransactionRef> accepted_txs;
    std::vector<CTransactionRef> missing_txs;
    valid_txs.reserve(solicited_txs.size());
    missing_txs.reserve(solicited_txs.size());
    {
        LOCK(cs_main);
        std::unordered_set<TxId, SaltedTxIdHasher> seen_missing;
        seen_missing.reserve(solicited_txs.size());
        for (const auto &tx : solicited_txs) {
            const TxId &txid = tx->GetId();
            if (m_mempool.exists(txid)) {
                valid_txs.push_back(tx);
            } else if (seen_missing.insert(txid).second) {
                missing_txs.push_back(tx);
            }
        }

        if (!missing_txs.empty()) {
            // Topologically sort missing_txs so any in-batch parents precede
            // their children before calling ProcessRawTxBatch.
            if (missing_txs.size() > 1) {
                std::unordered_map<TxId, size_t, SaltedTxIdHasher> txid_to_idx;
                txid_to_idx.reserve(missing_txs.size());
                for (size_t i = 0; i < missing_txs.size(); ++i) {
                    txid_to_idx.emplace(missing_txs[i]->GetId(), i);
                }
                std::vector<std::vector<size_t>> children(missing_txs.size());
                std::vector<size_t> in_degree(missing_txs.size(), 0);
                bool has_internal_deps = false;
                for (size_t i = 0; i < missing_txs.size(); ++i) {
                    for (const auto &in : missing_txs[i]->vin) {
                        auto it = txid_to_idx.find(in.prevout.GetTxId());
                        if (it != txid_to_idx.end() && it->second != i) {
                            children[it->second].push_back(i);
                            ++in_degree[i];
                            has_internal_deps = true;
                        }
                    }
                }
                if (has_internal_deps) {
                    std::vector<CTransactionRef> sorted;
                    sorted.reserve(missing_txs.size());
                    std::vector<uint8_t> placed(missing_txs.size(), 0);
                    bool progress = true;
                    while (progress && sorted.size() < missing_txs.size()) {
                        progress = false;
                        for (size_t i = 0; i < missing_txs.size(); ++i) {
                            if (!placed[i] && in_degree[i] == 0) {
                                placed[i] = 1;
                                sorted.push_back(missing_txs[i]);
                                for (const size_t child_idx : children[i]) {
                                    if (in_degree[child_idx] > 0) {
                                        --in_degree[child_idx];
                                    }
                                }
                                progress = true;
                            }
                        }
                    }
                    for (size_t i = 0; i < missing_txs.size(); ++i) {
                        if (!placed[i]) {
                            sorted.push_back(missing_txs[i]);
                        }
                    }
                    missing_txs = std::move(sorted);
                }
            }

            accepted_txs.reserve(missing_txs.size());
            const PackageMempoolAcceptResult batch_res = ProcessRawTxBatch(
                m_chainman.ActiveChainstate(), m_mempool, missing_txs,
                /*test_accept=*/false);
            if (batch_res.m_state.IsValid()) {
                for (const auto &tx : missing_txs) {
                    const TxId &txid = tx->GetId();
                    if (m_mempool.exists(txid)) {
                        valid_txs.push_back(tx);
                        accepted_txs.push_back(tx);
                    }
                }
            } else {
                // Per-tx fallback when a SHORTTX batch contains an invalid or
                // conflicting transaction so valid transactions in the batch
                // are still admitted.
                for (const auto &tx : missing_txs) {
                    const TxId &txid = tx->GetId();
                    if (m_mempool.exists(txid)) {
                        valid_txs.push_back(tx);
                        accepted_txs.push_back(tx);
                        continue;
                    }
                    const MempoolAcceptResult res =
                        m_chainman.ProcessTransaction(tx, /*test_accept=*/false);
                    if (res.m_result_type ==
                        MempoolAcceptResult::ResultType::VALID) {
                        valid_txs.push_back(tx);
                        accepted_txs.push_back(tx);
                    }
                }
            }
        }
    }

    m_peerman.MarkPeerKnownTxBatch(pfrom.GetId(), valid_txs);

    // The live mempool (null or relay-epoch context) is not a scoped set.
    if (!valid_txs.empty() && !relay_epoch &&
        !(scope == ReconScope::LIVE_MEMPOOL && resp.context_id.IsNull())) {
        std::vector<CTransactionRef> merged =
            GetScopedTransactions(scope, resp.context_id);
        merged.insert(merged.end(), valid_txs.begin(), valid_txs.end());
        SetScopedTransactions(scope, resp.context_id, std::move(merged));
    }

    m_peerman.RelayTransactionBatch(accepted_txs);
}

V2ProtocolHandlerStats V2PeerProtocolHandler::GetStats() const {
    LOCK(m_mutex);
    return m_stats;
}

std::optional<CInv> V2PeerProtocolHandler::GetLastFallbackInv() const {
    LOCK(m_mutex);
    return m_last_fallback_inv;
}

bool V2PeerProtocolHandler::SendRawPayloadToPeerLocked(
    NodeId peer_id, const char *msg_type, Span<const uint8_t> payload) {
    AssertLockHeld(m_mutex);
    bool sent = m_connman.ForNode(peer_id, [&](CNode *pnode) {
        m_connman.PushMessage(pnode, NetMsg::Make(msg_type, payload));
        return true;
    });
    if (!sent) {
        auto it = m_peer_nodes.find(peer_id);
        if (it != m_peer_nodes.end() && it->second != nullptr) {
            m_connman.PushMessage(it->second, NetMsg::Make(msg_type, payload));
            sent = true;
        }
    }
    return sent;
}

bool V2PeerProtocolHandler::IsFastSyncBlockRequested(const BlockHash &hash) const {
    LOCK(m_mutex);
    return m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING &&
           hash == m_swarm.undo_in_flight_hash;
}

void V2PeerProtocolHandler::BlockDataReceived(const BlockHash &hash) {
    NodeId undo_peer = -1;
    std::vector<uint8_t> payload;
    {
        LOCK(m_mutex);
        if (m_swarm.state != FastSyncSwarmState::PIVOT_ACTIVE_PEELING ||
            hash != m_swarm.undo_in_flight_hash ||
            !m_swarm.pending_undo_for_block) {
            return;
        }
        std::string err;
        if (!lotus::v2::EncodeBlockUndoMessage(*m_swarm.pending_undo_for_block,
                                               payload, err)) {
            return;
        }
        undo_peer = m_swarm.pending_undo_peer;
    }
    // Retain attribution to the undo supplier even if a different peer sent
    // the body. Reuse the same authenticated reverse-validation path.
    auto resume = [&](CNode *node) {
        DataStream stream{payload};
        HandleBlockUndo(*node, stream, GetTime<std::chrono::microseconds>());
        return true;
    };
    if (!m_connman.ForNode(undo_peer, resume)) {
        CNode *node = nullptr;
        {
            LOCK(m_mutex);
            auto it = m_peer_nodes.find(undo_peer);
            if (it != m_peer_nodes.end()) node = it->second;
        }
        if (node) resume(node);
    }
}

void V2PeerProtocolHandler::CheckFastSyncTimeouts(
    NodeId peer_id, std::chrono::microseconds now) {
    LOCK(m_mutex);
    bool pending =
        (m_swarm.state == FastSyncSwarmState::FETCHING_ROOTS &&
         m_swarm.roots_in_flight_peer == peer_id) ||
        (m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING &&
         m_swarm.undo_in_flight_peer == peer_id);
    if (m_swarm.state == FastSyncSwarmState::FETCHING_SHARDS) {
        for (const auto &[key, supplier] : m_swarm.in_flight_shards) {
            if (supplier == peer_id) pending = true;
        }
    }
    auto deadline = m_swarm.request_deadlines.find(peer_id);
    if (!pending) {
        m_swarm.request_deadlines.erase(peer_id);
    } else if (deadline != m_swarm.request_deadlines.end() &&
               now >= deadline->second) {
        m_swarm.request_deadlines.erase(deadline);
        HandleSwarmPeerFailureLocked(peer_id, std::nullopt);
    }
}

bool V2PeerProtocolHandler::RequestSwarmRootsLocked() {
    AssertLockHeld(m_mutex);
    const lotus::v2::GetUtxoRootsRequest req{m_swarm.pivot_v2_id};
    const std::vector<uint8_t> payload =
        lotus::v2::EncodeGetUtxoRootsRequest(req);
    while (!m_swarm.healthy_peers.empty()) {
        const size_t idx = m_swarm.rr_cursor % m_swarm.healthy_peers.size();
        const NodeId peer_id = m_swarm.healthy_peers[idx];
        ++m_swarm.rr_cursor;
        if (SendRawPayloadToPeerLocked(peer_id, NetMsgType::GETUTXOROOTS,
                                       Span{payload})) {
            m_swarm.request_deadlines[peer_id] =
                GetTime<std::chrono::microseconds>() + 30s;
            m_swarm.roots_in_flight_peer = peer_id;
            return true;
        }
        m_swarm.healthy_peers.erase(m_swarm.healthy_peers.begin() +
                                    static_cast<std::ptrdiff_t>(idx));
    }
    m_swarm.roots_in_flight_peer = -1;
    return false;
}

void V2PeerProtocolHandler::DispatchPendingSwarmShardsLocked() {
    AssertLockHeld(m_mutex);
    while (!m_swarm.pending_shards.empty() && !m_swarm.healthy_peers.empty()) {
        const ShardKey key = m_swarm.pending_shards.front();
        m_swarm.pending_shards.pop_front();

        lotus::v2::GetUtxoShardRequest req{};
        req.pivot_block_id = m_swarm.pivot_v2_id;
        req.prefix_depth = key.prefix_depth;
        req.prefix_bits = key.prefix_bits;
        std::vector<uint8_t> payload;
        std::string err;
        if (!lotus::v2::EncodeGetUtxoShardRequest(req, payload, err)) {
            m_swarm.state = FastSyncSwarmState::FAILED;
            return;
        }

        bool dispatched = false;
        while (!m_swarm.healthy_peers.empty()) {
            const size_t idx = m_swarm.rr_cursor % m_swarm.healthy_peers.size();
            const NodeId peer_id = m_swarm.healthy_peers[idx];
            ++m_swarm.rr_cursor;
            if (SendRawPayloadToPeerLocked(peer_id, NetMsgType::GETUTXOSHARD,
                                           Span{payload})) {
                m_swarm.request_deadlines[peer_id] =
                    GetTime<std::chrono::microseconds>() + 30s;
                m_swarm.in_flight_shards[key] = peer_id;
                dispatched = true;
                break;
            }
            m_swarm.healthy_peers.erase(m_swarm.healthy_peers.begin() +
                                        static_cast<std::ptrdiff_t>(idx));
        }
        if (!dispatched) {
            m_swarm.pending_shards.push_front(key);
            break;
        }
    }
    if (m_swarm.healthy_peers.empty() &&
        (!m_swarm.pending_shards.empty() ||
         !m_swarm.in_flight_shards.empty())) {
        m_swarm.state = FastSyncSwarmState::FAILED;
    }
}

bool V2PeerProtocolHandler::RequestNextReversePeelBlockLocked(
    int target_height, const BlockHash &target_hash, bool need_block_data) {
    AssertLockHeld(m_mutex);
    if (target_height <= 0 || target_hash.IsNull()) {
        m_swarm.undo_in_flight_hash = BlockHash{};
        m_swarm.undo_in_flight_peer = -1;
        m_swarm.pending_undo_for_block.reset();
        m_swarm.state = FastSyncSwarmState::COMPLETED;
        return true;
    }

    lotus::v2::GetBlockUndoRequest req{};
    std::memcpy(req.block_id.data(), target_hash.begin(), 32);
    const std::vector<uint8_t> payload =
        lotus::v2::EncodeGetBlockUndoRequest(req);
    while (!m_swarm.healthy_peers.empty()) {
        const size_t idx = m_swarm.rr_cursor % m_swarm.healthy_peers.size();
        const NodeId peer_id = m_swarm.healthy_peers[idx];
        ++m_swarm.rr_cursor;
        if (SendRawPayloadToPeerLocked(peer_id, NetMsgType::GETBLOCKUNDO,
                                       Span{payload})) {
            if (need_block_data) {
                const std::vector<CInv> invs{CInv(MSG_BLOCK, target_hash)};
                bool sent_getdata =
                    m_connman.ForNode(peer_id, [&](CNode *pnode) {
                        m_connman.PushMessage(
                            pnode, NetMsg::Make(NetMsgType::GETDATA, invs));
                        return true;
                    });
                if (!sent_getdata) {
                    auto it = m_peer_nodes.find(peer_id);
                    if (it != m_peer_nodes.end() && it->second != nullptr) {
                        m_connman.PushMessage(
                            it->second,
                            NetMsg::Make(NetMsgType::GETDATA, invs));
                    }
                }
            }
            m_swarm.pending_undo_for_block.reset();
            m_swarm.request_deadlines[peer_id] =
                GetTime<std::chrono::microseconds>() + 30s;
            m_swarm.undo_in_flight_hash = target_hash;
            m_swarm.undo_in_flight_peer = peer_id;
            return true;
        }
        m_swarm.healthy_peers.erase(m_swarm.healthy_peers.begin() +
                                    static_cast<std::ptrdiff_t>(idx));
    }
    m_swarm.undo_in_flight_hash = BlockHash{};
    m_swarm.undo_in_flight_peer = -1;
    m_swarm.state = FastSyncSwarmState::FAILED;
    return false;
}

void V2PeerProtocolHandler::HandleSwarmPeerFailureLocked(
    NodeId peer_id, std::optional<ShardKey> failed_shard) {
    AssertLockHeld(m_mutex);
    m_swarm.banned_peers.insert(peer_id);
    auto it_hp = std::find(m_swarm.healthy_peers.begin(),
                           m_swarm.healthy_peers.end(), peer_id);
    if (it_hp != m_swarm.healthy_peers.end()) {
        const size_t old_size = m_swarm.healthy_peers.size();
        const size_t erased_idx = static_cast<size_t>(
            std::distance(m_swarm.healthy_peers.begin(), it_hp));
        const size_t next_idx = m_swarm.rr_cursor % old_size;
        m_swarm.healthy_peers.erase(it_hp);
        if (!m_swarm.healthy_peers.empty()) {
            m_swarm.rr_cursor =
                (erased_idx < next_idx)
                    ? (next_idx - 1)
                    : (next_idx % m_swarm.healthy_peers.size());
        } else {
            m_swarm.rr_cursor = 0;
        }
    }

    auto enqueue_unique_front = [&](const ShardKey &k)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            if (m_swarm.verified_shards.find(k) !=
                m_swarm.verified_shards.end()) {
                return;
            }
            if (std::find(m_swarm.pending_shards.begin(),
                          m_swarm.pending_shards.end(),
                          k) == m_swarm.pending_shards.end()) {
                m_swarm.pending_shards.push_front(k);
            }
        };
    auto enqueue_unique_back = [&](const ShardKey &k)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            if (m_swarm.verified_shards.find(k) !=
                m_swarm.verified_shards.end()) {
                return;
            }
            if (std::find(m_swarm.pending_shards.begin(),
                          m_swarm.pending_shards.end(),
                          k) == m_swarm.pending_shards.end()) {
                m_swarm.pending_shards.push_back(k);
            }
        };

    if (failed_shard.has_value()) {
        m_swarm.in_flight_shards.erase(*failed_shard);
        enqueue_unique_front(*failed_shard);
    }

    for (auto it = m_swarm.in_flight_shards.begin();
         it != m_swarm.in_flight_shards.end();) {
        if (it->second == peer_id) {
            const ShardKey k = it->first;
            it = m_swarm.in_flight_shards.erase(it);
            enqueue_unique_back(k);
        } else {
            ++it;
        }
    }

    if (m_swarm.state == FastSyncSwarmState::FETCHING_ROOTS) {
        if (m_swarm.roots_in_flight_peer == peer_id ||
            m_swarm.roots_in_flight_peer == -1) {
            if (!RequestSwarmRootsLocked()) {
                m_swarm.state = FastSyncSwarmState::FAILED;
            }
        }
    } else if (m_swarm.state == FastSyncSwarmState::FETCHING_SHARDS) {
        DispatchPendingSwarmShardsLocked();
    } else if (m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING) {
        if (m_swarm.undo_in_flight_peer == peer_id &&
            !m_swarm.undo_in_flight_hash.IsNull()) {
            const BlockHash retry_hash = m_swarm.undo_in_flight_hash;
            RequestNextReversePeelBlockLocked(/*target_height=*/1, retry_hash,
                                              /*need_block_data=*/true);
        }
    }
}

bool V2PeerProtocolHandler::StartFastSyncSwarm(
    const BlockHash &pivot_hash, const std::vector<NodeId> &peer_ids,
    bool auto_peel, std::string &err) {
    if (!IsSnapSyncEnabled()) {
        err = "snapsync / reverse sync is disabled (-snapsync=0 or -reversesync=0); using traditional sync";
        return false;
    }

    int pivot_height = 0;
    std::optional<lotus::v2::Hash> expected_anchor;
    {
        LOCK(cs_main);
        Chainstate &cs = m_chainman.ActiveChainstate();
        if (!cs.IsSnapSyncEnabled()) {
            err = "snapsync / reverse sync is disabled (-snapsync=0 or -reversesync=0); using traditional sync";
            return false;
        }
        const CBlockIndex *pindex =
            m_chainman.m_blockman.LookupBlockIndex(pivot_hash);
        if (!pindex) {
            err = "pivot block header not found in block index";
            return false;
        }
        if (pindex->nHeight <= 0) {
            err = "pivot height must be > 0";
            return false;
        }
        pivot_height = pindex->nHeight;
        expected_anchor = cs.GetFastSyncStateAnchor(pivot_hash);
    }

    avalanche::Processor *ava = nullptr;
    {
        LOCK(m_mutex);
        ava = m_avalanche;
    }
    if (!expected_anchor.has_value() && ava) {
        if (auto fin_root = ava->getFinalizedStateRoot(pivot_hash)) {
            lotus::v2::Hash h{};
            std::memcpy(h.data(), fin_root->begin(), 32);
            expected_anchor = h;
            LOCK(cs_main);
            m_chainman.ActiveChainstate().SetFastSyncStateAnchor(pivot_hash, h);
        }
    }

    LOCK(m_mutex);
    std::vector<NodeId> peers;
    std::unordered_set<NodeId> seen;
    if (!peer_ids.empty()) {
        for (const NodeId pid : peer_ids) {
            if (PeerSupportsUtxoShardsLocked(pid) && seen.insert(pid).second) {
                peers.push_back(pid);
            }
        }
    } else {
        m_connman.ForEachNode([&](CNode *pnode) NO_THREAD_SAFETY_ANALYSIS {
            if (pnode && !pnode->fDisconnect &&
                PeerSupportsUtxoShardsLocked(pnode->GetId()) &&
                seen.insert(pnode->GetId()).second) {
                peers.push_back(pnode->GetId());
            }
        });
        for (const auto &[pid, pnode] : m_peer_nodes) {
            if (pnode && !pnode->fDisconnect &&
                PeerSupportsUtxoShardsLocked(pid) && seen.insert(pid).second) {
                peers.push_back(pid);
            }
        }
        std::sort(peers.begin(), peers.end());
    }
    if (peers.empty()) {
        err = "no NODE_UTXO_SHARD capable peers available for fast-sync swarm";
        return false;
    }

    m_swarm = FastSyncSwarmCoordinatorState{};
    m_swarm.state = FastSyncSwarmState::FETCHING_ROOTS;
    m_swarm.pivot_hash = pivot_hash;
    std::memcpy(m_swarm.pivot_v2_id.data(), pivot_hash.begin(), 32);
    m_swarm.pivot_height = pivot_height;
    m_swarm.expected_anchor = expected_anchor;
    m_swarm.auto_peel = auto_peel;
    m_swarm.healthy_peers = std::move(peers);

    if (!RequestSwarmRootsLocked()) {
        m_swarm.state = FastSyncSwarmState::FAILED;
        err = "failed to send GETUTXOROOTS to any swarm peer";
        return false;
    }
    err.clear();
    return true;
}

bool V2PeerProtocolHandler::StartReversePeelSwarm(
    const std::vector<NodeId> &peer_ids, std::string &err) {
    if (!IsReverseSyncEnabled()) {
        err = "reverse sync is disabled (-reversesync=0 or -snapsync=0); using traditional sync";
        return false;
    }

    BlockHash target_hash{};
    int target_height = 0;
    bool need_block_data = false;
    {
        LOCK(cs_main);
        Chainstate &cs = m_chainman.ActiveChainstate();
        if (!cs.IsReverseSyncEnabled()) {
            err = "reverse sync is disabled (-reversesync=0 or -snapsync=0); using traditional sync";
            return false;
        }
        if (!cs.IsFastSyncActive()) {
            err = "fast-sync mode is not active";
            return false;
        }
        const int earliest_h = cs.GetEarliestVerifiedHeight();
        const CBlockIndex *pindex = cs.GetEarliestVerifiedBlock();
        if (!pindex) {
            pindex = cs.m_chain[earliest_h];
        }
        if (!pindex || pindex->nHeight <= 0) {
            err = "earliest verified block index invalid or already at genesis";
            return false;
        }
        target_hash = pindex->GetBlockHash();
        target_height = pindex->nHeight;
        need_block_data = !pindex->nStatus.hasData();
    }

    LOCK(m_mutex);
    if (!peer_ids.empty()) {
        std::vector<NodeId> peers;
        std::unordered_set<NodeId> seen;
        for (const NodeId pid : peer_ids) {
            if (m_swarm.banned_peers.count(pid) == 0 &&
                PeerSupportsUtxoShardsLocked(pid) && seen.insert(pid).second) {
                peers.push_back(pid);
            }
        }
        m_swarm.healthy_peers = std::move(peers);
    } else if (m_swarm.healthy_peers.empty()) {
        std::vector<NodeId> conn_peers;
        m_connman.ForEachNode([&](CNode *pnode) {
            if (pnode && !pnode->fDisconnect) {
                conn_peers.push_back(pnode->GetId());
            }
        });
        std::unordered_set<NodeId> seen;
        for (const NodeId pid : conn_peers) {
            if (m_swarm.banned_peers.count(pid) == 0 &&
                PeerSupportsUtxoShardsLocked(pid) && seen.insert(pid).second) {
                m_swarm.healthy_peers.push_back(pid);
            }
        }
        for (const auto &[pid, pnode] : m_peer_nodes) {
            if (pnode && !pnode->fDisconnect &&
                m_swarm.banned_peers.count(pid) == 0 &&
                PeerSupportsUtxoShardsLocked(pid) && seen.insert(pid).second) {
                m_swarm.healthy_peers.push_back(pid);
            }
        }
        std::sort(m_swarm.healthy_peers.begin(), m_swarm.healthy_peers.end());
    }
    if (m_swarm.healthy_peers.empty()) {
        err = "no healthy NODE_UTXO_SHARD peers available for reverse peel swarm";
        return false;
    }

    m_swarm.auto_peel = true;
    m_swarm.state = FastSyncSwarmState::PIVOT_ACTIVE_PEELING;
    if (!RequestNextReversePeelBlockLocked(target_height, target_hash,
                                           need_block_data)) {
        err = "failed to send GETBLOCKUNDO to any swarm peer";
        return false;
    }
    err.clear();
    return true;
}

bool V2PeerProtocolHandler::SplitSwarmShardToSubShards(uint8_t prefix_depth,
                                                       uint16_t prefix_bits,
                                                       std::string &err) {
    if (prefix_depth < lotus::v2::kMinUtxoShardPrefixDepth ||
        prefix_depth >= lotus::v2::kMaxUtxoShardPrefixDepth) {
        err = "prefix_depth for sub-shard split must be in [8..15]";
        return false;
    }
    LOCK(m_mutex);
    if (m_swarm.state != FastSyncSwarmState::FETCHING_SHARDS) {
        err = "swarm is not currently fetching shards";
        return false;
    }
    const ShardKey target{prefix_depth, prefix_bits};
    if (m_swarm.verified_shards.count(target) > 0) {
        err = "shard is already verified";
        return false;
    }
    bool removed = false;
    if (m_swarm.in_flight_shards.erase(target) > 0) {
        removed = true;
    }
    auto it_pend = std::find(m_swarm.pending_shards.begin(),
                             m_swarm.pending_shards.end(), target);
    if (it_pend != m_swarm.pending_shards.end()) {
        m_swarm.pending_shards.erase(it_pend);
        removed = true;
    }
    if (!removed) {
        err = "target shard is neither pending nor in-flight";
        return false;
    }

    const uint8_t next_depth = static_cast<uint8_t>(prefix_depth + 1);
    const ShardKey sub0{next_depth, prefix_bits};
    const ShardKey sub1{
        next_depth,
        static_cast<uint16_t>(prefix_bits | (uint16_t{1} << prefix_depth))};
    ++m_swarm.total_non_empty_shards;
    m_swarm.pending_shards.push_front(sub1);
    m_swarm.pending_shards.push_front(sub0);
    DispatchPendingSwarmShardsLocked();
    err.clear();
    return true;
}

FastSyncSwarmStatus V2PeerProtocolHandler::GetFastSyncSwarmStatus() const {
    LOCK(m_mutex);
    FastSyncSwarmStatus status;
    status.state = m_swarm.state;
    status.pivot_block_hash = m_swarm.pivot_hash;
    status.pivot_height = m_swarm.pivot_height;
    if (m_swarm.expected_anchor.has_value()) {
        uint256 anchor_u256;
        std::memcpy(anchor_u256.begin(), m_swarm.expected_anchor->data(), 32);
        status.avalanche_state_anchor = anchor_u256;
    }
    status.total_non_empty_shards = m_swarm.total_non_empty_shards;
    status.verified_shards = m_swarm.verified_shards.size();
    status.pending_shards = m_swarm.pending_shards.size();
    status.in_flight_shards = m_swarm.in_flight_shards.size();
    status.active_peers = m_swarm.healthy_peers.size();
    status.banned_swarm_peers = m_swarm.banned_peers.size();
    status.coins_imported = m_swarm.coins_imported;
    status.corrupted_roots_rejected = m_stats.swarm_corrupted_roots_rejected;
    status.corrupted_shards_rejected = m_stats.swarm_corrupted_shards_rejected;
    status.corrupted_undo_rejected = m_stats.swarm_corrupted_undo_rejected;
    status.blocks_peeled = m_stats.swarm_blocks_peeled;
    return status;
}

void V2PeerProtocolHandler::HandleGetUtxoRoots(
    CNode &pfrom, DataStream &vRecv,
    std::chrono::microseconds /*time_received*/) {
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());
    {
        LOCK(m_mutex);
        ++m_stats.getutxoroots_received;
    }
    if (!IsServeUtxoShardsEnabled()) {
        return;
    }

    lotus::v2::GetUtxoRootsRequest req{};
    std::string err;
    if (!lotus::v2::DecodeGetUtxoRootsRequest(bytes, req, err)) {
        {
            LOCK(m_mutex);
            ++m_stats.malformed_messages;
        }
        pfrom.fDisconnect = true;
        return;
    }

    uint256 raw_hash;
    std::memcpy(raw_hash.begin(), req.pivot_block_id.data(), 32);
    const BlockHash block_hash{raw_hash};

    Chainstate::FastSyncBlockState block_state;
    {
        LOCK(cs_main);
        const CBlockIndex *pindex =
            m_chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pindex || !m_chainman.ActiveChain().Contains(pindex)) {
            return;
        }
        if (!m_chainman.ActiveChainstate().ExportV2BlockStateCoinsAndMonetary(
                pindex, block_state, err, /*populate_utxo_set=*/false)) {
            return;
        }
    }

    avalanche::Processor *ava = nullptr;
    {
        LOCK(m_mutex);
        ava = m_avalanche;
    }
    if (ava) {
        uint256 root_u256;
        std::memcpy(root_u256.begin(), block_state.utxo_root.data(), 32);
        ava->registerStateAnchor(block_hash, root_u256,
                                 /*localAccepted=*/true, /*poll=*/true);
    }

    lotus::v2::UtxoRootsMessage roots_msg{};
    if (!lotus::v2::ExportUtxoRootsFromSmt(block_state.smt_root,
                                           req.pivot_block_id,
                                           block_state.height,
                                           block_state.monetary, roots_msg,
                                           err)) {
        return;
    }
    const std::vector<uint8_t> payload =
        lotus::v2::EncodeUtxoRootsMessage(roots_msg);
    m_connman.PushMessage(&pfrom,
                          NetMsg::Make(NetMsgType::UTXOROOTS, Span{payload}));
}

void V2PeerProtocolHandler::HandleUtxoRoots(
    CNode &pfrom, DataStream &vRecv,
    std::chrono::microseconds /*time_received*/) {
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());

    lotus::v2::UtxoRootsMessage roots_msg{};
    std::string err;
    const bool decoded =
        lotus::v2::DecodeUtxoRootsMessage(bytes, roots_msg, err);

    BlockHash pivot_hash_for_anchor{};
    avalanche::Processor *ava = nullptr;
    {
        LOCK(m_mutex);
        pivot_hash_for_anchor = m_swarm.pivot_hash;
        ava = m_avalanche;
    }

    std::optional<lotus::v2::Hash> latest_anchor;
    if (!pivot_hash_for_anchor.IsNull()) {
        {
            LOCK(cs_main);
            if (!m_chainman.GetAll().empty()) {
                latest_anchor =
                    m_chainman.ActiveChainstate().GetFastSyncStateAnchor(
                        pivot_hash_for_anchor);
            }
        }
        if (!latest_anchor.has_value() && ava) {
            if (auto fin_root =
                    ava->getFinalizedStateRoot(pivot_hash_for_anchor)) {
                lotus::v2::Hash h{};
                std::memcpy(h.data(), fin_root->begin(), 32);
                latest_anchor = h;
                LOCK(cs_main);
                if (!m_chainman.GetAll().empty()) {
                    m_chainman.ActiveChainstate().SetFastSyncStateAnchor(
                        pivot_hash_for_anchor, h);
                }
            }
        }
    }

    bool need_discourage = false;
    bool activate_empty_pivot = false;
    BlockHash pivot_hash{};
    std::optional<lotus::v2::Hash> candidate_anchor_to_poll;
    {
        LOCK(m_mutex);
        ++m_stats.utxoroots_received;
        if (latest_anchor.has_value() && !m_swarm.expected_anchor.has_value()) {
            m_swarm.expected_anchor = latest_anchor;
        }
        if (!decoded) {
            ++m_stats.malformed_messages;
            ++m_stats.swarm_corrupted_roots_rejected;
            if (m_swarm.state == FastSyncSwarmState::FETCHING_ROOTS) {
                HandleSwarmPeerFailureLocked(pfrom.GetId(), std::nullopt);
            }
            need_discourage = true;
        } else if (m_swarm.state == FastSyncSwarmState::FETCHING_ROOTS &&
                   roots_msg.pivot_block_id == m_swarm.pivot_v2_id) {
            if (!m_swarm.expected_anchor.has_value() && ava != nullptr &&
                roots_msg.height ==
                    static_cast<uint64_t>(m_swarm.pivot_height)) {
                if (auto cand_folded =
                        lotus::v2::FoldDepth8ShardRoots(roots_msg.shards)) {
                    candidate_anchor_to_poll = *cand_folded;
                    pivot_hash = m_swarm.pivot_hash;
                }
            }
            lotus::v2::Hash folded_root{};
            if (!lotus::v2::VerifyUtxoRootsAgainstAnchor(
                    m_swarm.pivot_v2_id,
                    static_cast<uint64_t>(m_swarm.pivot_height),
                    m_swarm.expected_anchor, roots_msg, folded_root, err)) {
                ++m_stats.swarm_corrupted_roots_rejected;
                HandleSwarmPeerFailureLocked(pfrom.GetId(), std::nullopt);
                need_discourage = !candidate_anchor_to_poll.has_value();
            } else {
                m_swarm.has_verified_roots = true;
                m_swarm.verified_roots = roots_msg;
                m_swarm.roots_in_flight_peer = -1;
                m_swarm.pending_shards.clear();
                m_swarm.in_flight_shards.clear();
                m_swarm.verified_shards.clear();
                for (size_t i = 0; i < lotus::v2::kFastSyncShardCount; ++i) {
                    if (roots_msg.shards[i].cardinality_tag != 0) {
                        m_swarm.pending_shards.push_back(
                            ShardKey{8, static_cast<uint16_t>(i)});
                    }
                }
                m_swarm.total_non_empty_shards = m_swarm.pending_shards.size();
                pivot_hash = m_swarm.pivot_hash;
                if (m_swarm.pending_shards.empty()) {
                    activate_empty_pivot = true;
                } else {
                    m_swarm.state = FastSyncSwarmState::FETCHING_SHARDS;
                    DispatchPendingSwarmShardsLocked();
                }
            }
        }
    }

    if (candidate_anchor_to_poll.has_value() && !pivot_hash.IsNull() && ava) {
        uint256 root_u256;
        std::memcpy(root_u256.begin(), candidate_anchor_to_poll->data(), 32);
        ava->registerStateAnchor(pivot_hash, root_u256,
                                 /*localAccepted=*/false, /*poll=*/true);
    }

    if (need_discourage) {
        pfrom.fDisconnect = true;
        return;
    }

    if (activate_empty_pivot) {
        std::string act_err;
        bool activated = false;
        bool need_block_data = false;
        {
            LOCK(cs_main);
            CBlockIndex *pindex_pivot =
                m_chainman.m_blockman.LookupBlockIndex(pivot_hash);
            if (pindex_pivot &&
                m_chainman.ActiveChainstate().ActivateVerifiedFastSyncPivot(
                    pindex_pivot, roots_msg, {}, act_err)) {
                activated = true;
                need_block_data = !pindex_pivot->nStatus.hasData();
            }
        }
        LOCK(m_mutex);
        if (!activated) {
            m_swarm.state = FastSyncSwarmState::FAILED;
            return;
        }
        m_swarm.coins_imported = 0;
        if (m_swarm.auto_peel && m_swarm.pivot_height > 0) {
            m_swarm.state = FastSyncSwarmState::PIVOT_ACTIVE_PEELING;
            RequestNextReversePeelBlockLocked(
                m_swarm.pivot_height, m_swarm.pivot_hash, need_block_data);
        } else {
            m_swarm.state = FastSyncSwarmState::COMPLETED;
        }
    }
}

void V2PeerProtocolHandler::HandleGetUtxoShard(
    CNode &pfrom, DataStream &vRecv, std::chrono::microseconds time_received) {
    if (!CheckPeerShardRateLimit(pfrom.GetId(), time_received)) {
        vRecv.ignore(vRecv.size());
        return;
    }
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());
    {
        LOCK(m_mutex);
        ++m_stats.getutxoshard_received;
    }
    if (!IsServeUtxoShardsEnabled()) {
        return;
    }

    lotus::v2::GetUtxoShardRequest req{};
    std::string err;
    if (!lotus::v2::DecodeGetUtxoShardRequest(bytes, req, err)) {
        {
            LOCK(m_mutex);
            ++m_stats.malformed_messages;
        }
        pfrom.fDisconnect = true;
        return;
    }

    uint256 raw_hash;
    std::memcpy(raw_hash.begin(), req.pivot_block_id.data(), 32);
    const BlockHash block_hash{raw_hash};

    Chainstate::FastSyncBlockState block_state;
    {
        LOCK(cs_main);
        const CBlockIndex *pindex =
            m_chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pindex || !m_chainman.ActiveChain().Contains(pindex)) {
            return;
        }
        if (!m_chainman.ActiveChainstate().ExportV2BlockStateCoinsAndMonetary(
                pindex, block_state, err, /*populate_utxo_set=*/false)) {
            return;
        }
    }

    lotus::v2::UtxoShardMessage shard_msg{};
    if (!lotus::v2::ExportUtxoShardFromSmt(block_state.smt_root,
                                           req.pivot_block_id,
                                           req.prefix_depth, req.prefix_bits,
                                           shard_msg, err)) {
        return;
    }
    std::vector<uint8_t> payload;
    if (!lotus::v2::EncodeUtxoShardMessage(shard_msg, payload, err)) {
        return;
    }
    m_connman.PushMessage(&pfrom,
                          NetMsg::Make(NetMsgType::UTXOSHARD, Span{payload}));
}

void V2PeerProtocolHandler::HandleUtxoShard(
    CNode &pfrom, DataStream &vRecv,
    std::chrono::microseconds /*time_received*/) {
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());

    lotus::v2::UtxoShardMessage shard_msg{};
    std::string err;
    const bool decoded =
        lotus::v2::DecodeUtxoShardMessage(bytes, shard_msg, err);

    bool need_discourage = false;
    bool all_shards_ready = false;
    BlockHash pivot_hash{};
    lotus::v2::UtxoRootsMessage verified_roots{};
    std::vector<lotus::v2::UtxoShardMessage> verified_shards_vec;
    uint64_t total_coins_in_shards = 0;
    {
        LOCK(m_mutex);
        ++m_stats.utxoshard_received;
        if (!decoded) {
            ++m_stats.malformed_messages;
            ++m_stats.swarm_corrupted_shards_rejected;
            if (m_swarm.state == FastSyncSwarmState::FETCHING_SHARDS) {
                HandleSwarmPeerFailureLocked(pfrom.GetId(), std::nullopt);
            }
            need_discourage = true;
        } else if (m_swarm.state == FastSyncSwarmState::FETCHING_SHARDS &&
                   m_swarm.has_verified_roots &&
                   shard_msg.pivot_block_id == m_swarm.pivot_v2_id) {
            const ShardKey key{shard_msg.prefix_depth, shard_msg.prefix_bits};
            if (m_swarm.verified_shards.count(key) == 0) {
                const bool was_in_flight =
                    m_swarm.in_flight_shards.count(key) > 0;
                const auto it_pend = std::find(m_swarm.pending_shards.begin(),
                                               m_swarm.pending_shards.end(),
                                               key);
                const bool was_pending =
                    it_pend != m_swarm.pending_shards.end();
                if (was_in_flight || was_pending) {
                    const auto &expected_d8 =
                        m_swarm.verified_roots
                            .shards[shard_msg.prefix_bits & 0xFF];
                    if (!lotus::v2::VerifyAndBuildUtxoShard(
                            expected_d8,
                            static_cast<uint64_t>(m_swarm.pivot_height),
                            shard_msg, nullptr, err)) {
                        ++m_stats.swarm_corrupted_shards_rejected;
                        HandleSwarmPeerFailureLocked(pfrom.GetId(), key);
                        need_discourage = true;
                    } else {
                        ++m_stats.swarm_shards_verified;
                        m_swarm.in_flight_shards.erase(key);
                        if (was_pending) {
                            m_swarm.pending_shards.erase(it_pend);
                        }
                        m_swarm.verified_shards[key] = std::move(shard_msg);
                        if (m_swarm.pending_shards.empty() &&
                            m_swarm.in_flight_shards.empty() &&
                            m_swarm.verified_shards.size() ==
                                m_swarm.total_non_empty_shards) {
                            all_shards_ready = true;
                            pivot_hash = m_swarm.pivot_hash;
                            verified_roots = m_swarm.verified_roots;
                            verified_shards_vec.reserve(
                                m_swarm.verified_shards.size());
                            for (const auto &[_, s] : m_swarm.verified_shards) {
                                total_coins_in_shards += s.coins.size();
                                verified_shards_vec.push_back(s);
                            }
                        } else {
                            DispatchPendingSwarmShardsLocked();
                        }
                    }
                }
            }
        }
    }

    if (need_discourage) {
        pfrom.fDisconnect = true;
        return;
    }

    if (all_shards_ready) {
        std::string act_err;
        bool activated = false;
        bool need_block_data = false;
        {
            LOCK(cs_main);
            CBlockIndex *pindex_pivot =
                m_chainman.m_blockman.LookupBlockIndex(pivot_hash);
            if (pindex_pivot &&
                m_chainman.ActiveChainstate().ActivateVerifiedFastSyncPivot(
                    pindex_pivot, verified_roots, verified_shards_vec,
                    act_err)) {
                activated = true;
                need_block_data = !pindex_pivot->nStatus.hasData();
            }
        }
        LOCK(m_mutex);
        if (!activated) {
            m_swarm.state = FastSyncSwarmState::FAILED;
            return;
        }
        m_swarm.coins_imported = total_coins_in_shards;
        if (m_swarm.auto_peel && m_swarm.pivot_height > 0) {
            m_swarm.state = FastSyncSwarmState::PIVOT_ACTIVE_PEELING;
            RequestNextReversePeelBlockLocked(
                m_swarm.pivot_height, m_swarm.pivot_hash, need_block_data);
        } else {
            m_swarm.state = FastSyncSwarmState::COMPLETED;
        }
    }
}

void V2PeerProtocolHandler::HandleGetBlockUndo(
    CNode &pfrom, DataStream &vRecv,
    std::chrono::microseconds /*time_received*/) {
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());
    {
        LOCK(m_mutex);
        ++m_stats.getblockundo_received;
    }
    if (!IsServeUtxoShardsEnabled()) {
        return;
    }

    lotus::v2::GetBlockUndoRequest req{};
    std::string err;
    if (!lotus::v2::DecodeGetBlockUndoRequest(bytes, req, err)) {
        {
            LOCK(m_mutex);
            ++m_stats.malformed_messages;
        }
        pfrom.fDisconnect = true;
        return;
    }

    uint256 raw_hash;
    std::memcpy(raw_hash.begin(), req.block_id.data(), 32);
    const BlockHash block_hash{raw_hash};

    CBlock block;
    BlockHash parent_hash;
    Chainstate::FastSyncBlockState parent_state;
    {
        LOCK(cs_main);
        const CBlockIndex *pindex =
            m_chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pindex || pindex->nHeight <= 0 || !pindex->pprev ||
            !m_chainman.ActiveChain().Contains(pindex)) {
            return;
        }
        if (!m_chainman.m_blockman.ReadBlock(block, *pindex)) {
            return;
        }
        parent_hash = pindex->pprev->GetBlockHash();
        if (!m_chainman.ActiveChainstate().ExportV2BlockStateCoinsAndMonetary(
                pindex->pprev, parent_state, err,
                /*populate_utxo_set=*/false)) {
            return;
        }
    }

    avalanche::Processor *ava = nullptr;
    {
        LOCK(m_mutex);
        ava = m_avalanche;
    }
    if (ava) {
        uint256 parent_root_u256;
        std::memcpy(parent_root_u256.begin(), parent_state.utxo_root.data(),
                    32);
        ava->registerStateAnchor(parent_hash, parent_root_u256,
                                 /*localAccepted=*/true, /*poll=*/true);
    }

    std::set<COutPoint> created_outpoints;
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        const TxId txid = tx.GetId();
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (!tx.vout[j].scriptPubKey.IsUnspendable()) {
                created_outpoints.emplace(txid, static_cast<uint32_t>(j));
            }
        }
    }

    lotus::v2::BlockUndoMessage undo_msg{};
    undo_msg.block_id = req.block_id;
    undo_msg.parent_monetary_state =
        lotus::v2::EncodeMonetaryState(parent_state.monetary);
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        if (tx.IsCoinBase()) {
            continue;
        }
        for (const auto &txin : tx.vin) {
            if (created_outpoints.count(txin.prevout) > 0) {
                // Intra-block spend (I_h^intra): excluded from BlockUndo
                continue;
            }
            lotus::v2::Outpoint op{};
            std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(), 32);
            op.index = txin.prevout.GetN();
            std::shared_ptr<const lotus::v2::Coin> smt_coin =
                lotus::v2::SmtFind(parent_state.smt_root, op);
            if (smt_coin) {
                undo_msg.prior_spent_coins.push_back(*smt_coin);
            } else {
                const lotus::v2::Coin *found = parent_state.utxo.Find(op);
                if (!found) {
                    return;
                }
                undo_msg.prior_spent_coins.push_back(*found);
            }
        }
    }
    std::vector<uint8_t> payload;
    if (!lotus::v2::EncodeBlockUndoMessage(undo_msg, payload, err)) {
        return;
    }
    m_connman.PushMessage(&pfrom,
                          NetMsg::Make(NetMsgType::BLOCKUNDO, Span{payload}));
}

void V2PeerProtocolHandler::HandleBlockUndo(
    CNode &pfrom, DataStream &vRecv,
    std::chrono::microseconds /*time_received*/) {
    const auto span = MakeUCharSpan(vRecv);
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    vRecv.ignore(vRecv.size());

    lotus::v2::BlockUndoMessage undo_msg{};
    std::string err;
    const bool decoded =
        lotus::v2::DecodeBlockUndoMessage(bytes, undo_msg, err);

    BlockHash block_hash{};
    bool should_peel = false;
    bool need_discourage = false;
    avalanche::Processor *ava = nullptr;
    {
        LOCK(m_mutex);
        ava = m_avalanche;
        ++m_stats.blockundo_received;
        if (!decoded) {
            ++m_stats.malformed_messages;
            ++m_stats.swarm_corrupted_undo_rejected;
            if (m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING) {
                HandleSwarmPeerFailureLocked(pfrom.GetId(), std::nullopt);
            }
            need_discourage = true;
        } else {
            uint256 raw_hash;
            std::memcpy(raw_hash.begin(), undo_msg.block_id.data(), 32);
            block_hash = BlockHash{raw_hash};
            if (m_swarm.state == FastSyncSwarmState::PIVOT_ACTIVE_PEELING &&
                block_hash == m_swarm.undo_in_flight_hash) {
                should_peel = true;
            }
        }
    }

    if (need_discourage) {
        pfrom.fDisconnect = true;
        return;
    }

    if (!should_peel) {
        return;
    }

    bool peeled = false;
    bool waiting_for_block_data = false;
    bool fast_sync_still_active = false;
    bool next_need_block_data = false;
    int next_verified_height = 0;
    BlockHash parent_block_hash{};
    std::string peel_err;
    {
        LOCK(cs_main);
        Chainstate &cs = m_chainman.ActiveChainstate();
        CBlockIndex *pindex =
            m_chainman.m_blockman.LookupBlockIndex(block_hash);
        if (pindex && pindex->pprev) {
            parent_block_hash = pindex->pprev->GetBlockHash();
            if (ava &&
                !cs.GetFastSyncStateAnchor(parent_block_hash).has_value()) {
                if (auto fin_root =
                        ava->getFinalizedStateRoot(parent_block_hash)) {
                    lotus::v2::Hash h{};
                    std::memcpy(h.data(), fin_root->begin(), 32);
                    cs.SetFastSyncStateAnchor(parent_block_hash, h);
                }
            }
            if (!pindex->nStatus.hasData()) {
                waiting_for_block_data = true;
            } else {
                CBlock block;
                if (m_chainman.m_blockman.ReadBlock(block, *pindex)) {
                    peeled = cs.PeelFastSyncBlock(
                        block, pindex, undo_msg.prior_spent_coins, peel_err);
                    if (peeled) {
                        fast_sync_still_active = cs.IsFastSyncActive();
                        next_verified_height = cs.GetEarliestVerifiedHeight();
                        next_need_block_data =
                            !pindex->pprev->nStatus.hasData();
                    }
                }
            }
        }
    }

    if (waiting_for_block_data) {
        {
            LOCK(m_mutex);
            m_swarm.pending_undo_for_block = std::move(undo_msg);
            m_swarm.pending_undo_peer = pfrom.GetId();
        }
        m_connman.PushMessage(
            &pfrom, NetMsg::Make(NetMsgType::GETDATA,
                                 std::vector<CInv>{CInv(MSG_BLOCK, block_hash)}));
        return;
    }

    bool peel_failed_discourage = false;
    {
        LOCK(m_mutex);
        if (!peeled) {
            ++m_stats.swarm_corrupted_undo_rejected;
            HandleSwarmPeerFailureLocked(pfrom.GetId(), std::nullopt);
            peel_failed_discourage = true;
        } else {
            ++m_stats.swarm_blocks_peeled;
            ++m_swarm.blocks_peeled;
            m_swarm.undo_in_flight_hash = BlockHash{};
            m_swarm.undo_in_flight_peer = -1;
            m_swarm.pending_undo_for_block.reset();
            if (!fast_sync_still_active || next_verified_height <= 0) {
                m_swarm.state = FastSyncSwarmState::COMPLETED;
            } else if (m_swarm.auto_peel) {
                RequestNextReversePeelBlockLocked(next_verified_height,
                                                  parent_block_hash,
                                                  next_need_block_data);
            }
        }
    }

    if (peel_failed_discourage) {
        pfrom.fDisconnect = true;
    }
}


} // namespace lotus::v2::net
