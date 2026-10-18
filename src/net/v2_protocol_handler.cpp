// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/v2_protocol_handler.h>

#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/siphash.h>
#include <logging.h>
#include <lotus_v2/blocksnap.h>
#include <lotus_v2/tagged_hash.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <txmempool.h>
#include <validation.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_set>

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#elif defined(__x86_64__) && defined(__PCLMUL__)
#include <wmmintrin.h>
#endif

namespace lotus::v2::net {

namespace {

constexpr uint64_t GF64_REDUCTION_POLY = 0x1bULL; // z^64 + z^4 + z^3 + z + 1
constexpr size_t MAX_OVERLAYS_PER_PREV = 16;

struct GF64QuadraticBasis {
    std::array<uint64_t, 64> pivot_vec{};
    std::array<uint64_t, 64> pivot_preimage{};

    GF64QuadraticBasis() {
        for (int i = 1; i < 64; ++i) {
            const uint64_t e_i = 1ULL << i;
            uint64_t vec = GF64Square(e_i) ^ e_i;
            uint64_t pre = e_i;
            for (int b = 63; b >= 0; --b) {
                if (!((vec >> b) & 1ULL)) {
                    continue;
                }
                if (pivot_vec[b] != 0) {
                    vec ^= pivot_vec[b];
                    pre ^= pivot_preimage[b];
                } else {
                    pivot_vec[b] = vec;
                    pivot_preimage[b] = pre;
                    break;
                }
            }
        }
    }
};

const GF64QuadraticBasis &GetGF64QuadraticBasis() {
    static const GF64QuadraticBasis basis{};
    return basis;
}

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
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    const poly128_t prod =
        vmull_p64(static_cast<poly64_t>(a), static_cast<poly64_t>(b));
    const uint64x2_t prod_u64 = vreinterpretq_u64_p128(prod);
    const uint64_t lo = vgetq_lane_u64(prod_u64, 0);
    const uint64_t hi = vgetq_lane_u64(prod_u64, 1);
    const poly128_t red1 = vmull_p64(static_cast<poly64_t>(hi),
                                     static_cast<poly64_t>(GF64_REDUCTION_POLY));
    const uint64x2_t red1_u64 = vreinterpretq_u64_p128(red1);
    const uint64_t r1_lo = vgetq_lane_u64(red1_u64, 0);
    const uint64_t r1_hi = vgetq_lane_u64(red1_u64, 1);
    const uint64_t r2 = static_cast<uint64_t>(vgetq_lane_u64(
        vreinterpretq_u64_p128(vmull_p64(
            static_cast<poly64_t>(r1_hi),
            static_cast<poly64_t>(GF64_REDUCTION_POLY))),
        0));
    return lo ^ r1_lo ^ r2;
#elif defined(__x86_64__) && defined(__PCLMUL__)
    const __m128i va = _mm_cvtsi64_si128(static_cast<int64_t>(a));
    const __m128i vb = _mm_cvtsi64_si128(static_cast<int64_t>(b));
    const __m128i vpoly =
        _mm_cvtsi64_si128(static_cast<int64_t>(GF64_REDUCTION_POLY));
    const __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);
    const uint64_t lo = static_cast<uint64_t>(_mm_cvtsi128_si64(prod));
    const __m128i red1 = _mm_clmulepi64_si128(prod, vpoly, 0x01);
    const uint64_t r1_lo = static_cast<uint64_t>(_mm_cvtsi128_si64(red1));
    const __m128i red2 = _mm_clmulepi64_si128(red1, vpoly, 0x01);
    const uint64_t r2 = static_cast<uint64_t>(_mm_cvtsi128_si64(red2));
    return lo ^ r1_lo ^ r2;
#else
    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        if ((b >> i) & 1ULL) {
            result ^= a;
        }
        const bool hi = (a >> 63) & 1ULL;
        a <<= 1;
        if (hi) {
            a ^= GF64_REDUCTION_POLY;
        }
    }
    return result;
#endif
}

uint64_t GF64Square(uint64_t a) noexcept {
    return GF64Mul(a, a);
}

uint64_t GF64Cube(uint64_t a) noexcept {
    return GF64Mul(GF64Square(a), a);
}

uint64_t GF64Pow5(uint64_t a) noexcept {
    const uint64_t a2 = GF64Square(a);
    const uint64_t a4 = GF64Square(a2);
    return GF64Mul(a, a4);
}

uint64_t GF64Inv(uint64_t a) noexcept {
    if (a == 0) {
        return 0;
    }
    // In GF(2^64), a^(2^64 - 2) = a^(-1).
    uint64_t result = 1;
    uint64_t cur = a;
    for (int i = 1; i < 64; ++i) {
        cur = GF64Square(cur);
        result = GF64Mul(result, cur);
    }
    return result;
}

bool GF64SolveQuadratic(uint64_t c, uint64_t &y_out) noexcept {
    if (c == 0) {
        y_out = 0;
        return true;
    }
    const auto &basis = GetGF64QuadraticBasis();
    uint64_t rem = c;
    uint64_t y = 0;
    for (int b = 63; b >= 0; --b) {
        if ((rem >> b) & 1ULL) {
            if (basis.pivot_vec[b] == 0) {
                return false;
            }
            rem ^= basis.pivot_vec[b];
            y ^= basis.pivot_preimage[b];
        }
    }
    y_out = y;
    return true;
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

V2PeerProtocolHandler::V2PeerProtocolHandler(ChainstateManager &chainman,
                                             CTxMemPool &mempool,
                                             CConnman &connman,
                                             PeerManager &peerman)
    : m_chainman(chainman), m_mempool(mempool), m_connman(connman),
      m_peerman(peerman) {}

bool V2PeerProtocolHandler::TryHandleMessage(
    CNode &pfrom, const std::string &msg_type, DataStream &vRecv,
    std::chrono::microseconds time_received) {
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
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.malformed_messages;
        return;
    }

    // Defect C1 (Hole 7): Enforce coinbase serialization size cap before any
    // header/overlay processing.
    if (::GetSerializeSize(*sealed.coinbase_tx) >
        MAX_SEALEDHEADER_COINBASE_BYTES) {
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
        LOCK(m_mutex);
        ++m_stats.sealedheader_invalid;
        ++m_stats.sealedheader_rejected;
        return;
    }

    const BlockHash block_hash = sealed.header.GetHash();
    RecordPeerKnownBlock(pfrom.GetId(), block_hash);

    if (pindex && WITH_LOCK(cs_main, return pindex->nStatus.hasData())) {
        LOCK(m_mutex);
        ++m_stats.sealedheader_reconstructed;
        return;
    }

    std::shared_ptr<const CBlock> reconstructed = MatchCandidateOverlay(
        sealed.header, sealed.coinbase_tx, sealed.coinbase_merkle_branch,
        sealed.epoch_batch_ids);
    if (reconstructed) {
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

std::vector<CTransactionRef> V2PeerProtocolHandler::GetScopedTransactions(
    ReconScope scope, const uint256 &context_id) const {
    {
        LOCK(m_mutex);
        auto it = m_scoped_txs.find(ScopeKey{scope, context_id});
        if (it != m_scoped_txs.end()) {
            return it->second.txs;
        }
    }
    if (scope == ReconScope::LIVE_MEMPOOL) {
        std::vector<CTransactionRef> mempool_txs;
        {
            LOCK(m_mempool.cs);
            mempool_txs.reserve(m_mempool.mapTx.size());
            for (const auto &entry : m_mempool.mapTx) {
                mempool_txs.push_back(entry->GetSharedTx());
            }
        }
        return NormalizeCtorTxList(mempool_txs);
    }
    return {};
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
        const uint64_t sid = ComputeMerklixShortId(salt_k0, salt_k1, txid);
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
        const uint64_t sid = ComputeMerklixShortId(k0, k1, txid);
        local_buckets[b].count += 1;
        local_buckets[b].xor_short_id ^= sid;
        local_bucket_sids[b].insert(sid);
    }

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
                // Local has 1 extra tx in this bucket and 0 missing.
                continue;
            }
        }

        result.mismatched_bucket_mask |= static_cast<uint16_t>(1U << b);
    }

    // Defect D1 (Hole 1): Never treat a scope as converged when the 256-bit
    // candidate_root differs, even if all 16 64-bit bucket XORs/counts match.
    if (!result.root_matched && result.mismatched_bucket_mask == 0 &&
        result.single_missing_short_ids.empty()) {
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
        const uint64_t sid = ComputeMerklixShortId(salt_k0, salt_k1, txid);
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
        const uint64_t sid = ComputeMerklixShortId(k0, k1, txid);
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
    m_peer_window_start.erase(peer_id);
    m_peer_msg_counts.erase(peer_id);
    m_peer_known_blocks.erase(peer_id);
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

    const MerklixSyncDiffResult diff = DiffSyncSummary(summary);
    if (diff.root_matched) {
        return;
    }

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
                                sub.salt_k1)) {
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

    const MerklixSubBucketDiffResult diff = DiffSubBucketSummary(sub);
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
    if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
        return;
    }

    ShortTxRequest req;
    try {
        vRecv >> req;
    } catch (const std::exception &) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
        return;
    }

    if (!IsValidReconScope(req.scope) || req.short_ids.empty() ||
        req.short_ids.size() > ShortTxRequest::MAX_SHORT_IDS) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
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
    if (!CheckPeerRateLimit(pfrom.GetId(), time_received)) {
        return;
    }

    ShortTxResponse resp;
    try {
        vRecv >> resp;
    } catch (const std::exception &) {
        LOCK(m_mutex);
        ++m_stats.malformed_messages;
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
    std::vector<CTransactionRef> solicited_txs;
    {
        LOCK(m_mutex);
        const PendingShortTxKey key{pfrom.GetId(), scope, resp.context_id};
        auto it = m_pending_shorttx_requests.find(key);
        const bool high_bandwidth_opt_in =
            pfrom.m_bip152_highbandwidth_to.load() ||
            pfrom.m_bip152_highbandwidth_from.load() ||
            m_high_bandwidth_shorttx_peers.count(pfrom.GetId()) > 0 ||
            pfrom.HasPermission(NetPermissionFlags::Relay) ||
            gArgs.GetBoolArg("-highbandwidthtx", false);

        if (it != m_pending_shorttx_requests.end() &&
            !it->second.requested_short_ids.empty()) {
            solicited_txs.reserve(resp.txs.size());
            for (const auto &tx : resp.txs) {
                const uint64_t sid = ComputeMerklixShortId(
                    it->second.salt_k0, it->second.salt_k1, tx->GetId());
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

    for (const auto &tx : valid_txs) {
        m_peerman.MarkPeerKnownTx(pfrom.GetId(), tx->GetId());
    }

    if (!valid_txs.empty() &&
        !(scope == ReconScope::LIVE_MEMPOOL && resp.context_id.IsNull())) {
        std::vector<CTransactionRef> merged =
            GetScopedTransactions(scope, resp.context_id);
        merged.insert(merged.end(), valid_txs.begin(), valid_txs.end());
        SetScopedTransactions(scope, resp.context_id, std::move(merged));
    }

    for (const auto &tx : accepted_txs) {
        m_peerman.RelayTransaction(tx->GetId());
    }
}

V2ProtocolHandlerStats V2PeerProtocolHandler::GetStats() const {
    LOCK(m_mutex);
    return m_stats;
}

std::optional<CInv> V2PeerProtocolHandler::GetLastFallbackInv() const {
    LOCK(m_mutex);
    return m_last_fallback_inv;
}

} // namespace lotus::v2::net
