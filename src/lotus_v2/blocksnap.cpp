// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/blocksnap.h>

#include <blockencodings.h>
#include <crypto/sha256.h>
#include <hash.h>

#include <cstring>

namespace lotus::v2 {

namespace {

inline uint256 HashToUint256(const Hash &h) noexcept {
    uint256 out;
    std::memcpy(out.begin(), h.data(), 32);
    return out;
}

inline Hash Uint256ToHash(const uint256 &u) noexcept {
    Hash out{};
    std::memcpy(out.data(), u.begin(), 32);
    return out;
}

} // namespace

uint256 ComputeMerkleRootFromBranch(const uint256 &leaf,
                                    const std::vector<uint256> &branch,
                                    uint32_t index) noexcept {
    uint256 cur = leaf;
    uint8_t buf[64];
    for (const uint256 &sibling : branch) {
        if ((index & 1U) != 0) {
            std::memcpy(buf, sibling.begin(), 32);
            std::memcpy(buf + 32, cur.begin(), 32);
        } else {
            std::memcpy(buf, cur.begin(), 32);
            std::memcpy(buf + 32, sibling.begin(), 32);
        }
        SHA256D64(cur.begin(), buf, 1);
        index >>= 1U;
    }
    return cur;
}

void ComputeNullMerkleRootAndBranch(
    const std::vector<CTransactionRef> &sorted_txs,
    uint256 &null_merkle_root_out,
    std::vector<uint256> &coinbase_branch_out) {
    coinbase_branch_out.clear();
    if (sorted_txs.empty()) {
        null_merkle_root_out = uint256::ZERO;
        return;
    }

    const size_t total_leaves = 1 + sorted_txs.size();
    std::vector<uint256> level;
    level.reserve((total_leaves + 1) & ~size_t(1));
    level.push_back(uint256::ZERO);
    for (const auto &tx : sorted_txs) {
        level.push_back(tx ? tx->GetId() : uint256::ZERO);
    }

    while (level.size() > 1) {
        if (level.size() & 1U) {
            level.push_back(level.back());
        }
        coinbase_branch_out.push_back(level[1]);
        const size_t pairs = level.size() / 2;
        SHA256D64(level[0].begin(), level[0].begin(), pairs);
        level.resize(pairs);
    }
    null_merkle_root_out = level[0];
}

void ComputeBlockCoinbaseMerkleBranch(
    const CBlock &block, uint256 &null_merkle_root_out,
    std::vector<uint256> &coinbase_branch_out) {
    if (block.vtx.size() <= 1) {
        null_merkle_root_out = uint256::ZERO;
        coinbase_branch_out.clear();
        return;
    }
    std::vector<CTransactionRef> non_cb(block.vtx.begin() + 1, block.vtx.end());
    ComputeNullMerkleRootAndBranch(non_cb, null_merkle_root_out,
                                   coinbase_branch_out);
}

SealedBlock::SealedBlock(const CBlock &block,
                         std::vector<uint256> epoch_batch_ids_in)
    : header(block.GetBlockHeader()),
      tx_coinbase(block.vtx.empty() ? CTransactionRef{} : block.vtx[0]),
      epoch_batch_ids(std::move(epoch_batch_ids_in)) {
    uint256 unused_null_root;
    ComputeBlockCoinbaseMerkleBranch(block, unused_null_root,
                                     coinbase_merkle_branch);
}

SealedBlock::SealedBlock(const CBlockHeader &header_in,
                         CTransactionRef coinbase_in,
                         std::vector<uint256> branch_in,
                         std::vector<uint256> epoch_ids_in)
    : header(header_in), tx_coinbase(std::move(coinbase_in)),
      coinbase_merkle_branch(std::move(branch_in)),
      epoch_batch_ids(std::move(epoch_ids_in)) {}

SealedBlock::SealedBlock(const CBlockHeader &header_in,
                         CTransactionRef coinbase_in,
                         const MempoolOverlayLayer &layer)
    : header(header_in), tx_coinbase(std::move(coinbase_in)) {
    const auto &layer_branch = layer.GetCoinbaseMerkleBranch();
    coinbase_merkle_branch.reserve(layer_branch.size());
    for (const Hash &h : layer_branch) {
        coinbase_merkle_branch.push_back(HashToUint256(h));
    }
    epoch_batch_ids.push_back(HashToUint256(layer.GetSubtreeARoot()));
}

bool SealedBlock::VerifyMerkleSpine(
    const uint256 &local_null_merkle_root) const noexcept {
    if (!IsValid()) {
        return false;
    }
    const uint256 computed_null_root = ComputeMerkleRootFromBranch(
        uint256::ZERO, coinbase_merkle_branch, /*index=*/0);
    if (computed_null_root != local_null_merkle_root) {
        return false;
    }
    const uint256 computed_merkle_root = ComputeMerkleRootFromBranch(
        tx_coinbase->GetId(), coinbase_merkle_branch, /*index=*/0);
    return computed_merkle_root == header.hashMerkleRoot;
}

bool SealedBlock::VerifyAgainstLayer(const MempoolOverlayLayer &layer) const {
    if (!IsValid()) {
        return false;
    }
    const Hash cb_tx_id = Uint256ToHash(tx_coinbase->GetId());
    if (layer.Contains(cb_tx_id)) {
        return false;
    }
    const auto &layer_branch = layer.GetCoinbaseMerkleBranch();
    if (coinbase_merkle_branch.size() != layer_branch.size()) {
        return false;
    }
    const uint256 local_null_root = HashToUint256(layer.GetNullMerkleRoot());
    return VerifyMerkleSpine(local_null_root);
}

std::shared_ptr<const CBlock>
SealedBlock::ReconstructBlock(const MempoolOverlayLayer &layer) const {
    if (!VerifyAgainstLayer(layer)) {
        return nullptr;
    }
    auto block = std::make_shared<CBlock>(header);
    block->vtx.reserve(1 + layer.GetTxCount());
    block->vtx.push_back(tx_coinbase);
    for (const auto &[_, oentry] : layer.GetOrderedTxs()) {
        CTransactionRef tx =
            std::static_pointer_cast<const CTransaction>(oentry.tx_ref);
        if (!tx) {
            return nullptr;
        }
        block->vtx.push_back(std::move(tx));
    }
    // CheckBlock must still check the Merkle root and duplicate-tail mutation.
    return block;
}

std::shared_ptr<const CBlock>
SealedBlock::ReconstructBlock(const MerklixOverlayManager &mgr) const {
    if (!IsValid()) {
        return nullptr;
    }
    const auto &frozen = mgr.GetFrozenEpochs();
    if (!epoch_batch_ids.empty()) {
        for (const uint256 &target_id : epoch_batch_ids) {
            const Hash target_hash = Uint256ToHash(target_id);
            for (auto it = frozen.rbegin(); it != frozen.rend(); ++it) {
                if (it->GetSubtreeARoot() == target_hash ||
                    it->GetNullMerkleRoot() == target_hash) {
                    if (auto blk = ReconstructBlock(*it)) {
                        return blk;
                    }
                }
            }
            const auto &spec = mgr.GetSpeculativeOverlay();
            if (spec.GetSubtreeARoot() == target_hash ||
                spec.GetNullMerkleRoot() == target_hash) {
                if (auto blk = ReconstructBlock(spec)) {
                    return blk;
                }
            }
        }
    }

    for (auto it = frozen.rbegin(); it != frozen.rend(); ++it) {
        if (auto blk = ReconstructBlock(*it)) {
            return blk;
        }
    }
    return ReconstructBlock(mgr.GetSpeculativeOverlay());
}

} // namespace lotus::v2
