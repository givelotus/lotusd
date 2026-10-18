// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOTUS_V2_BLOCKSNAP_H
#define BITCOIN_LOTUS_V2_BLOCKSNAP_H

#include <lotus_v2/mempool_overlay.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace lotus::v2 {

/**
 * Compute the positional SHA-256d Merkle root from a leaf hash at `index`
 * (0 for the coinbase slot along the leftmost spine) and its sibling hashes
 * `branch` from bottom (leaf level) to top.
 */
uint256 ComputeMerkleRootFromBranch(const uint256 &leaf,
                                    const std::vector<uint256> &branch,
                                    uint32_t index = 0) noexcept;

/**
 * Given a CTOR-sorted list of non-coinbase transactions, run a single flat
 * SHA-256d pass with a placeholder `uint256::ZERO` leaf at index 0 to compute:
 * - `null_merkle_root_out`: positional Merkle root with `uint256::ZERO` at slot 0.
 * - `coinbase_branch_out`: the ceil(log2(N + 1)) (<= 16) sibling hashes along
 *   the leftmost spine.
 */
void ComputeNullMerkleRootAndBranch(
    const std::vector<CTransactionRef> &sorted_txs,
    uint256 &null_merkle_root_out,
    std::vector<uint256> &coinbase_branch_out);

/**
 * Extract the leftmost-spine `coinbase_merkle_branch` and `null_merkle_root`
 * directly from an assembled `CBlock` (`block.vtx[1..N]`).
 */
void ComputeBlockCoinbaseMerkleBranch(
    const CBlock &block, uint256 &null_merkle_root_out,
    std::vector<uint256> &coinbase_branch_out);

/**
 * Fixed-size BlockSnap (`SealedBlock`) announcement for standard 80-byte
 * headers and positional SHA-256d Merkle trees (~1.2 KB regardless of block
 * size).
 *
 * Carries:
 * - Standard 80-byte `CBlockHeader`
 * - `CTransactionRef tx_coinbase`
 * - `std::vector<uint256> coinbase_merkle_branch` (<= 16 spine siblings)
 * - `std::vector<uint256> epoch_batch_ids`
 *
 * Receiver verification (in O(log N) <= 16 SHA-256d hashes, zero tx re-hashing):
 * 1. `ComputeMerkleRootFromBranch(uint256::ZERO, coinbase_merkle_branch, 0) == local_epoch.null_merkle_root`
 *    (proves the miner used the exact same transaction set and authenticates the spine siblings)
 * 2. `ComputeMerkleRootFromBranch(tx_coinbase->GetId(), coinbase_merkle_branch, 0) == header.hashMerkleRoot`
 *    (proves `header.hashMerkleRoot` commits to `tx_coinbase` + the pre-synced epoch transactions)
 */
class SealedBlock {
public:
    static constexpr size_t MAX_MERKLE_BRANCH_DEPTH = 32;
    static constexpr size_t MAX_EPOCH_BATCH_IDS = 16;

    CBlockHeader header;
    CTransactionRef tx_coinbase;
    std::vector<uint256> coinbase_merkle_branch;
    std::vector<uint256> epoch_batch_ids;

    SealedBlock() = default;
    explicit SealedBlock(const CBlock &block,
                         std::vector<uint256> epoch_batch_ids_in = {});
    SealedBlock(const CBlockHeader &header_in, CTransactionRef coinbase_in,
                std::vector<uint256> branch_in = {},
                std::vector<uint256> epoch_ids_in = {});
    SealedBlock(const CBlockHeader &header_in, CTransactionRef coinbase_in,
                const MempoolOverlayLayer &layer);

    bool IsValid() const noexcept {
        return !header.IsNull() && tx_coinbase != nullptr &&
               !tx_coinbase->IsNull() && tx_coinbase->IsCoinBase() &&
               coinbase_merkle_branch.size() <= MAX_MERKLE_BRANCH_DEPTH &&
               epoch_batch_ids.size() <= MAX_EPOCH_BATCH_IDS;
    }

    /**
     * Authenticate both the transaction set (via `local_null_merkle_root`) and
     * the block header's `hashMerkleRoot` (via `tx_coinbase->GetId()`) using
     * only the leftmost Merkle spine.
     */
    bool VerifyMerkleSpine(const uint256 &local_null_merkle_root) const noexcept;

    /**
     * Verify this `SealedBlock` against a frozen or speculative
     * `MempoolOverlayLayer` in O(log N) (<= 16 SHA-256d hashes).
     */
    bool VerifyAgainstLayer(const MempoolOverlayLayer &layer) const;

    /**
     * Materialize a `CBlock` after the fast overlay Merkle-spine check.
     * `CheckBlock` must still validate its transaction Merkle root and check
     * for duplicate-tail mutation before trusting the reconstructed body.
     */
    std::shared_ptr<const CBlock>
    ReconstructBlock(const MempoolOverlayLayer &layer) const;

    /**
     * Search `mgr`'s frozen epoch layers and speculative layer (prioritizing
     * any `epoch_batch_ids` match) and reconstruct the full `CBlock` in O(1).
     */
    std::shared_ptr<const CBlock>
    ReconstructBlock(const MerklixOverlayManager &mgr) const;

    SERIALIZE_METHODS(SealedBlock, obj) {
        READWRITE(obj.header, Using<DefaultFormatter>(obj.tx_coinbase),
                  obj.coinbase_merkle_branch, obj.epoch_batch_ids);
    }
};

} // namespace lotus::v2

#endif // BITCOIN_LOTUS_V2_BLOCKSNAP_H
