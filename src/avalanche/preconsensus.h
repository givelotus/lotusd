// Copyright (c) 2024-2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AVALANCHE_PRECONSENSUS_H
#define BITCOIN_AVALANCHE_PRECONSENSUS_H

#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace avalanche {

/**
 * MempoolBatchAnnouncement represents a pre-consensus epoch batch header
 * (168 bytes) polled via Avalanche using MSG_AVA_MEMPOOL_BATCH.
 */
struct MempoolBatchAnnouncement {
    static constexpr size_t SERIALIZED_SIZE = 168;

    BlockHash prev_block_hash{};
    uint32_t epoch_seq{0};
    uint256 parent_batch_id{uint256::ZERO};
    uint256 subtree_a_root{uint256::ZERO};
    uint256 utxo_root{uint256::ZERO};
    uint32_t tx_count{0};
    uint256 short_ids_hash{uint256::ZERO};

    MempoolBatchAnnouncement() = default;
    MempoolBatchAnnouncement(const BlockHash &_prev_block_hash,
                             uint32_t _epoch_seq,
                             const uint256 &_parent_batch_id,
                             const uint256 &_subtree_a_root,
                             const uint256 &_utxo_root,
                             uint32_t _tx_count,
                             const uint256 &_short_ids_hash)
        : prev_block_hash(_prev_block_hash), epoch_seq(_epoch_seq),
          parent_batch_id(_parent_batch_id), subtree_a_root(_subtree_a_root),
          utxo_root(_utxo_root), tx_count(_tx_count),
          short_ids_hash(_short_ids_hash) {}

    SERIALIZE_METHODS(MempoolBatchAnnouncement, obj) {
        READWRITE(obj.prev_block_hash, obj.epoch_seq, obj.parent_batch_id,
                  obj.subtree_a_root, obj.utxo_root, obj.tx_count,
                  obj.short_ids_hash);
    }

    bool IsValid() const { return !prev_block_hash.IsNull() && tx_count > 0; }

    /**
     * Compute the 32-byte batch ID via TaggedHash(HashDomain::PreconsensusBatch, ...)
     * over the 168-byte announcement header.
     */
    uint256 ComputeBatchId() const;

    friend bool operator==(const MempoolBatchAnnouncement &a,
                           const MempoolBatchAnnouncement &b) {
        return a.prev_block_hash == b.prev_block_hash &&
               a.epoch_seq == b.epoch_seq &&
               a.parent_batch_id == b.parent_batch_id &&
               a.subtree_a_root == b.subtree_a_root &&
               a.utxo_root == b.utxo_root && a.tx_count == b.tx_count &&
               a.short_ids_hash == b.short_ids_hash;
    }

    friend bool operator!=(const MempoolBatchAnnouncement &a,
                           const MempoolBatchAnnouncement &b) {
        return !(a == b);
    }
};

/**
 * Compute the V2 Merklix Subtree-A root for a set of non-coinbase transactions.
 */
uint256 ComputeV2SubtreeARoot(
    const std::vector<CTransactionRef> &non_coinbase_txs);

/**
 * Combine a coinbase transaction and a pre-computed Subtree-A root into the V2
 * block TransactionRoot in O(1) (one domain-separated leaf hash + root hash).
 */
uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const uint256 &subtree_a_root);

/**
 * Vote item wrapper for pre-consensus epoch batches in AnyVoteItem.
 */
struct MempoolBatchVoteItem : public uint256 {
    constexpr MempoolBatchVoteItem() : uint256() {}
    constexpr explicit MempoolBatchVoteItem(const uint256 &b) : uint256(b) {}
    explicit MempoolBatchVoteItem(const MempoolBatchAnnouncement &announcement)
        : uint256(announcement.ComputeBatchId()) {}

    uint256 GetId() const { return uint256(*this); }
    uint256 GetBatchId() const { return uint256(*this); }
    bool isNull() const { return IsNull(); }

    static MempoolBatchVoteItem fromHex(const std::string &str) {
        return MempoolBatchVoteItem(uint256S(str));
    }
};

} // namespace avalanche

#endif // BITCOIN_AVALANCHE_PRECONSENSUS_H
