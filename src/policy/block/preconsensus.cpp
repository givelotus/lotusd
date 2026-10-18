// Copyright (c) 2024 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/block/preconsensus.h>

#include <avalanche/preconsensus.h>
#include <avalanche/processor.h>
#include <blockindex.h>
#include <consensus/merkle.h>
#include <kernel/disconnected_transactions.h>
#include <util/hasher.h>

#include <unordered_map>
#include <stdexcept>

bool PreConsensusPolicy::operator()(BlockPolicyValidationState &state) {
    if (!m_blockIndex.pprev) {
        return true;
    }
    if (!m_avalanche.isQuorumEstablished() ||
        !m_avalanche.isPreconsensusActivated(m_blockIndex.pprev)) {
        return true;
    }

    // Verify block compliance against any finalized pre-consensus mempool
    // batches for m_blockIndex.pprev->GetBlockHash().
    const auto finalizedBatches = m_avalanche.getFinalizedMempoolBatches(
        m_blockIndex.pprev->GetBlockHash());
    if (!finalizedBatches.empty()) {
        if (m_block.vtx.empty() || !m_block.vtx[0]) {
            return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                                 "finalized-batch-missing-coinbase",
                                 "Block is missing coinbase transaction");
        }
        // Match any finalized batch for this parent, independent of the
        // latest batch's size. Native headers commit coinbase plus SubtreeA.
        uint256 blockMerkleRoot;
        try {
            blockMerkleRoot = m_block.hashMerkleRoot.IsNull()
                                  ? BlockMerkleRoot(m_block)
                                  : m_block.hashMerkleRoot;
        } catch (const std::invalid_argument &) {
            return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                                 "finalized-batch-mismatch",
                                 "Block contains duplicate transaction identifiers");
        }
        bool matchedFinalizedBatch = false;
        for (const auto &batch : finalizedBatches) {
            const uint256 expectedRoot = avalanche::ComputeV2TxRootFromSubtreeA(
                *m_block.vtx[0], batch.subtree_a_root);
            if (expectedRoot == blockMerkleRoot) {
                matchedFinalizedBatch = true;
                break;
            }
        }
        if (!matchedFinalizedBatch) {
            return state.Invalid(
                BlockPolicyValidationResult::POLICY_VIOLATION,
                "finalized-batch-mismatch",
                strprintf("Block %s merkle root does not match finalized "
                          "mempool batch subtree_a_root",
                          m_block.GetHash().ToString()));
        }
    }

    if (!m_mempool) {
        return true;
    }

    AssertLockHeld(m_mempool->cs);

    // Finalized txs mined into a non-finalized block are removed from
    // mapNextTx, so GetConflictTx alone cannot see them during a reorg.
    // Build an outpoint index from disconnectpool entries that are still
    // preconsensus-finalized.
    std::unordered_map<COutPoint, TxId, SaltedOutpointHasher>
        finalizedDisconnectedSpends;
    if (m_disconnectpool) {
        for (const CTransactionRef &tx : m_disconnectpool->GetQueuedTx()) {
            const TxId txid = tx->GetId();
            // A coinbase tx can't be finalized, but this saves a lookup
            if (tx->IsCoinBase() ||
                !m_mempool->isAvalancheFinalizedPreConsensus(txid)) {
                continue;
            }
            for (const CTxIn &txin : tx->vin) {
                finalizedDisconnectedSpends.emplace(txin.prevout, txid);
            }
        }
    }

    auto rejectConflict = [&](const TxId &txid, const TxId &conflictingId) {
        return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                             "finalized-tx-conflict",
                             strprintf("Block %s contains tx %s that conflicts "
                                       "with finalized tx %s",
                                       m_block.GetHash().ToString(),
                                       txid.ToString(),
                                       conflictingId.ToString()));
    };

    // TODO Use a CoinViewCache
    for (const auto &tx : m_block.vtx) {
        const TxId txid = tx->GetId();
        for (const auto &txin : tx->vin) {
            const CTransactionRef ptxConflicting =
                m_mempool->GetConflictTx(txin.prevout);

            // Only allow for the exact txid for each coin spent
            if (ptxConflicting && ptxConflicting->GetId() != txid &&
                m_mempool->isAvalancheFinalizedPreConsensus(
                    ptxConflicting->GetId())) {
                return rejectConflict(txid, ptxConflicting->GetId());
            }

            auto it = finalizedDisconnectedSpends.find(txin.prevout);
            if (it != finalizedDisconnectedSpends.end() && it->second != txid) {
                return rejectConflict(txid, it->second);
            }
        }
    }

    return true;
}
