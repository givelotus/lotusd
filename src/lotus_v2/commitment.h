// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_COMMITMENT_H
#define LOTUS_V2_COMMITMENT_H

#include "header.h"

#include <array>
#include <cstdint>
#include <span>

namespace lotus::v2 {

// Inputs are canonical serialized P01 components supplied by the transaction
// codec. These functions hash bytes; they do not validate their grammar.
Hash InputCoreLeaf(std::span<const uint8_t> encoded_input_core);
Hash InputFullLeaf(std::span<const uint8_t> encoded_input);
Hash OutputLeaf(std::span<const uint8_t> serialized_output);
Hash CoinEntryLeaf(std::span<const uint8_t> serialized_resolved_output);
Hash BranchLeaf(std::span<const uint8_t> script);
Hash BranchNode(const Hash &a, const Hash &b);
// The selector leaf of a v7 input spending a legacy coin (the legacy bridge):
// TaggedHash(Branch, 0x03 || CS(|coin_script|) || coin_script
//                         || CS(|witness_script|) || witness_script).
// Prefix 0x03 differs from leaf 0x00 and node 0x01, so no V2 branch leaf
// equals it; it commits to the coin's template and to the redeem script.
Hash LegacyBridgeLeaf(std::span<const uint8_t> coin_script,
                      std::span<const uint8_t> witness_script);
Hash BranchProofRoot(const Hash &leaf, std::span<const Hash> bottom_up_siblings);

Hash IndexedNode(uint16_t layer, const Hash &left, const Hash &right);
Hash IndexedTreeRoot(std::span<const Hash> leaves);
// Proof contains one sibling per layer. Missing right children must be zero.
bool IndexedProofRoot(const Hash &leaf, uint32_t index, uint32_t count,
                      std::span<const Hash> bottom_up_siblings, Hash &out);

using TxHeaderCore = std::array<uint8_t, 16>;
Hash TransactionId(const ChainId &chain_id, const TxHeaderCore &header_core,
                   const Hash &inputs_root, const Hash &outputs_root);
Hash TransactionHash(const ChainId &chain_id, const TxHeaderCore &header_core,
                     const Hash &full_inputs_root, const Hash &outputs_root);

struct TxIdentityPair {
    Hash tx_hash;
    Hash tx_id;
};
// Defined for the empty vector as a tool primitive. Block validity requires
// a coinbase and imposes its own transaction-count limit.
bool TransactionRoot(std::span<const TxIdentityPair> transactions, Hash &out);
// Optimization (rolled into initial commitment primitives): expose O(1)
// Subtree A root and coinbase-combining helpers so block assembly, sealed
// header relay (sealedheader), and RCU mining snapshots reuse precomputed
// non-coinbase Subtree A roots without O(N) transaction tree rebuilds.
Hash TransactionSubtreeARoot(
    std::span<const TxIdentityPair> non_coinbase_transactions);
Hash TransactionRootFromSubtreeA(const TxIdentityPair &coinbase_tx,
                                 const Hash &subtree_a_root);

// Precompute the depth-0 SubtreeA Merklix root over non-coinbase transactions.
Hash BuildTxSubtreeA(std::span<const TxIdentityPair> non_coinbase_transactions);

// Combine a coinbase transaction identity pair with a precomputed SubtreeA root
// in O(1) (single tagged BLAKE3 leaf + root hash).
Hash CombineCoinbaseAndSubtreeA(const TxIdentityPair &coinbase_tx,
                                const Hash &subtree_a_root);

} // namespace lotus::v2
#endif
