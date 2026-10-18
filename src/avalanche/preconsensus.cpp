// Copyright (c) 2024-2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/preconsensus.h>

#include <lotus_v2/commitment.h>
#include <lotus_v2/tagged_hash.h>
#include <streams.h>

#include <algorithm>
#include <cassert>
#include <cstring>

namespace avalanche {

uint256 MempoolBatchAnnouncement::ComputeBatchId() const {
    DataStream ss{};
    ss << *this;
    assert(ss.size() == SERIALIZED_SIZE);
    const auto digest = lotus::v2::TaggedHash(
        lotus::v2::HashDomain::PreconsensusBatch,
        std::span<const uint8_t>(UCharCast(ss.data()), ss.size()));
    uint256 result;
    std::memcpy(result.begin(), digest.data(), digest.size());
    return result;
}

uint256 ComputeV2SubtreeARoot(
    const std::vector<CTransactionRef> &non_coinbase_txs) {
    std::vector<CTransactionRef> sorted_txs = non_coinbase_txs;
    std::sort(sorted_txs.begin(), sorted_txs.end(),
              [](const CTransactionRef &a, const CTransactionRef &b) {
                  return a->GetId() < b->GetId();
              });
    std::vector<lotus::v2::TxIdentityPair> pairs;
    pairs.reserve(sorted_txs.size());
    for (const auto &tx : sorted_txs) {
        if (!tx || tx->IsCoinBase()) {
            continue;
        }
        lotus::v2::TxIdentityPair pair{};
        std::memcpy(pair.tx_hash.data(), tx->GetHash().begin(), 32);
        std::memcpy(pair.tx_id.data(), tx->GetId().begin(), 32);
        pairs.push_back(pair);
    }
    const lotus::v2::Hash root = lotus::v2::BuildTxSubtreeA(pairs);
    uint256 out;
    std::memcpy(out.begin(), root.data(), 32);
    return out;
}

uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const uint256 &subtree_a_root) {
    lotus::v2::TxIdentityPair cb_pair{};
    std::memcpy(cb_pair.tx_hash.data(), coinbase_tx.GetHash().begin(), 32);
    std::memcpy(cb_pair.tx_id.data(), coinbase_tx.GetId().begin(), 32);
    lotus::v2::Hash sub_a{};
    std::memcpy(sub_a.data(), subtree_a_root.begin(), 32);
    const lotus::v2::Hash root =
        lotus::v2::CombineCoinbaseAndSubtreeA(cb_pair, sub_a);
    uint256 out;
    std::memcpy(out.begin(), root.data(), 32);
    return out;
}

} // namespace avalanche
