// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_VALIDATION_QUEUE_MEMORY_H
#define BITCOIN_UTIL_VALIDATION_QUEUE_MEMORY_H
#include <coins.h>
#include <core_memusage.h>
#include <memory>
#include <vector>
namespace validation_queue {
inline size_t TxBytes(const CTransactionRef &tx) {
    return RecursiveDynamicUsage(tx);
}
inline size_t BlockBytes(const std::shared_ptr<const CBlock> &block) {
    if (!block) return 0;
    size_t bytes =
        memusage::DynamicUsage(block) + memusage::DynamicUsage(block->vtx);
    for (const auto &tx : block->vtx)
        bytes += TxBytes(tx);
    return bytes;
}
inline size_t CoinBytes(const std::shared_ptr<const std::vector<Coin>> &coins) {
    if (!coins) return 0;
    size_t bytes =
        memusage::DynamicUsage(coins) + memusage::DynamicUsage(*coins);
    for (const auto &coin : *coins)
        bytes += coin.DynamicMemoryUsage();
    return bytes;
}
} // namespace validation_queue
#endif // BITCOIN_UTIL_VALIDATION_QUEUE_MEMORY_H
