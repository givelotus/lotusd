// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_POOL_COORDINATOR_H
#define LOTUS_V2_POOL_COORDINATOR_H
#include "development_runtime.h"
#include "transaction_history.h"
#include "transaction_pool.h"
namespace lotus::v2 {
struct PoolCoordinatorConfig {
    // Dedicated derived LevelDB path, normally chainstate-v2/transaction-index.
    std::string directory;
    Hash identity{}, profile_digest{};
    HeaderChainProfile headers;
    OrdinaryCandidateProfile ordinary;
    BlockCostProfile cost;
    PoolLimits pool;
    HistoryLimits history;
    leveldb::Env *history_env = nullptr; // Optional caller-owned storage backend.
    // Maximum durable history transitions in one Tick, independent of chain height.
    size_t max_path = 10000, max_detached_transactions = 10000;
    size_t max_detached_bytes = 16000000, max_block_bytes = 16000000;
};
struct PoolCoordinatorBudget {
    size_t header_reads = 32, blocks = 1;
    PoolBudget validation;
};
enum class CoordinatorResult { Ready, Progress, Deferred, Capacity, StorageError };
enum class TransactionState { Pending, Confirmed, Conflicted, Unknown, Inconclusive };
struct TransactionStatus {
    TransactionState state = TransactionState::Inconclusive;
    Hash txid{}, txhash{};
    std::optional<TransactionConfirmation> confirmation;
    std::string diagnostic;
};
// Serialized owner. Runtime mutations must not reenter any operation. A status
// is authoritative only at the same quiescent runtime/index/pool anchor.
class PoolCoordinator {
public:
    static bool Open(DevelopmentRuntime &, PoolCoordinatorConfig,
                     std::unique_ptr<PoolCoordinator> &, std::string &);
    ~PoolCoordinator();
    CoordinatorResult Tick(PoolCoordinatorBudget &, std::string &);
    PoolResult Submit(const std::vector<uint8_t> &, const Hash &expected_tip, PoolBudget &);
    PoolSnapshot Snapshot(size_t max_entries, size_t max_bytes) const;
    bool ReadWire(const Hash &txhash, std::vector<uint8_t> &out,
                  size_t max_bytes = 1000000) const;
    std::vector<Hash> Inventory(size_t offset, size_t count) const;
    bool SelectedHash(const Hash &txid, Hash &out) const;
    TransactionStatus Status(const Hash &txid, const std::optional<Hash> &txhash = {},
                             const std::vector<uint8_t> *wire = nullptr);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit PoolCoordinator(std::unique_ptr<Impl>);
};
}
#endif
