// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_TRANSACTION_POOL_H
#define LOTUS_V2_TRANSACTION_POOL_H
#include "block_cost.h"
#include <set>
#include <deque>
#include <optional>
namespace lotus::v2 {
struct PoolAnchor { Hash tip{}; uint64_t generation{}; bool operator==(const PoolAnchor &) const = default; };
enum class PoolMissingState { Unknown, Spent, Error };
struct PoolContext {
    PoolAnchor anchor;
    OrdinaryCandidateProfile profile;
    ChainId chain_id;
    CoinLookup active_coins;
    // Must fence the same backend snapshot used by active_coins. Serialized
    // callers only: callbacks must not reenter or mutate this pool.
    std::function<bool()> current;
    BlockCostProfile cost;
    std::function<PoolMissingState(const Outpoint &, std::string &)> classify_missing;
};
struct PoolLimits {
    size_t max_transaction_bytes = 1000000, max_entries = 1000;
    size_t max_bytes = 16000000, max_edges = 10000;
    size_t max_ancestors = 100, max_descendants = 100;
    uint64_t max_transaction_cost = 100000000;
};
struct PoolBudget { size_t validations = 1; VmCostUnits invocation_cost = 1000000; };
enum class PoolStatus { Accepted, Duplicate, Conflict, MissingParents, Invalid, Capacity, Stale, Operational };
struct PoolResult {
    PoolStatus status = PoolStatus::Operational;
    Hash txid{}, txhash{};
    std::vector<Outpoint> missing;
    std::string error;
};
struct PoolEntry {
    std::vector<uint8_t> wire;
    OrdinaryCandidateEffects effects;
    TransactionCosts costs;
    std::set<Hash> parents;
};
struct PoolSnapshot {
    PoolStatus status = PoolStatus::Stale;
    PoolAnchor anchor;
    std::vector<PoolEntry> entries;
};
// Initial policy forbids replacement. First accepted witness for a TxID wins;
// another TxHash for that TxID returns Conflict. Missing inputs are retriable.
class TransactionPool {
public:
    explicit TransactionPool(PoolLimits limits) : limits_(limits) {}
    PoolResult Admit(const std::vector<uint8_t> &, const PoolContext &, PoolBudget &);
    PoolSnapshot Snapshot(PoolAnchor, size_t max_entries, size_t max_bytes) const;
    bool ReadWire(const Hash &txhash, std::vector<uint8_t> &out) const;
    bool SelectedHash(const Hash &txid, Hash &out) const;
    std::vector<Hash> Inventory(size_t offset, size_t count) const;
    // Rebuild against the NEW authoritative anchor, even when old==new.
    // Operational/stale/capacity failures preserve data but disable every read
    // until a successful retry. Detached wires are ordinary transactions only.
    // Repeated calls with identical anchor/inputs resume a bounded rebuild.
    // Capacity with ReconcilePending() means fresh budget can make progress;
    // other failures discard staging. Changed anchor/inputs restart safely.
    PoolResult Reconcile(const PoolContext &, const std::set<Hash> &connected,
                         const std::vector<Outpoint> &connected_spends,
                         const std::vector<std::vector<uint8_t>> &detached,
                         PoolBudget &);
    // True only while a budget-limited rebuild can resume.
    bool ReconcilePending() const { return rebuild_.has_value(); }
    size_t Size() const { return entries_.size(); }
    bool Enabled() const { return enabled_; }
private:
    struct Rebuild {
        PoolAnchor anchor;
        std::set<Hash> connected;
        std::vector<Outpoint> connected_spends;
        std::vector<std::vector<uint8_t>> detached, wires;
        std::vector<std::vector<size_t>> children;
        std::vector<size_t> remaining;
        std::deque<size_t> ready;
        size_t bytes=0, edges=0;
        std::map<Hash, PoolEntry> entries;
        std::map<Hash, Hash> hashes;
        std::map<Outpoint, Hash, OutpointLess> spends;
    };
    std::optional<Rebuild> rebuild_;
    PoolLimits limits_;
    PoolAnchor anchor_{};
    bool anchored_ = false, enabled_ = true;
    size_t bytes_ = 0, edges_ = 0;
    std::map<Hash, PoolEntry> entries_;
    std::map<Hash, Hash> hashes_;
    std::map<Outpoint, Hash, OutpointLess> spends_;
};
}
#endif
