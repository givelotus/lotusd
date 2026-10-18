// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_TRANSACTION_HISTORY_H
#define LOTUS_V2_TRANSACTION_HISTORY_H
#include "sparse_state.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>
namespace leveldb { class Env; }
namespace lotus::v2 {
struct TransactionConfirmation {
    Hash txid{}, txhash{}, block{};
    uint64_t height{};
    std::vector<Outpoint> consumed;
};
struct HistoryBlock {
    Hash id{}, parent{};
    uint64_t height{};
    std::vector<TransactionConfirmation> transactions;
};
struct HistoryLimits {
    size_t max_transactions = 100000, max_block_bytes = 16000000;
};
// Derived index only. A synchronous batch commits rows, exact predecessor
// mappings and anchor together. Callers publish only after runtime tip fencing.
// Empty anchor means replay from genesis. No pruning or implicit migration.
class TransactionHistory {
public:
    TransactionHistory();
    ~TransactionHistory();
    TransactionHistory(TransactionHistory &&) noexcept;
    TransactionHistory &operator=(TransactionHistory &&) noexcept;
    static bool Open(const std::string &directory, const Hash &identity,
                     const Hash &profile, HistoryLimits,
                     TransactionHistory &out, std::string &error, leveldb::Env *env = nullptr);
    std::optional<Hash> Anchor() const;
    bool Lookup(const Hash &txid, std::optional<TransactionConfirmation> &,
                std::string &error) const;
    bool Spender(const Outpoint &, std::optional<Hash> &, std::string &error) const;
    bool Connect(const HistoryBlock &, std::string &error);
    bool Disconnect(const Hash &expected, std::string &error);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
#endif
