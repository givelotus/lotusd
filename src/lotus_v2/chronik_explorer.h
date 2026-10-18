// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CHRONIK_EXPLORER_H
#define LOTUS_V2_CHRONIK_EXPLORER_H
#include "transaction.h"
#include <span>
namespace lotus::v2 {
struct ChronikWireRange {
    uint64_t offset{}, length{};
    bool operator==(const ChronikWireRange &) const = default;
};
struct ChronikWitness {
    ChronikWireRange script, siblings_table;
    uint32_t siblings_count{};
    ChronikWireRange arguments_table;
    uint32_t arguments_count{};
};
struct ChronikFullInput {
    Hash32 prev_txid{};
    uint32_t prev_index{}, sequence{};
    uint8_t flags{}, path_index{};
    bool has_coinbase_data{};
    ChronikWireRange coinbase_data;
    std::vector<ChronikWitness> witnesses;
};
// Derive locations only from a native-decoded transaction. Re-encoding must
// match the entire exact source frame before any facts are published. This
// does not parse unknown bytes or resolve historical coins; DB staging owns
// resolution against its historical outputs and in-block writes.
bool MakeChronikExplorerFacts(const Transaction &, const TxProfile &,
                              std::span<const uint8_t> source,
                              std::vector<uint8_t> &wire,
                              std::vector<ChronikFullInput> &inputs,
                              std::string &error);
} // namespace lotus::v2
#endif
