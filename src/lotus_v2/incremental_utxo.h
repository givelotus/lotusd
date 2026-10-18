// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_INCREMENTAL_UTXO_H
#define LOTUS_V2_INCREMENTAL_UTXO_H

#include "sparse_state.h"

#include <cstddef>
#include <memory>

namespace lotus::v2 {

// In-memory path-local version of P02's collapsed sparse tree. The scalar
// UtxoSet remains the independent oracle. No disk or block undo is implied.
class IncrementalUtxoSet {
public:
    IncrementalUtxoSet();
    ~IncrementalUtxoSet();
    IncrementalUtxoSet(const IncrementalUtxoSet &) = delete;
    IncrementalUtxoSet &operator=(const IncrementalUtxoSet &) = delete;
    IncrementalUtxoSet(IncrementalUtxoSet &&) noexcept;
    IncrementalUtxoSet &operator=(IncrementalUtxoSet &&) noexcept;

    bool Insert(const Coin &coin);
    bool Erase(const Outpoint &outpoint);
    Hash Root() const;
    CoinProof Prove(const Outpoint &query) const;
    size_t Size() const { return size_; }

private:
    struct Node;
    static std::unique_ptr<Node> MakeLeaf(const Coin &coin, const Hash &key,
                                          const Hash &leaf_hash);
    static std::unique_ptr<Node> JoinLeaves(std::unique_ptr<Node> &existing,
                                            std::unique_ptr<Node> added,
                                            unsigned depth);
    static bool InsertAt(std::unique_ptr<Node> &node, const Coin &coin,
                         const Hash &key, const Hash &leaf_hash, unsigned depth);
    static bool EraseAt(std::unique_ptr<Node> &node, const Outpoint &outpoint,
                        const Hash &key, unsigned depth);

    std::unique_ptr<Node> root_;
    size_t size_{};
};

} // namespace lotus::v2
#endif
