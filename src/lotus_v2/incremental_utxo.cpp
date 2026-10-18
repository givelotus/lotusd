#include "incremental_utxo.h"

#include <array>
#include <cassert>
#include <utility>
#include <vector>


namespace lotus::v2 {
namespace {
bool KeyBit(const Hash &key, unsigned depth) {
    assert(depth < 256);
    return (key[depth / 8] >> (depth % 8)) & 1;
}

void SetBit(Hash &bitmap, unsigned depth) {
    assert(depth < 256);
    bitmap[depth / 8] |= uint8_t{1} << (depth % 8);
}

Hash NodeHash(unsigned depth, const Hash &left, const Hash &right) {
    Hash out;
    const bool valid = UtxoNode(depth, left, right, out);
    assert(valid);
    (void)valid;
    return out;
}
} // namespace

struct IncrementalUtxoSet::Node {
    Hash digest{};
    size_t count{};
    Hash key{};
    std::unique_ptr<Coin> coin;
    std::array<std::unique_ptr<Node>, 2> child;

    bool IsLeaf() const { return coin != nullptr; }
    Hash ChildHash(unsigned bit) const {
        return child[bit] ? child[bit]->digest : EmptyUtxoRoot();
    }
    void Refresh(unsigned depth) {
        digest = NodeHash(depth, ChildHash(0), ChildHash(1));
    }
};

IncrementalUtxoSet::IncrementalUtxoSet() = default;
IncrementalUtxoSet::~IncrementalUtxoSet() = default;
IncrementalUtxoSet::IncrementalUtxoSet(IncrementalUtxoSet &&other) noexcept
    : root_(std::move(other.root_)), size_(other.size_) {
    other.size_ = 0;
}
IncrementalUtxoSet &
IncrementalUtxoSet::operator=(IncrementalUtxoSet &&other) noexcept {
    if (this != &other) {
        root_ = std::move(other.root_);
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

std::unique_ptr<IncrementalUtxoSet::Node>
IncrementalUtxoSet::MakeLeaf(const Coin &coin, const Hash &key,
                             const Hash &leaf_hash) {
    auto node = std::make_unique<Node>();
    node->digest = leaf_hash;
    node->count = 1;
    node->key = key;
    node->coin = std::make_unique<Coin>(coin);
    return node;
}

std::unique_ptr<IncrementalUtxoSet::Node>
IncrementalUtxoSet::JoinLeaves(std::unique_ptr<Node> &existing,
                               std::unique_ptr<Node> added, unsigned depth) {
    assert(depth < 256 && existing->IsLeaf() && added->IsLeaf());
    assert(existing->key != added->key);
    const Hash old_key = existing->key;
    unsigned split = depth;
    while (KeyBit(existing->key, split) == KeyBit(added->key, split)) {
        ++split;
        assert(split < 256); // Different 256-bit keys must differ by bit 255.
    }
    // Allocate the entire new path before moving the old leaf. An allocation
    // failure therefore cannot remove an existing coin from the tree.
    std::vector<std::unique_ptr<Node>> branches;
    branches.reserve(split - depth + 1);
    for (unsigned d = depth; d <= split; ++d) branches.push_back(std::make_unique<Node>());
    auto subtree = std::move(branches.back());
    subtree->count = 2;
    const unsigned old_bit = KeyBit(existing->key, split);
    subtree->child[old_bit] = std::move(existing);
    subtree->child[1 - old_bit] = std::move(added);
    subtree->Refresh(split);
    for (unsigned d = split; d-- > depth;) {
        auto parent = std::move(branches[d - depth]);
        parent->count = 2;
        // Both leaves share bit d, so the old leaf's cached key selects the
        // only nonempty child at this level.
        parent->child[KeyBit(old_key, d)] = std::move(subtree);
        parent->Refresh(d);
        subtree = std::move(parent);
    }
    return subtree;
}

bool IncrementalUtxoSet::InsertAt(std::unique_ptr<Node> &node,
                                  const Coin &coin, const Hash &key,
                                  const Hash &leaf_hash, unsigned depth) {
    if (!node) {
        node = MakeLeaf(coin, key, leaf_hash);
        return true;
    }
    if (node->IsLeaf()) {
        // Same-key different-outpoint collision and identical outpoints both
        // reject before any mutation. No merge or overwrite is possible.
        if (node->key == key) return false;
        auto added = MakeLeaf(coin, key, leaf_hash);
        node = JoinLeaves(node, std::move(added), depth);
        return true;
    }
    if (depth >= 256) return false;
    if (!InsertAt(node->child[KeyBit(key, depth)], coin, key, leaf_hash, depth + 1)) return false;
    ++node->count;
    node->Refresh(depth);
    return true;
}

bool IncrementalUtxoSet::EraseAt(std::unique_ptr<Node> &node,
                                 const Outpoint &outpoint, const Hash &key,
                                 unsigned depth) {
    if (!node) return false;
    if (node->IsLeaf()) {
        if (node->key != key || node->coin->outpoint != outpoint) return false;
        node.reset();
        return true;
    }
    if (depth >= 256) return false;
    if (!EraseAt(node->child[KeyBit(key, depth)], outpoint, key, depth + 1)) return false;
    --node->count;
    if (node->count == 1) {
        const unsigned remaining = node->child[0] ? 0 : 1;
        assert(node->child[remaining] && node->child[remaining]->IsLeaf());
        auto survivor = std::move(node->child[remaining]);
        node = std::move(survivor);
    } else {
        node->Refresh(depth);
    }
    return true;
}

bool IncrementalUtxoSet::Insert(const Coin &coin) {
    Hash leaf_hash;
    if (!UtxoLeaf(coin, leaf_hash)) return false; // Includes output validation and burn pruning.
    const Hash key = OutpointKey(coin.outpoint);
    if (!InsertAt(root_, coin, key, leaf_hash, 0)) return false;
    ++size_;
    return true;
}

bool IncrementalUtxoSet::Erase(const Outpoint &outpoint) {
    if (!EraseAt(root_, outpoint, OutpointKey(outpoint), 0)) return false;
    --size_;
    return true;
}

Hash IncrementalUtxoSet::Root() const {
    return root_ ? root_->digest : EmptyUtxoRoot();
}

CoinProof IncrementalUtxoSet::Prove(const Outpoint &query) const {
    CoinProof proof;
    const Hash key = OutpointKey(query);
    const Node *node = root_.get();
    std::vector<std::pair<unsigned, Hash>> ancestors;
    unsigned depth = 0;
    while (node && !node->IsLeaf()) {
        assert(depth < 256);
        const unsigned bit = KeyBit(key, depth);
        ancestors.emplace_back(depth, node->ChildHash(1 - bit));
        node = node->child[bit].get();
        ++depth;
    }
    if (!node) {
        proof.presence = ProofPresence::Empty;
    } else {
        proof.presence = node->coin->outpoint == query
                             ? ProofPresence::Present : ProofPresence::OtherLeaf;
        proof.coin = *node->coin;
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
        if (it->second != EmptyUtxoRoot()) {
            SetBit(proof.bitmap, it->first);
            proof.siblings.push_back(it->second);
        }
    }
    return proof;
}

} // namespace lotus::v2
