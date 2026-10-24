// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool_overlay.h"

#include "tagged_hash.h"

#include <util/parallel_range.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstring>
#include <thread>

namespace lotus::v2 {

namespace {

constexpr MonetaryProfile kDefaultMonetaryProfile{
    2, 16, 2, 4, 32, 60, 2, 2000, 3, 1000, 200, Hash{2}};

/**
 * Reserve room for `extra` more elements while keeping amortized growth.
 * reserve(size() + extra) on every batch defeats the container's geometric
 * growth: each call reallocates (vector) or rehashes (unordered_map) the
 * whole container, so a stream of small batches costs O(n) per batch.
 */
template <typename Vec>
void ReserveAmortized(Vec &v, size_t extra) {
    const size_t needed = v.size() + extra;
    if (needed > v.capacity()) {
        v.reserve(std::max(needed, v.capacity() * 2));
    }
}

template <typename Map>
void ReserveBucketsAmortized(Map &m, size_t extra) {
    const size_t needed = m.size() + extra;
    if (needed > static_cast<size_t>(m.bucket_count() * m.max_load_factor())) {
        m.reserve(std::max(needed, m.size() * 2));
    }
}

template <typename Fn>
void ParallelForRange(size_t count, size_t min_per_thread, Fn &&fn) {
    if (count == 0) {
        return;
    }
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    const size_t max_threads = std::min<size_t>(hw, 16);
    const size_t needed_threads =
        (count + min_per_thread - 1) / std::max<size_t>(1, min_per_thread);
    const size_t num_threads = std::min(max_threads, std::max<size_t>(1, needed_threads));
    if (num_threads <= 1) {
        fn(0, count);
        return;
    }
    const size_t chunk = (count + num_threads - 1) / num_threads;
    util::GetParallelRangeExecutor().Run(
        num_threads, 1, [&](size_t first, size_t last) {
            for (size_t t = first; t < last; ++t) {
                const size_t begin = t * chunk;
                if (begin < count) {
                    const size_t end = std::min(count, begin + chunk);
                    fn(begin, end);
                }
            }
        });
}

template <typename Fn>
void ParallelFor16Shards(const std::array<bool, 16> &active_shards, Fn &&fn) {
    std::array<unsigned, 16> active_list{};
    size_t active_count = 0;
    for (unsigned s = 0; s < 16; ++s) {
        if (active_shards[s]) {
            active_list[active_count++] = s;
        }
    }
    if (active_count == 0) {
        return;
    }
    if (active_count == 1) {
        fn(active_list[0]);
        return;
    }
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    const size_t num_threads = std::min<size_t>({active_count, hw, 16});
    if (num_threads <= 1) {
        for (size_t i = 0; i < active_count; ++i) {
            fn(active_list[i]);
        }
        return;
    }
    std::atomic<size_t> next_idx{0};
    util::GetParallelRangeExecutor().Run(num_threads, 1, [&](size_t, size_t) {
        while (true) {
            const size_t i = next_idx.fetch_add(1, std::memory_order_relaxed);
            if (i >= active_count) {
                break;
            }
            fn(active_list[i]);
        }
    });
}

bool TxKeyBit(const Hash &tx_id, unsigned depth) noexcept {
    return (tx_id[depth / 8] >> (depth % 8)) & 1;
}

Hash ComputeTxLeafHash(const Hash &tx_id, const Hash &tx_hash) {
    std::array<uint8_t, 65> buf{};
    buf[0] = 0x00;
    std::memcpy(buf.data() + 1, tx_id.data(), 32);
    std::memcpy(buf.data() + 33, tx_hash.data(), 32);
    return TaggedHash(HashDomain::TxRoot, buf);
}

Hash ComputeTxNodeHash(unsigned depth, const Hash &left, const Hash &right) {
    std::array<uint8_t, 67> buf{};
    buf[0] = 0x01;
    buf[1] = static_cast<uint8_t>(depth & 0xff);
    buf[2] = static_cast<uint8_t>((depth >> 8) & 0xff);
    std::memcpy(buf.data() + 3, left.data(), 32);
    std::memcpy(buf.data() + 35, right.data(), 32);
    return TaggedHash(HashDomain::TxRoot, buf);
}

uint32_t ClampExpirationHeight32(uint64_t exp_height) noexcept {
    return static_cast<uint32_t>(
        std::min<uint64_t>(exp_height, UINT32_MAX));
}

std::shared_ptr<const SmtNode> MakeSmtLeaf(
    const Coin &coin, const Hash &key, const Hash &leaf_hash) {
    Coin stored = coin;
    if (stored.expiration_height == 0) {
        stored.expiration_height = ComputeUtxoExpirationHeight(
            stored.creation_height, stored.coinbase, stored.fee_per_output);
    }
    auto node = std::make_shared<SmtNode>();
    node->digest = leaf_hash;
    node->count = 1;
    node->total_value = stored.output.value;
    node->min_expiration_height =
        ClampExpirationHeight32(stored.expiration_height);
    node->key = key;
    node->coin = std::make_shared<const Coin>(std::move(stored));
    return node;
}

uint32_t ChildMinExpiration(const std::shared_ptr<const SmtNode> &a,
                            const std::shared_ptr<const SmtNode> &b) noexcept {
    return std::min(a ? a->min_expiration_height : UINT32_MAX,
                    b ? b->min_expiration_height : UINT32_MAX);
}

std::shared_ptr<const SmtNode>
JoinSmtLeaves(const std::shared_ptr<const SmtNode> &existing,
              const std::shared_ptr<const SmtNode> &added, unsigned depth) {
    const Hash old_key = existing->key;
    unsigned split = depth;
    while (SmtKeyBit(existing->key, split) == SmtKeyBit(added->key, split)) {
        ++split;
    }
    const uint64_t pair_value = existing->total_value + added->total_value;
    const uint32_t pair_min_exp = ChildMinExpiration(existing, added);
    auto subtree = std::make_shared<SmtNode>();
    subtree->count = 2;
    subtree->total_value = pair_value;
    subtree->min_expiration_height = pair_min_exp;
    const unsigned old_bit = SmtKeyBit(existing->key, split);
    subtree->child[old_bit] = existing;
    subtree->child[1 - old_bit] = added;
    subtree->Refresh(split);
    for (unsigned d = split; d-- > depth;) {
        auto parent = std::make_shared<SmtNode>();
        parent->count = 2;
        parent->total_value = pair_value;
        parent->min_expiration_height = pair_min_exp;
        parent->child[SmtKeyBit(old_key, d)] = std::move(subtree);
        parent->Refresh(d);
        subtree = std::move(parent);
    }
    return subtree;
}

std::shared_ptr<const SmtNode>
SmtInsertAt(const std::shared_ptr<const SmtNode> &node, const Coin &coin,
            const Hash &key, const Hash &leaf_hash, unsigned depth) {
    if (!node) {
        return MakeSmtLeaf(coin, key, leaf_hash);
    }
    if (node->IsLeaf()) {
        if (node->key == key) {
            const uint64_t coin_exp = ComputeUtxoExpirationHeight(coin);
            if (node->digest == leaf_hash &&
                node->min_expiration_height == coin_exp) {
                return node;
            }
            return MakeSmtLeaf(coin, key, leaf_hash);
        }
        return JoinSmtLeaves(
            node, MakeSmtLeaf(coin, key, leaf_hash), depth);
    }
    const unsigned bit = SmtKeyBit(key, depth);
    auto new_child = SmtInsertAt(node->child[bit], coin, key, leaf_hash,
                                 depth + 1);
    if (new_child == node->child[bit]) {
        return node;
    }
    auto next = std::make_shared<SmtNode>(*node);
    next->child[bit] = std::move(new_child);
    next->count = (next->child[0] ? next->child[0]->count : 0) +
                  (next->child[1] ? next->child[1]->count : 0);
    next->total_value = (next->child[0] ? next->child[0]->total_value : 0) +
                        (next->child[1] ? next->child[1]->total_value : 0);
    next->min_expiration_height =
        ChildMinExpiration(next->child[0], next->child[1]);
    next->Refresh(depth);
    return next;
}

std::shared_ptr<const SmtNode>
SmtEraseAt(const std::shared_ptr<const SmtNode> &node,
           const Outpoint &outpoint, const Hash &key, unsigned depth) {
    if (!node) {
        return nullptr;
    }
    if (node->IsLeaf()) {
        if (node->key != key || node->coin->outpoint != outpoint) {
            return node;
        }
        return nullptr;
    }
    const unsigned bit = SmtKeyBit(key, depth);
    auto new_child = SmtEraseAt(node->child[bit], outpoint, key, depth + 1);
    if (new_child == node->child[bit]) {
        return node;
    }
    const auto &other = node->child[1 - bit];
    const size_t new_count =
        (new_child ? new_child->count : 0) + (other ? other->count : 0);
    if (new_count == 1) {
        return new_child ? new_child : other;
    }
    auto next = std::make_shared<SmtNode>(*node);
    next->child[bit] = std::move(new_child);
    next->count = new_count;
    next->total_value = (next->child[0] ? next->child[0]->total_value : 0) +
                        (next->child[1] ? next->child[1]->total_value : 0);
    next->min_expiration_height =
        ChildMinExpiration(next->child[0], next->child[1]);
    next->Refresh(depth);
    return next;
}

std::shared_ptr<const SmtNode>
JoinSmtLeavesBatch(const std::shared_ptr<const SmtNode> &existing,
                   const std::shared_ptr<const SmtNode> &added,
                   unsigned depth) {
    const Hash old_key = existing->key;
    unsigned split = depth;
    while (SmtKeyBit(existing->key, split) == SmtKeyBit(added->key, split)) {
        ++split;
    }
    const uint64_t pair_value = existing->total_value + added->total_value;
    const uint64_t pair_min_exp = ChildMinExpiration(existing, added);
    auto subtree = std::make_shared<SmtNode>();
    subtree->count = 2;
    subtree->total_value = pair_value;
    subtree->min_expiration_height = pair_min_exp;
    const unsigned old_bit = SmtKeyBit(existing->key, split);
    subtree->child[old_bit] = existing;
    subtree->child[1 - old_bit] = added;
    for (unsigned d = split; d-- > depth;) {
        auto parent = std::make_shared<SmtNode>();
        parent->count = 2;
        parent->total_value = pair_value;
        parent->min_expiration_height = pair_min_exp;
        parent->child[SmtKeyBit(old_key, d)] = std::move(subtree);
        subtree = std::move(parent);
    }
    return subtree;
}

std::shared_ptr<const SmtNode>
SmtInsertBatchAt(const std::shared_ptr<const SmtNode> &node, const Coin &coin,
                 const Hash &key, const Hash &leaf_hash, unsigned depth) {
    if (!node) {
        return MakeSmtLeaf(coin, key, leaf_hash);
    }
    if (node->IsLeaf()) {
        if (node->key == key) {
            const uint64_t coin_exp = ComputeUtxoExpirationHeight(coin);
            if (node->digest == leaf_hash &&
                node->min_expiration_height == coin_exp) {
                return node;
            }
            return MakeSmtLeaf(coin, key, leaf_hash);
        }
        return JoinSmtLeavesBatch(
            node, MakeSmtLeaf(coin, key, leaf_hash), depth);
    }
    const unsigned bit = SmtKeyBit(key, depth);
    const auto &old_child = node->child[bit];
    auto new_child = SmtInsertBatchAt(old_child, coin, key, leaf_hash,
                                      depth + 1);
    const bool child_dirty =
        (new_child != old_child) ||
        (new_child != nullptr && !new_child->IsLeaf() &&
         new_child->digest == Hash{});
    if (!child_dirty) {
        return node;
    }
    if (node->digest == Hash{}) {
        auto *mut = const_cast<SmtNode *>(node.get());
        mut->child[bit] = std::move(new_child);
        mut->count = (mut->child[0] ? mut->child[0]->count : 0) +
                     (mut->child[1] ? mut->child[1]->count : 0);
        mut->total_value =
            (mut->child[0] ? mut->child[0]->total_value : 0) +
            (mut->child[1] ? mut->child[1]->total_value : 0);
        mut->min_expiration_height =
            ChildMinExpiration(mut->child[0], mut->child[1]);
        return node;
    }
    auto next = std::make_shared<SmtNode>();
    next->child[1 - bit] = node->child[1 - bit];
    next->child[bit] = std::move(new_child);
    next->count = (next->child[0] ? next->child[0]->count : 0) +
                  (next->child[1] ? next->child[1]->count : 0);
    next->total_value = (next->child[0] ? next->child[0]->total_value : 0) +
                        (next->child[1] ? next->child[1]->total_value : 0);
    next->min_expiration_height =
        ChildMinExpiration(next->child[0], next->child[1]);
    return next;
}

std::shared_ptr<const SmtNode>
SmtEraseBatchAt(const std::shared_ptr<const SmtNode> &node,
                const Outpoint &outpoint, const Hash &key, unsigned depth) {
    if (!node) {
        return nullptr;
    }
    if (node->IsLeaf()) {
        if (node->key != key || node->coin->outpoint != outpoint) {
            return node;
        }
        return nullptr;
    }
    const unsigned bit = SmtKeyBit(key, depth);
    const auto &old_child = node->child[bit];
    auto new_child = SmtEraseBatchAt(old_child, outpoint, key, depth + 1);
    const bool child_dirty =
        (new_child != old_child) ||
        (new_child != nullptr && !new_child->IsLeaf() &&
         new_child->digest == Hash{});
    if (!child_dirty) {
        return node;
    }
    const auto &other = node->child[1 - bit];
    const size_t new_count =
        (new_child ? new_child->count : 0) + (other ? other->count : 0);
    if (new_count == 0) {
        return nullptr;
    }
    if (new_count == 1) {
        return new_child ? new_child : other;
    }
    if (node->digest == Hash{}) {
        auto *mut = const_cast<SmtNode *>(node.get());
        mut->child[bit] = std::move(new_child);
        mut->count = new_count;
        mut->total_value =
            (mut->child[0] ? mut->child[0]->total_value : 0) +
            (mut->child[1] ? mut->child[1]->total_value : 0);
        mut->min_expiration_height =
            ChildMinExpiration(mut->child[0], mut->child[1]);
        return node;
    }
    auto next = std::make_shared<SmtNode>();
    next->child[1 - bit] = other;
    next->child[bit] = std::move(new_child);
    next->count = new_count;
    next->total_value = (next->child[0] ? next->child[0]->total_value : 0) +
                        (next->child[1] ? next->child[1]->total_value : 0);
    next->min_expiration_height =
        ChildMinExpiration(next->child[0], next->child[1]);
    return next;
}

void FinalizeSmtBatch(const std::shared_ptr<const SmtNode> &node,
                      unsigned depth) {
    if (!node || node->IsLeaf() || node->digest != Hash{}) {
        return;
    }
    FinalizeSmtBatch(node->child[0], depth + 1);
    FinalizeSmtBatch(node->child[1], depth + 1);
    auto *mut = const_cast<SmtNode *>(node.get());
    mut->count = (mut->child[0] ? mut->child[0]->count : 0) +
                 (mut->child[1] ? mut->child[1]->count : 0);
    mut->total_value = (mut->child[0] ? mut->child[0]->total_value : 0) +
                       (mut->child[1] ? mut->child[1]->total_value : 0);
    mut->min_expiration_height =
        ChildMinExpiration(mut->child[0], mut->child[1]);
    mut->Refresh(depth);
}

void UnzipSmtToDepth4(const std::shared_ptr<const SmtNode> &node,
                      unsigned depth, unsigned prefix,
                      std::array<std::shared_ptr<const SmtNode>, 16> &shards) {
    if (!node) {
        return;
    }
    if (depth == 4) {
        shards[prefix] = node;
        return;
    }
    if (node->IsLeaf()) {
        const unsigned s = static_cast<unsigned>(node->key[0] & 0x0Fu);
        shards[s] = node;
        return;
    }
    UnzipSmtToDepth4(node->child[0], depth + 1, prefix, shards);
    UnzipSmtToDepth4(node->child[1], depth + 1, prefix | (1u << depth), shards);
}

std::shared_ptr<const SmtNode>
ZipSmtFromDepth4(unsigned depth, unsigned prefix,
                 const std::array<std::shared_ptr<const SmtNode>, 16> &shards) {
    if (depth == 4) {
        return shards[prefix];
    }
    auto left = ZipSmtFromDepth4(depth + 1, prefix, shards);
    auto right = ZipSmtFromDepth4(depth + 1, prefix | (1u << depth), shards);
    const size_t lc = left ? left->count : 0;
    const size_t rc = right ? right->count : 0;
    const size_t total = lc + rc;
    if (total == 0) {
        return nullptr;
    }
    if (total == 1) {
        return left ? left : right;
    }
    auto branch = std::make_shared<SmtNode>();
    branch->count = total;
    branch->total_value =
        (left ? left->total_value : 0) + (right ? right->total_value : 0);
    branch->min_expiration_height = ChildMinExpiration(left, right);
    branch->child[0] = std::move(left);
    branch->child[1] = std::move(right);
    branch->Refresh(depth);
    return branch;
}

struct ExpiredLeafCandidate {
    uint64_t expiration_height;
    Hash key;
    Coin coin;
};

void CollectExpiredSmtAt(const std::shared_ptr<const SmtNode> &node,
                         uint64_t block_height,
                         std::vector<ExpiredLeafCandidate> &out) {
    if (!node || node->min_expiration_height > block_height) {
        return;
    }
    if (node->IsLeaf()) {
        if (node->coin && IsUtxoExpired(*node->coin, block_height)) {
            out.push_back({ComputeUtxoExpirationHeight(*node->coin), node->key,
                           *node->coin});
        }
        return;
    }
    CollectExpiredSmtAt(node->child[0], block_height, out);
    CollectExpiredSmtAt(node->child[1], block_height, out);
}

} // namespace

void SmtNode::Refresh(unsigned depth) {
    const bool ok = UtxoNode(depth, ChildHash(0), ChildHash(1), digest);
    assert(ok);
    (void)ok;
}

bool SmtKeyBit(const Hash &key, unsigned depth) noexcept {
    return (key[depth / 8] >> (depth % 8)) & 1;
}

void SmtInsert(std::shared_ptr<const SmtNode> &root, const Coin &coin) {
    Hash leaf_hash{};
    if (!UtxoLeaf(coin, leaf_hash)) {
        return;
    }
    const Hash key = OutpointKey(coin.outpoint);
    root = SmtInsertAt(root, coin, key, leaf_hash, 0);
}

void SmtErase(std::shared_ptr<const SmtNode> &root, const Outpoint &outpoint) {
    const Hash key = OutpointKey(outpoint);
    root = SmtEraseAt(root, outpoint, key, 0);
}

void SmtBatchUpdateParallel(
    std::shared_ptr<const SmtNode> &root,
    std::span<const Outpoint> erased,
    std::span<const Coin> inserted) {
    if (erased.empty() && inserted.empty()) {
        return;
    }

    std::vector<Hash> erased_keys(erased.size());
    ParallelForRange(erased.size(), 32, [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            erased_keys[i] = OutpointKey(erased[i]);
        }
    });

    std::vector<Hash> inserted_keys(inserted.size());
    std::vector<Hash> inserted_leaf_hashes(inserted.size());
    std::vector<uint8_t> inserted_valid(inserted.size(), 0);
    ParallelForRange(inserted.size(), 32, [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            if (UtxoLeaf(inserted[i], inserted_leaf_hashes[i])) {
                inserted_keys[i] = OutpointKey(inserted[i].outpoint);
                inserted_valid[i] = 1;
            }
        }
    });

    std::array<std::vector<size_t>, 16> shard_erased;
    std::array<std::vector<size_t>, 16> shard_inserted;
    std::array<bool, 16> active_shards{};
    for (size_t i = 0; i < erased.size(); ++i) {
        const unsigned s = static_cast<unsigned>(erased_keys[i][0] & 0x0Fu);
        shard_erased[s].push_back(i);
        active_shards[s] = true;
    }
    for (size_t i = 0; i < inserted.size(); ++i) {
        if (!inserted_valid[i]) {
            continue;
        }
        const unsigned s = static_cast<unsigned>(inserted_keys[i][0] & 0x0Fu);
        shard_inserted[s].push_back(i);
        active_shards[s] = true;
    }

    std::array<std::shared_ptr<const SmtNode>, 16> shards{};
    UnzipSmtToDepth4(root, 0, 0, shards);

    ParallelFor16Shards(active_shards, [&](unsigned s) {
        auto cur = shards[s];
        for (size_t idx : shard_erased[s]) {
            cur = SmtEraseBatchAt(cur, erased[idx], erased_keys[idx], 4);
        }
        for (size_t idx : shard_inserted[s]) {
            cur = SmtInsertBatchAt(cur, inserted[idx], inserted_keys[idx],
                                   inserted_leaf_hashes[idx], 4);
        }
        FinalizeSmtBatch(cur, 4);
        shards[s] = std::move(cur);
    });

    root = ZipSmtFromDepth4(0, 0, shards);
}

std::shared_ptr<const Coin> SmtFind(const std::shared_ptr<const SmtNode> &root,
                                    const Outpoint &outpoint) {
    if (!root) {
        return nullptr;
    }
    const Hash key = OutpointKey(outpoint);
    std::shared_ptr<const SmtNode> curr = root;
    unsigned depth = 0;
    while (curr && depth < 256) {
        if (curr->IsLeaf()) {
            if (curr->key == key && curr->coin &&
                curr->coin->outpoint == outpoint) {
                return curr->coin;
            }
            return nullptr;
        }
        const unsigned bit = SmtKeyBit(key, depth);
        curr = curr->child[bit];
        ++depth;
    }
    return nullptr;
}

Hash SmtRoot(const std::shared_ptr<const SmtNode> &root) {
    return root ? root->digest : EmptyUtxoRoot();
}

std::vector<Coin> SmtCollectExpired(
    const std::shared_ptr<const SmtNode> &root, uint64_t block_height,
    size_t max_sweeps) {
    if (!root || max_sweeps == 0 ||
        root->min_expiration_height > block_height) {
        return {};
    }
    std::vector<ExpiredLeafCandidate> candidates;
    CollectExpiredSmtAt(root, block_height, candidates);
    std::sort(candidates.begin(), candidates.end(),
              [](const ExpiredLeafCandidate &a, const ExpiredLeafCandidate &b) {
                  if (a.expiration_height != b.expiration_height) {
                      return a.expiration_height < b.expiration_height;
                  }
                  return a.key < b.key;
              });
    const size_t count = std::min(candidates.size(), max_sweeps);
    std::vector<Coin> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(std::move(candidates[i].coin));
    }
    return out;
}

ExpirySweepResult SmtSweepExpired(
    std::shared_ptr<const SmtNode> &root, uint64_t block_height,
    uint64_t total_block_fees_atoms, size_t max_sweeps) {
    ExpirySweepResult res{};
    res.swept_coins = SmtCollectExpired(root, block_height, max_sweeps);
    res.swept_count = res.swept_coins.size();
    for (const Coin &coin : res.swept_coins) {
        if (!coin.output.HasToken()) {
            res.burned_value_atoms += coin.output.value;
        }
        SmtErase(root, coin.outpoint);
    }
    res.cleaning_crew_bounty_atoms =
        ComputeCleaningCrewBounty(res.swept_count, total_block_fees_atoms);
    return res;
}

Hash EmptyTxRoot() {
    static const Hash kEmpty =
        TaggedHash(HashDomain::TxRoot, std::array<uint8_t, 1>{0x02});
    return kEmpty;
}

const MonetaryProfile &GetDefaultV2MonetaryProfile() noexcept {
    return kDefaultMonetaryProfile;
}

MonetaryState GetInitialV2MonetaryState() {
    MonetaryState state{};
    state.bootstrap_reserve = 9;
    state.tail_subsidy = 200;
    state.prev_work[0] = 2;
    state.ema_block_cost = 4;
    return InitializeMonetaryGenesis(kDefaultMonetaryProfile, state, 0);
}

// ============================================================================
// TxOverlayArena
// ============================================================================

TxOverlayArena::TxOverlayArena() {
    Reset();
}

void TxOverlayArena::Reset() {
    nodes_.clear();
    if (nodes_.capacity() < 512) {
        nodes_.reserve(512);
    }
    TxOverlayNode sentinel{};
    sentinel.digest = EmptyTxRoot();
    nodes_.push_back(sentinel);
}

void TxOverlayArena::Reserve(size_t capacity) {
    nodes_.reserve(capacity);
}

uint32_t TxOverlayArena::AllocNode(const TxOverlayNode &node) {
    const uint32_t idx = static_cast<uint32_t>(nodes_.size());
    nodes_.push_back(node);
    return idx;
}

uint32_t TxOverlayArena::MakeLeaf(const Hash &tx_id, const Hash &tx_hash,
                                  const Hash &leaf_hash) {
    TxOverlayNode leaf{};
    leaf.digest = leaf_hash;
    leaf.count = 1;
    leaf.key = tx_id;
    leaf.tx_hash = tx_hash;
    leaf.is_leaf = true;
    return AllocNode(leaf);
}

Hash TxOverlayArena::ChildHash(uint32_t idx) const {
    return idx != kNullIdx ? nodes_[idx].digest : EmptyTxRoot();
}

void TxOverlayArena::RefreshNode(uint32_t idx, unsigned depth) const {
    const uint32_t l = nodes_[idx].left;
    const uint32_t r = nodes_[idx].right;
    const Hash lh = ChildHash(l);
    const Hash rh = ChildHash(r);
    nodes_[idx].digest = ComputeTxNodeHash(depth, lh, rh);
    nodes_[idx].digest_dirty = false;
}

void TxOverlayArena::EnsureDigest(uint32_t idx, unsigned depth) const {
    if (idx == kNullIdx || nodes_[idx].is_leaf || !nodes_[idx].digest_dirty) {
        return;
    }
    if (depth == 0 && nodes_[idx].count >= 256) {
        std::array<uint32_t, 16> shard_roots{};
        shard_roots.fill(kNullIdx);
        std::array<bool, 16> active{};
        unsigned active_count = 0;
        auto collect = [&](auto &self, uint32_t n_idx, unsigned d, unsigned prefix) -> void {
            if (n_idx == kNullIdx || nodes_[n_idx].is_leaf || !nodes_[n_idx].digest_dirty) {
                return;
            }
            if (d == 4) {
                shard_roots[prefix] = n_idx;
                active[prefix] = true;
                ++active_count;
                return;
            }
            self(self, nodes_[n_idx].left, d + 1, prefix);
            self(self, nodes_[n_idx].right, d + 1, prefix | (1u << d));
        };
        collect(collect, idx, 0, 0);
        if (active_count >= 8) {
            ParallelFor16Shards(active, [&](unsigned s) {
                EnsureDigest(shard_roots[s], 4);
            });
        }
    }
    const uint32_t l = nodes_[idx].left;
    const uint32_t r = nodes_[idx].right;
    EnsureDigest(l, depth + 1);
    EnsureDigest(r, depth + 1);
    RefreshNode(idx, depth);
}

uint32_t TxOverlayArena::JoinLeaves(uint32_t existing_idx, uint32_t added_idx,
                                    unsigned depth) {
    const Hash existing_key = nodes_[existing_idx].key;
    const Hash added_key = nodes_[added_idx].key;
    unsigned split = depth;
    while (split < 256 &&
           TxKeyBit(existing_key, split) == TxKeyBit(added_key, split)) {
        ++split;
    }
    TxOverlayNode branch{};
    branch.count = 2;
    branch.is_leaf = false;
    branch.digest_dirty = true;
    if (TxKeyBit(existing_key, split)) {
        branch.left = added_idx;
        branch.right = existing_idx;
    } else {
        branch.left = existing_idx;
        branch.right = added_idx;
    }
    uint32_t subtree_idx = AllocNode(branch);

    for (unsigned d = split; d-- > depth;) {
        TxOverlayNode parent{};
        parent.count = 2;
        parent.is_leaf = false;
        parent.digest_dirty = true;
        if (TxKeyBit(existing_key, d)) {
            parent.right = subtree_idx;
        } else {
            parent.left = subtree_idx;
        }
        subtree_idx = AllocNode(parent);
    }
    return subtree_idx;
}

uint32_t TxOverlayArena::InsertAt(uint32_t node_idx, const Hash &tx_id,
                                  const Hash &tx_hash, const Hash &leaf_hash,
                                  unsigned depth) {
    if (node_idx == kNullIdx) {
        return MakeLeaf(tx_id, tx_hash, leaf_hash);
    }
    if (nodes_[node_idx].is_leaf) {
        if (nodes_[node_idx].key == tx_id) {
            if (nodes_[node_idx].tx_hash == tx_hash) {
                return node_idx;
            }
            return MakeLeaf(tx_id, tx_hash, leaf_hash);
        }
        const uint32_t added_idx = MakeLeaf(tx_id, tx_hash, leaf_hash);
        return JoinLeaves(node_idx, added_idx, depth);
    }
    const bool bit = TxKeyBit(tx_id, depth);
    const uint32_t old_child =
        bit ? nodes_[node_idx].right : nodes_[node_idx].left;
    const uint32_t new_child =
        InsertAt(old_child, tx_id, tx_hash, leaf_hash, depth + 1);
    if (new_child == old_child) {
        return node_idx;
    }
    TxOverlayNode copy = nodes_[node_idx];
    if (bit) {
        copy.right = new_child;
    } else {
        copy.left = new_child;
    }
    const uint32_t lc = copy.left != kNullIdx ? nodes_[copy.left].count : 0;
    const uint32_t rc = copy.right != kNullIdx ? nodes_[copy.right].count : 0;
    copy.count = lc + rc;
    copy.digest_dirty = true;
    return AllocNode(copy);
}

uint32_t TxOverlayArena::EraseAt(uint32_t node_idx, const Hash &tx_id,
                                 unsigned depth) {
    if (node_idx == kNullIdx) {
        return kNullIdx;
    }
    if (nodes_[node_idx].is_leaf) {
        if (nodes_[node_idx].key != tx_id) {
            return node_idx;
        }
        return kNullIdx;
    }
    const bool bit = TxKeyBit(tx_id, depth);
    const uint32_t old_child =
        bit ? nodes_[node_idx].right : nodes_[node_idx].left;
    const uint32_t other_child =
        bit ? nodes_[node_idx].left : nodes_[node_idx].right;
    const uint32_t new_child = EraseAt(old_child, tx_id, depth + 1);
    if (new_child == old_child) {
        return node_idx;
    }
    const uint32_t new_child_count =
        new_child != kNullIdx ? nodes_[new_child].count : 0;
    const uint32_t other_count =
        other_child != kNullIdx ? nodes_[other_child].count : 0;
    const uint32_t total_count = new_child_count + other_count;
    if (total_count == 1) {
        return new_child != kNullIdx ? new_child : other_child;
    }
    TxOverlayNode copy = nodes_[node_idx];
    if (bit) {
        copy.right = new_child;
    } else {
        copy.left = new_child;
    }
    copy.count = total_count;
    copy.digest_dirty = true;
    return AllocNode(copy);
}

uint32_t TxOverlayArena::InsertTxLeaf(uint32_t root_idx, const Hash &tx_id,
                                      const Hash &tx_hash) {
    const Hash leaf_hash = ComputeTxLeafHash(tx_id, tx_hash);
    return InsertAt(root_idx, tx_id, tx_hash, leaf_hash, 0);
}

uint32_t TxOverlayArena::EraseTxLeaf(uint32_t root_idx, const Hash &tx_id) {
    return EraseAt(root_idx, tx_id, 0);
}

uint32_t TxOverlayArena::InsertBatchParallel(
    uint32_t root_idx,
    std::span<const std::pair<Hash, Hash>> txs) {
    if (txs.empty()) {
        return root_idx;
    }
    EnsureDigest(root_idx, 0);

    std::vector<Hash> leaf_hashes(txs.size());
    ParallelForRange(txs.size(), 32, [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            leaf_hashes[i] = ComputeTxLeafHash(txs[i].first, txs[i].second);
        }
    });

    std::array<std::vector<size_t>, 16> shard_txs;
    std::array<bool, 16> active_shards{};
    for (size_t i = 0; i < txs.size(); ++i) {
        const unsigned s = static_cast<unsigned>(txs[i].first[0] & 0x0Fu);
        shard_txs[s].push_back(i);
        active_shards[s] = true;
    }

    std::array<uint32_t, 16> shard_roots{};
    shard_roots.fill(kNullIdx);
    auto unzip_tx = [&](auto &self, uint32_t node_idx, unsigned depth,
                        unsigned prefix) -> void {
        if (node_idx == kNullIdx) {
            return;
        }
        if (depth == 4) {
            shard_roots[prefix] = node_idx;
            return;
        }
        if (nodes_[node_idx].is_leaf) {
            const unsigned s =
                static_cast<unsigned>(nodes_[node_idx].key[0] & 0x0Fu);
            shard_roots[s] = node_idx;
            return;
        }
        self(self, nodes_[node_idx].left, depth + 1, prefix);
        self(self, nodes_[node_idx].right, depth + 1, prefix | (1u << depth));
    };
    unzip_tx(unzip_tx, root_idx, 0, 0);

    constexpr uint32_t kLocalBit = 0x80000000u;
    std::array<std::vector<TxOverlayNode>, 16> local_nodes;

    ParallelFor16Shards(active_shards, [&](unsigned s) {
        auto &loc = local_nodes[s];
        loc.reserve(shard_txs[s].size() * 3);

        auto get_node = [&](uint32_t idx) -> const TxOverlayNode & {
            return (idx & kLocalBit) ? loc[idx & ~kLocalBit] : nodes_[idx];
        };
        auto alloc_local = [&](const TxOverlayNode &n) -> uint32_t {
            const uint32_t idx = kLocalBit | static_cast<uint32_t>(loc.size());
            loc.push_back(n);
            return idx;
        };
        auto child_hash = [&](uint32_t idx) -> Hash {
            return idx != kNullIdx ? get_node(idx).digest : EmptyTxRoot();
        };
        auto refresh_local = [&](uint32_t local_idx, unsigned depth) {
            TxOverlayNode &target = loc[local_idx & ~kLocalBit];
            const Hash lh = child_hash(target.left);
            const Hash rh = child_hash(target.right);
            target.digest = ComputeTxNodeHash(depth, lh, rh);
        };
        auto make_leaf_local = [&](const Hash &tx_id, const Hash &tx_hash,
                                   const Hash &leaf_hash) -> uint32_t {
            TxOverlayNode leaf{};
            leaf.digest = leaf_hash;
            leaf.count = 1;
            leaf.key = tx_id;
            leaf.tx_hash = tx_hash;
            leaf.is_leaf = true;
            return alloc_local(leaf);
        };
        auto join_leaves_local = [&](uint32_t existing_idx, uint32_t added_idx,
                                     unsigned depth) -> uint32_t {
            const Hash existing_key = get_node(existing_idx).key;
            const Hash added_key = get_node(added_idx).key;
            unsigned split = depth;
            while (split < 256 &&
                   TxKeyBit(existing_key, split) ==
                       TxKeyBit(added_key, split)) {
                ++split;
            }
            TxOverlayNode branch{};
            branch.count = 2;
            branch.is_leaf = false;
            if (TxKeyBit(existing_key, split)) {
                branch.left = added_idx;
                branch.right = existing_idx;
            } else {
                branch.left = existing_idx;
                branch.right = added_idx;
            }
            uint32_t subtree_idx = alloc_local(branch);

            for (unsigned d = split; d-- > depth;) {
                TxOverlayNode parent{};
                parent.count = 2;
                parent.is_leaf = false;
                if (TxKeyBit(existing_key, d)) {
                    parent.right = subtree_idx;
                } else {
                    parent.left = subtree_idx;
                }
                subtree_idx = alloc_local(parent);
            }
            return subtree_idx;
        };
        auto insert_at_local = [&](auto &self, uint32_t node_idx,
                                   const Hash &tx_id, const Hash &tx_hash,
                                   const Hash &leaf_hash,
                                   unsigned depth) -> uint32_t {
            if (node_idx == kNullIdx) {
                return make_leaf_local(tx_id, tx_hash, leaf_hash);
            }
            const TxOverlayNode &cur_ref = get_node(node_idx);
            if (cur_ref.is_leaf) {
                if (cur_ref.key == tx_id) {
                    if (cur_ref.tx_hash == tx_hash) {
                        return node_idx;
                    }
                    if (node_idx & kLocalBit) {
                        TxOverlayNode &mut = loc[node_idx & ~kLocalBit];
                        mut.tx_hash = tx_hash;
                        mut.digest = leaf_hash;
                        return node_idx;
                    }
                    return make_leaf_local(tx_id, tx_hash, leaf_hash);
                }
                const uint32_t added_idx =
                    make_leaf_local(tx_id, tx_hash, leaf_hash);
                return join_leaves_local(node_idx, added_idx, depth);
            }
            if (depth >= 256) {
                return node_idx;
            }
            const bool bit = TxKeyBit(tx_id, depth);
            const uint32_t old_child = bit ? cur_ref.right : cur_ref.left;
            const uint32_t new_child = self(self, old_child, tx_id, tx_hash,
                                            leaf_hash, depth + 1);
            const bool child_dirty =
                (new_child != old_child) ||
                (new_child != kNullIdx && (new_child & kLocalBit) &&
                 loc[new_child & ~kLocalBit].digest == Hash{});
            if (!child_dirty) {
                return node_idx;
            }
            if (node_idx & kLocalBit) {
                TxOverlayNode &mut = loc[node_idx & ~kLocalBit];
                if (bit) {
                    mut.right = new_child;
                } else {
                    mut.left = new_child;
                }
                mut.digest = Hash{};
                return node_idx;
            }
            TxOverlayNode copy = get_node(node_idx);
            if (bit) {
                copy.right = new_child;
            } else {
                copy.left = new_child;
            }
            copy.digest = Hash{};
            return alloc_local(copy);
        };
        auto finalize_local = [&](auto &self, uint32_t idx,
                                  unsigned depth) -> void {
            if (idx == kNullIdx || !(idx & kLocalBit)) {
                return;
            }
            const uint32_t local_pos = idx & ~kLocalBit;
            if (loc[local_pos].is_leaf || loc[local_pos].digest != Hash{}) {
                return;
            }
            const uint32_t l = loc[local_pos].left;
            const uint32_t r = loc[local_pos].right;
            self(self, l, depth + 1);
            self(self, r, depth + 1);
            const uint32_t lc = l != kNullIdx ? get_node(l).count : 0;
            const uint32_t rc = r != kNullIdx ? get_node(r).count : 0;
            loc[local_pos].count = lc + rc;
            refresh_local(idx, depth);
        };

        uint32_t cur_root = shard_roots[s];
        for (size_t idx : shard_txs[s]) {
            cur_root = insert_at_local(insert_at_local, cur_root,
                                       txs[idx].first, txs[idx].second,
                                       leaf_hashes[idx], 4);
        }
        finalize_local(finalize_local, cur_root, 4);
        shard_roots[s] = cur_root;
    });

    size_t total_new_nodes = 16;
    for (unsigned s = 0; s < 16; ++s) {
        total_new_nodes += local_nodes[s].size();
    }
    ReserveAmortized(nodes_, total_new_nodes);

    for (unsigned s = 0; s < 16; ++s) {
        if (local_nodes[s].empty()) {
            continue;
        }
        const uint32_t base = static_cast<uint32_t>(nodes_.size());
        auto remap = [base](uint32_t idx) -> uint32_t {
            return (idx & kLocalBit) ? (base + (idx & ~kLocalBit)) : idx;
        };
        for (TxOverlayNode &n : local_nodes[s]) {
            n.left = remap(n.left);
            n.right = remap(n.right);
            nodes_.push_back(n);
        }
        shard_roots[s] = remap(shard_roots[s]);
    }

    auto zip_tx = [&](auto &self, unsigned depth, unsigned prefix) -> uint32_t {
        if (depth == 4) {
            return shard_roots[prefix];
        }
        const uint32_t left = self(self, depth + 1, prefix);
        const uint32_t right = self(self, depth + 1, prefix | (1u << depth));
        const uint32_t lc = left != kNullIdx ? nodes_[left].count : 0;
        const uint32_t rc = right != kNullIdx ? nodes_[right].count : 0;
        const uint32_t total = lc + rc;
        if (total == 0) {
            return kNullIdx;
        }
        if (total == 1) {
            return left != kNullIdx ? left : right;
        }
        TxOverlayNode branch{};
        branch.count = total;
        branch.left = left;
        branch.right = right;
        branch.is_leaf = false;
        const uint32_t idx = AllocNode(branch);
        RefreshNode(idx, depth);
        return idx;
    };

    return zip_tx(zip_tx, 0, 0);
}

Hash TxOverlayArena::SubtreeARoot(uint32_t root_idx) const {
    if (root_idx == kNullIdx) {
        return EmptyTxRoot();
    }
    EnsureDigest(root_idx, 0);
    return nodes_[root_idx].digest;
}

uint32_t TxOverlayArena::Count(uint32_t root_idx) const noexcept {
    return root_idx != kNullIdx ? nodes_[root_idx].count : 0;
}

// ============================================================================
// UtxoOverlayArena
// ============================================================================

UtxoOverlayArena::UtxoOverlayArena() {
    Reset(nullptr);
}

UtxoOverlayArena::UtxoOverlayArena(std::shared_ptr<const SmtNode> base_root) {
    Reset(std::move(base_root));
}

void UtxoOverlayArena::Reset(std::shared_ptr<const SmtNode> base_root) {
    nodes_.clear();
    if (nodes_.capacity() < 512) {
        nodes_.reserve(512);
    }
    UtxoOverlayNode sentinel{};
    sentinel.digest = EmptyUtxoRoot();
    nodes_.push_back(sentinel);

    base_smt_root_ = base_root;
    current_smt_root_ = base_root;
    smt_root_dirty_ = false;
    root_idx_ = ImportSmtNode(base_smt_root_);
}

void UtxoOverlayArena::Reserve(size_t capacity) {
    nodes_.reserve(capacity);
}

uint32_t UtxoOverlayArena::AllocNode(const UtxoOverlayNode &node) {
    const uint32_t idx = static_cast<uint32_t>(nodes_.size());
    nodes_.push_back(node);
    return idx;
}

uint32_t
UtxoOverlayArena::ImportSmtNode(const std::shared_ptr<const SmtNode> &smt_node) {
    if (!smt_node) {
        return kNullIdx;
    }
    UtxoOverlayNode node{};
    node.digest = smt_node->digest;
    node.count = static_cast<uint32_t>(smt_node->count);
    node.base_self = smt_node;
    node.key = smt_node->key;
    node.is_leaf = smt_node->IsLeaf();
    if (node.is_leaf && smt_node->coin) {
        node.coin = smt_node->coin;
    } else {
        node.base_child[0] = smt_node->child[0];
        node.base_child[1] = smt_node->child[1];
    }
    return AllocNode(node);
}

std::shared_ptr<const SmtNode>
UtxoOverlayArena::ExportSmtNode(uint32_t node_idx) const {
    if (node_idx == kNullIdx) {
        return nullptr;
    }
    const UtxoOverlayNode &n = nodes_[node_idx];
    if (n.base_self && !n.digest_dirty) {
        return n.base_self;
    }
    auto smt = std::make_shared<SmtNode>();
    smt->digest = n.digest;
    smt->count = n.count;
    if (n.is_leaf) {
        smt->total_value = n.coin ? n.coin->output.value : 0;
        smt->min_expiration_height =
            n.coin ? ClampExpirationHeight32(ComputeUtxoExpirationHeight(*n.coin))
                   : UINT32_MAX;
        smt->key = n.key;
        smt->coin = n.coin;
        return smt;
    }
    smt->child[0] =
        (n.child[0] != kNullIdx) ? ExportSmtNode(n.child[0]) : n.base_child[0];
    smt->child[1] =
        (n.child[1] != kNullIdx) ? ExportSmtNode(n.child[1]) : n.base_child[1];
    smt->total_value = (smt->child[0] ? smt->child[0]->total_value : 0) +
                       (smt->child[1] ? smt->child[1]->total_value : 0);
    smt->min_expiration_height = ChildMinExpiration(smt->child[0], smt->child[1]);
    return smt;
}

uint32_t UtxoOverlayArena::MakeLeaf(const Coin &coin, const Hash &key,
                                    const Hash &leaf_hash) {
    Coin stored = coin;
    if (stored.expiration_height == 0) {
        stored.expiration_height = ComputeUtxoExpirationHeight(
            stored.creation_height, stored.coinbase, stored.fee_per_output);
    }
    UtxoOverlayNode leaf{};
    leaf.digest = leaf_hash;
    leaf.count = 1;
    leaf.key = key;
    leaf.coin = std::make_shared<const Coin>(std::move(stored));
    leaf.is_leaf = true;
    return AllocNode(leaf);
}

Hash UtxoOverlayArena::ChildHash(const UtxoOverlayNode &node,
                                 unsigned bit) const {
    if (node.child[bit] != kNullIdx) {
        return nodes_[node.child[bit]].digest;
    }
    if (node.base_child[bit]) {
        return node.base_child[bit]->digest;
    }
    return EmptyUtxoRoot();
}

uint32_t UtxoOverlayArena::ChildCount(const UtxoOverlayNode &node,
                                      unsigned bit) const {
    if (node.child[bit] != kNullIdx) {
        return nodes_[node.child[bit]].count;
    }
    if (node.base_child[bit]) {
        return static_cast<uint32_t>(node.base_child[bit]->count);
    }
    return 0;
}

void UtxoOverlayArena::RefreshNode(uint32_t idx, unsigned depth) const {
    const Hash lh = ChildHash(nodes_[idx], 0);
    const Hash rh = ChildHash(nodes_[idx], 1);
    const bool ok = UtxoNode(depth, lh, rh, nodes_[idx].digest);
    assert(ok);
    (void)ok;
    nodes_[idx].digest_dirty = false;
}

void UtxoOverlayArena::EnsureDigest(uint32_t idx, unsigned depth) const {
    if (idx == kNullIdx || nodes_[idx].is_leaf || !nodes_[idx].digest_dirty) {
        return;
    }
    if (depth == 0 && (nodes_[idx].count >= 64 || nodes_.size() >= 64)) {
        std::array<uint32_t, 16> shard_roots{};
        shard_roots.fill(kNullIdx);
        std::array<bool, 16> active{};
        unsigned active_count = 0;
        auto collect = [&](auto &self, uint32_t n_idx, unsigned d, unsigned prefix) -> void {
            if (n_idx == kNullIdx || nodes_[n_idx].is_leaf || !nodes_[n_idx].digest_dirty) {
                return;
            }
            if (d == 4) {
                shard_roots[prefix] = n_idx;
                active[prefix] = true;
                ++active_count;
                return;
            }
            self(self, nodes_[n_idx].child[0], d + 1, prefix);
            self(self, nodes_[n_idx].child[1], d + 1, prefix | (1u << d));
        };
        collect(collect, idx, 0, 0);
        if (active_count >= 2) {
            ParallelFor16Shards(active, [&](unsigned s) {
                EnsureDigest(shard_roots[s], 4);
            });
        }
    }
    const uint32_t c0 = nodes_[idx].child[0];
    const uint32_t c1 = nodes_[idx].child[1];
    EnsureDigest(c0, depth + 1);
    EnsureDigest(c1, depth + 1);
    RefreshNode(idx, depth);
}

uint32_t UtxoOverlayArena::EnsureChildLoaded(uint32_t node_idx, unsigned bit) {
    if (nodes_[node_idx].child[bit] != kNullIdx) {
        return nodes_[node_idx].child[bit];
    }
    if (!nodes_[node_idx].base_child[bit]) {
        return kNullIdx;
    }
    auto base_ptr = nodes_[node_idx].base_child[bit];
    const uint32_t imported = ImportSmtNode(base_ptr);
    nodes_[node_idx].child[bit] = imported;
    nodes_[node_idx].base_child[bit].reset();
    return imported;
}

uint32_t UtxoOverlayArena::JoinLeaves(uint32_t existing_idx, uint32_t added_idx,
                                      unsigned depth) {
    const Hash existing_key = nodes_[existing_idx].key;
    const Hash added_key = nodes_[added_idx].key;
    unsigned split = depth;
    while (split < 256 &&
           SmtKeyBit(existing_key, split) == SmtKeyBit(added_key, split)) {
        ++split;
    }
    UtxoOverlayNode branch{};
    branch.count = 2;
    branch.is_leaf = false;
    branch.digest_dirty = true;
    const unsigned old_bit = SmtKeyBit(existing_key, split);
    branch.child[old_bit] = existing_idx;
    branch.child[1 - old_bit] = added_idx;
    uint32_t subtree_idx = AllocNode(branch);

    for (unsigned d = split; d-- > depth;) {
        UtxoOverlayNode parent{};
        parent.count = 2;
        parent.is_leaf = false;
        parent.digest_dirty = true;
        parent.child[SmtKeyBit(existing_key, d)] = subtree_idx;
        subtree_idx = AllocNode(parent);
    }
    return subtree_idx;
}

uint32_t UtxoOverlayArena::InsertAt(uint32_t node_idx, const Coin &coin,
                                    const Hash &key, const Hash &leaf_hash,
                                    unsigned depth) {
    if (node_idx == kNullIdx) {
        return MakeLeaf(coin, key, leaf_hash);
    }
    if (nodes_[node_idx].is_leaf) {
        if (nodes_[node_idx].key == key) {
            if (nodes_[node_idx].digest == leaf_hash) {
                return node_idx;
            }
            return MakeLeaf(coin, key, leaf_hash);
        }
        const uint32_t added_idx = MakeLeaf(coin, key, leaf_hash);
        return JoinLeaves(node_idx, added_idx, depth);
    }
    const unsigned bit = SmtKeyBit(key, depth);
    const uint32_t old_child = EnsureChildLoaded(node_idx, bit);
    const uint32_t new_child = InsertAt(old_child, coin, key, leaf_hash,
                                        depth + 1);
    if (new_child == old_child &&
        (new_child == kNullIdx || !nodes_[new_child].digest_dirty)) {
        return node_idx;
    }
    nodes_[node_idx].child[bit] = new_child;
    nodes_[node_idx].base_child[bit].reset();
    nodes_[node_idx].base_self.reset();
    nodes_[node_idx].count =
        ChildCount(nodes_[node_idx], 0) + ChildCount(nodes_[node_idx], 1);
    nodes_[node_idx].digest_dirty = true;
    return node_idx;
}

uint32_t UtxoOverlayArena::EraseAt(uint32_t node_idx, const Outpoint &outpoint,
                                   const Hash &key, unsigned depth) {
    if (node_idx == kNullIdx) {
        return kNullIdx;
    }
    if (nodes_[node_idx].is_leaf) {
        if (nodes_[node_idx].key != key || !nodes_[node_idx].coin ||
            nodes_[node_idx].coin->outpoint != outpoint) {
            return node_idx;
        }
        return kNullIdx;
    }
    const unsigned bit = SmtKeyBit(key, depth);
    const uint32_t old_child = EnsureChildLoaded(node_idx, bit);
    const uint32_t new_child = EraseAt(old_child, outpoint, key, depth + 1);
    if (new_child == old_child &&
        (new_child == kNullIdx || !nodes_[new_child].digest_dirty)) {
        return node_idx;
    }
    nodes_[node_idx].child[bit] = new_child;
    nodes_[node_idx].base_child[bit].reset();
    nodes_[node_idx].base_self.reset();
    const uint32_t new_count =
        ChildCount(nodes_[node_idx], 0) + ChildCount(nodes_[node_idx], 1);
    if (new_count == 0) {
        return kNullIdx;
    }
    if (new_count == 1) {
        if (new_child != kNullIdx) {
            return new_child;
        }
        return EnsureChildLoaded(node_idx, 1 - bit);
    }
    nodes_[node_idx].count = new_count;
    nodes_[node_idx].digest_dirty = true;
    return node_idx;
}

void UtxoOverlayArena::InsertCoin(const Coin &coin) {
    Hash leaf_hash{};
    if (!UtxoLeaf(coin, leaf_hash)) {
        return;
    }
    if (nodes_.capacity() < nodes_.size() + 32) {
        nodes_.reserve(std::max<size_t>(nodes_.capacity() * 2, 1024));
    }
    const Hash key = OutpointKey(coin.outpoint);
    root_idx_ = InsertAt(root_idx_, coin, key, leaf_hash, 0);
    // [Optimization — Rolls into Patch 020]: Defer SmtNode export until GetSmtRoot()
    smt_root_dirty_ = true;
}

void UtxoOverlayArena::EraseOutpoint(const Outpoint &outpoint) {
    if (nodes_.capacity() < nodes_.size() + 32) {
        nodes_.reserve(std::max<size_t>(nodes_.capacity() * 2, 1024));
    }
    const Hash key = OutpointKey(outpoint);
    root_idx_ = EraseAt(root_idx_, outpoint, key, 0);
    // [Optimization — Rolls into Patch 020]: Defer SmtNode export until GetSmtRoot()
    smt_root_dirty_ = true;
}

void UtxoOverlayArena::BatchUpdateParallel(
    std::span<const Outpoint> erased,
    std::span<const Coin> inserted) {
    if (erased.empty() && inserted.empty()) {
        return;
    }
    EnsureDigest(root_idx_, 0);
    const size_t needed = nodes_.size() + (erased.size() + inserted.size()) * 4 + 64;
    if (nodes_.capacity() < needed) {
        nodes_.reserve(std::max<size_t>(nodes_.capacity() * 2, needed));
    }

    std::vector<Hash> erased_keys(erased.size());
    ParallelForRange(erased.size(), 32, [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            erased_keys[i] = OutpointKey(erased[i]);
        }
    });

    std::vector<Hash> inserted_keys(inserted.size());
    std::vector<Hash> inserted_leaf_hashes(inserted.size());
    std::vector<uint8_t> inserted_valid(inserted.size(), 0);
    ParallelForRange(inserted.size(), 32, [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            if (UtxoLeaf(inserted[i], inserted_leaf_hashes[i])) {
                inserted_keys[i] = OutpointKey(inserted[i].outpoint);
                inserted_valid[i] = 1;
            }
        }
    });

    std::array<std::vector<size_t>, 16> shard_erased;
    std::array<std::vector<size_t>, 16> shard_inserted;
    std::array<bool, 16> active_shards{};
    for (size_t i = 0; i < erased.size(); ++i) {
        const unsigned s = static_cast<unsigned>(erased_keys[i][0] & 0x0Fu);
        shard_erased[s].push_back(i);
        active_shards[s] = true;
    }
    for (size_t i = 0; i < inserted.size(); ++i) {
        if (!inserted_valid[i]) {
            continue;
        }
        const unsigned s = static_cast<unsigned>(inserted_keys[i][0] & 0x0Fu);
        shard_inserted[s].push_back(i);
        active_shards[s] = true;
    }

    std::array<uint32_t, 16> shard_roots{};
    shard_roots.fill(kNullIdx);
    auto unzip_utxo = [&](auto &self, uint32_t node_idx, unsigned depth,
                          unsigned prefix) -> void {
        if (node_idx == kNullIdx) {
            return;
        }
        if (depth == 4) {
            shard_roots[prefix] = node_idx;
            return;
        }
        if (nodes_[node_idx].is_leaf) {
            const unsigned s =
                static_cast<unsigned>(nodes_[node_idx].key[0] & 0x0Fu);
            shard_roots[s] = node_idx;
            return;
        }
        const uint32_t c0 = EnsureChildLoaded(node_idx, 0);
        const uint32_t c1 = EnsureChildLoaded(node_idx, 1);
        self(self, c0, depth + 1, prefix);
        self(self, c1, depth + 1, prefix | (1u << depth));
    };
    unzip_utxo(unzip_utxo, root_idx_, 0, 0);

    constexpr uint32_t kLocalBit = 0x80000000u;
    std::array<std::vector<UtxoOverlayNode>, 16> local_nodes;

    ParallelFor16Shards(active_shards, [&](unsigned s) {
        auto &loc = local_nodes[s];
        loc.reserve((shard_erased[s].size() + shard_inserted[s].size()) * 3);

        auto get_node = [&](uint32_t idx) -> const UtxoOverlayNode & {
            return (idx & kLocalBit) ? loc[idx & ~kLocalBit] : nodes_[idx];
        };
        auto alloc_local = [&](const UtxoOverlayNode &n) -> uint32_t {
            const uint32_t idx = kLocalBit | static_cast<uint32_t>(loc.size());
            loc.push_back(n);
            return idx;
        };
        auto import_smt_local =
            [&](const std::shared_ptr<const SmtNode> &smt_node) -> uint32_t {
            if (!smt_node) {
                return kNullIdx;
            }
            UtxoOverlayNode node{};
            node.digest = smt_node->digest;
            node.count = static_cast<uint32_t>(smt_node->count);
            node.key = smt_node->key;
            node.base_self = smt_node;
            node.is_leaf = smt_node->IsLeaf();
            if (node.is_leaf && smt_node->coin) {
                node.coin = smt_node->coin;
            } else {
                node.base_child[0] = smt_node->child[0];
                node.base_child[1] = smt_node->child[1];
            }
            return alloc_local(node);
        };
        auto ensure_child_local = [&](uint32_t node_idx,
                                      unsigned bit) -> uint32_t {
            const UtxoOverlayNode &cur_ref = get_node(node_idx);
            if (cur_ref.child[bit] != kNullIdx) {
                return cur_ref.child[bit];
            }
            if (!cur_ref.base_child[bit]) {
                return kNullIdx;
            }
            const std::shared_ptr<const SmtNode> base_ptr =
                cur_ref.base_child[bit];
            const uint32_t imported = import_smt_local(base_ptr);
            if (node_idx & kLocalBit) {
                UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
                mut.child[bit] = imported;
                mut.base_child[bit].reset();
            }
            return imported;
        };
        auto child_hash_local = [&](const UtxoOverlayNode &node,
                                    unsigned bit) -> Hash {
            if (node.child[bit] != kNullIdx) {
                return get_node(node.child[bit]).digest;
            }
            if (node.base_child[bit]) {
                return node.base_child[bit]->digest;
            }
            return EmptyUtxoRoot();
        };
        auto child_count_local = [&](const UtxoOverlayNode &node,
                                     unsigned bit) -> uint32_t {
            if (node.child[bit] != kNullIdx) {
                return get_node(node.child[bit]).count;
            }
            if (node.base_child[bit]) {
                return static_cast<uint32_t>(node.base_child[bit]->count);
            }
            return 0;
        };
        auto refresh_local = [&](uint32_t local_idx, unsigned depth) {
            UtxoOverlayNode &target = loc[local_idx & ~kLocalBit];
            const Hash lh = child_hash_local(target, 0);
            const Hash rh = child_hash_local(target, 1);
            const bool ok = UtxoNode(depth, lh, rh, target.digest);
            assert(ok);
            (void)ok;
        };
        auto make_leaf_local =
            [&](const Coin &coin, const Hash &key, const Hash &leaf_hash) -> uint32_t {
            UtxoOverlayNode leaf{};
            leaf.digest = leaf_hash;
            leaf.count = 1;
            leaf.key = key;
            leaf.coin = std::make_shared<const Coin>(coin);
            leaf.is_leaf = true;
            return alloc_local(leaf);
        };
        auto join_leaves_local = [&](uint32_t existing_idx, uint32_t added_idx,
                                     unsigned depth) -> uint32_t {
            const Hash existing_key = get_node(existing_idx).key;
            const Hash added_key = get_node(added_idx).key;
            unsigned split = depth;
            while (split < 256 &&
                   SmtKeyBit(existing_key, split) ==
                       SmtKeyBit(added_key, split)) {
                ++split;
            }
            UtxoOverlayNode branch{};
            branch.count = 2;
            branch.is_leaf = false;
            const unsigned old_bit = SmtKeyBit(existing_key, split);
            branch.child[old_bit] = existing_idx;
            branch.child[1 - old_bit] = added_idx;
            uint32_t subtree_idx = alloc_local(branch);

            for (unsigned d = split; d-- > depth;) {
                UtxoOverlayNode parent{};
                parent.count = 2;
                parent.is_leaf = false;
                parent.child[SmtKeyBit(existing_key, d)] = subtree_idx;
                subtree_idx = alloc_local(parent);
            }
            return subtree_idx;
        };
        auto insert_at_local =
            [&](auto &self, uint32_t node_idx, const Coin &coin,
                const Hash &key, const Hash &leaf_hash,
                unsigned depth) -> uint32_t {
            if (node_idx == kNullIdx) {
                return make_leaf_local(coin, key, leaf_hash);
            }
            const UtxoOverlayNode &cur_ref = get_node(node_idx);
            if (cur_ref.is_leaf) {
                if (cur_ref.key == key) {
                    if (cur_ref.digest == leaf_hash) {
                        return node_idx;
                    }
                    if (node_idx & kLocalBit) {
                        UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
                        mut.digest = leaf_hash;
                        mut.coin = std::make_shared<const Coin>(coin);
                        mut.base_self.reset();
                        return node_idx;
                    }
                    return make_leaf_local(coin, key, leaf_hash);
                }
                const uint32_t added_idx =
                    make_leaf_local(coin, key, leaf_hash);
                return join_leaves_local(node_idx, added_idx, depth);
            }
            if (depth >= 256) {
                return node_idx;
            }
            const unsigned bit = SmtKeyBit(key, depth);
            const uint32_t old_child = ensure_child_local(node_idx, bit);
            const uint32_t new_child =
                self(self, old_child, coin, key, leaf_hash, depth + 1);
            const bool child_dirty =
                (new_child != old_child) ||
                (new_child != kNullIdx && (new_child & kLocalBit) &&
                 loc[new_child & ~kLocalBit].digest == Hash{});
            if (!child_dirty) {
                return node_idx;
            }
            if (node_idx & kLocalBit) {
                UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
                mut.child[bit] = new_child;
                mut.base_child[bit].reset();
                mut.base_self.reset();
                mut.count =
                    child_count_local(mut, 0) + child_count_local(mut, 1);
                mut.digest = Hash{};
                return node_idx;
            }
            const UtxoOverlayNode &src = get_node(node_idx);
            UtxoOverlayNode copy{};
            copy.child[0] = src.child[0];
            copy.child[1] = src.child[1];
            copy.base_child[1 - bit] = src.base_child[1 - bit];
            copy.child[bit] = new_child;
            copy.is_leaf = false;
            copy.count =
                child_count_local(copy, 0) + child_count_local(copy, 1);
            return alloc_local(copy);
        };
        auto erase_at_local = [&](auto &self, uint32_t node_idx,
                                  const Outpoint &outpoint, const Hash &key,
                                  unsigned depth) -> uint32_t {
            if (node_idx == kNullIdx) {
                return kNullIdx;
            }
            const UtxoOverlayNode &cur_ref = get_node(node_idx);
            if (cur_ref.is_leaf) {
                if (cur_ref.key != key || !cur_ref.coin ||
                    cur_ref.coin->outpoint != outpoint) {
                    return node_idx;
                }
                return kNullIdx;
            }
            if (depth >= 256) {
                return node_idx;
            }
            const unsigned bit = SmtKeyBit(key, depth);
            const uint32_t old_child = ensure_child_local(node_idx, bit);
            const uint32_t new_child =
                self(self, old_child, outpoint, key, depth + 1);
            const bool child_dirty =
                (new_child != old_child) ||
                (new_child != kNullIdx && (new_child & kLocalBit) &&
                 loc[new_child & ~kLocalBit].digest == Hash{});
            if (!child_dirty) {
                return node_idx;
            }
            if (node_idx & kLocalBit) {
                UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
                mut.child[bit] = new_child;
                mut.base_child[bit].reset();
                mut.base_self.reset();
                const uint32_t new_count =
                    child_count_local(mut, 0) + child_count_local(mut, 1);
                if (new_count == 0) {
                    return kNullIdx;
                }
                if (new_count == 1) {
                    if (new_child != kNullIdx) {
                        return new_child;
                    }
                    return ensure_child_local(node_idx, 1 - bit);
                }
                mut.count = new_count;
                mut.digest = Hash{};
                return node_idx;
            }
            const UtxoOverlayNode &src = get_node(node_idx);
            UtxoOverlayNode copy{};
            copy.child[0] = src.child[0];
            copy.child[1] = src.child[1];
            copy.base_child[1 - bit] = src.base_child[1 - bit];
            copy.child[bit] = new_child;
            copy.is_leaf = false;
            const uint32_t new_count =
                child_count_local(copy, 0) + child_count_local(copy, 1);
            if (new_count == 0) {
                return kNullIdx;
            }
            if (new_count == 1) {
                if (new_child != kNullIdx) {
                    return new_child;
                }
                return ensure_child_local(node_idx, 1 - bit);
            }
            copy.count = new_count;
            return alloc_local(copy);
        };
        auto finalize_local = [&](auto &self, uint32_t idx,
                                  unsigned depth) -> void {
            if (idx == kNullIdx || !(idx & kLocalBit)) {
                return;
            }
            const uint32_t local_pos = idx & ~kLocalBit;
            if (loc[local_pos].is_leaf || loc[local_pos].digest != Hash{}) {
                return;
            }
            const uint32_t c0 = loc[local_pos].child[0];
            const uint32_t c1 = loc[local_pos].child[1];
            self(self, c0, depth + 1);
            self(self, c1, depth + 1);
            loc[local_pos].count =
                child_count_local(loc[local_pos], 0) +
                child_count_local(loc[local_pos], 1);
            refresh_local(idx, depth);
        };

        uint32_t cur_root = shard_roots[s];
        for (size_t idx : shard_erased[s]) {
            cur_root = erase_at_local(erase_at_local, cur_root, erased[idx],
                                      erased_keys[idx], 4);
        }
        for (size_t idx : shard_inserted[s]) {
            cur_root = insert_at_local(insert_at_local, cur_root,
                                       inserted[idx], inserted_keys[idx],
                                       inserted_leaf_hashes[idx], 4);
        }
        finalize_local(finalize_local, cur_root, 4);
        shard_roots[s] = cur_root;
    });

    size_t total_new_nodes = 16;
    for (unsigned s = 0; s < 16; ++s) {
        total_new_nodes += local_nodes[s].size();
    }
    ReserveAmortized(nodes_, total_new_nodes);

    for (unsigned s = 0; s < 16; ++s) {
        if (local_nodes[s].empty()) {
            continue;
        }
        const uint32_t base = static_cast<uint32_t>(nodes_.size());
        auto remap = [base](uint32_t idx) -> uint32_t {
            return (idx & kLocalBit) ? (base + (idx & ~kLocalBit)) : idx;
        };
        for (UtxoOverlayNode &n : local_nodes[s]) {
            n.child[0] = remap(n.child[0]);
            n.child[1] = remap(n.child[1]);
            nodes_.push_back(std::move(n));
        }
        shard_roots[s] = remap(shard_roots[s]);
    }

    auto zip_utxo = [&](auto &self, unsigned depth,
                        unsigned prefix) -> uint32_t {
        if (depth == 4) {
            return shard_roots[prefix];
        }
        const uint32_t left = self(self, depth + 1, prefix);
        const uint32_t right = self(self, depth + 1, prefix | (1u << depth));
        const uint32_t lc = left != kNullIdx ? nodes_[left].count : 0;
        const uint32_t rc = right != kNullIdx ? nodes_[right].count : 0;
        const uint32_t total = lc + rc;
        if (total == 0) {
            return kNullIdx;
        }
        if (total == 1) {
            return left != kNullIdx ? left : right;
        }
        UtxoOverlayNode branch{};
        branch.count = total;
        branch.child[0] = left;
        branch.child[1] = right;
        branch.is_leaf = false;
        const uint32_t idx = AllocNode(branch);
        RefreshNode(idx, depth);
        return idx;
    };

    root_idx_ = zip_utxo(zip_utxo, 0, 0);
    smt_root_dirty_ = true;
}

const std::shared_ptr<const SmtNode> &UtxoOverlayArena::GetSmtRoot() const {
    if (smt_root_dirty_) {
        // No-op mutations may load paths without changing the imported root.
        // Preserve that immutable tree before the parallel exporter rebuilds
        // its upper levels, just as ExportSmtNode preserves clean subtrees.
        if (root_idx_ != kNullIdx && nodes_[root_idx_].base_self &&
            !nodes_[root_idx_].digest_dirty) {
            current_smt_root_ = nodes_[root_idx_].base_self;
            smt_root_dirty_ = false;
            return current_smt_root_;
        }
        EnsureDigest(root_idx_, 0);
        if (root_idx_ != kNullIdx && !nodes_[root_idx_].is_leaf &&
            (nodes_[root_idx_].count >= 64 || nodes_.size() >= 64)) {
            std::array<uint32_t, 16> shard_idx{};
            shard_idx.fill(kNullIdx);
            std::array<std::shared_ptr<const SmtNode>, 16> shard_base{};
            std::array<bool, 16> active{};
            auto collect = [&](auto &self, uint32_t n_idx,
                               const std::shared_ptr<const SmtNode> &b_ptr,
                               unsigned d, unsigned prefix) -> void {
                if (d == 4) {
                    if (n_idx != kNullIdx) {
                        shard_idx[prefix] = n_idx;
                        active[prefix] = true;
                    } else {
                        shard_base[prefix] = b_ptr;
                    }
                    return;
                }
                if (n_idx == kNullIdx) {
                    if (!b_ptr) {
                        return;
                    }
                    if (b_ptr->IsLeaf()) {
                        const unsigned s =
                            static_cast<unsigned>(b_ptr->key[0] & 0x0Fu);
                        shard_base[s] = b_ptr;
                        return;
                    }
                    self(self, kNullIdx, b_ptr->child[0], d + 1, prefix);
                    self(self, kNullIdx, b_ptr->child[1], d + 1,
                         prefix | (1u << d));
                    return;
                }
                const UtxoOverlayNode &n = nodes_[n_idx];
                if (n.is_leaf) {
                    const unsigned s = static_cast<unsigned>(n.key[0] & 0x0Fu);
                    shard_idx[s] = n_idx;
                    active[s] = true;
                    return;
                }
                self(self, n.child[0],
                     n.child[0] == kNullIdx ? n.base_child[0] : nullptr, d + 1,
                     prefix);
                self(self, n.child[1],
                     n.child[1] == kNullIdx ? n.base_child[1] : nullptr, d + 1,
                     prefix | (1u << d));
            };
            collect(collect, root_idx_, nullptr, 0, 0);
            ParallelFor16Shards(active, [&](unsigned s) {
                shard_base[s] = ExportSmtNode(shard_idx[s]);
            });
            current_smt_root_ = ZipSmtFromDepth4(0, 0, shard_base);
        } else {
            current_smt_root_ = ExportSmtNode(root_idx_);
        }
        smt_root_dirty_ = false;
    }
    return current_smt_root_;
}

Hash UtxoOverlayArena::RootDigest() const {
    if (root_idx_ == kNullIdx) {
        return EmptyUtxoRoot();
    }
    EnsureDigest(root_idx_, 0);
    return nodes_[root_idx_].digest;
}

Hash UtxoOverlayArena::RootDigestWithExtraCoins(
    std::span<const Coin> extra_coins) const {
    EnsureDigest(root_idx_, 0);
    if (extra_coins.empty()) {
        return root_idx_ != kNullIdx ? nodes_[root_idx_].digest
                                     : EmptyUtxoRoot();
    }

    constexpr uint32_t kLocalBit = 0x80000000u;
    std::vector<UtxoOverlayNode> loc;
    loc.reserve(extra_coins.size() * 8 + 16);

    auto get_node = [&](uint32_t idx) -> const UtxoOverlayNode & {
        return (idx & kLocalBit) ? loc[idx & ~kLocalBit] : nodes_[idx];
    };
    auto alloc_local = [&](const UtxoOverlayNode &n) -> uint32_t {
        const uint32_t idx = kLocalBit | static_cast<uint32_t>(loc.size());
        loc.push_back(n);
        return idx;
    };
    auto import_smt_local =
        [&](const std::shared_ptr<const SmtNode> &smt_node) -> uint32_t {
        if (!smt_node) {
            return kNullIdx;
        }
        UtxoOverlayNode node{};
        node.digest = smt_node->digest;
        node.count = static_cast<uint32_t>(smt_node->count);
        node.key = smt_node->key;
        node.is_leaf = smt_node->IsLeaf();
        if (node.is_leaf && smt_node->coin) {
            node.coin = smt_node->coin;
        } else {
            node.base_child[0] = smt_node->child[0];
            node.base_child[1] = smt_node->child[1];
        }
        return alloc_local(node);
    };
    auto ensure_child_local = [&](uint32_t node_idx, unsigned bit) -> uint32_t {
        const UtxoOverlayNode &cur_ref = get_node(node_idx);
        if (cur_ref.child[bit] != kNullIdx) {
            return cur_ref.child[bit];
        }
        if (!cur_ref.base_child[bit]) {
            return kNullIdx;
        }
        const std::shared_ptr<const SmtNode> base_ptr = cur_ref.base_child[bit];
        const uint32_t imported = import_smt_local(base_ptr);
        if (node_idx & kLocalBit) {
            UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
            mut.child[bit] = imported;
            mut.base_child[bit].reset();
        }
        return imported;
    };
    auto child_hash_local = [&](const UtxoOverlayNode &node,
                                unsigned bit) -> Hash {
        if (node.child[bit] != kNullIdx) {
            return get_node(node.child[bit]).digest;
        }
        if (node.base_child[bit]) {
            return node.base_child[bit]->digest;
        }
        return EmptyUtxoRoot();
    };
    auto child_count_local = [&](const UtxoOverlayNode &node,
                                 unsigned bit) -> uint32_t {
        if (node.child[bit] != kNullIdx) {
            return get_node(node.child[bit]).count;
        }
        if (node.base_child[bit]) {
            return static_cast<uint32_t>(node.base_child[bit]->count);
        }
        return 0;
    };
    auto make_leaf_local = [&](const Coin &coin, const Hash &key,
                               const Hash &leaf_hash) -> uint32_t {
        UtxoOverlayNode leaf{};
        leaf.digest = leaf_hash;
        leaf.count = 1;
        leaf.key = key;
        leaf.coin = std::make_shared<const Coin>(coin);
        leaf.is_leaf = true;
        return alloc_local(leaf);
    };
    auto join_leaves_local = [&](uint32_t existing_idx, uint32_t added_idx,
                                 unsigned depth) -> uint32_t {
        const Hash existing_key = get_node(existing_idx).key;
        const Hash added_key = get_node(added_idx).key;
        unsigned split = depth;
        while (split < 256 &&
               SmtKeyBit(existing_key, split) == SmtKeyBit(added_key, split)) {
            ++split;
        }
        UtxoOverlayNode branch{};
        branch.count = 2;
        branch.is_leaf = false;
        const unsigned old_bit = SmtKeyBit(existing_key, split);
        branch.child[old_bit] = existing_idx;
        branch.child[1 - old_bit] = added_idx;
        uint32_t subtree_idx = alloc_local(branch);

        for (unsigned d = split; d-- > depth;) {
            UtxoOverlayNode parent{};
            parent.count = 2;
            parent.is_leaf = false;
            parent.child[SmtKeyBit(existing_key, d)] = subtree_idx;
            subtree_idx = alloc_local(parent);
        }
        return subtree_idx;
    };
    auto insert_at_local = [&](auto &self, uint32_t node_idx, const Coin &coin,
                               const Hash &key, const Hash &leaf_hash,
                               unsigned depth) -> uint32_t {
        if (node_idx == kNullIdx) {
            return make_leaf_local(coin, key, leaf_hash);
        }
        const UtxoOverlayNode &cur_ref = get_node(node_idx);
        if (cur_ref.is_leaf) {
            if (cur_ref.key == key) {
                if (cur_ref.digest == leaf_hash) {
                    return node_idx;
                }
                if (node_idx & kLocalBit) {
                    UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
                    mut.digest = leaf_hash;
                    mut.coin = std::make_shared<const Coin>(coin);
                    return node_idx;
                }
                return make_leaf_local(coin, key, leaf_hash);
            }
            const uint32_t added_idx = make_leaf_local(coin, key, leaf_hash);
            return join_leaves_local(node_idx, added_idx, depth);
        }
        if (depth >= 256) {
            return node_idx;
        }
        const unsigned bit = SmtKeyBit(key, depth);
        const uint32_t old_child = ensure_child_local(node_idx, bit);
        const uint32_t new_child =
            self(self, old_child, coin, key, leaf_hash, depth + 1);
        const bool child_dirty =
            (new_child != old_child) ||
            (new_child != kNullIdx && (new_child & kLocalBit) &&
             loc[new_child & ~kLocalBit].digest == Hash{});
        if (!child_dirty) {
            return node_idx;
        }
        if (node_idx & kLocalBit) {
            UtxoOverlayNode &mut = loc[node_idx & ~kLocalBit];
            mut.child[bit] = new_child;
            mut.base_child[bit].reset();
            mut.count = child_count_local(mut, 0) + child_count_local(mut, 1);
            mut.digest = Hash{};
            return node_idx;
        }
        const UtxoOverlayNode &src = get_node(node_idx);
        UtxoOverlayNode copy{};
        copy.child[0] = src.child[0];
        copy.child[1] = src.child[1];
        copy.base_child[1 - bit] = src.base_child[1 - bit];
        copy.child[bit] = new_child;
        copy.is_leaf = false;
        copy.count = child_count_local(copy, 0) + child_count_local(copy, 1);
        return alloc_local(copy);
    };
    auto finalize_local = [&](auto &self, uint32_t idx, unsigned depth) -> void {
        if (idx == kNullIdx || !(idx & kLocalBit)) {
            return;
        }
        const uint32_t local_pos = idx & ~kLocalBit;
        if (loc[local_pos].is_leaf || loc[local_pos].digest != Hash{}) {
            return;
        }
        const uint32_t c0 = loc[local_pos].child[0];
        const uint32_t c1 = loc[local_pos].child[1];
        self(self, c0, depth + 1);
        self(self, c1, depth + 1);
        loc[local_pos].count =
            child_count_local(loc[local_pos], 0) +
            child_count_local(loc[local_pos], 1);
        const Hash lh = child_hash_local(loc[local_pos], 0);
        const Hash rh = child_hash_local(loc[local_pos], 1);
        const bool ok = UtxoNode(depth, lh, rh, loc[local_pos].digest);
        assert(ok);
        (void)ok;
    };

    uint32_t cur_root = root_idx_;
    for (const Coin &coin : extra_coins) {
        Hash leaf_hash{};
        if (!UtxoLeaf(coin, leaf_hash)) {
            continue;
        }
        const Hash key = OutpointKey(coin.outpoint);
        cur_root = insert_at_local(insert_at_local, cur_root, coin, key,
                                   leaf_hash, 0);
    }
    finalize_local(finalize_local, cur_root, 0);
    return cur_root != kNullIdx ? get_node(cur_root).digest : EmptyUtxoRoot();
}

// ============================================================================
// MempoolOverlayLayer
// ============================================================================

MempoolOverlayLayer::MempoolOverlayLayer()
    : base_mon_state_(GetInitialV2MonetaryState()) {}

MempoolOverlayLayer::MempoolOverlayLayer(
    const Hash &parent_block_id,
    std::shared_ptr<const SmtNode> base_utxo_root,
    const MonetaryState &base_mon_state,
    uint64_t height,
    uint64_t parent_mtp,
    uint64_t layer_id) {
    Reset(parent_block_id, std::move(base_utxo_root), base_mon_state, height,
          parent_mtp, layer_id);
}

void MempoolOverlayLayer::Reset(const Hash &parent_block_id,
                                std::shared_ptr<const SmtNode> base_utxo_root,
                                const MonetaryState &base_mon_state,
                                uint64_t height,
                                uint64_t parent_mtp,
                                uint64_t layer_id) {
    layer_id_ = layer_id;
    parent_block_id_ = parent_block_id;
    height_ = height;
    parent_mtp_ = parent_mtp;
    base_mon_state_ = base_mon_state;

    // Keeps the store: freed slots are reused by the next membership.
    tx_tree_.Clear();
    utxo_arena_.Reset(std::move(base_utxo_root));
    utxo_arena_dirty_ = false;
    sum_non_cb_effective_cost_ = 0;

    active_txs_.clear();
    created_coins_.clear();
    spent_outpoints_.clear();
}

void MempoolOverlayLayer::EnsureUtxoArenaUpdated() const {
    if (!utxo_arena_dirty_) {
        return;
    }
    auto base_root = utxo_arena_.GetBaseSmtRoot();
    utxo_arena_.Reset(std::move(base_root));
    std::vector<Outpoint> erased;
    erased.reserve(spent_outpoints_.size());
    for (const auto &[op, count] : spent_outpoints_) {
        if (count > 0 && created_coins_.find(op) == created_coins_.end()) {
            erased.push_back(op);
        }
    }
    std::vector<Coin> inserted;
    inserted.reserve(created_coins_.size());
    for (const auto &[op, coin] : created_coins_) {
        if (spent_outpoints_.find(op) == spent_outpoints_.end()) {
            inserted.push_back(coin);
        }
    }
    if (erased.size() + inserted.size() >= 16) {
        utxo_arena_.BatchUpdateParallel(erased, inserted);
    } else {
        for (const auto &op : erased) {
            utxo_arena_.EraseOutpoint(op);
        }
        for (const auto &coin : inserted) {
            utxo_arena_.InsertCoin(coin);
        }
    }
    utxo_arena_dirty_ = false;
}

bool MempoolOverlayLayer::Contains(const Hash &tx_id) const {
    return active_txs_.find(tx_id) != active_txs_.end();
}

bool MempoolOverlayLayer::AddTransaction(
    const Hash &tx_id,
    const Hash &tx_hash,
    uint64_t linear_cost,
    const std::vector<Outpoint> &spent_outpoints,
    const std::vector<Coin> &created_coins,
    int64_t fee_sats,
    int64_t sigchecks,
    std::shared_ptr<const void> tx_ref,
    uint32_t payload_bytes) {
    if (active_txs_.find(tx_id) != active_txs_.end()) {
        return false;
    }

    const uint64_t eff_cost =
        TransactionEffectiveCost(linear_cost, kDefaultMonetaryProfile);

    tx_tree_.Insert(tx_id, tx_hash, tx_ref, payload_bytes);
    sum_non_cb_effective_cost_ += eff_cost;

    for (const auto &op : spent_outpoints) {
        ++spent_outpoints_[op];
    }

    for (const auto &coin : created_coins) {
        created_coins_[coin.outpoint] = coin;
    }
    utxo_arena_dirty_ = true;

    OverlayTxEntry entry{};
    entry.tx_id = tx_id;
    entry.tx_hash = tx_hash;
    entry.linear_cost = linear_cost;
    entry.effective_cost = eff_cost;
    entry.fee_sats = fee_sats;
    entry.sigchecks = sigchecks;
    entry.payload_bytes = payload_bytes;
    entry.spent_outpoints = spent_outpoints;
    entry.created_coins = created_coins;
    entry.tx_ref = std::move(tx_ref);

    active_txs_.emplace(tx_id, std::move(entry));
    return true;
}

size_t MempoolOverlayLayer::AddTransactionBatch(
    std::span<OverlayTxEntry> entries) {
    return AddTransactionBatch(entries, false);
}

size_t MempoolOverlayLayer::AddTransactionBatch(
    std::span<OverlayTxEntry> entries, bool tree_already_contains) {
    if (entries.empty()) {
        return 0;
    }
    if (entries.size() == 1 && !tree_already_contains) {
        auto &e = entries[0];
        return AddTransaction(e.tx_id, e.tx_hash, e.linear_cost,
                              e.spent_outpoints, e.created_coins, e.fee_sats,
                              e.sigchecks, std::move(e.tx_ref),
                              e.payload_bytes)
                   ? 1
                   : 0;
    }

    ReserveBucketsAmortized(created_coins_, entries.size() * 2);
    ReserveBucketsAmortized(spent_outpoints_, entries.size() * 2);

    size_t added_count = 0;
    for (auto &entry : entries) {
        if (active_txs_.find(entry.tx_id) != active_txs_.end()) {
            continue;
        }
        // Tree first: an allocation failure leaves the layer unchanged for
        // this entry.
        if (!tree_already_contains) {
            tx_tree_.Insert(entry.tx_id, entry.tx_hash, entry.tx_ref,
                            entry.payload_bytes);
        }
        entry.effective_cost =
            TransactionEffectiveCost(entry.linear_cost, kDefaultMonetaryProfile);
        sum_non_cb_effective_cost_ += entry.effective_cost;

        for (const auto &op : entry.spent_outpoints) {
            ++spent_outpoints_[op];
        }

        for (const auto &coin : entry.created_coins) {
            created_coins_[coin.outpoint] = coin;
        }

        const Hash tx_id = entry.tx_id;
        active_txs_.emplace(tx_id, std::move(entry));
        ++added_count;
    }

    if (added_count == 0) {
        return 0;
    }

    if (tree_already_contains && tx_tree_.Count() != active_txs_.size()) {
        // The adopted tree did not describe exactly these entries; rebuild it
        // from the authoritative entry map rather than publish a wrong root.
        tx_tree_.Clear();
        for (const auto &[tx_id, entry] : active_txs_) {
            tx_tree_.Insert(tx_id, entry.tx_hash, entry.tx_ref,
                            entry.payload_bytes);
        }
    }

    utxo_arena_dirty_ = true;
    return added_count;
}

bool MempoolOverlayLayer::RemoveTransaction(const Hash &tx_id) {
    auto it = active_txs_.find(tx_id);
    if (it == active_txs_.end()) {
        return false;
    }

    const OverlayTxEntry &entry = it->second;
    tx_tree_.Erase(tx_id);
    assert(sum_non_cb_effective_cost_ >= entry.effective_cost);
    sum_non_cb_effective_cost_ -= entry.effective_cost;

    for (const auto &coin : entry.created_coins) {
        created_coins_.erase(coin.outpoint);
    }

    for (const auto &op : entry.spent_outpoints) {
        auto sp_it = spent_outpoints_.find(op);
        if (sp_it != spent_outpoints_.end()) {
            if (--sp_it->second == 0) {
                spent_outpoints_.erase(sp_it);
            }
        }
    }

    utxo_arena_dirty_ = true;
    active_txs_.erase(it);
    return true;
}

std::vector<Outpoint> MempoolOverlayLayer::GetNetErasedOutpoints() const {
    std::vector<Outpoint> erased;
    erased.reserve(spent_outpoints_.size());
    for (const auto &[op, count] : spent_outpoints_) {
        if (count > 0 && created_coins_.find(op) == created_coins_.end()) {
            erased.push_back(op);
        }
    }
    std::sort(erased.begin(), erased.end(), OutpointLess{});
    return erased;
}

std::vector<Coin> MempoolOverlayLayer::GetNetInsertedCoins() const {
    std::vector<Coin> inserted;
    inserted.reserve(created_coins_.size());
    for (const auto &[op, coin] : created_coins_) {
        if (spent_outpoints_.find(op) == spent_outpoints_.end()) {
            inserted.push_back(coin);
        }
    }
    std::sort(inserted.begin(), inserted.end(),
              [](const Coin &a, const Coin &b) {
                  return OutpointLess{}(a.outpoint, b.outpoint);
              });
    return inserted;
}

// ============================================================================
// MerklixOverlayManager
// ============================================================================

MerklixOverlayManager::MerklixOverlayManager() = default;

void MerklixOverlayManager::ResetToTip(
    const Hash &tip_block_id,
    std::shared_ptr<const SmtNode> base_utxo_root,
    const MonetaryState &base_mon_state,
    uint64_t next_height,
    uint64_t parent_mtp) {
    frozen_epochs_.clear();
    speculative_layer_.Reset(tip_block_id, std::move(base_utxo_root),
                             base_mon_state, next_height, parent_mtp,
                             next_epoch_id_);
}

void MerklixOverlayManager::Clear() {
    frozen_epochs_.clear();
    speculative_layer_.Reset(speculative_layer_.GetParentBlockId(),
                             speculative_layer_.GetBaseUtxoRoot(),
                             speculative_layer_.GetBaseMonetaryState(),
                             speculative_layer_.GetHeight(),
                             speculative_layer_.GetParentMtp(), next_epoch_id_);
}

bool MerklixOverlayManager::IsAnchoredAt(const Hash &tip_block_id,
                                         uint64_t next_height,
                                         uint64_t parent_mtp) const noexcept {
    return speculative_layer_.GetParentBlockId() == tip_block_id &&
           speculative_layer_.GetHeight() == next_height &&
           speculative_layer_.GetParentMtp() == parent_mtp;
}

void MerklixOverlayManager::ReanchorExistingTxs(
    const Hash &tip_block_id,
    std::shared_ptr<const SmtNode> base_utxo_root,
    const MonetaryState &base_mon_state,
    uint64_t next_height,
    uint64_t parent_mtp) {
    const auto &cur_mon = speculative_layer_.GetBaseMonetaryState();
    if (IsAnchoredAt(tip_block_id, next_height, parent_mtp) &&
        speculative_layer_.GetBaseUtxoRoot() == base_utxo_root &&
        cur_mon.bootstrap_reserve == base_mon_state.bootstrap_reserve &&
        cur_mon.tail_subsidy == base_mon_state.tail_subsidy &&
        cur_mon.prev_work == base_mon_state.prev_work &&
        cur_mon.ema_block_cost == base_mon_state.ema_block_cost) {
        return;
    }

    const bool same_or_unset_tip =
        (speculative_layer_.GetParentBlockId() == tip_block_id ||
         speculative_layer_.GetParentBlockId() == Hash{});
    auto old_frozen = std::move(frozen_epochs_);
    frozen_epochs_.clear();
    if (same_or_unset_tip) {
        for (const auto &old_layer : old_frozen) {
            MempoolOverlayLayer reanchored(tip_block_id, base_utxo_root,
                                           base_mon_state, next_height,
                                           parent_mtp, old_layer.GetLayerId());
            // Membership (TxId, TxHash) is unchanged by re-anchoring; share
            // the frozen tree and its completed digests instead of rebuilding.
            reanchored.AdoptTxTree(old_layer.GetTxTree());
            std::vector<OverlayTxEntry> batch;
            batch.reserve(old_layer.GetOrderedTxs().size());
            for (auto [tx_id, entry] : old_layer.GetOrderedTxs()) {
                for (auto &coin : entry.created_coins) {
                    coin.creation_height = next_height;
                    coin.creation_parent_mtp = parent_mtp;
                    coin.expiration_height = ComputeUtxoExpirationHeight(
                        next_height, coin.coinbase, coin.fee_per_output);
                }
                batch.push_back(std::move(entry));
            }
            reanchored.AddTransactionBatch(batch, true);
            frozen_epochs_.push_back(std::move(reanchored));
        }
    }

    auto existing_txs = speculative_layer_.GetOrderedTxs();
    txmerklix::Tree existing_tree = speculative_layer_.GetTxTree();
    speculative_layer_.Reset(tip_block_id, std::move(base_utxo_root),
                             base_mon_state, next_height, parent_mtp,
                             next_epoch_id_);
    speculative_layer_.AdoptTxTree(std::move(existing_tree));

    std::vector<OverlayTxEntry> batch;
    batch.reserve(existing_txs.size());
    for (auto &[tx_id, entry] : existing_txs) {
        for (auto &coin : entry.created_coins) {
            coin.creation_height = next_height;
            coin.creation_parent_mtp = parent_mtp;
            coin.expiration_height = ComputeUtxoExpirationHeight(
                next_height, coin.coinbase, coin.fee_per_output);
        }
        batch.push_back(std::move(entry));
    }
    speculative_layer_.AddTransactionBatch(batch, true);
}

bool MerklixOverlayManager::AddTransaction(
    const Hash &tx_id,
    const Hash &tx_hash,
    uint64_t linear_cost,
    const std::vector<Outpoint> &spent_outpoints,
    const std::vector<Coin> &created_coins,
    int64_t fee_sats,
    int64_t sigchecks,
    std::shared_ptr<const void> tx_ref) {
    return speculative_layer_.AddTransaction(
        tx_id, tx_hash, linear_cost, spent_outpoints, created_coins, fee_sats,
        sigchecks, std::move(tx_ref));
}

size_t MerklixOverlayManager::AddTransactionBatch(
    std::span<OverlayTxEntry> entries) {
    return speculative_layer_.AddTransactionBatch(entries);
}

bool MerklixOverlayManager::RemoveTransaction(const Hash &tx_id) {
    return speculative_layer_.RemoveTransaction(tx_id);
}

const MempoolOverlayLayer &MerklixOverlayManager::FreezeEpochBatch() {
    (void)speculative_layer_.GetSubtreeARoot();
    (void)speculative_layer_.GetUtxoRootDigest();
    frozen_epochs_.push_back(speculative_layer_);
    ++next_epoch_id_;
    return frozen_epochs_.back();
}

} // namespace lotus::v2
