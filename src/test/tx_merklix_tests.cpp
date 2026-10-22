// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/commitment.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/minhash.h>
#include <lotus_v2/tx_merklix.h>
#include <script/script.h>
#include <streams.h>
#include <txmempool.h>
#include <validation.h>

#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <thread>
#include <vector>

using V2Hash = lotus::v2::Hash;
using lotus::v2::TxIdentityPair;
namespace txm = lotus::v2::txmerklix;
namespace mh = lotus::v2::minhash;

namespace {
V2Hash RandomHash(FastRandomContext &rng) {
    const uint256 v = rng.rand256();
    V2Hash out;
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

V2Hash Reference(const std::map<V2Hash, V2Hash> &members) {
    std::vector<TxIdentityPair> pairs;
    pairs.reserve(members.size());
    for (const auto &[id, hash] : members) pairs.push_back({hash, id});
    return lotus::v2::BuildTxSubtreeA(pairs);
}

std::vector<uint64_t> ReferenceSketch(const std::map<V2Hash, V2Hash> &members) {
    std::vector<uint64_t> values;
    for (const auto &[id, hash] : members) values.push_back(mh::Value(id, hash));
    return mh::Reference(std::move(values));
}

std::map<V2Hash, V2Hash> Members(const txm::Snapshot &snapshot) {
    std::map<V2Hash, V2Hash> out;
    snapshot.ForEachLeaf([&](const txm::Leaf &leaf) { out.emplace(leaf.key, leaf.tx_hash); });
    return out;
}

uint64_t Counter(const std::atomic<uint64_t> &c) { return c.load(); }
} // namespace

BOOST_FIXTURE_TEST_SUITE(tx_merklix_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(canonical_root_equivalence_with_consensus_and_legacy_arena) {
    FastRandomContext rng{uint256{0x51}};
    for (size_t n : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{17},
                     size_t{1000}, size_t{5000}}) {
        txm::Tree tree;
        lotus::v2::TxOverlayArena legacy;
        uint32_t legacy_root{lotus::v2::TxOverlayArena::kNullIdx};
        std::map<V2Hash, V2Hash> members;
        while (members.size() < n) {
            const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
            members.emplace(id, hash);
            BOOST_CHECK(tree.Insert(id, hash) == txm::Tree::Change::Inserted);
            legacy_root = legacy.InsertTxLeaf(legacy_root, id, hash);
        }
        BOOST_CHECK_EQUAL(tree.Count(), n);
        const V2Hash expected = Reference(members);
        BOOST_CHECK(tree.RootDigest() == expected);
        BOOST_CHECK(legacy.SubtreeARoot(legacy_root) == expected);
        // Remove a random half, then re-add it: every intermediate root matches.
        std::vector<V2Hash> removed;
        for (auto it = members.begin(); it != members.end();) {
            if (rng.randbool()) {
                BOOST_CHECK(tree.Erase(it->first));
                legacy_root = legacy.EraseTxLeaf(legacy_root, it->first);
                removed.push_back(it->first);
                it = members.erase(it);
            } else {
                ++it;
            }
        }
        BOOST_CHECK(tree.RootDigest() == Reference(members));
        BOOST_CHECK(legacy.SubtreeARoot(legacy_root) == Reference(members));
        BOOST_CHECK(!tree.Erase(RandomHash(rng))); // non-member
        for (const V2Hash &id : removed) {
            const V2Hash hash = RandomHash(rng);
            members.emplace(id, hash);
            tree.Insert(id, hash);
        }
        BOOST_CHECK(tree.RootDigest() == Reference(members));
        for (const auto &[id, hash] : members) {
            BOOST_CHECK(tree.FindHash(id) == hash);
        }
    }
}

BOOST_AUTO_TEST_CASE(adversarial_prefixes_and_deepest_split) {
    std::map<V2Hash, V2Hash> members;
    txm::Tree tree;
    for (uint64_t i = 0; i < 4097; ++i) {
        V2Hash id{}, hash{};
        for (unsigned byte = 0; byte < 8; ++byte) {
            id[2 + byte] = hash[byte] = (i >> (8 * byte)) & 255;
        }
        members.emplace(id, hash);
        tree.Insert(id, hash);
    }
    BOOST_CHECK(tree.RootDigest() == Reference(members));
    // Two keys differing only at canonical bit 255.
    txm::Tree deep;
    std::map<V2Hash, V2Hash> pair;
    V2Hash a{}, b{};
    b[31] = 128;
    pair.emplace(a, a);
    pair.emplace(b, a);
    deep.Insert(a, a);
    deep.Insert(b, a);
    BOOST_CHECK(deep.RootDigest() == Reference(pair));
    BOOST_CHECK(deep.Erase(b));
    pair.erase(b);
    BOOST_CHECK(deep.RootDigest() == Reference(pair));
}

BOOST_AUTO_TEST_CASE(duplicate_replacement_and_readd_semantics) {
    FastRandomContext rng{uint256{0x52}};
    txm::Tree tree;
    const V2Hash id = RandomHash(rng), h1 = RandomHash(rng), h2 = RandomHash(rng);
    BOOST_CHECK(tree.Insert(id, h1) == txm::Tree::Change::Inserted);
    const uint64_t v1 = tree.Version();
    const auto sketch1 = tree.CurrentSketch().values;
    const V2Hash root1 = tree.RootDigest();
    // Identical membership: no version, sketch or structure change.
    BOOST_CHECK(tree.Insert(id, h1) == txm::Tree::Change::Unchanged);
    BOOST_CHECK_EQUAL(tree.Version(), v1);
    BOOST_CHECK(tree.CurrentSketch().values == sketch1);
    // Same TxId, different TxHash: one element replaced, never counted twice.
    BOOST_CHECK(tree.Insert(id, h2) == txm::Tree::Change::Replaced);
    BOOST_CHECK_EQUAL(tree.Count(), 1U);
    BOOST_CHECK_GT(tree.Version(), v1);
    BOOST_CHECK(tree.CurrentSketch().values == std::vector<uint64_t>{mh::Value(id, h2)});
    BOOST_CHECK(tree.RootDigest() != root1);
    // Remove and re-add the original: identical root and sketch again.
    BOOST_CHECK(tree.Erase(id));
    BOOST_CHECK(tree.RootDigest() == txm::EmptyDigest());
    BOOST_CHECK(tree.CurrentSketch().values.empty());
    tree.Insert(id, h1);
    BOOST_CHECK(tree.RootDigest() == root1);
    BOOST_CHECK(tree.CurrentSketch().values == sketch1);
}

BOOST_AUTO_TEST_CASE(ordinary_readers_do_not_hash) {
    FastRandomContext rng{uint256{0x53}};
    txm::Tree tree;
    std::vector<V2Hash> ids;
    const uint64_t hashes_before = Counter(txm::Stats().node_hashes);
    for (int i = 0; i < 2000; ++i) {
        ids.push_back(RandomHash(rng));
        tree.Insert(ids.back(), RandomHash(rng));
    }
    for (int i = 0; i < 500; ++i) tree.Erase(ids[i]);
    const auto pinned = tree.Pin();
    for (const V2Hash &id : ids) {
        (void)tree.Contains(id);
        (void)pinned->FindHash(id);
    }
    V2Hash prefix{};
    (void)pinned->Leaves(prefix, 8, 64);
    (void)Members(*pinned);
    // Structure maintenance, lookups, pins and leaf enumeration hash nothing.
    BOOST_CHECK_EQUAL(Counter(txm::Stats().node_hashes), hashes_before);
    (void)pinned->RootDigest();
    BOOST_CHECK_GT(Counter(txm::Stats().node_hashes), hashes_before);
}

BOOST_AUTO_TEST_CASE(pinned_snapshot_is_stable_under_later_writes) {
    FastRandomContext rng{uint256{0x54}};
    txm::Tree tree;
    std::map<V2Hash, V2Hash> members;
    for (int i = 0; i < 3000; ++i) {
        const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
        members.emplace(id, hash);
        tree.Insert(id, hash);
    }
    // Pin before any hashing: the lazy commitment must still describe the
    // pinned membership after the working view diverges.
    const auto pinned = tree.Pin();
    const auto pinned_members = members;
    const uint64_t pinned_version = pinned->Version();
    const auto pinned_sketch = pinned->GetSketch().values;
    for (int i = 0; i < 2000; ++i) {
        const int op = rng.randrange(3);
        if (op == 0 || members.empty()) {
            const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
            members.emplace(id, hash);
            tree.Insert(id, hash);
        } else {
            auto it = members.begin();
            std::advance(it, rng.randrange(members.size()));
            if (op == 1) {
                tree.Erase(it->first);
                members.erase(it);
            } else {
                it->second = RandomHash(rng);
                tree.Insert(it->first, it->second);
            }
        }
        if (i % 500 == 0) (void)tree.RootDigest(); // hash shared nodes too
    }
    BOOST_CHECK(Members(*pinned) == pinned_members);
    BOOST_CHECK_EQUAL(pinned->Count(), pinned_members.size());
    BOOST_CHECK_EQUAL(pinned->Version(), pinned_version);
    BOOST_CHECK(pinned->GetSketch().values == pinned_sketch);
    BOOST_CHECK(pinned_sketch == ReferenceSketch(pinned_members));
    BOOST_CHECK(pinned->RootDigest() == Reference(pinned_members));
    BOOST_CHECK(tree.RootDigest() == Reference(members));
    BOOST_CHECK(tree.CurrentSketch().values == ReferenceSketch(members));
}

BOOST_AUTO_TEST_CASE(concurrent_hashers_and_releases_during_writes) {
    // One writer mutates and pins under its own (single-thread) ownership;
    // reader threads hash and enumerate pinned snapshots concurrently, then
    // release them on their own threads while the writer keeps allocating.
    FastRandomContext rng{uint256{0x55}};
    txm::Tree tree;
    std::map<V2Hash, V2Hash> members;
    for (int i = 0; i < 1500; ++i) {
        const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
        members.emplace(id, hash);
        tree.Insert(id, hash);
    }
    struct Work {
        std::shared_ptr<const txm::Snapshot> snapshot;
        V2Hash expected;
        size_t count;
    };
    std::mutex queue_mutex;
    std::vector<Work> queue;
    std::atomic<bool> done{false};
    std::atomic<int> failures{0}, checked{0};
    auto reader = [&] {
        while (true) {
            Work work;
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                if (queue.empty()) {
                    if (done) return;
                } else {
                    work = std::move(queue.back());
                    queue.pop_back();
                }
            }
            if (!work.snapshot) {
                std::this_thread::yield();
                continue;
            }
            // Two hashers on the same pinned version race through the cache.
            V2Hash a, b;
            std::thread twin([&] { b = work.snapshot->RootDigest(); });
            a = work.snapshot->RootDigest();
            twin.join();
            if (a != work.expected || b != work.expected ||
                work.snapshot->Count() != work.count) {
                ++failures;
            }
            ++checked;
            work.snapshot.reset(); // release off the writer thread
        }
    };
    std::vector<std::thread> readers;
    for (int i = 0; i < 3; ++i) readers.emplace_back(reader);
    for (int round = 0; round < 60; ++round) {
        for (int i = 0; i < 50; ++i) {
            if (rng.randbool() || members.empty()) {
                const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
                members.emplace(id, hash);
                tree.Insert(id, hash);
            } else {
                auto it = members.begin();
                std::advance(it, rng.randrange(members.size()));
                tree.Erase(it->first);
                members.erase(it);
            }
        }
        if (round % 7 == 0) (void)tree.RootDigest(); // writer hashes shared nodes too
        Work work{tree.Pin(), Reference(members), members.size()};
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue.push_back(std::move(work));
    }
    done = true;
    for (auto &t : readers) t.join();
    BOOST_CHECK_EQUAL(failures.load(), 0);
    BOOST_CHECK_EQUAL(checked.load(), 60);
    BOOST_CHECK(tree.RootDigest() == Reference(members));
}

BOOST_AUTO_TEST_CASE(pin_defers_exhausted_sketch_refill_to_immutable_snapshot) {
    FastRandomContext rng{uint256{0x72}};
    txm::Tree tree;
    std::map<V2Hash, V2Hash> members;
    std::vector<std::pair<uint64_t, V2Hash>> ranked;
    for (int i = 0; i < 1000; ++i) {
        const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
        members.emplace(id, hash);
        tree.Insert(id, hash);
        ranked.emplace_back(mh::Value(id, hash), id);
    }
    std::sort(ranked.begin(), ranked.end());
    for (int i = 0; i < 193; ++i) {
        tree.Erase(ranked[i].second);
        members.erase(ranked[i].second);
    }
    const auto expected = ReferenceSketch(members);
    const auto before = Counter(txm::Stats().sketch_rebuild_members);
    const auto pinned = tree.Pin();
    BOOST_CHECK_EQUAL(Counter(txm::Stats().sketch_rebuild_members), before);
    tree.Clear(); // refill must use the pinned version, never the live tree
    std::atomic<int> failures{0};
    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&] {
            if (pinned->GetSketch().values != expected) ++failures;
        });
    }
    for (auto &reader : readers) reader.join();
    BOOST_CHECK_EQUAL(failures.load(), 0);
    BOOST_CHECK_EQUAL(Counter(txm::Stats().sketch_rebuild_members), before + members.size());
    BOOST_CHECK(pinned->RootDigest() == Reference(members));
}

BOOST_AUTO_TEST_CASE(incremental_minhash_matches_reference_through_deletions) {
    FastRandomContext rng{uint256{0x56}};
    txm::Tree tree;
    std::map<V2Hash, V2Hash> members;
    const uint64_t rebuilds_before = Counter(txm::Stats().sketch_rebuilds);
    for (int step = 0; step < 6000; ++step) {
        const int op = rng.randrange(10);
        if (op < 6 || members.size() < 10) {
            const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
            members.emplace(id, hash);
            tree.Insert(id, hash);
        } else if (op < 9) {
            auto it = members.begin();
            std::advance(it, rng.randrange(members.size()));
            tree.Erase(it->first);
            members.erase(it);
        } else {
            auto it = members.begin();
            std::advance(it, rng.randrange(members.size()));
            it->second = RandomHash(rng);
            tree.Insert(it->first, it->second);
        }
        if (step % 97 == 0) {
            BOOST_CHECK(tree.CurrentSketch().values == ReferenceSketch(members));
        }
    }
    BOOST_CHECK(tree.CurrentSketch().values == ReferenceSketch(members));
    // Adversarial deletions: repeatedly remove the current minimum members,
    // forcing the candidate buffer to drain and rebuild from the tree.
    std::map<uint64_t, V2Hash> by_value;
    for (const auto &[id, hash] : members) by_value.emplace(mh::Value(id, hash), id);
    for (int i = 0; i < int(mh::CANDIDATES) + 50 && !by_value.empty(); ++i) {
        const V2Hash id = by_value.begin()->second;
        by_value.erase(by_value.begin());
        tree.Erase(id);
        members.erase(id);
        if (i % 16 == 0) {
            BOOST_CHECK(tree.CurrentSketch().values == ReferenceSketch(members));
        }
    }
    BOOST_CHECK(tree.CurrentSketch().values == ReferenceSketch(members));
    BOOST_CHECK_GT(Counter(txm::Stats().sketch_rebuilds), rebuilds_before);
    // Jaccard estimates: identical sets are 1; disjoint sets are 0.
    const auto s = tree.CurrentSketch().values;
    BOOST_CHECK_EQUAL(mh::EstimateJaccard(s, s), 1.0);
    txm::Tree other;
    for (int i = 0; i < 500; ++i) other.Insert(RandomHash(rng), RandomHash(rng));
    BOOST_CHECK_EQUAL(mh::EstimateJaccard(s, other.CurrentSketch().values), 0.0);
}

BOOST_AUTO_TEST_CASE(shared_subtrees_copy_only_touched_paths) {
    FastRandomContext rng{uint256{0x57}};
    txm::Tree tree;
    std::map<V2Hash, V2Hash> members;
    for (int i = 0; i < 4096; ++i) {
        const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
        members.emplace(id, hash);
        tree.Insert(id, hash);
    }
    // Unshared working view mutates in place: no path copies.
    const uint64_t copies0 = Counter(txm::Stats().path_copies);
    const uint64_t inplace0 = Counter(txm::Stats().inplace_updates);
    for (int i = 0; i < 100; ++i) tree.Insert(RandomHash(rng), RandomHash(rng));
    BOOST_CHECK_EQUAL(Counter(txm::Stats().path_copies), copies0);
    BOOST_CHECK_GT(Counter(txm::Stats().inplace_updates), inplace0);
    // Copy shares everything (O(1)); one write copies at most one path.
    const V2Hash root_before = tree.RootDigest();
    txm::Tree copy = tree;
    const size_t live_before = tree.GetStore()->LiveBranches();
    copy.Insert(RandomHash(rng), RandomHash(rng));
    const uint64_t copied = Counter(txm::Stats().path_copies) - copies0;
    BOOST_CHECK_GT(copied, 0U);
    BOOST_CHECK_LE(copied, 40U); // ~log2(4196) path, never O(n)
    BOOST_CHECK_LE(tree.GetStore()->LiveBranches() - live_before, copied + 1);
    // The second write on the same path finds it unique: in place.
    const uint64_t copies1 = Counter(txm::Stats().path_copies);
    copy.Insert(RandomHash(rng), RandomHash(rng));
    BOOST_CHECK_LE(Counter(txm::Stats().path_copies) - copies1, 40U);
    BOOST_CHECK(tree.RootDigest() == root_before);
    BOOST_CHECK_EQUAL(copy.Count(), tree.Count() + 2);
}

BOOST_AUTO_TEST_CASE(reclamation_slot_reuse_and_weak_generations) {
    FastRandomContext rng{uint256{0x58}};
    auto store = txm::Store::Create();
    txm::Tree tree{store};
    std::vector<V2Hash> ids;
    for (int i = 0; i < 1000; ++i) {
        ids.push_back(RandomHash(rng));
        tree.Insert(ids.back(), RandomHash(rng));
    }
    BOOST_CHECK_EQUAL(store->LiveLeaves(), 1000U);
    BOOST_CHECK_EQUAL(store->LiveBranches(), 999U);
    auto pinned = tree.Pin();
    const txm::NodeId root = tree.Root();
    const auto weak_root = store->Weak(root);
    // A long-lived snapshot keeps its whole version alive after the working
    // view is cleared; nothing is freed or reused underneath it.
    tree.Clear();
    BOOST_CHECK_EQUAL(store->LiveLeaves(), 1000U);
    const txm::NodeId retained = store->TryRetain(weak_root);
    BOOST_CHECK_EQUAL(retained, root);
    store->Release(retained);
    const V2Hash pinned_root = pinned->RootDigest();
    // Releasing the last owner reclaims every node.
    pinned.reset();
    BOOST_CHECK_EQUAL(store->LiveLeaves(), 0U);
    BOOST_CHECK_EQUAL(store->LiveBranches(), 0U);
    BOOST_CHECK_EQUAL(store->TryRetain(weak_root), txm::kNull);
    // New members reuse freed slots; a stale weak handle never resolves to the
    // new occupant (generation mismatch), even if the slot index matches.
    const uint64_t reuses0 = Counter(txm::Stats().slot_reuses);
    for (int i = 0; i < 1000; ++i) tree.Insert(RandomHash(rng), RandomHash(rng));
    BOOST_CHECK_GE(Counter(txm::Stats().slot_reuses) - reuses0, 1999U);
    BOOST_CHECK_EQUAL(store->TryRetain(weak_root), txm::kNull);
    BOOST_CHECK(tree.RootDigest() != pinned_root);
    // Sole owner clearing an otherwise unused store returns its chunks.
    store.reset();
    tree.Clear();
    BOOST_CHECK_EQUAL(tree.GetStore()->RetainedBytes(), sizeof(txm::Branch));
}

BOOST_AUTO_TEST_CASE(weak_handle_stays_stale_after_trim_and_reallocation) {
    FastRandomContext rng{uint256{0x92}};
    txm::Tree tree;
    tree.Insert(RandomHash(rng), RandomHash(rng));
    const auto weak = tree.GetStore()->Weak(tree.Root());
    tree.Clear(); // sole owner: deallocates the leaf slab
    tree.Insert(RandomHash(rng), RandomHash(rng));
    BOOST_CHECK_EQUAL(tree.Root(), weak.node); // same slot, new allocation epoch
    const auto retained = tree.GetStore()->TryRetain(weak);
    BOOST_CHECK_EQUAL(retained, txm::kNull);
    if (retained != txm::kNull) tree.GetStore()->Release(retained);
}

BOOST_AUTO_TEST_CASE(overlay_layer_freeze_and_reanchor_share_trees) {
    FastRandomContext rng{uint256{0x59}};
    lotus::v2::MerklixOverlayManager manager;
    std::map<V2Hash, V2Hash> members;
    for (int i = 0; i < 300; ++i) {
        const V2Hash id = RandomHash(rng), hash = RandomHash(rng);
        members.emplace(id, hash);
        manager.AddTransaction(id, hash, 100, {}, {});
    }
    BOOST_CHECK(manager.GetSpeculativeOverlay().GetSubtreeARoot() == Reference(members));
    const uint64_t copies0 = Counter(txm::Stats().path_copies);
    const auto &frozen = manager.FreezeEpochBatch();
    const V2Hash frozen_root = frozen.GetSubtreeARoot();
    // Freezing is a structural share: no node copies until the next write.
    BOOST_CHECK_EQUAL(Counter(txm::Stats().path_copies), copies0);
    const V2Hash extra = RandomHash(rng);
    manager.AddTransaction(extra, extra, 100, {}, {});
    members.emplace(extra, extra);
    BOOST_CHECK(manager.GetFrozenEpochs().back().GetSubtreeARoot() == frozen_root);
    BOOST_CHECK(manager.GetSpeculativeOverlay().GetSubtreeARoot() == Reference(members));
    // Re-anchoring keeps membership and reuses the existing trees.
    V2Hash tip{};
    tip[0] = 1;
    const uint64_t leaves0 = Counter(txm::Stats().leaf_allocs);
    manager.ReanchorExistingTxs(tip, nullptr, lotus::v2::GetInitialV2MonetaryState(), 2, 0);
    BOOST_CHECK_EQUAL(Counter(txm::Stats().leaf_allocs), leaves0);
    BOOST_CHECK(manager.GetSpeculativeOverlay().GetSubtreeARoot() == Reference(members));
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), members.size());
}

BOOST_AUTO_TEST_SUITE_END()
