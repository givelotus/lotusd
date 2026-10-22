// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics_collectors.h>

#include <addrman.h>
#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <banman.h>
#include <feerate.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/tx_merklix.h>
#include <net/full_mempool_reconciliation.h>
#include <net/v2_protocol_handler.h>
#include <net_processing.h>
#include <node/context.h>
#include <node/metrics.h>
#include <sync.h>
#include <txconflicting.h>
#include <txmempool.h>
#include <txorphanage.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace node {

namespace {
    GlobalMutex g_collectors_mutex;
    std::vector<uint64_t> g_collectors GUARDED_BY(g_collectors_mutex);

    void AddAvalancheCollector(NodeMetrics &m, avalanche::Processor &ava) {
        g_collectors.push_back(m.registry.AddCollector([&m, &ava] {
            const auto quorum{ava.getQuorumFigures()};
            m.avalanche_quorum_established.Set(ava.isQuorumLatched() ? 1 : 0);
            m.avalanche_quorum_nodes.Set(double(quorum.nodeCount));
            m.avalanche_quorum_score.Set(double(quorum.totalScore), 0);
            m.avalanche_quorum_score.Set(double(quorum.connectedScore), 1);
            // cs_peerManager, briefly: four size reads
            ava.withPeerManager([&](const avalanche::PeerManager &pm) {
                using P = AvalancheProofPool;
                m.avalanche_proofs.Set(
                    double(pm.getValidProofPool().countProofs()),
                    size_t(P::VALID));
                m.avalanche_proofs.Set(
                    double(pm.getConflictingProofPool().countProofs()),
                    size_t(P::CONFLICTING));
                m.avalanche_proofs.Set(
                    double(pm.getImmatureProofPool().countProofs()),
                    size_t(P::IMMATURE));
                m.avalanche_proofs.Set(
                    double(pm.getDanglingProofPool().countProofs()),
                    size_t(P::DANGLING));
            });
        }));
    }
    void AddMempoolCollector(NodeMetrics &m, CTxMemPool &mempool) {
        g_collectors.push_back(m.registry.AddCollector([&m, &mempool] {
            // mempool.cs, briefly, as getmempoolinfo and estimatefee take it
            const auto per_byte{[](const CFeeRate &rate) {
                return double(rate.GetFeePerK() / SATOSHI) / 1000;
            }};
            m.mempool_min_fee_rate.Set(per_byte(mempool.GetMinFee()), 0);
            m.mempool_min_fee_rate.Set(per_byte(mempool.estimateFee()), 1);
            // The pools' own mutexes, briefly
            m.tx_pool_transactions.Set(
                double(mempool.withOrphanage(
                    [](const TxOrphanage &pool) { return pool.Size(); })),
                0);
            m.tx_pool_transactions.Set(
                double(mempool.withConflicting(
                    [](const TxConflicting &pool) { return pool.Size(); })),
                1);
        }));
    }
    void AddSnapshotSyncCollector(NodeMetrics &m,
                                  lotus::v2::net::V2PeerProtocolHandler &v2) {
        g_collectors.push_back(m.registry.AddCollector([&m, &v2] {
            // The handler's mutex, briefly, as getfastsyncinfo takes it
            const auto status{v2.GetFastSyncSwarmStatus()};
            for (size_t i = 0; i < metric_labels::SnapshotSyncStates().size();
                 ++i) {
                m.snapshot_sync_state.Set(size_t(status.state) == i ? 1 : 0, i);
            }
            m.snapshot_sync_pivot_height.Set(double(status.pivot_height));
            m.snapshot_sync_shards.Set(double(status.total_non_empty_shards),
                                       0);
            m.snapshot_sync_shards.Set(double(status.verified_shards), 1);
            m.snapshot_sync_shards.Set(double(status.pending_shards), 2);
            m.snapshot_sync_shards.Set(double(status.in_flight_shards), 3);
            m.snapshot_sync_coins_imported.Set(double(status.coins_imported));
            m.snapshot_sync_blocks_peeled.Set(double(status.blocks_peeled));
            m.snapshot_sync_peers.Set(double(status.active_peers), 0);
            m.snapshot_sync_peers.Set(double(status.banned_swarm_peers), 1);
        }));
    }

    void AddAdaptiveCapacityCollector(NodeMetrics &m) {
        g_collectors.push_back(m.registry.AddCollector([&m] {
            // The controller's own mutex, briefly
            const auto &c{lotus::v2::GetGlobalFeeHysteresisController()};
            using A = AdaptiveLimit;
            m.adaptive_block_size.Set(double(c.GetAdaptiveMaxBlockSize()),
                                      size_t(A::MAX));
            m.adaptive_block_size.Set(double(c.GetAdaptiveTargetBlockSize()),
                                      size_t(A::TARGET));
            m.adaptive_block_size.Set(
                double(c.GetAdaptiveMaxGeneratedBlockSize()),
                size_t(A::MAX_GENERATED));
            m.adaptive_block_size.Set(double(c.GetEmaBlockSizeBytes()),
                                      size_t(A::EMA));
            m.adaptive_block_size_history_complete.Set(
                c.HasCompleteAdaptiveHistory() ? 1 : 0);
        }));
    }
    void AddPeersCollector(NodeMetrics &m, const AddrMan *addrman,
                           BanMan *banman) {
        g_collectors.push_back(m.registry.AddCollector([&m, addrman, banman] {
            if (addrman) {
                // addrman's own mutex, briefly
                const auto [new_count, tried_count]{addrman->NewTriedCounts()};
                m.addrman_addresses.Set(double(new_count), 0);
                m.addrman_addresses.Set(double(tried_count), 1);
            }
            if (banman) {
                // The ban list's mutex, for a copy (as listbanned)
                banmap_t banned;
                banman->GetBanned(banned);
                m.p2p_banned.Set(double(banned.size()));
            }
        }));
    }
    /**
     * Slab Merklix tree and full-mempool reconciliation series. The process
     * counters live in the subsystems (relaxed atomics); these metrics read
     * them at scrape time. Registered once per process.
     */
    void AddMerklixMetrics(NodeMetrics &m) {
        static std::once_flag registered;
        std::call_once(registered, [&m] {
            auto counter = [&m](const char *name, const char *help, auto fn) {
                m.registry.Add(std::make_unique<metrics::FunctionCounter>(
                    MetricName(name), help, fn));
            };
            using lotus::v2::txmerklix::Stats;
            auto u = [](const std::atomic<uint64_t> &a) { return a.load(std::memory_order_relaxed); };
            counter("txmerklix_leaf_allocations_total", "Slab Merklix leaf nodes allocated.",
                    [u] { return u(Stats().leaf_allocs); });
            counter("txmerklix_branch_allocations_total", "Slab Merklix branch nodes allocated (new branch points and path copies).",
                    [u] { return u(Stats().branch_allocs); });
            counter("txmerklix_slot_reuses_total", "Slab Merklix allocations served from reclaimed slots.",
                    [u] { return u(Stats().slot_reuses); });
            counter("txmerklix_path_copies_total", "Shared Merklix branches copied because a snapshot or tree copy still referenced them.",
                    [u] { return u(Stats().path_copies); });
            counter("txmerklix_inplace_updates_total", "Exclusively owned Merklix branches mutated in place.",
                    [u] { return u(Stats().inplace_updates); });
            counter("txmerklix_nodes_freed_total", "Merklix nodes reclaimed after their last owner was released.",
                    [u] { return u(Stats().frees); });
            counter("txmerklix_node_hashes_total", "Lazy Merklix digest computations (leaves, branches and unary folds).",
                    [u] { return u(Stats().node_hashes); });
            counter("txmerklix_hash_races_total", "Concurrent digest computations that lost the cache publication race.",
                    [u] { return u(Stats().hash_cas_losses); });
            counter("txmerklix_pins_total", "Immutable Merklix snapshots pinned.",
                    [u] { return u(Stats().pins); });
            counter("txmerklix_parallel_completions_total", "Large dirty commitments completed with parallel subtree hashing.",
                    [u] { return u(Stats().parallel_completions); });
            counter("txmerklix_sketch_rebuilds_total", "MinHash candidate rebuilds after deletions exhausted the candidate buffer.",
                    [u] { return u(Stats().sketch_rebuilds); });
            counter("txmerklix_sketch_rebuild_members_total", "Members scanned by MinHash candidate rebuilds.",
                    [u] { return u(Stats().sketch_rebuild_members); });
            using lotus::v2::net::fullrecon::GlobalCounters;
            counter("fullrecon_captures_total", "Full-mempool reconciliation snapshots captured.",
                    [u] { return u(GlobalCounters().captures); });
            counter("fullrecon_capture_pins_total", "Captures served by an O(1) pinned mempool Merklix tree.",
                    [u] { return u(GlobalCounters().capture_pins); });
            counter("fullrecon_capture_fallbacks_total", "Captures that rebuilt a tree from copied mempool transactions.",
                    [u] { return u(GlobalCounters().capture_fallbacks); });
            counter("fullrecon_capture_lock_microseconds_total", "Time holding cs_main and the mempool lock to capture snapshots.",
                    [u] { return u(GlobalCounters().capture_lock_us); });
            counter("fullrecon_capture_build_microseconds_total", "Time constructing captured snapshots after the locks.",
                    [u] { return u(GlobalCounters().capture_build_us); });
            counter("fullrecon_commitment_microseconds_total", "Lazy commitment completion for offered roots, outside mempool locks.",
                    [u] { return u(GlobalCounters().commitment_us); });
            counter("fullrecon_offers_total", "Full-mempool reconciliation offers sent.",
                    [u] { return u(GlobalCounters().offers); });
            counter("fullrecon_coverage_complete_total", "Remote snapshots whose authenticated traversal completed.",
                    [u] { return u(GlobalCounters().coverage_complete); });
            counter("fullrecon_sketch_offers_total", "Received offers whose MinHash hint was evaluated.",
                    [u] { return u(GlobalCounters().sketch_offers); });
            counter("fullrecon_sketch_jaccard_ppm_total", "Summed estimated Jaccard similarity (parts per million) of evaluated offers.",
                    [u] { return u(GlobalCounters().sketch_jaccard_ppm); });
            counter("fullrecon_sketch_estimated_remote_only_total", "Summed MinHash estimates of remote-only members at offer time.",
                    [u] { return u(GlobalCounters().sketch_estimated_remote_only); });
            counter("fullrecon_sketch_completed_total", "Completed traversals with a MinHash estimate to compare.",
                    [u] { return u(GlobalCounters().sketch_completed); });
            counter("fullrecon_sketch_actual_recovered_total", "Members actually recovered by completed traversals with estimates.",
                    [u] { return u(GlobalCounters().sketch_actual_recovered); });
            counter("fullrecon_sketch_abs_error_total", "Summed absolute error between MinHash estimates and recovered members.",
                    [u] { return u(GlobalCounters().sketch_abs_error); });
            auto &live_leaves = m.registry.Add(std::make_unique<metrics::Gauge>(
                MetricName("txmerklix_live_leaves"), "Live slab Merklix leaf nodes (all stores)."));
            auto &live_branches = m.registry.Add(std::make_unique<metrics::Gauge>(
                MetricName("txmerklix_live_branches"), "Live slab Merklix branch nodes (all stores)."));
            auto &retained = m.registry.Add(std::make_unique<metrics::Gauge>(
                MetricName("txmerklix_retained_slot_bytes"), "Bytes of constructed slab slots retained for reuse or live (all stores)."));
            auto &stores = m.registry.Add(std::make_unique<metrics::Gauge>(
                MetricName("txmerklix_stores"), "Live slab Merklix stores."));
            m.registry.AddCollector([&live_leaves, &live_branches, &retained, &stores] {
                auto &s = Stats();
                live_leaves.Set(double(s.live_leaves.load(std::memory_order_relaxed)));
                live_branches.Set(double(s.live_branches.load(std::memory_order_relaxed)));
                retained.Set(double(s.retained_leaf_slots.load(std::memory_order_relaxed)) *
                                 sizeof(lotus::v2::txmerklix::Leaf) +
                             double(s.retained_branch_slots.load(std::memory_order_relaxed)) *
                                 sizeof(lotus::v2::txmerklix::Branch));
                stores.Set(double(s.stores.load(std::memory_order_relaxed)));
            });
        });
    }
} // namespace

void StartNodeMetricsCollectors(NodeContext &node) {
    NodeMetrics *m{GetNodeMetrics()};
    if (!m) {
        return;
    }
    LOCK(g_collectors_mutex);
    if (node.avalanche) {
        AddAvalancheCollector(*m, *node.avalanche);
    }
    if (node.mempool) {
        AddMempoolCollector(*m, *node.mempool);
    }
    if (node.peerman) {
        if (auto *v2{node.peerman->GetV2ProtocolHandler()}) {
            AddSnapshotSyncCollector(*m, *v2);
        }
    }
    AddAdaptiveCapacityCollector(*m);
    AddPeersCollector(*m, node.addrman.get(), node.banman.get());
    AddMerklixMetrics(*m);
}

void StopNodeMetricsCollectors() {
    NodeMetrics *m{GetNodeMetrics()};
    LOCK(g_collectors_mutex);
    if (m) {
        for (const uint64_t id : g_collectors) {
            m->registry.RemoveCollector(id);
        }
    }
    g_collectors.clear();
}

} // namespace node
