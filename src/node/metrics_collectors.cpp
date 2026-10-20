// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics_collectors.h>

#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <feerate.h>
#include <lotus_v2/fee_hysteresis.h>
#include <net/v2_protocol_handler.h>
#include <net_processing.h>
#include <node/context.h>
#include <node/metrics.h>
#include <sync.h>
#include <txconflicting.h>
#include <txmempool.h>
#include <txorphanage.h>

#include <cstdint>
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
