// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics_collectors.h>

#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <feerate.h>
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
