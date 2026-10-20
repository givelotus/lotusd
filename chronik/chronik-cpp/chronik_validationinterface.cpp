// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chronik-cpp/util/hash.h>
#include <chronik_lib/src/ffi.rs.h>
#include <kernel/chain.h>
#include <logging.h>
#include <node/context.h>
#include <node/metrics.h>
#include <primitives/block.h>
#include <txmempool.h>
#include <validationinterface.h>

#include <util/validation_queue_memory.h>
#include <shutdown.h>
#include <util/bounded_task_queue.h>

#include <functional>

namespace chronik {

/**
 * CValidationInterface connecting bitcoind events to Chronik
 */
class ChronikValidationInterface final : public CValidationInterface {
public:
    ChronikValidationInterface(const node::NodeContext &node,
                               rust::Box<chronik_bridge::Chronik> chronik_box)
        : m_chronik(std::move(chronik_box)), m_node(node),
          m_queue(MAX_QUEUE_BYTES, MAX_QUEUE_SIZE, [] {
              LogPrintf("FATAL: Chronik worker queue overflow or worker "
                        "failure; stopping node. "
                        "Restart to resync Chronik from block files.\n");
              StartShutdown();
          }) {}

    ~ChronikValidationInterface() { StopWorker(); }

    void Register() {
        m_node.validation_signals->RegisterValidationInterface(this);
    }

    void Unregister() {
        m_node.validation_signals->UnregisterValidationInterface(this);
    }

    void InterruptChronik() { m_chronik->interrupt(); }

    // Normal-operation fence for work already forwarded by ValidationSignals.
    // Once shutdown starts, StopWorker/join owns draining the remaining FIFO.
    void SyncTransactionQueue() override { m_queue.Sync(); }

    void StopWorker() { m_queue.Stop(); }

    bool StopChronik() {
        StopWorker();
        try {
            m_chronik->stop();
        } catch (const std::exception &e) {
            LogPrintf("Error stopping Chronik: %s\n", e.what());
            return false;
        }
        return true;
    }

private:
    static constexpr size_t MAX_QUEUE_SIZE = 65536;
    static constexpr size_t MAX_QUEUE_BYTES = 256 * 1024 * 1024;
    static constexpr size_t TASK_OVERHEAD = 256;

    rust::Box<chronik_bridge::Chronik> m_chronik;
    const node::NodeContext &m_node;
    BoundedTaskQueue m_queue;

    void Enqueue(std::function<void()> task, size_t bytes = 0) {
        // Overflow is fatal: never block the shared ValidationSignals
        // scheduler.
        m_queue.Enqueue(TASK_OVERHEAD + bytes, std::move(task));
    }

    using CValidationInterface::TransactionAddedToMempool;

    void TransactionAddedToMempool(
        const CTransactionRef &ptx,
        std::shared_ptr<const std::vector<Coin>> spent_coins,
        uint64_t /* mempool_sequence */, int64_t entry_time) override {
        if (spent_coins) {
            const int64_t tx_time =
                entry_time != 0
                    ? entry_time
                    : m_node.mempool->info(ptx->GetId()).m_time.count();
            const size_t bytes = validation_queue::TxBytes(ptx) + validation_queue::CoinBytes(spent_coins);
            Enqueue(
                [this, ptx, spent_coins = std::move(spent_coins), tx_time]() {
                    m_chronik->handle_tx_added_to_mempool(*ptx, *spent_coins,
                                                          tx_time);
                },
                bytes);
        } else {
            LogPrintf("Chronik: transaction %s added to mempool but spent "
                      "coins are not available\n",
                      ptx->GetId().ToString());
        }
    }

    void
    TransactionRemovedFromMempool(const CTransactionRef &ptx,
                                  MemPoolRemovalReason /* reason */,
                                  uint64_t /* mempool_sequence */) override {
        const auto txid = chronik::util::HashToArray(ptx->GetId());
        Enqueue([this, txid]() {
            m_chronik->handle_tx_removed_from_mempool(txid);
        });
    }

    void BlockConnected(ChainstateRole role,
                        const std::shared_ptr<const CBlock> &block,
                        const CBlockIndex *pindex) override {
        // Ignore events from the assumed-valid chain; we will process its
        // blocks (sequentially) after it is fully verified by the background
        // chainstate.
        if (role == ChainstateRole::ASSUMEDVALID) {
            return;
        }

        // We can safely pass T& here as Rust guarantees us that no references
        // can be kept after the below function call completed.
        Enqueue(
            [this, block, pindex]() {
                m_chronik->handle_block_connected(*block, *pindex);
                node::SetChronikIndexedHeight(pindex->nHeight);
            },
            validation_queue::BlockBytes(block));
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock> &block,
                           const CBlockIndex *pindex) override {
        // See BlockConnected for safety
        Enqueue(
            [this, block, pindex]() {
                m_chronik->handle_block_disconnected(*block, *pindex);
                node::SetChronikIndexedHeight(pindex->nHeight - 1);
            },
            validation_queue::BlockBytes(block));
    }

    void BlockFinalized(const CBlockIndex *pindex) override {
        Enqueue(
            [this, pindex]() { m_chronik->handle_block_finalized(*pindex); });
    }

    void BlockInvalidated(const CBlockIndex *pindex,
                          const std::shared_ptr<const CBlock> &block) override {
        Enqueue(
            [this, block, pindex]() {
                m_chronik->handle_block_invalidated(*block, *pindex);
            },
            validation_queue::BlockBytes(block));
    }

    void TransactionFinalized(const CTransactionRef &tx) override {
        const auto txid = chronik::util::HashToArray(tx->GetId());
        Enqueue([this, txid]() { m_chronik->handle_tx_finalized(txid); });
    }

    void TransactionInvalidated(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<Coin>> spent_coins) override {
        if (spent_coins) {
            const size_t bytes = validation_queue::TxBytes(tx) + validation_queue::CoinBytes(spent_coins);
            Enqueue(
                [this, tx, spent_coins = std::move(spent_coins)]() {
                    m_chronik->handle_tx_invalidated(*tx, *spent_coins);
                },
                bytes);
        } else {
            LogPrintf("Chronik: transaction %s invalidated but spent coins are "
                      "not available\n",
                      tx->GetId().ToString());
        }
    }
};

std::unique_ptr<ChronikValidationInterface> g_chronik_validation_interface;

void StartChronikValidationInterface(
    const node::NodeContext &node,
    rust::Box<chronik_bridge::Chronik> chronik_box) {
    g_chronik_validation_interface =
        std::make_unique<ChronikValidationInterface>(node,
                                                     std::move(chronik_box));
    g_chronik_validation_interface->Register();
}

void InterruptChronikRequestHandlers() {
    if (g_chronik_validation_interface) {
        g_chronik_validation_interface->InterruptChronik();
    }
}

void StopChronikValidationInterface() {
    if (g_chronik_validation_interface) {
        g_chronik_validation_interface->Unregister();
        g_chronik_validation_interface->StopChronik();
        // Reset so the Box is dropped and all handles are released.
        g_chronik_validation_interface.reset();
    }
}

} // namespace chronik
