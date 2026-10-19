// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik/chronik-cpp/chronik_validationinterface.cpp and of the
// event handlers of chronik-lib/src/bridge.rs (`Chronik::handle_*`), feeding
// the native Service instead of the Rust indexer.

#include <hosts/abc/abc_subscriber.h>

#include <chronik/native/service.h>
#include <hosts/abc/abc_host.h>

#include <blockindex.h>
#include <kernel/chain.h>
#include <logging.h>
#include <node/context.h>
#include <primitives/block.h>
#include <shutdown.h>
#include <txmempool.h>
#include <undo.h>
#include <util/bounded_task_queue.h>
#include <util/validation_queue_memory.h>
#include <validationinterface.h>

#include <functional>

namespace chronik::native::abc {

namespace {

class NativeChronikValidationInterface final : public CValidationInterface {
public:
    NativeChronikValidationInterface(const node::NodeContext &node,
                                     const AbcHost &host,
                                     std::shared_ptr<Service> service)
        : m_node(node), m_host(host), m_service(std::move(service)),
          m_queue(MAX_QUEUE_BYTES, MAX_QUEUE_SIZE, [] {
              LogPrintf("FATAL: Chronik worker queue overflow or worker "
                        "failure; stopping node. "
                        "Restart to resync Chronik from block files.\n");
              StartShutdown();
          }) {}

    ~NativeChronikValidationInterface() { StopWorker(); }

    void Register() {
        m_node.validation_signals->RegisterValidationInterface(this);
    }

    void Unregister() {
        m_node.validation_signals->UnregisterValidationInterface(this);
    }

    void InterruptChronik() { m_service->Interrupt(); }

    // Normal-operation fence for work already forwarded by ValidationSignals.
    // Once shutdown starts, StopWorker/join owns draining the remaining FIFO.
    void SyncTransactionQueue() override { m_queue.Sync(); }

    void StopWorker() { m_queue.Stop(); }

    bool StopChronik() {
        StopWorker();
        try {
            m_service->Stop();
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

    const node::NodeContext &m_node;
    const AbcHost &m_host;
    std::shared_ptr<Service> m_service;
    BoundedTaskQueue m_queue;

    void Enqueue(std::function<void()> task, size_t bytes = 0) {
        // Overflow is fatal: never block the shared ValidationSignals
        // scheduler.
        m_queue.Enqueue(TASK_OVERHEAD + bytes, std::move(task));
    }

    using CValidationInterface::TransactionAddedToMempool;

    void TransactionAddedToMempool(
        const CTransactionRef &ptx,
        std::shared_ptr<const std::vector<::Coin>> spent_coins,
        uint64_t /* mempool_sequence */, int64_t entry_time) override {
        if (!spent_coins) {
            LogPrintf("Chronik: transaction %s added to mempool but spent "
                      "coins are not available\n",
                      ptx->GetId().ToString());
            return;
        }
        const int64_t tx_time =
            entry_time != 0
                ? entry_time
                : m_node.mempool->info(ptx->GetId()).m_time.count();
        const size_t bytes = validation_queue::TxBytes(ptx) +
                             validation_queue::CoinBytes(spent_coins);
        Enqueue(
            [this, ptx, spent_coins = std::move(spent_coins), tx_time]() {
                OkOrAbort(m_host, "handle_tx_added_to_mempool", [&] {
                    auto tx = std::make_shared<const Tx>(
                        ConvertTx(false, *ptx, *spent_coins));
                    m_service->HandleTxAddedToMempool(tx, tx_time);
                    m_host.Log(LogLevel::Debug,
                               "Chronik: transaction " +
                                   ptx->GetId().ToString() +
                                   " added to mempool\n");
                });
            },
            bytes);
    }

    void
    TransactionRemovedFromMempool(const CTransactionRef &ptx,
                                  MemPoolRemovalReason /* reason */,
                                  uint64_t /* mempool_sequence */) override {
        Enqueue([this, ptx]() {
            OkOrAbort(m_host, "handle_tx_removed_from_mempool", [&] {
                TxId txid;
                std::memcpy(txid.b.data(), ptx->GetId().begin(), 32);
                m_service->HandleTxRemovedFromMempool(txid);
            });
            m_host.Log(LogLevel::Debug, "Chronik: transaction " +
                                            ptx->GetId().ToString() +
                                            " removed from mempool\n");
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
        Enqueue(
            [this, block, pindex]() {
                OkOrAbort(m_host, "handle_block_connected", [&] {
                    std::unique_ptr<CBlockUndo> undo =
                        m_host.LoadBlockUndo(*pindex);
                    if (!undo) {
                        throw std::runtime_error(
                            "Reading block undo data failed");
                    }
                    Block nblock = ConvertBlock(*block, *undo, *pindex);
                    const size_t num_txs = nblock.txs.size();
                    m_service->HandleBlockConnected(std::move(nblock));
                    m_host.Log(LogLevel::Debug,
                               "Chronik: block " +
                                   block->GetHash().ToString() +
                                   " connected with " +
                                   std::to_string(num_txs) + " txs\n");
                });
            },
            validation_queue::BlockBytes(block));
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock> &block,
                           const CBlockIndex *pindex) override {
        Enqueue(
            [this, block, pindex]() {
                OkOrAbort(m_host, "handle_block_disconnected", [&] {
                    std::unique_ptr<CBlockUndo> undo =
                        m_host.LoadBlockUndo(*pindex);
                    if (!undo) {
                        throw std::runtime_error(
                            "Reading block undo data failed");
                    }
                    Block nblock = ConvertBlock(*block, *undo, *pindex);
                    const size_t num_txs = nblock.txs.size();
                    m_service->HandleBlockDisconnected(std::move(nblock));
                    m_host.Log(LogLevel::Debug,
                               "Chronik: block " +
                                   block->GetHash().ToString() +
                                   " disconnected with " +
                                   std::to_string(num_txs) + " txs\n");
                });
            },
            validation_queue::BlockBytes(block));
    }

    void BlockFinalized(const CBlockIndex *pindex) override {
        Enqueue([this, pindex]() {
            OkOrAbort(m_host, "handle_block_finalized", [&] {
                BlockInfo info = WITH_LOCK(::cs_main,
                                           return ConvertBlockInfo(*pindex));
                m_service->HandleBlockFinalized(info);
            });
        });
    }

    void BlockInvalidated(const CBlockIndex *pindex,
                          const std::shared_ptr<const CBlock> &block) override {
        Enqueue(
            [this, block, pindex]() {
                OkOrAbort(m_host, "handle_block_invalidated", [&] {
                    // Like Rust: silently skip if the undo data is missing.
                    std::unique_ptr<CBlockUndo> undo =
                        m_host.LoadBlockUndo(*pindex);
                    if (!undo) {
                        return;
                    }
                    Block nblock = ConvertBlock(*block, *undo, *pindex);
                    m_service->HandleBlockInvalidated(std::move(nblock));
                });
            },
            validation_queue::BlockBytes(block));
    }

    void TransactionFinalized(const CTransactionRef &tx) override {
        Enqueue([this, tx]() {
            OkOrAbort(m_host, "handle_tx_finalized", [&] {
                TxId txid;
                std::memcpy(txid.b.data(), tx->GetId().begin(), 32);
                m_service->HandleTxFinalized(txid);
            });
        });
    }

    void TransactionInvalidated(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<::Coin>> spent_coins) override {
        if (!spent_coins) {
            LogPrintf("Chronik: transaction %s invalidated but spent coins are "
                      "not available\n",
                      tx->GetId().ToString());
            return;
        }
        const size_t bytes = validation_queue::TxBytes(tx) +
                             validation_queue::CoinBytes(spent_coins);
        Enqueue(
            [this, tx, spent_coins = std::move(spent_coins)]() {
                OkOrAbort(m_host, "handle_tx_invalidated", [&] {
                    m_service->HandleTxInvalidated(std::make_shared<const Tx>(
                        ConvertTx(false, *tx, *spent_coins)));
                });
            },
            bytes);
    }
};

std::unique_ptr<NativeChronikValidationInterface> g_subscriber;

} // namespace

void StartSubscriber(const node::NodeContext &node, const AbcHost &host,
                     std::shared_ptr<Service> service) {
    g_subscriber = std::make_unique<NativeChronikValidationInterface>(
        node, host, std::move(service));
    g_subscriber->Register();
}

void InterruptSubscriber() {
    if (g_subscriber) {
        g_subscriber->InterruptChronik();
    }
}

void StopSubscriber() {
    if (g_subscriber) {
        g_subscriber->Unregister();
        g_subscriber->StopChronik();
        g_subscriber.reset();
    }
}

} // namespace chronik::native::abc
