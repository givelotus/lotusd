// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/transaction.h>

#include <common/args.h>
#include <config.h>
#include <consensus/validation.h>
#include <index/txindex.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/metrics.h>
#include <node/txadmission.h>
#include <node/types.h>
#include <primitives/blockhash.h>
#include <primitives/txid.h>
#include <txmempool.h>
#include <util/threadnames.h>
#include <validation.h>
#include <validationinterface.h>

#include <array>
#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <condition_variable>
#include <exception>
#include <future>
#include <mutex>
#include <thread>

namespace node {
static TransactionError HandleATMPError(const TxValidationState &state,
                                        std::string &err_string_out) {
    err_string_out = state.ToString();
    if (state.IsInvalid()) {
        if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS) {
            return TransactionError::MISSING_INPUTS;
        }
        return TransactionError::MEMPOOL_REJECTED;
    } else {
        return TransactionError::MEMPOOL_ERROR;
    }
}

namespace {
    RpcAdmissionOutcome
    AdmitBroadcastLocked(const NodeContext &node, const CTransactionRef &tx,
                         const MempoolAdmissionLimits &limits, bool relay,
                         bool wait_callback,
                         const PrecomputedAdmissionChecks *precomputed,
                         const std::shared_ptr<util::CompletionSignal> &promise)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        RpcAdmissionOutcome outcome;
        const TxId &txid = tx->GetId();
        // If the transaction is already confirmed in the chain, don't do
        // anything and return early.
        CCoinsViewCache &view = node.chainman->ActiveChainstate().CoinsTip();
        for (size_t o = 0; o < tx->vout.size(); o++) {
            const Coin &existingCoin = view.AccessCoin(COutPoint(txid, o));
            // IsSpent doesn't mean the coin is spent, it means the output
            // doesn't exist. So if the output does exist, then this transaction
            // exists in the chain.
            if (!existingCoin.IsSpent()) {
                return {TransactionError::ALREADY_IN_CHAIN, {}, {}};
            }
        }

        if (!node.mempool->exists(txid)) {
            // Transaction is not already in the mempool.
            // Validate caller fee bounds before insertion in this one ATMP
            // pass.
            const MempoolAcceptResult result =
                node.chainman->ProcessTransaction(tx, /*test_accept=*/false,
                                                  limits, precomputed);
            if (result.m_result_type !=
                MempoolAcceptResult::ResultType::VALID) {
                if (result.m_state.GetRejectReason() == "max-fee-exceeded") {
                    return {TransactionError::MAX_FEE_EXCEEDED, {}, {}};
                }
                outcome.result = HandleATMPError(result.m_state, outcome.error);
                return outcome;
            }

            // Transaction was accepted to the mempool.

            if (relay) {
                // the mempool tracks locally submitted transactions to make a
                // best-effort of initial broadcast
                node.mempool->AddUnbroadcastTx(txid);
            }

            if (wait_callback && node.validation_signals) {
                // For transactions broadcast from outside the wallet, make sure
                // that the wallet has been notified of the transaction before
                // continuing.
                //
                // This prevents a race where a user might call
                // sendrawtransaction with a transaction to/from their wallet,
                // immediately call some wallet RPC, and get a stale result
                // because callbacks have not yet been processed.
                node.validation_signals->CallFunctionInValidationInterfaceQueue(
                    [promise] { promise->Complete(); });
                outcome.notification = promise;
            }
        }
        return outcome;
    }
} // namespace

struct RpcAdmissionDispatcher::Impl {
    // Bounds include queued and executing requests. Larger/full requests keep
    // the existing direct path: overload never drops an RPC or changes policy.
    static constexpr size_t MAX_BYTES = 32 << 20;
    static constexpr size_t MAX_SLICE = 32;
    static constexpr uint64_t STOPPED = uint64_t{1} << 63;
    struct Request : std::enable_shared_from_this<Request> {
        Request(size_t size, std::function<RpcAdmissionOutcome()> fn)
            : bytes(size), commit(std::move(fn)) {}
        size_t bytes;
        std::function<RpcAdmissionOutcome()> commit;
        std::optional<std::promise<RpcAdmissionOutcome>> completed;
        Completion async_completed;
        std::shared_ptr<Request> retained;
        std::optional<RpcAdmissionOutcome> outcome;
        std::exception_ptr error;
    };
    boost::lockfree::queue<Request *, boost::lockfree::capacity<256>> queue;
    std::atomic<size_t> bytes{0};
    // High bit closes registration; low bits count producer calls through
    // completion. A registered producer can publish after Stop() begins.
    std::atomic<uint64_t> producers{0};
    std::mutex wake_mutex;
    std::condition_variable wake;
    std::thread worker;

    Impl() : worker([this] { Run(); }) {}
    ~Impl() { Stop(); }

    void Notify() {
        // Publication is lock-free. This short mutex only closes the condition
        // variable's check/sleep race; no chain/mempool operation owns it.
        {
            std::lock_guard<std::mutex> lock(wake_mutex);
        }
        wake.notify_one();
    }
    void Stop() {
        producers.fetch_or(STOPPED, std::memory_order_acq_rel);
        Notify();
        if (worker.joinable()) worker.join();
    }
    std::optional<RpcAdmissionOutcome>
    Dispatch(size_t nbytes, std::function<RpcAdmissionOutcome()> commit) {
        AssertLockNotHeld(cs_main);
        uint64_t observed = producers.load(std::memory_order_acquire);
        do {
            if (observed & STOPPED) return std::nullopt;
        } while (!producers.compare_exchange_weak(observed, observed + 1,
                                                  std::memory_order_acq_rel));
        struct Producer {
            Impl &owner;
            ~Producer() {
                owner.producers.fetch_sub(1, std::memory_order_acq_rel);
                owner.Notify();
            }
        } producer{*this};
        if (nbytes > MAX_BYTES) return std::nullopt;
        auto request = std::make_shared<Request>(nbytes, std::move(commit));
        auto completed = request->completed.emplace().get_future();
        size_t used = bytes.load(std::memory_order_relaxed);
        do {
            if (used > MAX_BYTES - nbytes) return std::nullopt;
        } while (!bytes.compare_exchange_weak(used, used + nbytes,
                                              std::memory_order_relaxed));
        if (!queue.push(request.get())) {
            bytes.fetch_sub(nbytes, std::memory_order_relaxed);
            return std::nullopt;
        }
        Notify();
        // The request owns its inputs. Transfer the typed verdict, error text
        // and independent notification barrier to the waiting RPC producer.
        return completed.get();
    }
    bool DispatchAsync(size_t nbytes, std::function<RpcAdmissionOutcome()> commit,
                       Completion completion) {
        AssertLockNotHeld(cs_main);
        assert(completion);
        uint64_t observed = producers.load(std::memory_order_acquire);
        do {
            if (observed & STOPPED) return false;
        } while (!producers.compare_exchange_weak(observed, observed + 1,
                                                   std::memory_order_acq_rel));
        struct Producer {
            Impl &owner;
            ~Producer() {
                owner.producers.fetch_sub(1, std::memory_order_acq_rel);
                owner.Notify();
            }
        } producer{*this};
        if (nbytes > MAX_BYTES) return false;
        auto request = std::make_shared<Request>(nbytes, std::move(commit));
        request->async_completed = std::move(completion);
        size_t used = bytes.load(std::memory_order_relaxed);
        do {
            if (used > MAX_BYTES - nbytes) return false;
        } while (!bytes.compare_exchange_weak(used, used + nbytes,
                                               std::memory_order_relaxed));
        // Unlike a synchronous producer, the coroutine returns to its executor
        // immediately. Keep the raw queue entry owned until the worker pops it.
        request->retained = request;
        if (!queue.push(request.get())) {
            request->retained.reset();
            bytes.fetch_sub(nbytes, std::memory_order_relaxed);
            return false;
        }
        Notify();
        return true;
    }
    void Run() {
        util::ThreadRename("rpcadmit");
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(wake_mutex);
                wake.wait(lock, [&] {
                    return !queue.empty() ||
                           producers.load(std::memory_order_acquire) == STOPPED;
                });
            }
            std::array<std::shared_ptr<Request>, MAX_SLICE> slice{};
            size_t count = 0;
            Request *pending = nullptr;
            while (count < slice.size() && queue.pop(pending)) {
                slice[count] = pending->shared_from_this();
                slice[count]->retained.reset();
                ++count;
            }
            if (count == 0) {
                if (producers.load(std::memory_order_acquire) == STOPPED)
                    return;
                continue;
            }
            {
                const auto waiting = SteadyClock::now();
                LOCK(cs_main);
                AdmissionLockTimer timer(waiting);
                for (size_t i = 0; i < count; ++i) {
                    try {
                        slice[i]->outcome.emplace(slice[i]->commit());
                    } catch (...) {
                        slice[i]->error = std::current_exception();
                    }
                }
            }
            for (size_t i = 0; i < count; ++i) {
                const auto &request = slice[i];
                bytes.fetch_sub(request->bytes, std::memory_order_relaxed);
                // Retain ownership through set_value/set_exception: the
                // waiting producer may immediately release its own reference.
                if (request->async_completed) {
                    request->async_completed(request->error,
                        request->outcome ? std::move(*request->outcome)
                                         : RpcAdmissionOutcome{});
                } else if (request->error) {
                    request->completed->set_exception(request->error);
                } else {
                    request->completed->set_value(std::move(*request->outcome));
                }
            }
        }
    }
};

RpcAdmissionDispatcher::RpcAdmissionDispatcher()
    : m_impl(std::make_unique<Impl>()) {}
RpcAdmissionDispatcher::~RpcAdmissionDispatcher() = default;
void RpcAdmissionDispatcher::Stop() {
    m_impl->Stop();
}
std::optional<RpcAdmissionOutcome>
RpcAdmissionDispatcher::Dispatch(size_t bytes,
                                 std::function<RpcAdmissionOutcome()> commit) {
    return m_impl->Dispatch(bytes, std::move(commit));
}

bool RpcAdmissionDispatcher::DispatchAsync(
    size_t bytes, std::function<RpcAdmissionOutcome()> commit,
    Completion completion) {
    return m_impl->DispatchAsync(bytes, std::move(commit), std::move(completion));
}

void SubmitRpcAdmission(const NodeContext &node, CTransactionRef tx,
                        Amount max_tx_fee,
                        RpcAdmissionDispatcher::Completion completion) {
    AssertLockNotHeld(cs_main);
    assert(node.chainman && node.mempool && node.peerman);
    const auto notification = std::make_shared<util::CompletionSignal>();
    const MempoolAdmissionLimits limits{max_tx_fee, true};
    std::optional<PrecomputedAdmissionChecks> prepared;
    if (node.args && node.args->GetBoolArg("-parallelmempool", DEFAULT_PARALLEL_MEMPOOL)) {
        prepared = PrecomputeMempoolAdmission(*node.chainman, tx, limits);
    }
    if (node.rpc_admission && node.rpc_admission->DispatchAsync(
        tx->GetTotalSize(),
        [&node, tx, limits, notification, prepared = std::move(prepared)]()
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            return AdmitBroadcastLocked(node, tx, limits, true, true,
                prepared ? &*prepared : nullptr, notification);
        }, completion)) {
        return;
    }
    // Preserve the existing overload/stopped fallback and all authoritative
    // checks. It can take cs_main; notification waits remain asynchronous.
    RpcAdmissionOutcome outcome;
    std::exception_ptr error;
    try {
        const auto waiting = SteadyClock::now();
        LOCK(cs_main);
        AdmissionLockTimer timer(waiting);
        outcome = AdmitBroadcastLocked(node, tx, limits, true, true, nullptr,
                                       notification);
    } catch (...) {
        error = std::current_exception();
    }
    completion(error, std::move(outcome));
}

TransactionError
BroadcastTransaction(const NodeContext &node, const CTransactionRef tx,
                     std::string &err_string, const Amount max_tx_fee,
                     bool relay, bool wait_callback, bool rpc_fee_hysteresis,
                     bool use_rpc_admission_queue) {
    // BroadcastTransaction can be called by either sendrawtransaction RPC or
    // the wallet. chainman, mempool and peerman are initialized before the RPC
    // server and wallet are started and reset after the RPC server and wallet
    // are stopped.
    assert(node.chainman);
    assert(node.mempool);
    assert(node.peerman);

    // The queue can retain a barrier even if scheduling it throws. Give the
    // callback ownership independent of an RPC frame or disconnected client.
    const auto promise =
        wait_callback ? std::make_shared<util::CompletionSignal>() : nullptr;
    TxId txid = tx->GetId();
    const MempoolAdmissionLimits limits{max_tx_fee, rpc_fee_hysteresis};
    std::optional<PrecomputedAdmissionChecks> precomputed;
    if (wait_callback && node.args &&
        node.args->GetBoolArg("-parallelmempool", DEFAULT_PARALLEL_MEMPOOL)) {
        // Synchronous callers guarantee they hold no chain/mempool/wallet
        // locks. RPC clients can therefore verify concurrently. The existing
        // critical section below decides every verdict,
        // fee bound, broadcast marker and notification in the same order.
        precomputed = PrecomputeMempoolAdmission(
            *node.chainman, tx, limits, node.mempool.get());
    }

    RpcAdmissionOutcome outcome;
    bool queued = false;
    // The queued task owns transaction/preparation/limits and its barrier.
    // Only node is borrowed: AppInit/Shutdown pin its dependencies through
    // HTTP handler drain and dispatcher destruction.
    if (use_rpc_admission_queue && wait_callback && node.rpc_admission) {
        auto completed = node.rpc_admission->Dispatch(
            tx->GetTotalSize(),
            [&node, tx, limits, relay, wait_callback, promise,
             prepared = std::move(precomputed)]()
                EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                    return AdmitBroadcastLocked(
                        node, tx, limits, relay, wait_callback,
                        prepared ? &*prepared : nullptr, promise);
                });
        // A rejected queue reservation consumed only advisory preparation;
        // direct fallback performs the same authoritative checks without it.
        precomputed.reset();
        if (completed) {
            outcome = std::move(*completed);
            queued = true;
        }
    }
    if (!queued) {
        const auto waiting = SteadyClock::now();
        LOCK(cs_main);
        AdmissionLockTimer timer(waiting);
        outcome = AdmitBroadcastLocked(node, tx, limits, relay, wait_callback,
                                       precomputed ? &*precomputed : nullptr,
                                       promise);
    }
    if (!outcome.error.empty()) err_string = std::move(outcome.error);
    if (outcome.result != TransactionError::OK) return outcome.result;

    if (outcome.notification) {
        // Wait until Validation Interface clients have been notified of the
        // transaction entering the mempool.
        outcome.notification->Wait();
        // Subscribers that deliver on their own worker (the wallet, Chronik)
        // received the event from the main queue; wait for them too.
        node.validation_signals->SyncSecondaryQueues();
    }

    if (relay) {
        node.peerman->RelayTransaction(txid);
    }

    return TransactionError::OK;
}

CTransactionRef GetTransaction(const CBlockIndex *const block_index,
                               const CTxMemPool *const mempool,
                               const TxId &txid, BlockHash &hashBlock,
                               const BlockManager &blockman) {
    if (mempool && !block_index) {
        CTransactionRef ptx = mempool->get(txid);
        if (ptx) {
            return ptx;
        }
    }
    if (g_txindex) {
        CTransactionRef tx;
        BlockHash block_hash;
        if (g_txindex->FindTx(txid, block_hash, tx)) {
            if (!block_index || block_index->GetBlockHash() == block_hash) {
                // Don't return the transaction if the provided block hash
                // doesn't match.
                // The case where a transaction appears in multiple blocks
                // (e.g. reorgs or BIP30) is handled by the block lookup below.
                hashBlock = block_hash;
                return tx;
            }
        }
    }
    if (block_index) {
        CBlock block;
        if (blockman.ReadBlock(block, *block_index)) {
            for (const auto &tx : block.vtx) {
                if (tx->GetId() == txid) {
                    hashBlock = block_index->GetBlockHash();
                    return tx;
                }
            }
        }
    }
    return nullptr;
}
} // namespace node
