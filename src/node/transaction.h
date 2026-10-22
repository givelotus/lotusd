// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TRANSACTION_H
#define BITCOIN_NODE_TRANSACTION_H

#include <cstddef>
#include <feerate.h>
#include <functional>
#include <future>
#include <memory>
#include <node/types.h>
#include <optional>
#include <primitives/transaction.h>
#include <string>

struct BlockHash;
class CBlockIndex;
class Config;
class CTxMemPool;
struct TxId;

namespace Consensus {
struct Params;
}

namespace node {
class BlockManager;
struct NodeContext;

/** Owned RPC admission verdict. Commit completion is distinct from downstream
 * wallet/Chronik notification completion. This is not a P2P scoring result.
 */
struct RpcAdmissionOutcome {
    TransactionError result{TransactionError::OK};
    std::string error;
    std::shared_ptr<std::promise<void>> notification;
};

/** Bounded immediate-drain independent RPC commit dispatcher.
 * Dispatch callbacks run under cs_main. Callers wait without daemon locks and
 * receive an owned outcome through a future. nullopt means
 * stopped/full/oversized: use ordinary direct admission. This does not batch
 * atomic packages, native verification, callbacks, or snapshot publication.
 */
class RpcAdmissionDispatcher {
    struct Impl;
    std::unique_ptr<Impl> m_impl;

public:
    RpcAdmissionDispatcher();
    ~RpcAdmissionDispatcher();
    RpcAdmissionDispatcher(const RpcAdmissionDispatcher &) = delete;
    RpcAdmissionDispatcher &operator=(const RpcAdmissionDispatcher &) = delete;
    std::optional<RpcAdmissionOutcome>
    Dispatch(size_t bytes, std::function<RpcAdmissionOutcome()> commit);
    void Stop();
};

/**
 * Maximum fee rate for sendrawtransaction and testmempoolaccept RPC calls.
 * Also used by the GUI when broadcasting a completed PSBT.
 * By default, a transaction with a fee rate higher than this will be rejected
 * by these RPCs and the GUI. This can be overridden with the maxfeerate
 * argument.
 */
static const CFeeRate DEFAULT_MAX_RAW_TX_FEE_RATE{COIN / 10};

/**
 * Submit a transaction to the mempool and (optionally) relay it to all P2P
 * peers.
 *
 * Mempool submission can be synchronous (will await mempool entry notification
 * over the CValidationInterface) or asynchronous (will submit and not wait for
 * notification), depending on the value of wait_callback. wait_callback MUST
 * NOT be set while cs_main, cs_mempool or cs_wallet are held to avoid
 * deadlock: the wait covers subscribers' worker queues (the wallet notification
 * worker needs cs_wallet).
 *
 * @param[in]  node reference to node context
 * @param[in]  tx the transaction to broadcast
 * @param[out] err_string reference to std::string to fill with error string
 * if available
 * @param[in]  max_tx_fee reject txs with fees higher than this (if 0, accept
 * any fee)
 * @param[in]  relay flag if both mempool insertion and p2p relay are requested
 * @param[in]  wait_callback wait until callbacks, and their secondary worker
 * queues, have been processed to avoid stale result due to a sequentially RPC.
 * @param[in] use_rpc_admission_queue opt in only for an unlocked public RPC;
 * wallet/Chronik/internal callers keep the direct path
 * @return error
 */
[[nodiscard]] TransactionError
BroadcastTransaction(const NodeContext &node, CTransactionRef tx,
                     std::string &err_string, Amount max_tx_fee, bool relay,
                     bool wait_callback, bool rpc_fee_hysteresis = false,
                     bool use_rpc_admission_queue = false);

/**
 * Return transaction with a given txid.
 * If mempool is provided and block_index is not provided, check it first for
 * the tx.
 * If -txindex is available, check it next for the tx.
 * Finally, if block_index is provided, check for tx by reading entire block
 * from disk.
 *
 * @param[in]  block_index     The block to read from disk, or nullptr
 * @param[in]  mempool         If provided, check mempool for tx
 * @param[in]  txid            The txid
 * @param[out] hashBlock       The block hash, if the tx was found via -txindex
 *                             or block_index
 * @returns                    The tx if found, otherwise nullptr
 */
CTransactionRef GetTransaction(const CBlockIndex *const block_index,
                               const CTxMemPool *const mempool,
                               const TxId &txid, BlockHash &hashBlock,
                               const BlockManager &blockman);
} // namespace node

#endif // BITCOIN_NODE_TRANSACTION_H
