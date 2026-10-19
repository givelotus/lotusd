// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/broadcast.rs (QueryBroadcast) and the
// broadcast handlers of chronik-http server.rs.

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/subs.h>

#include <chrono>

namespace chronik::native::query {

namespace {

/** Host-decoded tx with all input coins set (Rust: Some(Coin) per input). */
struct LookedUpTx {
    Tx tx;
    std::vector<OutPoint> to_uncache;
};

/** Rust lookup_spent_coins + Tx::from(ffi_tx): missing coins default. */
std::vector<OutPoint> LookupCoins(const Host &host, Tx &tx) {
    SpentCoinLookup lookup = host.LookupSpentCoins(tx);
    for (TxInput &input : tx.inputs) {
        if (!input.coin) {
            input.coin = Coin{};
        }
    }
    return std::move(lookup.to_uncache);
}

/** QueryBroadcast::do_token_checks; returns the coins to uncache. */
std::vector<OutPoint> DoTokenChecks(const IndexerImpl &indexer,
                                    const Host &host,
                                    const std::vector<Bytes> &raw_txs) {
    std::vector<OutPoint> coins_to_uncache;
    std::vector<Tx> txs;
    std::exception_ptr deferred;
    // Host calls first, without holding the state lock. An error at tx k is
    // raised after the token checks of txs 0..k-1, as in Rust.
    try {
        for (const Bytes &raw_tx : raw_txs) {
            DecodedTx decoded = host.DecodeRawTx(raw_tx);
            if (!decoded.ok) {
                throw ChronikError("400: Parsing tx failed " + decoded.error);
            }
            std::vector<OutPoint> tx_coins_to_uncache =
                LookupCoins(host, decoded.tx);
            coins_to_uncache.insert(coins_to_uncache.end(),
                                    tx_coins_to_uncache.begin(),
                                    tx_coins_to_uncache.end());
            txs.push_back(std::move(decoded.tx));
        }
    } catch (...) {
        deferred = std::current_exception();
    }

    std::vector<std::pair<TxId, std::vector<std::string>>> token_errors;
    {
        IndexerSnapshot snap = indexer.Snapshot();
        const mem::MempoolTokens *tokens = SnapshotMempoolTokens(snap);
        std::set<TxId> batch_txids;
        mem::BatchTokenTxs batch_txs;
        for (const Tx &tx : txs) {
            std::optional<TxTokenData> token =
                TxTokenData::FromUnbroadcastTxBatch(
                    snap.Store(), snap.Txn(), snap.Mempool(), tokens, tx,
                    &batch_txids, batch_txs);
            // Add this tx to batch_txs and batch_txids after the call so that
            // later txs in the batch can resolve token inputs that reference
            // earlier txs (e.g. chained SEND then BURN).
            if (token) {
                batch_txs.insert_or_assign(tx.txid, token->tx);
            }
            batch_txids.insert(tx.txid);
            if (!token) {
                continue;
            }
            std::vector<std::string> burn_msgs;
            for (const token::FailedParsing &failed_parsing :
                 token->tx.failed_parsings) {
                burn_msgs.push_back(failed_parsing.ToString());
            }
            for (const token::TokenTxEntry &entry : token->tx.entries) {
                if (!entry.IsNormal()) {
                    burn_msgs.push_back(entry.BurnSummary());
                }
            }
            if (!burn_msgs.empty()) {
                token_errors.emplace_back(tx.txid, std::move(burn_msgs));
            }
        }
    }
    if (deferred) {
        std::rethrow_exception(deferred);
    }
    std::string error_msg;
    for (size_t tx_idx = 0; tx_idx < token_errors.size(); ++tx_idx) {
        const auto &[txid, errors] = token_errors[tx_idx];
        error_msg += "Tx " + HashToHex(txid) + " failed token checks: ";
        for (size_t error_idx = 0; error_idx < errors.size(); ++error_idx) {
            error_msg += errors[error_idx];
            error_msg += '.';
            if (tx_idx != token_errors.size() - 1 ||
                error_idx != errors.size() - 1) {
                error_msg += ' ';
            }
        }
    }
    if (!token_errors.empty()) {
        throw ChronikError("400: " + error_msg);
    }
    return coins_to_uncache;
}

/**
 * Rust BroadcastResult: receivers for the broadcast txids; the destructor
 * drops them, then unsubscribes the txid members (BroadcastResult::drop).
 */
class BroadcastSubs {
public:
    explicit BroadcastSubs(std::shared_ptr<SubsHub> hub)
        : m_hub(std::move(hub)) {}
    BroadcastSubs(const BroadcastSubs &) = delete;
    BroadcastSubs &operator=(const BroadcastSubs &) = delete;
    ~BroadcastSubs() {
        m_receivers.clear();
        if (m_txids.empty()) {
            return;
        }
        auto guard = m_hub->Write();
        for (const TxId &txid : m_txids) {
            guard->SubsTxId().UnsubscribeFromMember(
                ByteView(txid.b.data(), txid.b.size()));
        }
    }

    void Subscribe(const std::vector<TxId> &txids) {
        auto guard = m_hub->Write();
        for (const TxId &txid : txids) {
            m_receivers.push_back(guard->SubsTxId().SubscribeToMember(
                ByteView(txid.b.data(), txid.b.size())));
        }
        m_txids = txids;
    }

    /** BroadcastResult::wait_for_finalization */
    void WaitForFinalization(uint64_t timeout_secs) {
        if (m_receivers.empty() || timeout_secs == 0) {
            return;
        }
        using Clock = std::chrono::steady_clock;
        const Clock::time_point deadline =
            Clock::now() + std::chrono::seconds(timeout_secs);
        std::optional<std::string> first_error;
        for (BroadcastReceiver<TxMsg> &receiver : m_receivers) {
            for (;;) {
                const auto now = Clock::now();
                if (now >= deadline) {
                    TimedOut(timeout_secs);
                }
                RecvResult<TxMsg> result = receiver.RecvFor(deadline - now);
                if (result.status == RecvStatus::Message) {
                    if (result.msg->msg_type.kind ==
                        TxMsgType::Kind::Finalized) {
                        break;
                    }
                    continue;
                }
                if (result.status == RecvStatus::Empty) {
                    TimedOut(timeout_secs);
                }
                // tokio broadcast::error::RecvError Display
                if (!first_error) {
                    first_error =
                        result.status == RecvStatus::Lagged
                            ? "channel lagged by " +
                                  std::to_string(result.lagged)
                            : std::string("channel closed");
                }
                break;
            }
        }
        if (first_error) {
            throw ChronikError(*first_error);
        }
    }

private:
    [[noreturn]] static void TimedOut(uint64_t timeout_secs) {
        throw ChronikError("504: Transaction(s) failed to finalize within " +
                           std::to_string(timeout_secs) + "s");
    }

    std::shared_ptr<SubsHub> m_hub;
    std::vector<BroadcastReceiver<TxMsg>> m_receivers;
    std::vector<TxId> m_txids;
};

} // namespace

uint64_t VerifyTimeoutFinalization(uint64_t timeout_finalization_secs) {
    if (timeout_finalization_secs > MAX_TIMEOUT_FINALIZATION_SECS) {
        throw ChronikError("400: Finalization timeout of " +
                           std::to_string(timeout_finalization_secs) +
                           "s exceeds maximum of " +
                           std::to_string(MAX_TIMEOUT_FINALIZATION_SECS) + "s");
    }
    return timeout_finalization_secs;
}

std::vector<TxId> BroadcastTxs(const IndexerImpl &indexer, const Host &host,
                               const std::vector<Bytes> &raw_txs,
                               bool skip_token_checks,
                               uint64_t finalization_timeout_secs) {
    const uint64_t timeout_finalization =
        VerifyTimeoutFinalization(finalization_timeout_secs);
    const bool should_subscribe = timeout_finalization != 0;
    BroadcastSubs subs(indexer.SubsPtr());
    std::vector<TxId> txids;
    std::exception_ptr broadcast_error;
    try {
        std::vector<OutPoint> coins_to_uncache;
        if (!skip_token_checks && indexer.IsTokenIndexEnabled()) {
            coins_to_uncache = DoTokenChecks(indexer, host, raw_txs);
        }
        txids.reserve(raw_txs.size());
        for (const Bytes &raw_tx : raw_txs) {
            const int64_t max_fee = host.CalcMaxFee(raw_tx.size());
            const BroadcastResult result = host.Broadcast(raw_tx, max_fee);
            if (!result.ok) {
                host.UncacheCoins(coins_to_uncache);
                throw ChronikError("400: Broadcast failed: " + result.error);
            }
            txids.push_back(result.txid);
        }
        if (should_subscribe) {
            subs.Subscribe(txids);
        }
    } catch (...) {
        broadcast_error = std::current_exception();
    }
    // Block for indexer being synced before returning so the user can query
    // the broadcast txs right away
    host.SyncWithIndexer();
    if (broadcast_error) {
        std::rethrow_exception(broadcast_error);
    }
    subs.WaitForFinalization(timeout_finalization);
    return txids;
}

proto::Tx ValidateTx(const IndexerImpl &indexer, const Host &host,
                     const Bytes &raw_tx) {
    DecodedTx decoded = host.DecodeRawTx(raw_tx);
    if (!decoded.ok) {
        throw ChronikError(decoded.error);
    }
    Tx tx = std::move(decoded.tx);
    const std::vector<OutPoint> coins_to_uncache = LookupCoins(host, tx);
    host.UncacheCoins(coins_to_uncache);
    std::optional<TxTokenData> token;
    Avalanche avalanche;
    {
        IndexerSnapshot snap = indexer.Snapshot();
        avalanche = snap.GetAvalanche();
        if (indexer.IsTokenIndexEnabled()) {
            token = TxTokenData::FromUnbroadcastTxBatch(
                snap.Store(), snap.Txn(), snap.Mempool(),
                SnapshotMempoolTokens(snap), tx, nullptr, mem::BatchTokenTxs{});
        }
    }
    const bool is_final_preconsensus = IsFinalPreconsensus(host, tx.txid);
    const OutputsSpent outputs_spent;
    return MakeTxProto(MakeTxProtoParams{tx, outputs_spent, 0, false, nullptr,
                                         avalanche, token ? &*token : nullptr,
                                         is_final_preconsensus});
}

} // namespace chronik::native::query
