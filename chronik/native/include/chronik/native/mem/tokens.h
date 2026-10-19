// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_TOKENS_H
#define CHRONIK_NATIVE_MEM_TOKENS_H

#include <chronik/native/error.h>
#include <chronik/native/groups/token_id.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/script/result.h>
#include <chronik/native/store.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/types.h>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * Port of chronik-db mem/tokens.rs ([`MempoolTokens`]), implementing the
 * Mempool's MempoolTokenHook (with TokenIdGroup and TokenIdGroupAux).
 *
 * Construct with `std::make_unique<mem::MempoolTokens>()` and pass it as the
 * Mempool's `token_hook`; `Mempool::Tokens()` can be cast back with
 * `MempoolTokens::FromHook`.
 */
namespace chronik::native::mem {

/** Rust `MempoolTokensError` (typed, comparable; ToString() = Rust text). */
struct MempoolTokensError {
    enum class Kind : uint8_t {
        /** Mempool tx spends outputs of non-existent tx */
        InputTxNotFound,
        /** Mempool tx spends non-existent output of existing tx */
        InputTxNoSuchOutput,
    };
    Kind kind = Kind::InputTxNotFound;
    /** InputTxNotFound */
    TxId txid;
    /** InputTxNoSuchOutput */
    OutPoint outpoint;

    static MempoolTokensError InputTxNotFound(const TxId &txid) {
        return {Kind::InputTxNotFound, txid, {}};
    }
    static MempoolTokensError InputTxNoSuchOutput(const OutPoint &outpoint) {
        return {Kind::InputTxNoSuchOutput, {}, outpoint};
    }
    /**
     * "Failed indexing mempool token tx: Tx is spending {txid} which is found
     * neither in the mempool nor DB" /
     * "Failed indexing mempool token tx: Tx spends non-existent token output
     * {outpoint:?}"
     */
    std::string ToString() const;
    bool operator==(const MempoolTokensError &) const = default;
};

/** MempoolTokensError thrown as an exception (Rust `?` into the Report). */
class MempoolTokensException : public ChronikError {
public:
    explicit MempoolTokensException(MempoolTokensError err)
        : ChronikError(err.ToString()), error(std::move(err)) {}
    MempoolTokensError error;
};

using SpentTokens = std::vector<std::optional<token::SpentToken>>;
using SpentTokensResult = Result<SpentTokens, MempoolTokensError>;
using BatchTokenTxs =
    std::unordered_map<TxId, token::TokenTx, Hash32Hasher>;

/** Token data of the mempool */
class MempoolTokens final : public MempoolTokenHook {
public:
    MempoolTokens() = default;

    /** nullptr if `hook` is not a MempoolTokens. */
    static const MempoolTokens *FromHook(const MempoolTokenHook *hook) {
        return dynamic_cast<const MempoolTokens *>(hook);
    }

    // ---- MempoolTokenHook ----
    const GroupDef &TokenIdGroup() const override { return m_group; }
    /** MempoolTokens::insert */
    void Insert(const KvStore &store, const MempoolTx &tx,
                const IsMempoolTxFn &is_mempool_tx) override;
    /** TokenIdGroupAux::from_mempool */
    std::shared_ptr<const GroupAux> AuxFromMempool(const Tx &tx) override;
    /** MempoolTokens::remove */
    void Remove(const TxId &txid) override;
    /** probe + TokenIdGroupAux::from_probed_tx; nullptr if no token data */
    std::shared_ptr<const GroupAux>
    Probe(const KvStore &store, const MempoolTx &tx,
          const IsMempoolTxFn &is_mempool_tx) const override;

    // ---- Rust MempoolTokens API ----

    /**
     * Parse, color and verify a potential token tx. Throws
     * MempoolTokensException if inputs can't be found, ChronikError on DB
     * errors.
     */
    std::optional<std::pair<token::TokenTx, SpentTokens>>
    ProbeTx(const KvStore &store, const ReadTxn &txn, const Tx &tx,
            const IsMempoolTxFn &is_mempool_tx) const;

    /** Insert, reading from `txn` */
    void InsertTx(const KvStore &store, const ReadTxn &txn, const MempoolTx &tx,
                  const IsMempoolTxFn &is_mempool_tx);

    /**
     * Fetch the spent tokens of the given tx. Returns Err for invalid txs
     * (inputs not found), throws for unexpected DB errors.
     */
    SpentTokensResult
    FetchTxSpentTokens(const KvStore &store, const ReadTxn &txn, const Tx &tx,
                       const IsMempoolTxFn &is_mempool_tx) const;

    /**
     * Same as [`FetchTxSpentTokens`] but accepts `batch_txs` for chained
     * broadcast validation, where earlier txs in the batch are not yet in the
     * mempool.
     */
    SpentTokensResult FetchTxSpentTokensBatch(
        const KvStore &store, const ReadTxn &txn, const Tx &tx,
        const IsMempoolTxFn &is_mempool_tx,
        const BatchTokenTxs &batch_txs) const;

    /** Get the [`TokenTx`] attached to a tx in the mempool, if any */
    const token::TokenTx *TokenTx(const TxId &txid) const;

    /** Get the [`SpentToken`] inputs of a tx in the mempool, if any */
    const SpentTokens *TxTokenInputs(const TxId &txid) const;

    /** Get the [`SpentToken`] of an outpoint in the mempool, if any */
    Result<std::optional<token::SpentToken>, MempoolTokensError>
    SpentToken(const OutPoint &outpoint) const;

    /**
     * Get the [`GenesisInfo`] of a GENESIS tx by [`TxId`], if this is a valid
     * GENESIS tx.
     */
    const token::GenesisInfo *GenesisInfo(const TxId &txid) const;

    /** Reset (Rust `MempoolTokens::default()`). */
    void Clear();

private:
    groups::TokenIdGroup m_group;
    std::unordered_map<TxId, token::TokenTx, Hash32Hasher> m_token_txs;
    std::unordered_map<TxId, SpentTokens, Hash32Hasher> m_tx_token_inputs;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_TOKENS_H
