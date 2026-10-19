// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_MEMPOOL_H
#define CHRONIK_NATIVE_MEM_MEMPOOL_H

#include <chronik/native/error.h>
#include <chronik/native/extension.h>
#include <chronik/native/groups/lokad_id.h>
#include <chronik/native/mem/group_history.h>
#include <chronik/native/mem/group_utxos.h>
#include <chronik/native/mem/mempool_tx.h>
#include <chronik/native/mem/spent_by.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <memory>
#include <optional>
#include <unordered_map>

/**
 * Port of chronik-db mem/mempool.rs (eCash tier, without plugins).
 *
 * Token data (Rust MempoolTokens and the TokenIdGroup) is supplied through
 * MempoolTokenHook, so this module has no token dependency; the Mempool
 * itself indexes the token ID history/UTXOs with the hook's group, in the
 * Rust order.
 */
namespace chronik::native::mem {

/** Rust `MempoolError`. */
class MempoolError : public ChronikError {
public:
    using ChronikError::ChronikError;
};

/**
 * Hook for the token index of the mempool (Rust MempoolTokens and
 * TokenIdGroupAux::from_*). Errors are thrown, like Rust's `?`.
 */
class MempoolTokenHook {
public:
    virtual ~MempoolTokenHook() = default;

    /** The token ID group (Rust TokenIdGroup); outlives the hook's use. */
    virtual const GroupDef &TokenIdGroup() const = 0;

    /** MempoolTokens::insert */
    virtual void Insert(const KvStore &store, const MempoolTx &tx,
                        const IsMempoolTxFn &is_mempool_tx) = 0;

    /** TokenIdGroupAux::from_mempool */
    virtual std::shared_ptr<const GroupAux> AuxFromMempool(const Tx &tx) = 0;

    /** MempoolTokens::remove */
    virtual void Remove(const TxId &txid) = 0;

    /**
     * MempoolTokens::probe + TokenIdGroupAux::from_probed_tx; nullptr if the
     * tx has no token data.
     */
    virtual std::shared_ptr<const GroupAux>
    Probe(const KvStore &store, const MempoolTx &tx,
          const IsMempoolTxFn &is_mempool_tx) const = 0;
};

/** Rust `MempoolResult` (without plugin outputs). */
struct MempoolResult {
    /** Mempool tx that was just added/removed/probed */
    MempoolTx mempool_tx;
    /** TokenIdGroupAux generated while indexing the mempool tx (or nullptr) */
    std::shared_ptr<const GroupAux> token_id_aux;
};

/** Mempool of Chronik: txs and their group indexes. */
class Mempool {
public:
    /**
     * `script_group` is the ScriptGroup; `token_hook` is required if
     * `enable_token_index`.
     */
    Mempool(std::shared_ptr<const GroupDef> script_group,
            bool enable_token_index, bool is_lokad_id_index_enabled,
            std::unique_ptr<MempoolTokenHook> token_hook = nullptr);

    /** Insert tx into the mempool. */
    MempoolResult Insert(const KvStore &store, MempoolTx mempool_tx);

    /** Remove tx from the mempool. */
    MempoolResult Remove(const TxId &txid);

    /** Remove mined tx from the mempool (nullopt if not in it). */
    std::optional<MempoolTx> RemoveMined(const TxId &txid);

    /** Analyze a tx which is not already in the mempool without adding it */
    MempoolResult ProbeTx(const KvStore &store, MempoolTx mempool_tx) const;

    const std::unordered_map<TxId, MempoolTx, Hash32Hasher> &Txs() const {
        return m_txs;
    }
    /** nullptr if not found */
    const MempoolTx *GetTx(const TxId &txid) const;

    const MempoolGroupHistory &ScriptHistory() const {
        return m_script_history;
    }
    const MempoolGroupUtxos &ScriptUtxos() const { return m_script_utxos; }
    const MempoolSpentBy &SpentBy() const { return m_spent_by; }
    /** nullptr if the token index is disabled */
    const MempoolTokenHook *Tokens() const { return m_token_hook.get(); }
    MempoolTokenHook *Tokens() { return m_token_hook.get(); }
    /** nullptr if the token index is disabled */
    const MempoolGroupHistory *TokenIdHistory() const {
        return m_token_id_history.get();
    }
    const MempoolGroupUtxos *TokenIdUtxos() const {
        return m_token_id_utxos.get();
    }
    const MempoolGroupHistory &LokadIdHistory() const {
        return m_lokad_id_history;
    }

private:
    bool IsMempoolTx(const TxId &txid) const;

    std::unordered_map<TxId, MempoolTx, Hash32Hasher> m_txs;
    std::shared_ptr<const GroupDef> m_script_group;
    MempoolGroupHistory m_script_history;
    MempoolGroupUtxos m_script_utxos;
    MempoolSpentBy m_spent_by;
    std::unique_ptr<MempoolTokenHook> m_token_hook;
    std::unique_ptr<MempoolGroupHistory> m_token_id_history;
    std::unique_ptr<MempoolGroupUtxos> m_token_id_utxos;
    groups::LokadIdGroup m_lokad_id_group;
    MempoolGroupHistory m_lokad_id_history;
    bool m_is_token_index_enabled;
    bool m_is_lokad_id_index_enabled;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_MEMPOOL_H
