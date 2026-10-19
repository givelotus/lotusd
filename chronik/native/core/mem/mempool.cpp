// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/mem/mempool.h>

#include <chronik/native/codec/hex.h>

namespace chronik::native::mem {

Mempool::Mempool(std::shared_ptr<const GroupDef> script_group,
                 bool enable_token_index, bool is_lokad_id_index_enabled,
                 std::unique_ptr<MempoolTokenHook> token_hook)
    : m_script_group(std::move(script_group)),
      m_script_history(*m_script_group), m_script_utxos(*m_script_group),
      m_token_hook(std::move(token_hook)),
      m_lokad_id_history(m_lokad_id_group),
      m_is_token_index_enabled(enable_token_index),
      m_is_lokad_id_index_enabled(is_lokad_id_index_enabled) {
    if (m_is_token_index_enabled) {
        if (!m_token_hook) {
            throw ChronikError(
                "Token index enabled, but no mempool token hook given");
        }
        m_token_id_history = std::make_unique<MempoolGroupHistory>(
            m_token_hook->TokenIdGroup());
        m_token_id_utxos = std::make_unique<MempoolGroupUtxos>(
            m_token_hook->TokenIdGroup());
    }
}

bool Mempool::IsMempoolTx(const TxId &txid) const {
    return m_txs.count(txid) > 0;
}

MempoolResult Mempool::Insert(const KvStore &store, MempoolTx mempool_tx) {
    const TxId txid = mempool_tx.tx->txid;
    const IsMempoolTxFn is_mempool_tx = [this](const TxId &id) {
        return IsMempoolTx(id);
    };
    m_script_history.Insert(mempool_tx, nullptr);
    m_script_utxos.Insert(mempool_tx, is_mempool_tx, nullptr);
    m_spent_by.Insert(mempool_tx);
    std::shared_ptr<const GroupAux> token_id_aux;
    if (m_is_token_index_enabled) {
        m_token_hook->Insert(store, mempool_tx, is_mempool_tx);
        token_id_aux = m_token_hook->AuxFromMempool(*mempool_tx.tx);
        m_token_id_history->Insert(mempool_tx, token_id_aux.get());
        m_token_id_utxos->Insert(mempool_tx, is_mempool_tx,
                                 token_id_aux.get());
    }
    if (m_is_lokad_id_index_enabled) {
        m_lokad_id_history.Insert(mempool_tx, nullptr);
    }
    // Like Rust's HashMap::insert, a duplicate replaces the entry, then fails
    const auto [it, inserted] = m_txs.insert_or_assign(txid, mempool_tx);
    if (!inserted) {
        throw MempoolError("Tx " + HashToHex(txid) +
                           " already exists in mempool");
    }
    return MempoolResult{it->second, std::move(token_id_aux)};
}

MempoolResult Mempool::Remove(const TxId &txid) {
    const auto it = m_txs.find(txid);
    if (it == m_txs.end()) {
        throw MempoolError("No such mempool tx: " + HashToHex(txid));
    }
    MempoolTx mempool_tx = std::move(it->second);
    m_txs.erase(it);
    const IsMempoolTxFn is_mempool_tx = [this](const TxId &id) {
        return IsMempoolTx(id);
    };
    m_script_history.Remove(mempool_tx, nullptr);
    m_script_utxos.Remove(mempool_tx, is_mempool_tx, nullptr);
    m_spent_by.Remove(mempool_tx);
    std::shared_ptr<const GroupAux> token_id_aux;
    if (m_is_token_index_enabled) {
        token_id_aux = m_token_hook->AuxFromMempool(*mempool_tx.tx);
        m_token_id_history->Remove(mempool_tx, token_id_aux.get());
        m_token_id_utxos->Remove(mempool_tx, is_mempool_tx,
                                 token_id_aux.get());
        m_token_hook->Remove(txid);
    }
    if (m_is_lokad_id_index_enabled) {
        m_lokad_id_history.Remove(mempool_tx, nullptr);
    }
    return MempoolResult{std::move(mempool_tx), std::move(token_id_aux)};
}

std::optional<MempoolTx> Mempool::RemoveMined(const TxId &txid) {
    const auto it = m_txs.find(txid);
    if (it == m_txs.end()) {
        return std::nullopt;
    }
    MempoolTx mempool_tx = std::move(it->second);
    m_txs.erase(it);
    m_script_history.Remove(mempool_tx, nullptr);
    m_script_utxos.RemoveMined(mempool_tx, nullptr);
    m_spent_by.Remove(mempool_tx);
    if (m_is_token_index_enabled) {
        const std::shared_ptr<const GroupAux> token_id_aux =
            m_token_hook->AuxFromMempool(*mempool_tx.tx);
        m_token_id_history->Remove(mempool_tx, token_id_aux.get());
        m_token_id_utxos->RemoveMined(mempool_tx, token_id_aux.get());
        m_token_hook->Remove(txid);
    }
    if (m_is_lokad_id_index_enabled) {
        m_lokad_id_history.Remove(mempool_tx, nullptr);
    }
    return mempool_tx;
}

MempoolResult Mempool::ProbeTx(const KvStore &store,
                               MempoolTx mempool_tx) const {
    std::shared_ptr<const GroupAux> token_id_aux;
    if (m_is_token_index_enabled) {
        token_id_aux = m_token_hook->Probe(
            store, mempool_tx,
            [this](const TxId &id) { return IsMempoolTx(id); });
    }
    return MempoolResult{std::move(mempool_tx), std::move(token_id_aux)};
}

const MempoolTx *Mempool::GetTx(const TxId &txid) const {
    const auto it = m_txs.find(txid);
    return it == m_txs.end() ? nullptr : &it->second;
}

} // namespace chronik::native::mem
