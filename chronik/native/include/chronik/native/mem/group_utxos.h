// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_GROUP_UTXOS_H
#define CHRONIK_NATIVE_MEM_GROUP_UTXOS_H

#include <chronik/native/error.h>
#include <chronik/native/extension.h>
#include <chronik/native/mem/mempool_tx.h>
#include <chronik/native/types.h>

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>

/** Port of chronik-db mem/group_utxos.rs. */
namespace chronik::native::mem {

/** Function telling whether a txid is in the mempool. */
using IsMempoolTxFn = std::function<bool(const TxId &)>;

/**
 * Errors (Rust `MempoolGroupUtxosError`), with the exact texts:
 *  - DuplicateUtxo: "Inconsistent mempool: UTXO <OutPoint> already exists in
 *    mempool"
 *  - UtxoAlreadyUnspent: "Inconsistent mempool: UTXO <OutPoint> already
 *    unspent in mempool"
 *  - UtxoDoesntExistForRemoval: "Inconsistent mempool when removing tx:
 *    UTXO <OutPoint> doesn't exist in mempool"
 *  - UtxoDoesntExist: "Inconsistent mempool: UTXO <OutPoint> spent by
 *    <txid> doesn't exist in mempool"
 */
class MempoolGroupUtxosError : public ChronikError {
public:
    using ChronikError::ChronikError;
};

/** UTXOs of a group in the mempool. */
class MempoolGroupUtxos {
public:
    using Utxos = std::set<OutPoint>;
    using Map = std::map<Bytes, Utxos, std::less<>>;

    /** The group must outlive this. */
    explicit MempoolGroupUtxos(const GroupDef &group);

    /**
     * Add tx to the group's mempool UTXO set. This also removes the mempool
     * outputs spent by the tx, which is why we need `is_mempool_tx`.
     */
    void Insert(const MempoolTx &tx, const IsMempoolTxFn &is_mempool_tx,
                const GroupAux *aux);

    /**
     * Remove tx from the group's mempool UTXO set, restoring the mempool
     * UTXOs spent by `tx`. Only for TransactionRemovedFromMempool (assumes
     * the tx has no dependents in the mempool).
     */
    void Remove(const MempoolTx &tx, const IsMempoolTxFn &is_mempool_tx,
                const GroupAux *aux);

    /**
     * Remove tx from the group's UTXO set, when this tx has been mined in a
     * block (assumes all its dependencies have been mined as well).
     */
    void RemoveMined(const MempoolTx &tx, const GroupAux *aux);

    /** UTXOs of a given serialized member, or nullptr if none. */
    const Utxos *GetUtxos(ByteView member_ser) const;

    /**
     * Visit all group members with a given prefix, starting from
     * `member_start` (Rust `prefix_iterator`). `visit` returns false to stop.
     */
    void VisitPrefix(
        ByteView member_prefix, ByteView member_start,
        const std::function<bool(const Bytes &, const Utxos &)> &visit) const;

    const Map &All() const { return m_utxos; }

private:
    Utxos &EnsureEntry(ByteView member_ser);
    /** Returns the error message instead of throwing (nullopt on success). */
    std::optional<std::string> RemoveUtxo(ByteView member_ser,
                                          const TxId *txid,
                                          const OutPoint &outpoint);

    Map m_utxos;
    const GroupDef &m_group;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_GROUP_UTXOS_H
