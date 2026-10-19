// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_GROUP_UTXOS_H
#define CHRONIK_NATIVE_INDEX_GROUP_UTXOS_H

#include <chronik/native/extension.h>
#include <chronik/native/index/data.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

/**
 * Port of chronik-db io/group_utxos.rs (eCash tier, schema v13).
 *
 * The UTXOs of a member are the duplicate values of key `<serialized member>`
 * in a DUPSORT table, sorted by their 12-byte `tx_num BE8 || out_idx BE4`
 * outpoint prefix, followed by the UtxoDataKind payload (see extension.h).
 *
 * Within one Insert/Delete call, dup writes are collected like the Rust
 * WriteBatch (keyed by member and outpoint prefix): a UTXO created and spent
 * within the call cancels out without touching the table.
 */
namespace chronik::native::index {

/** Entry in the UTXO DB for a group (Rust `UtxoEntry<D>`). */
struct UtxoEntry {
    /** Outpoint of the UTXO. */
    DbOutpoint outpoint;
    /** UtxoDataValue / first part of UtxoDataOutput. */
    int64_t sats = 0;
    /** UtxoDataOutput only (empty for UtxoDataValue). */
    Bytes script;

    bool operator==(const UtxoEntry &) const = default;
};

/** In-memory data for indexing UTXOs of a group. */
struct GroupUtxoStats {
    /** Total number of txs updated. */
    size_t n_total = 0;
    /** Time [s] for insert/delete. */
    double t_total = 0;
};

struct GroupUtxoMemData {
    GroupUtxoStats stats;
};

/** `tx_num BE8 || out_idx BE4` */
std::array<uint8_t, 12> EncodeOutpointPrefix(const DbOutpoint &outpoint);

/** Dup value of the entry (Rust `encode_utxo_dup`). */
Bytes EncodeUtxoDup(UtxoDataKind kind, const UtxoEntry &entry);

/** Rust `decode_utxo_dup`, with its SerError texts. */
UtxoEntry DecodeUtxoDup(UtxoDataKind kind, ByteView bytes);

/** The UTXO conf of the group; throws if it has none. */
GroupUtxoConf RequireUtxoConf(const GroupDef &group);

/** Write UTXOs of a group to the DB. */
class GroupUtxoWriter {
public:
    GroupUtxoWriter(const KvStore &store, const GroupDef &group);

    /**
     * Insert the txs of a block: add all the UTXOs created by the outputs of
     * the txs, remove all the UTXOs spent by the inputs of the txs.
     */
    void Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                const GroupAux *aux, GroupUtxoMemData &mem_data) const;

    /**
     * Remove the txs of a block: add all the UTXOs spent by the inputs of
     * the txs and remove all the UTXOs created by the outputs of the txs.
     */
    void Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                const GroupAux *aux, GroupUtxoMemData &mem_data) const;

    /** Clear all UTXO data from the DB */
    void Wipe(WriteTxn &txn) const;

    /** Data of an output / spent coin (Rust `UtxoData::from_output`). */
    UtxoEntry OutputUtxo(const IndexTx &index_tx, size_t idx) const;
    UtxoEntry InputUtxo(const IndexTx &index_tx, size_t idx) const;

private:
    const GroupDef &m_group;
    UtxoDataKind m_kind;
    TableId m_cf;
};

/** Read UTXOs of a group from the DB. */
class GroupUtxoReader {
public:
    GroupUtxoReader(const KvStore &store, const ReadTxn &txn,
                    const GroupDef &group);

    /** Query the UTXOs for the given serialized member. */
    std::optional<std::vector<UtxoEntry>> Utxos(ByteView member) const;

    /**
     * Visit all group members with a given prefix, starting from the first
     * key >= `member_start` (or the first key if empty), stopping at the
     * first key without the prefix (Rust `prefix_iterator`). `visit` returns
     * false to stop early.
     */
    void VisitPrefix(
        ByteView member_prefix, ByteView member_start,
        const std::function<bool(ByteView member,
                                 std::vector<UtxoEntry> &&utxos)> &visit)
        const;

private:
    const ReadTxn &m_txn;
    UtxoDataKind m_kind;
    TableId m_cf;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_GROUP_UTXOS_H
