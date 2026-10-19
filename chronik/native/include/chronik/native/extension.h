// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXTENSION_H
#define CHRONIK_NATIVE_EXTENSION_H

#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

/**
 * Groups and extensions (design C1 §5.3), adapted to chronik-db group.rs.
 *
 * A GroupDef is the runtime form of Rust's `Group` trait: it finds the members
 * of a tx's inputs and outputs, serializes them for the DB and names the
 * tables used by GroupHistoryWriter/GroupUtxoWriter (index/group_history.h,
 * index/group_utxos.h) and the mempool group indexes (mem/).
 *
 * Members are passed as raw bytes ("Member" in Rust, e.g. the script
 * bytecode), and SerMember turns them into the DB key ("MemberSer", e.g. the
 * compressed script). Writers group by raw member, ordered bytewise like the
 * Rust BTreeMap, then serialize.
 */
namespace chronik::native {

/** Rust `GroupQuery`: everything a group needs to find a tx's members. */
struct GroupQuery {
    /** Whether the tx is a coinbase tx. */
    bool is_coinbase = false;
    /** The transaction that should be grouped. */
    const Tx *tx = nullptr;
};

/** Rust `MemberItem`: a member and the input/output index it was found at. */
struct MemberItem {
    /** Index of the item in the list of inputs/outputs. */
    size_t idx = 0;
    /** Member of this item (raw, not serialized). */
    Bytes member;

    bool operator==(const MemberItem &) const = default;
};

/**
 * Auxiliary data when grouping members (Rust `Group::Aux`). Groups without
 * aux data (Rust `()`) ignore it and accept nullptr; e.g. the token ID group
 * downcasts it to its own aux type.
 */
class GroupAux {
public:
    virtual ~GroupAux() = default;
};

/** Rust `GroupHistoryConf`. */
struct GroupHistoryConf {
    /** Column family to store the group history pages. */
    std::string_view cf_page_name;
    /** Column family to store the last page num of the group history. */
    std::string_view cf_num_txs_name;
    /** Page size for each member of the group. */
    uint32_t page_size = 0;
    /**
     * Column family to store a mapping from member_hash -> ser_member.
     * Currently only used for ScriptGroup for the ElectrumX API.
     */
    std::optional<std::string_view> cf_member_hash_name;
};

/** Rust `GroupUtxoConf`. */
struct GroupUtxoConf {
    /** Column family to store the group utxos entries. */
    std::string_view cf_name;
};

/**
 * Data attached to a UTXO by a group (Rust `UtxoData` impls). The dup value
 * is always `tx_num BE8 || out_idx BE4` followed by:
 *  - Value (`UtxoDataValue = i64`): sats LE8; fixed size 20 (MDBX_DUPFIXED);
 *  - Output (`UtxoDataOutput = (i64, Bytes)`): sats LE8 || raw script;
 *    variable size (DUPSORT only).
 */
enum class UtxoDataKind { Value, Output };

/** Fixed dup size of the kind (Rust `UtxoData::FIXED_DUP_SIZE`). */
std::optional<uint32_t> UtxoFixedDupSize(UtxoDataKind kind);

/** Runtime form of Rust's `Group` trait. */
class GroupDef {
public:
    virtual ~GroupDef() = default;

    /** Name for diagnostics, e.g. "ScriptGroup". */
    virtual std::string_view Name() const = 0;

    /**
     * Find the group's members in the given query's tx's inputs, appending
     * them to `out`. A member may be returned multiple times per query.
     */
    virtual void InputMembers(const GroupQuery &query, const GroupAux *aux,
                              std::vector<MemberItem> &out) const = 0;

    /** Same as InputMembers, for the outputs. */
    virtual void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                               std::vector<MemberItem> &out) const = 0;

    /**
     * Serialize the given member; the key in the DB. For group history, this
     * is suffixed by a 4-byte page number.
     */
    virtual Bytes SerMember(ByteView member) const = 0;

    /** Whether this group supports SerHashMember. */
    virtual bool IsHashMemberSupported() const { return false; }

    /**
     * Hash the given member (big-endian bytes). Only used for ScriptGroup,
     * for the scripthash -> script index of the ElectrumX API. Throws if
     * unsupported (Rust: unimplemented!()).
     */
    virtual std::array<uint8_t, 32> SerHashMember(ByteView member) const;

    /** The GroupHistoryConf; nullopt where Rust panics (no history). */
    virtual std::optional<GroupHistoryConf> TxHistoryConf() const = 0;

    /** The GroupUtxoConf; nullopt where Rust panics (no UTXOs). */
    virtual std::optional<GroupUtxoConf> UtxoConf() const = 0;

    /** Data attached to a UTXO for this group. */
    virtual UtxoDataKind UtxoData() const = 0;
};

/**
 * Rust `tx_members_for_group`: the members of both inputs and outputs of the
 * tx (inputs first).
 */
std::vector<Bytes> TxMembersForGroup(const GroupDef &group,
                                     const GroupQuery &query,
                                     const GroupAux *aux);

/**
 * Tables a group uses (Rust `GroupHistoryWriter::add_cfs` and
 * `GroupUtxoWriter::add_cfs`): page, num_txs, [member_hash], [utxo].
 */
std::vector<TableSpec> GroupTableSpecs(const GroupDef &group);

class Router;
class SubscriptionHub;

/**
 * Host/tier-supplied indexing extension (design C1 §5.3). Extensions are
 * driven by the indexer after (OwnEnv) or inside (SameEnv) the core's write
 * txn, with the same Block the core indexes.
 */
class Extension {
public:
    virtual ~Extension() = default;

    enum class Txn { SameEnv, OwnEnv };

    /** Groups indexed by the core's group writers on behalf of this ext. */
    virtual std::vector<const GroupDef *> Groups() const { return {}; }
    /** Whether Connect/Disconnect get the core's write txn. */
    virtual Txn TxnMode() const = 0;
    virtual void Open(const std::filesystem::path & /*index_dir*/,
                      bool /*wipe*/) {}
    /** Called after the core's resync. */
    virtual void Resync() {}
    /** same_env_txn is the core's txn for SameEnv, nullptr for OwnEnv. */
    virtual void Connect(const Block &block, WriteTxn *same_env_txn) = 0;
    virtual void Disconnect(const Block &block, WriteTxn *same_env_txn) = 0;
    virtual void RegisterRoutes(Router & /*router*/) {}
    virtual void RegisterWsScriptTypes(SubscriptionHub & /*hub*/) {}
    virtual void Close() {}
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_EXTENSION_H
