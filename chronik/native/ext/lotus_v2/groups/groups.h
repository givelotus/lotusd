// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_GROUPS_GROUPS_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_GROUPS_GROUPS_H

#include <chronik/native/extension.h>
#include <chronik/native/subs.h>

#include <ext/lotus_v2/types.h>

#include <optional>
#include <string_view>
#include <vector>

/**
 * Lotus V2 groups of the legacy Chronik index: port of chronik-db
 * groups/v2.rs (V2 tier). Outputs whose script is a native V2 output frame
 * (as the V2 host adapter indexes native outputs) are grouped by each
 * public branch root and by their asset ID. Members and serialized members
 * are the raw 32 bytes (wire order); UTXOs carry their sats (UtxoDataValue).
 *
 * The tables live in the legacy Chronik env next to the eCash tables and are
 * registered only by this extension:
 *   v2_branch_history, v2_branch_history_num_txs, v2_branch_utxo,
 *   v2_asset_history, v2_asset_history_num_txs, v2_asset_utxo.
 *
 * Rust also keeps mempool indexes of both groups, read only by the Electrum
 * server; the native implementation has no Electrum server and does not
 * keep them.
 */
namespace chronik::native::lotus_v2 {

inline constexpr std::string_view kV2BranchHistory = "v2_branch_history";
inline constexpr std::string_view kV2BranchHistoryNumTxs =
    "v2_branch_history_num_txs";
inline constexpr std::string_view kV2BranchUtxo = "v2_branch_utxo";
inline constexpr std::string_view kV2AssetHistory = "v2_asset_history";
inline constexpr std::string_view kV2AssetHistoryNumTxs =
    "v2_asset_history_num_txs";
inline constexpr std::string_view kV2AssetUtxo = "v2_asset_utxo";

/** The six legacy-env tables of the V2 groups, in Rust db.rs order. */
std::vector<std::string_view> LegacyV2TableNames();

/**
 * Rust `decode_v2_output_script`: the native V2 output of a script that is
 * exactly a native output frame, or `0x6a || frame` (CTxOut::FromV2Output
 * burns) of at least 44 bytes.
 */
std::optional<Output> DecodeV2OutputScript(ByteView script);

/**
 * Rust `V2ThreeBranchOutput`: a 3-branch Taproot-style output (key branch,
 * optional script and data branches, optional asset ID).
 */
struct V2ThreeBranchOutput {
    Hash32 key_branch;
    std::optional<Hash32> script_branch;
    std::optional<Hash32> data_branch;
    std::optional<Hash32> asset_id;
    uint64_t value = 0;
    bool is_burn = false;

    /** Canonical output: distinct branches, one path per branch. */
    Output ToV2Output() const;
    /** The output's native frame, or nullopt if it is invalid. */
    std::optional<Bytes> ToScript() const;
};

/** Rust `V2BranchGroup`: one member per branch root of each output. */
class V2BranchGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "V2BranchGroup"; }
    /** Branches of spent V2 coins (none for coinbase txs). */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** Branches of non-burn V2 outputs. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    Bytes SerMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override;
    std::optional<GroupUtxoConf> UtxoConf() const override;
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Value; }
};

/** Rust `V2AssetGroup`: the asset ID of token outputs. */
class V2AssetGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "V2AssetGroup"; }
    /** Asset IDs of spent V2 token coins (none for coinbase txs). */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** Asset IDs of non-burn V2 token outputs. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    Bytes SerMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override;
    std::optional<GroupUtxoConf> UtxoConf() const override;
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Value; }
};

/**
 * Subscription group of a GroupDef without aux data (Rust SubsGroup<G>):
 * members are tx_members_for_group with is_coinbase = false.
 */
class GroupSubsKind final : public SubsGroupKind {
public:
    explicit GroupSubsKind(const GroupDef &group) : m_group(group) {}
    Bytes SerMember(ByteView member) const override;
    void TxMembers(const Tx &tx, const SubsAux &aux,
                   std::vector<SubsMember> &out) const override;

private:
    const GroupDef &m_group;
};

/**
 * Extension indexing the V2 groups in the legacy env (inside the core's
 * write txn), with the subscriptions of ws.rs: WsSub script types
 * "v2-branch" and "taproot" (32-byte branch root) and "v2-asset" (32-byte
 * asset ID).
 */
class LegacyGroupsExtension final : public Extension {
public:
    std::vector<const GroupDef *> Groups() const override {
        return {&m_branch, &m_asset};
    }
    Txn TxnMode() const override { return Txn::SameEnv; }
    /** The core's group writers index the groups; nothing else to do. */
    void Connect(const Block &, WriteTxn *) override {}
    void Disconnect(const Block &, WriteTxn *) override {}
    void RegisterWsScriptTypes(SubscriptionHub &hub) override;

    const V2BranchGroup &BranchGroup() const { return m_branch; }
    const V2AssetGroup &AssetGroup() const { return m_asset; }

private:
    V2BranchGroup m_branch;
    V2AssetGroup m_asset;
};

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_GROUPS_GROUPS_H
