// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_GROUPS_TXID_H
#define CHRONIK_NATIVE_GROUPS_TXID_H

#include <chronik/native/extension.h>

/**
 * Port of chronik-db groups/txid.rs: groups a tx by its own TxId (used for
 * subscriptions only; no history or UTXO tables). The member is the TxId in
 * internal byte order; serialized big-endian (reversed).
 */
namespace chronik::native::groups {

class TxIdGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "TxIdGroup"; }
    /** Always empty; actual parsing happens in OutputMembers. */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** One item {0, txid}. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    Bytes SerMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override {
        return std::nullopt;
    }
    std::optional<GroupUtxoConf> UtxoConf() const override {
        return std::nullopt;
    }
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Output; }
};

} // namespace chronik::native::groups

#endif // CHRONIK_NATIVE_GROUPS_TXID_H
