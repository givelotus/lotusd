// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_GROUPS_LOKAD_ID_H
#define CHRONIK_NATIVE_GROUPS_LOKAD_ID_H

#include <chronik/native/extension.h>

/**
 * Port of chronik-db groups/lokad_id.rs: index txs by LOKAD ID (4 bytes).
 * LOKAD ID is per-tx, not per-UTXO, so only OutputMembers is used (with the
 * tx-wide parse_tx_lokad_ids result) and there is no UTXO table.
 */
namespace chronik::native::groups {

class LokadIdGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "LokadIdGroup"; }
    /** Always empty; actual parsing happens in OutputMembers. */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** The tx's LOKAD IDs, idx enumerating them. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    Bytes SerMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override;
    std::optional<GroupUtxoConf> UtxoConf() const override {
        return std::nullopt;
    }
    /** Ignored, LOKAD ID doesn't apply to UTXOs but to entire txs */
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Output; }
};

} // namespace chronik::native::groups

#endif // CHRONIK_NATIVE_GROUPS_LOKAD_ID_H
