// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_GROUPS_SCRIPT_H
#define CHRONIK_NATIVE_GROUPS_SCRIPT_H

#include <chronik/native/extension.h>
#include <chronik/native/store.h>

/**
 * Port of chronik-db groups/script.rs: index by output script. Members are
 * the raw scripts; serialized as compressed scripts. Tables script_history,
 * script_history_num_txs, scripthash (member hash) and script_utxo.
 */
namespace chronik::native::groups {

class ScriptGroup final : public GroupDef {
public:
    /** `sha256` hashes members for the scripthash index. */
    explicit ScriptGroup(Sha256Fn sha256);

    std::string_view Name() const override { return "ScriptGroup"; }
    /** Spent coins' scripts; stops at the first input without coin. */
    void InputMembers(const GroupQuery &query, const GroupAux *aux,
                      std::vector<MemberItem> &out) const override;
    /** Output scripts, skipping OP_RETURN scripts. */
    void OutputMembers(const GroupQuery &query, const GroupAux *aux,
                       std::vector<MemberItem> &out) const override;
    Bytes SerMember(ByteView member) const override;
    bool IsHashMemberSupported() const override { return true; }
    /** sha256(script) as big-endian bytes (Rust Sha256::to_be_bytes) */
    std::array<uint8_t, 32> SerHashMember(ByteView member) const override;
    std::optional<GroupHistoryConf> TxHistoryConf() const override;
    std::optional<GroupUtxoConf> UtxoConf() const override;
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Value; }

private:
    Sha256Fn m_sha256;
};

} // namespace chronik::native::groups

#endif // CHRONIK_NATIVE_GROUPS_SCRIPT_H
