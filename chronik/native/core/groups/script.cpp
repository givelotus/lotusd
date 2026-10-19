// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/groups/script.h>

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/schema.h>
#include <chronik/native/script/script.h>

namespace chronik::native::groups {

ScriptGroup::ScriptGroup(Sha256Fn sha256) : m_sha256(std::move(sha256)) {}

void ScriptGroup::InputMembers(const GroupQuery &query, const GroupAux *,
                               std::vector<MemberItem> &out) const {
    if (query.is_coinbase) {
        return;
    }
    const std::vector<TxInput> &inputs = query.tx->inputs;
    for (size_t idx = 0; idx < inputs.size(); ++idx) {
        // Rust `?`: iteration ends at the first input without a coin
        if (!inputs[idx].coin) {
            return;
        }
        out.push_back(MemberItem{idx, inputs[idx].coin->output.script});
    }
}

void ScriptGroup::OutputMembers(const GroupQuery &query, const GroupAux *,
                                std::vector<MemberItem> &out) const {
    const std::vector<TxOutput> &outputs = query.tx->outputs;
    for (size_t idx = 0; idx < outputs.size(); ++idx) {
        // Skip OP_RETURN scripts
        if (script::Script(ByteView(outputs[idx].script)).IsOpReturn()) {
            continue;
        }
        out.push_back(MemberItem{idx, outputs[idx].script});
    }
}

Bytes ScriptGroup::SerMember(ByteView member) const {
    return CompressScript(member);
}

std::array<uint8_t, 32> ScriptGroup::SerHashMember(ByteView member) const {
    std::array<uint8_t, 32> hash;
    m_sha256(member, hash.data());
    // Sha256::to_be_bytes
    return Hash32::FromBytes(hash).Reversed();
}

std::optional<GroupHistoryConf> ScriptGroup::TxHistoryConf() const {
    return GroupHistoryConf{schema::kScriptHistory,
                            schema::kScriptHistoryNumTxs, 1000,
                            schema::kScripthash};
}

std::optional<GroupUtxoConf> ScriptGroup::UtxoConf() const {
    return GroupUtxoConf{schema::kScriptUtxo};
}

} // namespace chronik::native::groups
