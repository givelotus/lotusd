// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/groups/groups.h>

#include <algorithm>
#include <memory>

namespace chronik::native::lotus_v2 {

namespace {

Bytes HashBytes(const Hash32 &h) { return Bytes(h.b.begin(), h.b.end()); }

/** Page size of both V2 group histories (Rust tx_history_conf). */
constexpr uint32_t kPageSize = 1000;

} // namespace

std::vector<std::string_view> LegacyV2TableNames() {
    return {kV2BranchHistory, kV2BranchHistoryNumTxs, kV2BranchUtxo,
            kV2AssetHistory,  kV2AssetHistoryNumTxs,  kV2AssetUtxo};
}

std::optional<Output> DecodeV2OutputScript(ByteView script) {
    if (auto out = Output::Decode(script)) {
        return out;
    }
    if (!script.empty() && script[0] == 0x6a && script.size() >= 44) {
        return Output::Decode(script.subspan(1));
    }
    return std::nullopt;
}

Output V2ThreeBranchOutput::ToV2Output() const {
    Output out;
    out.branches.push_back(key_branch);
    for (const auto &branch : {script_branch, data_branch}) {
        if (branch && std::find(out.branches.begin(), out.branches.end(),
                                *branch) == out.branches.end()) {
            out.branches.push_back(*branch);
        }
    }
    if (asset_id && *asset_id != Hash32{}) {
        out.flags |= 1;
        out.token_id = *asset_id;
    }
    if (is_burn) {
        out.flags |= 2;
    } else {
        for (size_t idx = 0; idx < out.branches.size(); ++idx) {
            out.paths.push_back({uint8_t(idx)});
        }
    }
    out.value = value;
    return out;
}

std::optional<Bytes> V2ThreeBranchOutput::ToScript() const {
    return ToV2Output().Encode();
}

// ---- V2BranchGroup ----

void V2BranchGroup::InputMembers(const GroupQuery &query, const GroupAux *,
                                 std::vector<MemberItem> &out) const {
    if (query.is_coinbase) {
        return;
    }
    for (size_t idx = 0; idx < query.tx->inputs.size(); ++idx) {
        const auto &coin = query.tx->inputs[idx].coin;
        if (!coin) {
            continue;
        }
        if (auto v2_out = DecodeV2OutputScript(coin->output.script)) {
            for (const Hash32 &branch : v2_out->branches) {
                out.push_back(MemberItem{idx, HashBytes(branch)});
            }
        }
    }
}

void V2BranchGroup::OutputMembers(const GroupQuery &query, const GroupAux *,
                                  std::vector<MemberItem> &out) const {
    for (size_t idx = 0; idx < query.tx->outputs.size(); ++idx) {
        auto v2_out = DecodeV2OutputScript(query.tx->outputs[idx].script);
        if (!v2_out || v2_out->IsBurn()) {
            continue;
        }
        for (const Hash32 &branch : v2_out->branches) {
            out.push_back(MemberItem{idx, HashBytes(branch)});
        }
    }
}

Bytes V2BranchGroup::SerMember(ByteView member) const {
    return Bytes(member.begin(), member.end());
}

std::optional<GroupHistoryConf> V2BranchGroup::TxHistoryConf() const {
    return GroupHistoryConf{kV2BranchHistory, kV2BranchHistoryNumTxs,
                            kPageSize, std::nullopt};
}

std::optional<GroupUtxoConf> V2BranchGroup::UtxoConf() const {
    return GroupUtxoConf{kV2BranchUtxo};
}

// ---- V2AssetGroup ----

void V2AssetGroup::InputMembers(const GroupQuery &query, const GroupAux *,
                                std::vector<MemberItem> &out) const {
    if (query.is_coinbase) {
        return;
    }
    for (size_t idx = 0; idx < query.tx->inputs.size(); ++idx) {
        const auto &coin = query.tx->inputs[idx].coin;
        if (!coin) {
            continue;
        }
        auto v2_out = DecodeV2OutputScript(coin->output.script);
        if (v2_out && v2_out->HasToken()) {
            out.push_back(MemberItem{idx, HashBytes(v2_out->token_id)});
        }
    }
}

void V2AssetGroup::OutputMembers(const GroupQuery &query, const GroupAux *,
                                 std::vector<MemberItem> &out) const {
    for (size_t idx = 0; idx < query.tx->outputs.size(); ++idx) {
        auto v2_out = DecodeV2OutputScript(query.tx->outputs[idx].script);
        if (v2_out && v2_out->HasToken() && !v2_out->IsBurn()) {
            out.push_back(MemberItem{idx, HashBytes(v2_out->token_id)});
        }
    }
}

Bytes V2AssetGroup::SerMember(ByteView member) const {
    return Bytes(member.begin(), member.end());
}

std::optional<GroupHistoryConf> V2AssetGroup::TxHistoryConf() const {
    return GroupHistoryConf{kV2AssetHistory, kV2AssetHistoryNumTxs, kPageSize,
                            std::nullopt};
}

std::optional<GroupUtxoConf> V2AssetGroup::UtxoConf() const {
    return GroupUtxoConf{kV2AssetUtxo};
}

// ---- subscriptions ----

Bytes GroupSubsKind::SerMember(ByteView member) const {
    return m_group.SerMember(member);
}

void GroupSubsKind::TxMembers(const Tx &tx, const SubsAux &,
                              std::vector<SubsMember> &out) const {
    const GroupQuery query{/*is_coinbase=*/false, &tx};
    for (const Bytes &member : TxMembersForGroup(m_group, query, nullptr)) {
        out.push_back(SubsMember{m_group.SerMember(member), std::nullopt});
    }
}

void LegacyGroupsExtension::RegisterWsScriptTypes(SubscriptionHub &hub) {
    const size_t branch = hub.AddGroup(std::make_unique<GroupSubsKind>(m_branch));
    const size_t asset = hub.AddGroup(std::make_unique<GroupSubsKind>(m_asset));
    hub.AddWsScriptType({"v2-branch", 32, branch, "V2 branch"});
    hub.AddWsScriptType({"taproot", 32, branch, "V2 branch"});
    hub.AddWsScriptType({"v2-asset", 32, asset, "V2 asset"});
}

} // namespace chronik::native::lotus_v2
