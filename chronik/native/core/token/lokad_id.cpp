// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/lokad_id.h>
#include <chronik/native/token/parse.h>

#include <algorithm>

namespace chronik::native::token {

namespace {

std::optional<LokadId> LokadIdFromPushop(const script::Op &op) {
    if (!op.is_push || op.data.size() != 4) {
        return std::nullopt;
    }
    LokadId id;
    std::copy(op.data.begin(), op.data.end(), id.begin());
    return id;
}

} // namespace

std::optional<LokadId> ParseOpreturnLokadId(ByteView script) {
    script::ScriptOpIter ops(script);
    auto first = ops.Next();
    if (!first || !first->ok() || first->value().is_push ||
        first->value().opcode != script::OP_RETURN) {
        return std::nullopt;
    }
    auto second = ops.Next();
    if (!second || !second->ok()) {
        return std::nullopt;
    }
    return LokadIdFromPushop(second->value());
}

std::vector<LokadId> EmppLokadIds(const std::vector<Bytes> &pushdata) {
    std::vector<LokadId> ids;
    for (const Bytes &data : pushdata) {
        if (data.size() < 4) {
            break;
        }
        LokadId id;
        std::copy(data.begin(), data.begin() + 4, id.begin());
        ids.push_back(id);
    }
    return ids;
}

std::optional<LokadId> ParseInputScriptLokadId(ByteView script) {
    script::ScriptOpIter ops(script);
    auto first = ops.Next();
    if (!first || !first->ok()) {
        return std::nullopt;
    }
    return LokadIdFromPushop(first->value());
}

std::vector<LokadId> ParseTxLokadIds(const Tx &tx) {
    std::vector<LokadId> ids;
    if (!tx.outputs.empty()) {
        const Bytes &script = tx.outputs[0].script;
        if (auto id = ParseOpreturnLokadId(script)) {
            ids.push_back(*id);
        }
        auto empp_data = empp::Parse(script);
        if (empp_data.ok() && empp_data.value()) {
            for (const LokadId &id : EmppLokadIds(*empp_data.value())) {
                ids.push_back(id);
            }
        }
    }
    for (const TxInput &input : tx.inputs) {
        auto id = ParseInputScriptLokadId(input.script);
        if (!id) {
            break;
        }
        ids.push_back(*id);
    }
    return ids;
}

} // namespace chronik::native::token
