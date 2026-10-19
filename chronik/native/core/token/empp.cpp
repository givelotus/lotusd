// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/parse.h>

namespace chronik::native::token::empp {

using script::Op;
using script::Opcode;

std::string ParseError::ToString() const {
    switch (kind) {
        case Kind::DataError:
            return "Failed parsing script: " + data_error.ToString();
        case Kind::EmptyScript:
            return "Empty script";
        case Kind::MissingOpReturn:
            return "Expected OP_RETURN, but got " + opcode.ToString();
        case Kind::EmptyOpReturn:
            return "Empty OP_RETURN";
        case Kind::MissingOpReserved:
            return "Missing OP_RESERVED, but got " + opcode.ToString();
        case Kind::InvalidPushOpcode:
            return "Invalid push opcode " + opcode.ToString() +
                   ": OP_0, OP_1NEGATE, OP_RESERVED, OP_1, .. OP_16 not "
                   "allowed";
        case Kind::InvalidNonPushOpcode:
            return "Invalid non-push opcode " + opcode.ToString();
        case Kind::EmptyPushdata:
            return "Empty pushdata not allowed (used " + opcode.ToString() +
                   ")";
    }
    return {};
}

Result<EmppData, ParseError> ParseWithIgnoredErr(ByteView script) {
    using K = ParseError::Kind;
    script::ScriptOpIter ops(script);
    auto op_return = ops.Next();
    if (!op_return) {
        return Err(ParseError::Make(K::EmptyScript));
    }
    if (!op_return->ok() || op_return->value().is_push ||
        op_return->value().opcode != script::OP_RETURN) {
        return Err(ParseError::Make(K::MissingOpReturn, Opcode{script[0]}));
    }
    auto op_reserved = ops.Next();
    if (!op_reserved) {
        return Err(ParseError::Make(K::EmptyOpReturn));
    }
    if (!op_reserved->ok() || op_reserved->value().is_push ||
        op_reserved->value().opcode != script::OP_RESERVED) {
        return Err(ParseError::Make(K::MissingOpReserved, Opcode{script[1]}));
    }
    EmppData empp_data;
    while (auto pushop = ops.Next()) {
        if (!pushop->ok()) {
            return Err(ParseError::FromDataError(pushop->error()));
        }
        Op &op = pushop->value();
        if (!op.is_push) {
            if (op.opcode == script::OP_0) {
                return Err(ParseError::Make(K::EmptyPushdata, script::OP_0));
            }
            if (op.opcode.n >= script::OP_1NEGATE.n &&
                op.opcode.n <= script::OP_16.n) {
                return Err(ParseError::Make(K::InvalidPushOpcode, op.opcode));
            }
            return Err(ParseError::Make(K::InvalidNonPushOpcode, op.opcode));
        }
        if (op.data.empty()) {
            return Err(ParseError::Make(K::EmptyPushdata, op.opcode));
        }
        empp_data.push_back(std::move(op.data));
    }
    return empp_data;
}

namespace {
bool ShouldIgnoreErr(const ParseError &err) {
    using K = ParseError::Kind;
    return err.kind == K::EmptyScript || err.kind == K::MissingOpReturn ||
           err.kind == K::EmptyOpReturn || err.kind == K::MissingOpReserved;
}
} // namespace

Result<std::optional<EmppData>, ParseError> Parse(ByteView script) {
    auto result = ParseWithIgnoredErr(script);
    if (result.ok()) {
        return std::optional<EmppData>(std::move(result.value()));
    }
    if (ShouldIgnoreErr(result.error())) {
        return std::optional<EmppData>();
    }
    return Err(result.error());
}

} // namespace chronik::native::token::empp
