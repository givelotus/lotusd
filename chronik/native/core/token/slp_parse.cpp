// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/parse.h>

#include <algorithm>
#include <cstring>

namespace chronik::native::token::slp {

using script::Op;
using script::Opcode;
using K = ParseError::Kind;

// ---- ParseError ----

ParseError ParseError::FromDataError(script::DataError err) {
    ParseError e = Make(K::DataError);
    e.data_error = std::move(err);
    return e;
}
ParseError ParseError::MissingOpReturn(Opcode opcode) {
    ParseError e = Make(K::MissingOpReturn);
    e.opcode = opcode;
    return e;
}
ParseError ParseError::WrongLokadId(Bytes bytes) {
    ParseError e = Make(K::WrongLokadId);
    e.bytes = std::move(bytes);
    return e;
}
ParseError ParseError::InvalidLokadIdOpcode(Opcode opcode) {
    ParseError e = Make(K::InvalidLokadIdOpcode);
    e.opcode = opcode;
    return e;
}
ParseError ParseError::NonPushOp(Opcode opcode, size_t op_idx) {
    ParseError e = Make(K::NonPushOp);
    e.opcode = opcode;
    e.op_idx = op_idx;
    return e;
}
ParseError ParseError::DisallowedPush(Opcode opcode, size_t op_idx) {
    ParseError e = Make(K::DisallowedPush);
    e.opcode = opcode;
    e.op_idx = op_idx;
    return e;
}
ParseError ParseError::InvalidFieldSize(std::string field_name,
                                        std::vector<size_t> expected,
                                        size_t actual) {
    ParseError e = Make(K::InvalidFieldSize);
    e.field_name = std::move(field_name);
    e.expected_sizes = std::move(expected);
    e.actual = actual;
    return e;
}
ParseError ParseError::InvalidDecimals(size_t actual) {
    ParseError e = Make(K::InvalidDecimals);
    e.actual = actual;
    return e;
}
ParseError ParseError::InvalidMintBatonIdx(uint8_t idx) {
    ParseError e = Make(K::InvalidMintBatonIdx);
    e.byte = idx;
    return e;
}
ParseError ParseError::Nft1ChildInvalidInitialQuantity(Atoms atoms) {
    ParseError e = Make(K::Nft1ChildInvalidInitialQuantity);
    e.atoms = atoms;
    return e;
}
ParseError ParseError::Nft1ChildInvalidDecimals(uint8_t decimals) {
    ParseError e = Make(K::Nft1ChildInvalidDecimals);
    e.byte = decimals;
    return e;
}
ParseError ParseError::TooFewPushes(size_t expected, size_t actual) {
    ParseError e = Make(K::TooFewPushes);
    e.expected = expected;
    e.actual = actual;
    return e;
}
ParseError ParseError::UnexpectedNumPushes(size_t expected, size_t actual) {
    ParseError e = Make(K::UnexpectedNumPushes);
    e.expected = expected;
    e.actual = actual;
    return e;
}
ParseError ParseError::SuperfluousPushes(size_t expected, size_t actual) {
    ParseError e = Make(K::SuperfluousPushes);
    e.expected = expected;
    e.actual = actual;
    return e;
}
ParseError ParseError::InvalidTokenType(Bytes bytes) {
    ParseError e = Make(K::InvalidTokenType);
    e.bytes = std::move(bytes);
    return e;
}
ParseError ParseError::InvalidTxType(Bytes bytes) {
    ParseError e = Make(K::InvalidTxType);
    e.bytes = std::move(bytes);
    return e;
}

std::string ParseError::ToString() const {
    switch (kind) {
        case K::DataError:
            return "Failed parsing pushdata: " + data_error.ToString();
        case K::EmptyScript:
            return "First must be OP_RETURN (0x6a), but got no opcodes";
        case K::MissingOpReturn:
            return "First must be OP_RETURN (0x6a), but got " +
                   opcode.ToString();
        case K::MissingLokadId:
            return "Missing LOKAD ID";
        case K::WrongLokadId:
            return "Wrong LOKAD ID: " + script::DebugBytes(bytes);
        case K::InvalidLokadIdOpcode:
            return "Invalid opcode instead of LOKAD ID pushop: " +
                   opcode.ToString();
        case K::InvalidAlpLokadId:
            return "Invalid LOKAD ID \"SLP2\", did you forget to use eMPP?";
        case K::NonPushOp:
            return "Non-push op: " + opcode.ToString() + " at op " +
                   std::to_string(op_idx);
        case K::DisallowedPush:
            return "Disallowed push: " + opcode.ToString() + " at op " +
                   std::to_string(op_idx);
        case K::InvalidFieldSize:
            return "Field has invalid length: expected one of " +
                   script::DebugSizes(expected_sizes) + " but got " +
                   std::to_string(actual) + " for field " + field_name;
        case K::InvalidDecimals:
            return "Too many decimals, only max. 9 allowed, but got " +
                   std::to_string(actual);
        case K::InvalidMintBatonIdx:
            return "Mint baton at invalid output index, must be between 2 "
                   "and 255, but got " +
                   std::to_string(byte);
        case K::Nft1ChildCannotHaveMintBaton:
            return "NFT1 Child GENESIS cannot have mint baton";
        case K::Nft1ChildInvalidInitialQuantity:
            return "Invalid NFT1 Child GENESIS initial quantity, expected 1 "
                   "but got " +
                   std::to_string(atoms);
        case K::Nft1ChildInvalidDecimals:
            return "Invalid NFT1 Child GENESIS decimals, expected 0 but got " +
                   std::to_string(byte);
        case K::TooFewPushes:
            return "Too few pushes, expected at least " +
                   std::to_string(expected) + " but only got " +
                   std::to_string(actual);
        case K::UnexpectedNumPushes:
            return "Unexpected number of pushes, expected exactly " +
                   std::to_string(expected) + " but only got " +
                   std::to_string(actual);
        case K::SuperfluousPushes:
            return "Pushed superfluous data: expected at most " +
                   std::to_string(expected) + " pushes, but got " +
                   std::to_string(actual);
        case K::InvalidTokenType:
            return "Token type must be 1 byte long, got " +
                   std::to_string(bytes.size()) + ": " +
                   std::to_string(bytes.size());
        case K::InvalidTxType:
            return "Invalid tx type: " + script::DebugBytes(bytes);
    }
    return {};
}

// ---- Parsing ----

namespace {

Result<Atoms, ParseError> ParseAtoms(const Bytes &atoms_bytes,
                                     const char *field_name) {
    if (atoms_bytes.size() != 8) {
        return Err(ParseError::InvalidFieldSize(field_name, {8},
                                                atoms_bytes.size()));
    }
    Atoms atoms = 0;
    for (uint8_t b : atoms_bytes) {
        atoms = (atoms << 8) | b;
    }
    return atoms;
}

Result<TokenId, ParseError> ParseTokenId(const Bytes &token_id_bytes) {
    if (token_id_bytes.size() != 32) {
        return Err(ParseError::InvalidFieldSize("token_id", {32},
                                                token_id_bytes.size()));
    }
    std::array<uint8_t, 32> be;
    std::copy(token_id_bytes.begin(), token_id_bytes.end(), be.begin());
    return TokenId::FromBeBytes(be);
}

std::optional<ParseError> ParseLokadId(ByteView script) {
    script::ScriptOpIter ops(script);
    auto first = ops.Next();
    if (!first) {
        return ParseError::Make(K::EmptyScript);
    }
    if (!first->ok() || first->value().is_push ||
        first->value().opcode != script::OP_RETURN) {
        return ParseError::MissingOpReturn(Opcode{script[0]});
    }
    auto second = ops.Next();
    if (!second) {
        return ParseError::Make(K::MissingLokadId);
    }
    if (!second->ok() || !second->value().is_push) {
        return ParseError::InvalidLokadIdOpcode(Opcode{script[1]});
    }
    const Bytes &lokad_id = second->value().data;
    const auto &alp = alp_consts::ALP_LOKAD_ID;
    if (lokad_id.size() >= alp.size() &&
        std::equal(alp.begin(), alp.end(), lokad_id.begin())) {
        return ParseError::Make(K::InvalidAlpLokadId);
    }
    const auto &slp = slp_consts::SLP_LOKAD_ID;
    if (lokad_id.size() != slp.size() ||
        !std::equal(slp.begin(), slp.end(), lokad_id.begin())) {
        return ParseError::WrongLokadId(lokad_id);
    }
    return std::nullopt;
}

Result<std::vector<Bytes>, ParseError>
ParseOpreturnOps(std::vector<Op> ops) {
    std::vector<Bytes> pushes;
    for (size_t op_idx = 0; op_idx < ops.size(); ++op_idx) {
        Op &op = ops[op_idx];
        if (op_idx == 0) {
            if (!op.is_push && op.opcode == script::OP_RETURN) {
                continue;
            }
            return Err(ParseError::MissingOpReturn(op.opcode));
        }
        if (!op.is_push) {
            if (op.opcode == script::OP_0 ||
                (op.opcode.n >= script::OP_1NEGATE.n &&
                 op.opcode.n <= script::OP_16.n)) {
                return Err(ParseError::DisallowedPush(op.opcode, op_idx));
            }
            return Err(ParseError::NonPushOp(op.opcode, op_idx));
        }
        if (op.opcode == script::OP_0 ||
            op.opcode.n > script::OP_PUSHDATA4.n) {
            return Err(ParseError::DisallowedPush(op.opcode, op_idx));
        }
        pushes.push_back(std::move(op.data));
    }
    return pushes;
}

SlpTokenType ParseTokenType(const Bytes &bytes) {
    switch (bytes[0]) {
        case slp_consts::TOKEN_TYPE_V1:
            return SlpTokenType::Fungible();
        case slp_consts::TOKEN_TYPE_V2:
            return SlpTokenType::MintVault();
        case slp_consts::TOKEN_TYPE_V1_NFT1_GROUP:
            return SlpTokenType::Nft1Group();
        case slp_consts::TOKEN_TYPE_V1_NFT1_CHILD:
            return SlpTokenType::Nft1Child();
        default:
            return SlpTokenType::Unknown(bytes[0]);
    }
}

/** Parsed mint field of a GENESIS: baton out idx or vault scripthash */
struct MintField {
    bool is_vault = false;
    std::optional<uint8_t> baton_out_idx;
    script::ShaRmd160 vault_scripthash{};

    std::optional<uint8_t> MintBatonOutIdx() const {
        return is_vault ? std::nullopt : baton_out_idx;
    }
    std::optional<script::ShaRmd160> MintVaultScripthash() const {
        if (!is_vault) {
            return std::nullopt;
        }
        return vault_scripthash;
    }
};

Result<MintField, ParseError> ParseMintField(SlpTokenType token_type,
                                             const Bytes &mint_field) {
    if (token_type == SlpTokenType::MintVault()) {
        if (mint_field.size() != 20) {
            return Err(ParseError::InvalidFieldSize("mint_vault_scripthash",
                                                    {20}, mint_field.size()));
        }
        MintField field;
        field.is_vault = true;
        std::copy(mint_field.begin(), mint_field.end(),
                  field.vault_scripthash.begin());
        return field;
    }
    if (!mint_field.empty() && mint_field.size() != 1) {
        return Err(ParseError::InvalidFieldSize("mint_baton_out_idx", {0, 1},
                                                mint_field.size()));
    }
    if (mint_field.size() == 1 && mint_field[0] < 2) {
        return Err(ParseError::InvalidMintBatonIdx(mint_field[0]));
    }
    MintField field;
    if (!mint_field.empty()) {
        field.baton_out_idx = mint_field[0];
    }
    return field;
}

Result<ParsedData, ParseError>
ParseGenesisData(const TxId &txid, SlpTokenType token_type,
                 std::vector<Bytes> opreturn_data) {
    if (opreturn_data.size() != 10) {
        return Err(ParseError::UnexpectedNumPushes(10, opreturn_data.size()));
    }
    Bytes &token_ticker = opreturn_data[3];
    Bytes &token_name = opreturn_data[4];
    Bytes &token_document_url = opreturn_data[5];
    Bytes &token_document_hash = opreturn_data[6];
    Bytes &decimals_bytes = opreturn_data[7];
    Bytes &mint_field_bytes = opreturn_data[8];
    Bytes &initial_quantity_bytes = opreturn_data[9];
    if (!token_document_hash.empty() && token_document_hash.size() != 32) {
        return Err(ParseError::InvalidFieldSize(
            "token_document_hash", {0, 32}, token_document_hash.size()));
    }
    if (decimals_bytes.size() != 1) {
        return Err(ParseError::InvalidFieldSize("decimals", {1},
                                                decimals_bytes.size()));
    }
    auto mint_field = ParseMintField(token_type, mint_field_bytes);
    if (!mint_field) {
        return Err(mint_field.error());
    }
    auto initial_quantity =
        ParseAtoms(initial_quantity_bytes, "initial_quantity");
    if (!initial_quantity) {
        return Err(initial_quantity.error());
    }
    if (decimals_bytes[0] > 9) {
        return Err(ParseError::InvalidDecimals(decimals_bytes[0]));
    }
    const uint8_t decimals = decimals_bytes[0];
    const auto baton_out_idx = mint_field.value().MintBatonOutIdx();
    if (token_type == SlpTokenType::Nft1Child()) {
        if (baton_out_idx) {
            return Err(ParseError::Make(K::Nft1ChildCannotHaveMintBaton));
        }
        if (initial_quantity.value() != 1) {
            return Err(ParseError::Nft1ChildInvalidInitialQuantity(
                initial_quantity.value()));
        }
        if (decimals != 0) {
            return Err(ParseError::Nft1ChildInvalidDecimals(decimals));
        }
    }
    std::vector<Atoms> atoms_vec{initial_quantity.value()};
    if (baton_out_idx) {
        atoms_vec.resize(atoms_vec.size() + *baton_out_idx - 2, 0);
    }
    ParsedGenesis genesis;
    genesis.info.token_ticker = std::move(token_ticker);
    genesis.info.token_name = std::move(token_name);
    genesis.info.mint_vault_scripthash =
        mint_field.value().MintVaultScripthash();
    genesis.info.url = std::move(token_document_url);
    if (token_document_hash.size() == 32) {
        std::array<uint8_t, 32> hash;
        std::copy(token_document_hash.begin(), token_document_hash.end(),
                  hash.begin());
        genesis.info.hash = hash;
    }
    genesis.info.decimals = decimals;
    genesis.mint_data.atoms_vec = std::move(atoms_vec);
    genesis.mint_data.num_batons = baton_out_idx ? 1 : 0;
    return ParsedData{TokenMeta{TokenId{txid}, TokenType::Slp(token_type)},
                      ParsedTxType::MakeGenesis(std::move(genesis))};
}

Result<ParsedData, ParseError>
ParseMintDataBaton(SlpTokenType token_type, std::vector<Bytes> opreturn_data) {
    if (opreturn_data.size() != 6) {
        return Err(ParseError::UnexpectedNumPushes(6, opreturn_data.size()));
    }
    auto token_id = ParseTokenId(opreturn_data[3]);
    if (!token_id) {
        return Err(token_id.error());
    }
    const Bytes &baton = opreturn_data[4];
    if (!baton.empty() && baton.size() != 1) {
        return Err(ParseError::InvalidFieldSize("mint_baton_out_idx", {0, 1},
                                                baton.size()));
    }
    if (baton.size() == 1 && baton[0] < 2) {
        return Err(ParseError::InvalidMintBatonIdx(baton[0]));
    }
    std::optional<size_t> baton_out_idx;
    if (!baton.empty()) {
        baton_out_idx = baton[0];
    }
    auto additional_quantity =
        ParseAtoms(opreturn_data[5], "additional_quantity");
    if (!additional_quantity) {
        return Err(additional_quantity.error());
    }
    ParsedMintData mint;
    mint.atoms_vec.push_back(additional_quantity.value());
    if (baton_out_idx) {
        mint.atoms_vec.resize(mint.atoms_vec.size() + *baton_out_idx - 2, 0);
    }
    mint.num_batons = baton_out_idx ? 1 : 0;
    return ParsedData{
        TokenMeta{token_id.value(), TokenType::Slp(token_type)},
        ParsedTxType::MakeMint(std::move(mint))};
}

Result<std::vector<Atoms>, ParseError>
ParseQuantities(const std::vector<Bytes> &opreturn_data,
                const char *const *field_names) {
    std::vector<Atoms> atoms_vec;
    for (size_t idx = 4; idx < opreturn_data.size(); ++idx) {
        auto atoms = ParseAtoms(opreturn_data[idx], field_names[idx - 4]);
        if (!atoms) {
            return Err(atoms.error());
        }
        atoms_vec.push_back(atoms.value());
    }
    return atoms_vec;
}

Result<ParsedData, ParseError>
ParseMintDataMintVault(std::vector<Bytes> opreturn_data) {
    if (opreturn_data.size() < 5) {
        return Err(ParseError::TooFewPushes(5, opreturn_data.size()));
    }
    if (opreturn_data.size() > 23) {
        return Err(ParseError::SuperfluousPushes(23, opreturn_data.size()));
    }
    auto token_id = ParseTokenId(opreturn_data[3]);
    if (!token_id) {
        return Err(token_id.error());
    }
    auto atoms_vec =
        ParseQuantities(opreturn_data, ADDITIONAL_QUANTITY_FIELD_NAMES);
    if (!atoms_vec) {
        return Err(atoms_vec.error());
    }
    ParsedMintData mint;
    mint.atoms_vec = std::move(atoms_vec.value());
    mint.num_batons = 0;
    return ParsedData{
        TokenMeta{token_id.value(),
                  TokenType::Slp(SlpTokenType::MintVault())},
        ParsedTxType::MakeMint(std::move(mint))};
}

Result<ParsedData, ParseError>
ParseSendData(SlpTokenType token_type, std::vector<Bytes> opreturn_data) {
    if (opreturn_data.size() < 5) {
        return Err(ParseError::TooFewPushes(5, opreturn_data.size()));
    }
    if (opreturn_data.size() > 23) {
        return Err(ParseError::SuperfluousPushes(23, opreturn_data.size()));
    }
    auto token_id = ParseTokenId(opreturn_data[3]);
    if (!token_id) {
        return Err(token_id.error());
    }
    auto atoms_vec =
        ParseQuantities(opreturn_data, TOKEN_OUTPUT_QUANTITY_FIELD_NAMES);
    if (!atoms_vec) {
        return Err(atoms_vec.error());
    }
    return ParsedData{
        TokenMeta{token_id.value(), TokenType::Slp(token_type)},
        ParsedTxType::MakeSend(std::move(atoms_vec.value()))};
}

Result<ParsedData, ParseError>
ParseBurnData(SlpTokenType token_type, std::vector<Bytes> opreturn_data) {
    if (opreturn_data.size() != 5) {
        return Err(ParseError::UnexpectedNumPushes(5, opreturn_data.size()));
    }
    auto token_id = ParseTokenId(opreturn_data[3]);
    if (!token_id) {
        return Err(token_id.error());
    }
    auto burn = ParseAtoms(opreturn_data[4], "token_burn_quantity");
    if (!burn) {
        return Err(burn.error());
    }
    return ParsedData{
        TokenMeta{token_id.value(), TokenType::Slp(token_type)},
        ParsedTxType::MakeBurn(burn.value())};
}

bool ShouldIgnoreErr(const ParseError &err) {
    return err.kind == K::EmptyScript || err.kind == K::MissingOpReturn ||
           err.kind == K::MissingLokadId ||
           err.kind == K::InvalidLokadIdOpcode || err.kind == K::WrongLokadId;
}

} // namespace

const char *const ADDITIONAL_QUANTITY_FIELD_NAMES[19] = {
    "additional_quantity1",  "additional_quantity2",  "additional_quantity3",
    "additional_quantity4",  "additional_quantity5",  "additional_quantity6",
    "additional_quantity7",  "additional_quantity8",  "additional_quantity9",
    "additional_quantity10", "additional_quantity11", "additional_quantity12",
    "additional_quantity13", "additional_quantity14", "additional_quantity15",
    "additional_quantity16", "additional_quantity17", "additional_quantity18",
    "additional_quantity19",
};

const char *const TOKEN_OUTPUT_QUANTITY_FIELD_NAMES[19] = {
    "token_output_quantity1",  "token_output_quantity2",
    "token_output_quantity3",  "token_output_quantity4",
    "token_output_quantity5",  "token_output_quantity6",
    "token_output_quantity7",  "token_output_quantity8",
    "token_output_quantity9",  "token_output_quantity10",
    "token_output_quantity11", "token_output_quantity12",
    "token_output_quantity13", "token_output_quantity14",
    "token_output_quantity15", "token_output_quantity16",
    "token_output_quantity17", "token_output_quantity18",
    "token_output_quantity19",
};

Result<ParsedData, ParseError> ParseWithIgnoredErr(const TxId &txid,
                                                   ByteView script) {
    if (auto err = ParseLokadId(script)) {
        return Err(std::move(*err));
    }
    std::vector<Op> ops;
    script::ScriptOpIter iter(script);
    while (auto op = iter.Next()) {
        if (!op->ok()) {
            return Err(ParseError::FromDataError(op->error()));
        }
        ops.push_back(std::move(op->value()));
    }
    auto opreturn_data_result = ParseOpreturnOps(std::move(ops));
    if (!opreturn_data_result) {
        return Err(opreturn_data_result.error());
    }
    std::vector<Bytes> &opreturn_data = opreturn_data_result.value();
    if (opreturn_data.size() < 3) {
        return Err(ParseError::TooFewPushes(3, opreturn_data.size()));
    }
    if (opreturn_data[1].size() != 1) {
        return Err(ParseError::InvalidTokenType(opreturn_data[1]));
    }
    const SlpTokenType token_type = ParseTokenType(opreturn_data[1]);
    if (token_type.kind == SlpTokenType::Kind::Unknown) {
        return ParsedData{TokenMeta{TokenId{}, TokenType::Slp(token_type)},
                          ParsedTxType::MakeUnknown()};
    }
    const Bytes &tx_type = opreturn_data[2];
    if (tx_type == GENESIS) {
        return ParseGenesisData(txid, token_type, std::move(opreturn_data));
    }
    if (tx_type == MINT && token_type == SlpTokenType::MintVault()) {
        return ParseMintDataMintVault(std::move(opreturn_data));
    }
    if (tx_type == MINT) {
        return ParseMintDataBaton(token_type, std::move(opreturn_data));
    }
    if (tx_type == SEND) {
        return ParseSendData(token_type, std::move(opreturn_data));
    }
    if (tx_type == BURN) {
        return ParseBurnData(token_type, std::move(opreturn_data));
    }
    return Err(ParseError::InvalidTxType(tx_type));
}

Result<std::optional<ParsedData>, ParseError> Parse(const TxId &txid,
                                                    ByteView script) {
    auto result = ParseWithIgnoredErr(txid, script);
    if (result.ok()) {
        return std::optional<ParsedData>(std::move(result.value()));
    }
    if (ShouldIgnoreErr(result.error())) {
        return std::optional<ParsedData>();
    }
    return Err(result.error());
}

Result<std::optional<ParsedData>, ParseError> ParseTx(const Tx &tx) {
    if (tx.outputs.empty()) {
        return std::optional<ParsedData>();
    }
    return Parse(tx.txid, tx.outputs[0].script);
}

// ---- Builders ----

namespace {

ByteView TokenTypeBytes(SlpTokenType token_type, uint8_t &storage) {
    if (token_type.kind == SlpTokenType::Kind::Unknown) {
        throw std::logic_error("Cannot use 'Unknown' token type here");
    }
    storage = token_type.ToU8();
    return ByteView(&storage, 1);
}

void PutBe64(script::ScriptMut &script, uint64_t v) {
    uint8_t be[8];
    for (int i = 0; i < 8; ++i) {
        be[i] = uint8_t(v >> (56 - 8 * i));
    }
    script.PutSlpPushdata(ByteView(be, 8));
}

script::ScriptMut Header(SlpTokenType token_type, const Bytes &tx_type) {
    script::ScriptMut script;
    script.PutOpcodes({script::OP_RETURN});
    script.PutSlpPushdata(slp_consts::SLP_LOKAD_ID);
    uint8_t storage;
    script.PutSlpPushdata(TokenTypeBytes(token_type, storage));
    script.PutSlpPushdata(tx_type);
    return script;
}

} // namespace

script::Script GenesisOpreturn(const GenesisInfo &genesis_info,
                               SlpTokenType token_type,
                               std::optional<uint8_t> mint_baton_out_idx,
                               Atoms initial_quantity) {
    auto script = Header(token_type, GENESIS);
    script.PutSlpPushdata(genesis_info.token_ticker);
    script.PutSlpPushdata(genesis_info.token_name);
    script.PutSlpPushdata(genesis_info.url);
    if (genesis_info.hash) {
        script.PutSlpPushdata(*genesis_info.hash);
    } else {
        script.PutSlpPushdata({});
    }
    script.PutSlpPushdata(ByteView(&genesis_info.decimals, 1));
    if (token_type == SlpTokenType::MintVault()) {
        if (genesis_info.mint_vault_scripthash) {
            script.PutSlpPushdata(*genesis_info.mint_vault_scripthash);
        } else {
            script.PutSlpPushdata({});
        }
    } else if (mint_baton_out_idx) {
        script.PutSlpPushdata(ByteView(&*mint_baton_out_idx, 1));
    } else {
        script.PutSlpPushdata({});
    }
    PutBe64(script, initial_quantity);
    return script.Freeze();
}

script::Script MintOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            std::optional<uint8_t> mint_baton_out_idx,
                            Atoms additional_quantity) {
    auto script = Header(token_type, MINT);
    script.PutSlpPushdata(token_id.ToBeBytes());
    if (mint_baton_out_idx) {
        script.PutSlpPushdata(ByteView(&*mint_baton_out_idx, 1));
    } else {
        script.PutSlpPushdata({});
    }
    PutBe64(script, additional_quantity);
    return script.Freeze();
}

script::Script MintVaultOpreturn(const TokenId &token_id,
                                 const std::vector<Atoms> &quantities) {
    auto script = Header(SlpTokenType::MintVault(), MINT);
    script.PutSlpPushdata(token_id.ToBeBytes());
    for (Atoms q : quantities) {
        PutBe64(script, q);
    }
    return script.Freeze();
}

script::Script SendOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            const std::vector<Atoms> &send_atoms) {
    auto script = Header(token_type, SEND);
    script.PutSlpPushdata(token_id.ToBeBytes());
    for (Atoms a : send_atoms) {
        PutBe64(script, a);
    }
    return script.Freeze();
}

script::Script BurnOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            Atoms burn_atoms) {
    auto script = Header(token_type, BURN);
    script.PutSlpPushdata(token_id.ToBeBytes());
    PutBe64(script, burn_atoms);
    return script.Freeze();
}

} // namespace chronik::native::token::slp
