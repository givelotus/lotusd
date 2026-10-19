// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/parse.h>

#include <algorithm>

namespace chronik::native::token::alp {

using K = ParseError::Kind;

ParseError ParseError::FromDataError(script::DataError err) {
    ParseError e;
    e.kind = K::DataError;
    e.data_error = std::move(err);
    return e;
}
ParseError ParseError::NotEnoughBytes(std::string field_name, size_t expected,
                                      size_t actual) {
    ParseError e;
    e.kind = K::NotEnoughBytes;
    e.field_name = std::move(field_name);
    e.expected = expected;
    e.actual = actual;
    return e;
}
ParseError ParseError::SizeOutOfRange(std::string field_name, uint8_t size) {
    ParseError e;
    e.kind = K::SizeOutOfRange;
    e.field_name = std::move(field_name);
    e.byte = size;
    return e;
}
ParseError ParseError::MissingLokadId(Bytes bytes) {
    ParseError e;
    e.kind = K::MissingLokadId;
    e.bytes = std::move(bytes);
    return e;
}
ParseError ParseError::InvalidLokadId(LokadId lokad_id) {
    ParseError e;
    e.kind = K::InvalidLokadId;
    e.lokad_id = lokad_id;
    return e;
}
ParseError ParseError::InvalidSlpLokadId() {
    ParseError e;
    e.kind = K::InvalidSlpLokadId;
    return e;
}
ParseError ParseError::UnknownTxType(Bytes bytes) {
    ParseError e;
    e.kind = K::UnknownTxType;
    e.bytes = std::move(bytes);
    return e;
}
ParseError ParseError::DecimalsOutOfRange(uint8_t decimals) {
    ParseError e;
    e.kind = K::DecimalsOutOfRange;
    e.byte = decimals;
    return e;
}
ParseError ParseError::LeftoverBytes(Bytes bytes) {
    ParseError e;
    e.kind = K::LeftoverBytes;
    e.bytes = std::move(bytes);
    return e;
}

std::string ParseError::ToString() const {
    switch (kind) {
        case K::DataError:
            return "Failed parsing pushdata: " + data_error.ToString();
        case K::NotEnoughBytes:
            return "Not enough bytes: expected " + std::to_string(expected) +
                   " more bytes but got " + std::to_string(actual) +
                   " for field " + field_name;
        case K::SizeOutOfRange:
            return "Size out of range: " + std::to_string(byte) +
                   ", must be 0-127 for field " + field_name;
        case K::MissingLokadId:
            return "Missing LOKAD ID: " + script::DebugBytes(bytes);
        case K::InvalidLokadId: {
            std::vector<size_t> nums(lokad_id.begin(), lokad_id.end());
            return "Invalid LOKAD ID: " + script::DebugSizes(nums);
        }
        case K::InvalidSlpLokadId:
            return "Invalid LOKAD ID \"SLP\\0\", did you accidentally use "
                   "eMPP?";
        case K::UnknownTxType:
            return "Unknown tx type: " + script::DebugBytes(bytes);
        case K::DecimalsOutOfRange:
            return "Decimals out of range: " + std::to_string(byte) +
                   ", must be 0-9";
        case K::LeftoverBytes:
            return "Leftover bytes: " + script::DebugBytes(bytes);
    }
    return {};
}

namespace {

/** Cursor over the remaining section bytes (Rust's `&mut Bytes`). */
struct Reader {
    ByteView data;
};

template <typename T> using R = Result<T, ParseError>;

/** ParsedNamed::named: give the field name to length/size errors. */
template <typename T> R<T> Named(R<T> result, const char *field_name) {
    if (result.ok()) {
        return result;
    }
    const ParseError &err = result.error();
    if (err.kind == K::DataError &&
        err.data_error.kind == script::DataError::Kind::InvalidLength) {
        return Err(ParseError::NotEnoughBytes(
            field_name, err.data_error.expected, err.data_error.actual));
    }
    if (err.kind == K::SizeOutOfRange) {
        return Err(ParseError::SizeOutOfRange(field_name, err.byte));
    }
    return result;
}

R<Bytes> ReadBytes(Reader &r, size_t n) {
    if (r.data.size() < n) {
        return Err(ParseError::FromDataError(
            script::DataError::InvalidLength(n, r.data.size())));
    }
    Bytes out(r.data.begin(), r.data.begin() + n);
    r.data = r.data.subspan(n);
    return out;
}

R<uint8_t> ReadByte(Reader &r) {
    auto b = ReadBytes(r, 1);
    if (!b) {
        return Err(b.error());
    }
    return b.value()[0];
}

R<size_t> ReadSize(Reader &r) {
    auto size = ReadByte(r);
    if (!size) {
        return Err(size.error());
    }
    if (size.value() > 127) {
        return Err(ParseError::SizeOutOfRange("", size.value()));
    }
    return size_t(size.value());
}

R<Atoms> ReadAtoms(Reader &r) {
    auto bytes = ReadBytes(r, 6);
    if (!bytes) {
        return Err(bytes.error());
    }
    Atoms atoms = 0;
    for (int i = 5; i >= 0; --i) {
        atoms = (atoms << 8) | bytes.value()[i];
    }
    return atoms;
}

R<std::vector<Atoms>> ReadAtomsVec(Reader &r) {
    auto size = ReadSize(r);
    if (!size) {
        return Err(size.error());
    }
    std::vector<Atoms> amounts;
    amounts.reserve(size.value());
    for (size_t i = 0; i < size.value(); ++i) {
        auto atoms = ReadAtoms(r);
        if (!atoms) {
            return Err(atoms.error());
        }
        amounts.push_back(atoms.value());
    }
    return amounts;
}

R<Bytes> ReadVarBytes(Reader &r) {
    auto size = ReadSize(r);
    if (!size) {
        return Err(size.error());
    }
    return ReadBytes(r, size.value());
}

R<TokenId> ReadTokenId(Reader &r) {
    auto bytes = Named(ReadBytes(r, 32), "token_id");
    if (!bytes) {
        return Err(bytes.error());
    }
    return TokenId{Hash32::FromBytes(bytes.value())};
}

R<ParsedMintData> ParseMintData(Reader &r) {
    auto atoms_vec = Named(ReadAtomsVec(r), "mint_amount");
    if (!atoms_vec) {
        return Err(atoms_vec.error());
    }
    auto num_batons = Named(ReadSize(r), "num_batons");
    if (!num_batons) {
        return Err(num_batons.error());
    }
    return ParsedMintData{std::move(atoms_vec.value()), num_batons.value()};
}

#define TRY_ASSIGN(var, expr)                                                  \
    auto var##_result = (expr);                                                \
    if (!var##_result) {                                                       \
        return Err(var##_result.error());                                      \
    }                                                                          \
    auto var = std::move(var##_result.value())

R<ParsedData> ParseGenesis(const TxId &txid, AlpTokenType token_type,
                           Reader &r) {
    TRY_ASSIGN(token_ticker, Named(ReadVarBytes(r), "token_ticker"));
    TRY_ASSIGN(token_name, Named(ReadVarBytes(r), "token_name"));
    TRY_ASSIGN(url, Named(ReadVarBytes(r), "url"));
    TRY_ASSIGN(data, Named(ReadVarBytes(r), "data"));
    TRY_ASSIGN(auth_pubkey, Named(ReadVarBytes(r), "auth_pubkey"));
    TRY_ASSIGN(decimals, Named(ReadByte(r), "decimals"));
    TRY_ASSIGN(mint_data, ParseMintData(r));
    if (decimals > 9) {
        return Err(ParseError::DecimalsOutOfRange(decimals));
    }
    ParsedGenesis genesis;
    genesis.info.token_ticker = std::move(token_ticker);
    genesis.info.token_name = std::move(token_name);
    genesis.info.url = std::move(url);
    genesis.info.data = std::move(data);
    genesis.info.auth_pubkey = std::move(auth_pubkey);
    genesis.info.decimals = decimals;
    genesis.mint_data = std::move(mint_data);
    return ParsedData{TokenMeta{TokenId{txid}, TokenType::Alp(token_type)},
                      ParsedTxType::MakeGenesis(std::move(genesis))};
}

R<ParsedData> ParseMint(AlpTokenType token_type, Reader &r) {
    TRY_ASSIGN(token_id, ReadTokenId(r));
    TRY_ASSIGN(mint_data, ParseMintData(r));
    return ParsedData{TokenMeta{token_id, TokenType::Alp(token_type)},
                      ParsedTxType::MakeMint(std::move(mint_data))};
}

R<ParsedData> ParseSend(AlpTokenType token_type, Reader &r) {
    TRY_ASSIGN(token_id, ReadTokenId(r));
    TRY_ASSIGN(amounts, Named(ReadAtomsVec(r), "send_amount"));
    return ParsedData{TokenMeta{token_id, TokenType::Alp(token_type)},
                      ParsedTxType::MakeSend(std::move(amounts))};
}

R<ParsedData> ParseBurn(AlpTokenType token_type, Reader &r) {
    TRY_ASSIGN(token_id, ReadTokenId(r));
    TRY_ASSIGN(amount, Named(ReadAtoms(r), "burn_amount"));
    return ParsedData{TokenMeta{token_id, TokenType::Alp(token_type)},
                      ParsedTxType::MakeBurn(amount)};
}

} // namespace

Result<ParsedData, ParseError> ParseSectionWithIgnoredErr(const TxId &txid,
                                                          Bytes pushdata) {
    if (pushdata.size() < 4) {
        return Err(ParseError::MissingLokadId(std::move(pushdata)));
    }
    Reader r{pushdata};
    LokadId lokad_id;
    std::copy(pushdata.begin(), pushdata.begin() + 4, lokad_id.begin());
    r.data = r.data.subspan(4);
    if (lokad_id == slp_consts::SLP_LOKAD_ID) {
        return Err(ParseError::InvalidSlpLokadId());
    }
    if (lokad_id != alp_consts::ALP_LOKAD_ID) {
        return Err(ParseError::InvalidLokadId(lokad_id));
    }
    TRY_ASSIGN(token_type_byte, Named(ReadByte(r), "token_type"));
    const AlpTokenType token_type =
        token_type_byte == alp_consts::STANDARD_TOKEN_TYPE
            ? AlpTokenType::Standard()
            : AlpTokenType::Unknown(token_type_byte);
    if (token_type.kind == AlpTokenType::Kind::Unknown) {
        return ParsedData{TokenMeta{TokenId{}, TokenType::Alp(token_type)},
                          ParsedTxType::MakeUnknown()};
    }
    TRY_ASSIGN(tx_type, Named(ReadVarBytes(r), "tx_type"));
    R<ParsedData> parsed = Err(ParseError{});
    if (tx_type == GENESIS) {
        parsed = ParseGenesis(txid, token_type, r);
    } else if (tx_type == MINT) {
        parsed = ParseMint(token_type, r);
    } else if (tx_type == SEND) {
        parsed = ParseSend(token_type, r);
    } else if (tx_type == BURN) {
        parsed = ParseBurn(token_type, r);
    } else {
        return Err(ParseError::UnknownTxType(std::move(tx_type)));
    }
    if (!parsed) {
        return parsed;
    }
    if (!r.data.empty()) {
        return Err(ParseError::LeftoverBytes(Bytes(r.data.begin(),
                                                   r.data.end())));
    }
    return parsed;
}

#undef TRY_ASSIGN

Result<std::optional<ParsedData>, ParseError> ParseSection(const TxId &txid,
                                                           Bytes pushdata) {
    auto result = ParseSectionWithIgnoredErr(txid, std::move(pushdata));
    if (result.ok()) {
        return std::optional<ParsedData>(std::move(result.value()));
    }
    if (result.error().kind == K::MissingLokadId ||
        result.error().kind == K::InvalidLokadId) {
        return std::optional<ParsedData>();
    }
    return Err(result.error());
}

// ---- Builders ----

namespace {

void PutAtoms(Bytes &section, Atoms atoms) {
    for (int i = 0; i < 6; ++i) {
        section.push_back(uint8_t(atoms >> (8 * i)));
    }
}

void PutMintData(Bytes &section, const ParsedMintData &mint_data) {
    section.push_back(uint8_t(mint_data.atoms_vec.size()));
    for (Atoms atoms : mint_data.atoms_vec) {
        PutAtoms(section, atoms);
    }
    section.push_back(uint8_t(mint_data.num_batons));
}

void PutVarBytes(Bytes &section, ByteView bytes) {
    section.push_back(uint8_t(bytes.size()));
    section.insert(section.end(), bytes.begin(), bytes.end());
}

Bytes SectionHeader(AlpTokenType token_type, const Bytes &tx_type) {
    Bytes section(alp_consts::ALP_LOKAD_ID.begin(),
                  alp_consts::ALP_LOKAD_ID.end());
    section.push_back(token_type.ToU8());
    PutVarBytes(section, tx_type);
    return section;
}

} // namespace

script::Script SectionsOpreturn(const std::vector<Bytes> &sections) {
    script::ScriptMut script;
    script.PutOpcodes({script::OP_RETURN, script::OP_RESERVED});
    for (const Bytes &section : sections) {
        script.PutPushdata(section);
    }
    return script.Freeze();
}

Bytes GenesisSection(AlpTokenType token_type, const GenesisInfo &genesis_info,
                     const ParsedMintData &mint_data) {
    Bytes section = SectionHeader(token_type, GENESIS);
    PutVarBytes(section, genesis_info.token_ticker);
    PutVarBytes(section, genesis_info.token_name);
    PutVarBytes(section, genesis_info.url);
    PutVarBytes(section, genesis_info.data ? *genesis_info.data : Bytes{});
    PutVarBytes(section,
                genesis_info.auth_pubkey ? *genesis_info.auth_pubkey : Bytes{});
    section.push_back(genesis_info.decimals);
    PutMintData(section, mint_data);
    return section;
}

Bytes MintSection(const TokenId &token_id, AlpTokenType token_type,
                  const ParsedMintData &mint_data) {
    Bytes section = SectionHeader(token_type, MINT);
    section.insert(section.end(), token_id.txid.b.begin(),
                   token_id.txid.b.end());
    PutMintData(section, mint_data);
    return section;
}

Bytes BurnSection(const TokenId &token_id, AlpTokenType token_type,
                  Atoms atoms) {
    Bytes section = SectionHeader(token_type, BURN);
    section.insert(section.end(), token_id.txid.b.begin(),
                   token_id.txid.b.end());
    PutAtoms(section, atoms);
    return section;
}

Bytes SendSection(const TokenId &token_id, AlpTokenType token_type,
                  const std::vector<Atoms> &send_amounts) {
    Bytes section = SectionHeader(token_type, SEND);
    section.insert(section.end(), token_id.txid.b.begin(),
                   token_id.txid.b.end());
    section.push_back(uint8_t(send_amounts.size()));
    for (Atoms atoms : send_amounts) {
        PutAtoms(section, atoms);
    }
    return section;
}

} // namespace chronik::native::token::alp
