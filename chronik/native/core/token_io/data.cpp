// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token_io/data.h>

namespace chronik::native::token_io {

using namespace token;

DbToken DbToken::WithIdx(TokenIdx new_idx) const {
    switch (kind) {
    case Kind::Atoms:
        return MakeAtoms(new_idx, atoms);
    case Kind::MintBaton:
        return MintBaton(new_idx);
    default:
        return *this;
    }
}

std::optional<TokenIdx> DbToken::TokenNumIdx() const {
    switch (kind) {
    case Kind::Atoms:
    case Kind::MintBaton:
        return idx;
    default:
        return std::nullopt;
    }
}

std::string DbToken::Debug() const {
    switch (kind) {
    case Kind::NoToken:
        return "NoToken";
    case Kind::Atoms:
        return "Atoms(" + std::to_string(idx) + ", " + std::to_string(atoms) +
               ")";
    case Kind::MintBaton:
        return "MintBaton(" + std::to_string(idx) + ")";
    case Kind::UnknownSlp:
        return "UnknownSlp(" + std::to_string(token_type) + ")";
    case Kind::UnknownAlp:
        return "UnknownAlp(" + std::to_string(token_type) + ")";
    }
    return "";
}

std::optional<TxNum> DbTokenTx::TokenTxNum(const DbToken &db_token) const {
    const auto idx = db_token.TokenNumIdx();
    if (!idx || *idx >= token_tx_nums.size()) {
        return std::nullopt;
    }
    return token_tx_nums[*idx];
}

std::optional<TxNum>
DbTokenTx::GroupTokenTxNum(const DbToken &db_token) const {
    const auto idx = db_token.TokenNumIdx();
    if (!idx) {
        return std::nullopt;
    }
    const auto it = group_token_indices.find(*idx);
    if (it == group_token_indices.end() ||
        it->second >= token_tx_nums.size()) {
        return std::nullopt;
    }
    return token_tx_nums[it->second];
}

// ---- postcard ----

namespace {

[[noreturn]] void ThrowUnknownVariant() {
    throw postcard::Error(std::string(postcard::kSerdeDeCustom));
}

template <size_t N>
void WriteArray(postcard::Writer &w, const std::array<uint8_t, N> &a) {
    w.Raw(ByteView(a.data(), a.size()));
}

} // namespace

void WriteDbToken(postcard::Writer &w, const DbToken &token) {
    w.EnumIndex(uint32_t(token.kind));
    switch (token.kind) {
    case DbToken::Kind::NoToken:
        break;
    case DbToken::Kind::Atoms:
        w.U32(token.idx);
        w.U64(token.atoms);
        break;
    case DbToken::Kind::MintBaton:
        w.U32(token.idx);
        break;
    case DbToken::Kind::UnknownSlp:
    case DbToken::Kind::UnknownAlp:
        w.U8(token.token_type);
        break;
    }
}

DbToken ReadDbToken(postcard::Reader &r) {
    switch (r.EnumIndex()) {
    case 0:
        return DbToken::NoToken();
    case 1: {
        const TokenIdx idx = r.U32();
        const Atoms atoms = r.U64();
        return DbToken::MakeAtoms(idx, atoms);
    }
    case 2:
        return DbToken::MintBaton(r.U32());
    case 3:
        return DbToken::UnknownSlp(r.U8());
    case 4:
        return DbToken::UnknownAlp(r.U8());
    default:
        ThrowUnknownVariant();
    }
}

void WriteTokenType(postcard::Writer &w, const TokenType &token_type) {
    if (token_type.IsSlp()) {
        w.EnumIndex(0);
        w.EnumIndex(uint32_t(token_type.slp.kind));
        if (token_type.slp.kind == SlpTokenType::Kind::Unknown) {
            w.U8(token_type.slp.unknown);
        }
    } else {
        w.EnumIndex(1);
        w.EnumIndex(uint32_t(token_type.alp.kind));
        if (token_type.alp.kind == AlpTokenType::Kind::Unknown) {
            w.U8(token_type.alp.unknown);
        }
    }
}

TokenType ReadTokenType(postcard::Reader &r) {
    switch (r.EnumIndex()) {
    case 0: {
        switch (r.EnumIndex()) {
        case 0:
            return TokenType::Slp(SlpTokenType::Fungible());
        case 1:
            return TokenType::Slp(SlpTokenType::MintVault());
        case 2:
            return TokenType::Slp(SlpTokenType::Nft1Group());
        case 3:
            return TokenType::Slp(SlpTokenType::Nft1Child());
        case 4:
            return TokenType::Slp(SlpTokenType::Unknown(r.U8()));
        default:
            ThrowUnknownVariant();
        }
    }
    case 1: {
        switch (r.EnumIndex()) {
        case 0:
            return TokenType::Alp(AlpTokenType::Standard());
        case 1:
            return TokenType::Alp(AlpTokenType::Unknown(r.U8()));
        default:
            ThrowUnknownVariant();
        }
    }
    default:
        ThrowUnknownVariant();
    }
}

void WriteTokenMeta(postcard::Writer &w, const TokenMeta &meta) {
    // TokenId(TxId(Sha256d([u8; 32]))): newtypes of a byte array
    WriteArray(w, meta.token_id.txid.b);
    WriteTokenType(w, meta.token_type);
}

TokenMeta ReadTokenMeta(postcard::Reader &r) {
    TokenMeta meta;
    meta.token_id.txid.b = r.Array<32>();
    meta.token_type = ReadTokenType(r);
    return meta;
}

void WriteGenesisInfo(postcard::Writer &w, const GenesisInfo &info) {
    w.ByteVec(info.token_ticker);
    w.ByteVec(info.token_name);
    w.OptionTag(info.mint_vault_scripthash.has_value());
    if (info.mint_vault_scripthash) {
        WriteArray(w, *info.mint_vault_scripthash);
    }
    w.ByteVec(info.url);
    w.OptionTag(info.hash.has_value());
    if (info.hash) {
        WriteArray(w, *info.hash);
    }
    w.OptionTag(info.data.has_value());
    if (info.data) {
        w.ByteVec(*info.data);
    }
    w.OptionTag(info.auth_pubkey.has_value());
    if (info.auth_pubkey) {
        w.ByteVec(*info.auth_pubkey);
    }
    w.U8(info.decimals);
}

GenesisInfo ReadGenesisInfo(postcard::Reader &r) {
    GenesisInfo info;
    info.token_ticker = r.ByteVec();
    info.token_name = r.ByteVec();
    if (r.OptionTag()) {
        info.mint_vault_scripthash = r.Array<20>();
    }
    info.url = r.ByteVec();
    if (r.OptionTag()) {
        info.hash = r.Array<32>();
    }
    if (r.OptionTag()) {
        info.data = r.ByteVec();
    }
    if (r.OptionTag()) {
        info.auth_pubkey = r.ByteVec();
    }
    info.decimals = r.U8();
    return info;
}

void WriteDbTokenTx(postcard::Writer &w, const DbTokenTx &tx) {
    w.SeqLen(tx.token_tx_nums.size());
    for (const TxNum tx_num : tx.token_tx_nums) {
        w.U64(tx_num);
    }
    w.SeqLen(tx.group_token_indices.size());
    for (const auto &[idx, group_idx] : tx.group_token_indices) {
        w.U32(idx);
        w.U32(group_idx);
    }
    w.SeqLen(tx.inputs.size());
    for (const DbToken &token : tx.inputs) {
        WriteDbToken(w, token);
    }
    w.SeqLen(tx.outputs.size());
    for (const DbToken &token : tx.outputs) {
        WriteDbToken(w, token);
    }
    w.U8(tx.flags);
}

DbTokenTx ReadDbTokenTx(postcard::Reader &r) {
    DbTokenTx tx;
    const uint64_t num_token_tx_nums = r.SeqLen();
    for (uint64_t i = 0; i < num_token_tx_nums; ++i) {
        tx.token_tx_nums.push_back(r.U64());
    }
    const uint64_t num_group = r.SeqLen();
    for (uint64_t i = 0; i < num_group; ++i) {
        const TokenIdx idx = r.U32();
        const TokenIdx group_idx = r.U32();
        // serde's BTreeMap visitor: later duplicates overwrite
        tx.group_token_indices[idx] = group_idx;
    }
    const uint64_t num_inputs = r.SeqLen();
    for (uint64_t i = 0; i < num_inputs; ++i) {
        tx.inputs.push_back(ReadDbToken(r));
    }
    const uint64_t num_outputs = r.SeqLen();
    for (uint64_t i = 0; i < num_outputs; ++i) {
        tx.outputs.push_back(ReadDbToken(r));
    }
    tx.flags = r.U8();
    return tx;
}

Bytes SerializeDbTokenTx(const DbTokenTx &tx) {
    Bytes out;
    postcard::Writer w(out);
    WriteDbTokenTx(w, tx);
    return out;
}

DbTokenTx DeserializeDbTokenTx(ByteView bytes) {
    return postcard::DbDeserialize(bytes, kDbTokenTxTypeName, ReadDbTokenTx);
}

Bytes SerializeTokenMeta(const TokenMeta &meta) {
    Bytes out;
    postcard::Writer w(out);
    WriteTokenMeta(w, meta);
    return out;
}

TokenMeta DeserializeTokenMeta(ByteView bytes) {
    return postcard::DbDeserialize(bytes, kTokenMetaTypeName, ReadTokenMeta);
}

Bytes SerializeGenesisInfo(const GenesisInfo &info) {
    Bytes out;
    postcard::Writer w(out);
    WriteGenesisInfo(w, info);
    return out;
}

GenesisInfo DeserializeGenesisInfo(ByteView bytes) {
    return postcard::DbDeserialize(bytes, kGenesisInfoTypeName,
                                   ReadGenesisInfo);
}

} // namespace chronik::native::token_io
