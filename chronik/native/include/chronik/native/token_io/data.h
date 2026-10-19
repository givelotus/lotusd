// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_IO_DATA_H
#define CHRONIK_NATIVE_TOKEN_IO_DATA_H

#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/index/data.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/types.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Port of chronik-db io/token/data.rs ([`DbTokenTx`], [`DbToken`]) plus the
 * postcard (serde) encodings of the values stored in the token tables:
 *  - `token_tx`:           TxNum BE8 -> DbTokenTx
 *  - `token_meta`:         TxNum BE8 (of GENESIS) -> TokenMeta
 *  - `token_genesis_info`: TxNum BE8 (of GENESIS) -> GenesisInfo
 */
namespace chronik::native::token_io {

using index::TxNum;

/**
 * Bit flag of whether the token tx has the required SLP V2 mint vault script
 * in the list of inputs.
 */
inline constexpr uint8_t FLAGS_HAS_MINT_VAULT = 1;

/**
 * u32 index into `token_tx_nums` to know which `token_tx_num` the
 * input/output has.
 */
using TokenIdx = uint32_t;

/** Token from the DB (Rust `DbToken`; postcard enum, variants in order). */
struct DbToken {
    enum class Kind : uint8_t {
        /** No token value */
        NoToken,
        /** Token amount in atoms (base tokens) */
        Atoms,
        /** Mint baton */
        MintBaton,
        /** Unknown SLP token */
        UnknownSlp,
        /** Unknown ALP token */
        UnknownAlp,
    };
    Kind kind = Kind::NoToken;
    /** Atoms, MintBaton */
    TokenIdx idx{};
    /** Atoms */
    token::Atoms atoms{};
    /** UnknownSlp, UnknownAlp */
    uint8_t token_type{};

    static DbToken NoToken() { return {}; }
    static DbToken MakeAtoms(TokenIdx idx, token::Atoms atoms) {
        return {Kind::Atoms, idx, atoms, 0};
    }
    static DbToken MintBaton(TokenIdx idx) {
        return {Kind::MintBaton, idx, 0, 0};
    }
    static DbToken UnknownSlp(uint8_t token_type) {
        return {Kind::UnknownSlp, 0, 0, token_type};
    }
    static DbToken UnknownAlp(uint8_t token_type) {
        return {Kind::UnknownAlp, 0, 0, token_type};
    }

    /** Create a new [`DbToken`] but with a different index. */
    DbToken WithIdx(TokenIdx new_idx) const;
    /**
     * Return the idx of the token_tx_num the token it pointing to, or None if
     * it's not pointing to any token_tx_num.
     */
    std::optional<TokenIdx> TokenNumIdx() const;
    /** Rust Debug, e.g. "Atoms(0, 1000)", "NoToken" */
    std::string Debug() const;

    bool operator==(const DbToken &) const = default;
};

/**
 * Token tx stored in the DB with only the data that cannot be reconstructed
 * from the tx easily (Rust `DbTokenTx`).
 */
struct DbTokenTx {
    /**
     * All token nums used in the tx, including inputs, outputs,
     * group_token_id. This is not ordered in any canonical way.
     */
    std::vector<TxNum> token_tx_nums;
    /**
     * Which items in token_nums have which token_num as their group (for
     * group_token_id). Maps indices: `token_num_idx -> group_token_num_idx`
     */
    std::map<TokenIdx, TokenIdx> group_token_indices;
    /** Inputs of the tx, reflecting the tx inputs 1-to-1 */
    std::vector<DbToken> inputs;
    /** Outputs of the tx, reflecting the tx outputs 1-to-1 */
    std::vector<DbToken> outputs;
    /** Bit flags of the tx, e.g. whether the mint vault input is present */
    uint8_t flags{};

    /** Return the token [`TxNum`] of the given [`DbToken`]. */
    std::optional<TxNum> TokenTxNum(const DbToken &db_token) const;

    /**
     * Return the [`TxNum`] of the group token of the given [`DbToken`].
     * These are set for NFT1 CHILD tokens.
     */
    std::optional<TxNum> GroupTokenTxNum(const DbToken &db_token) const;

    /**
     * Build a [`SpentToken`] from a [`DbToken`], using a provided function to
     * lookup [`TokenMeta`] by [`TxNum`]. `fn_meta` throws on failure (Rust's
     * `?`). Indexing out of `token_tx_nums` throws (Rust panics).
     */
    template <typename FnMeta>
    std::optional<token::SpentToken> SpentToken(const DbToken &db_token,
                                                FnMeta &&fn_meta) const;

    /**
     * Whether the token tx has the required SLP V2 mint vault script in the
     * list of inputs.
     */
    bool HasMintVault() const { return (flags & FLAGS_HAS_MINT_VAULT) != 0; }

    bool operator==(const DbTokenTx &) const = default;
};

/** std::any::type_name of the stored types (for SerError texts). */
inline constexpr std::string_view kDbTokenTxTypeName =
    "chronik_db::io::token::data::DbTokenTx";
inline constexpr std::string_view kTokenMetaTypeName =
    "bitcoinsuite_slp::structs::TokenMeta";
inline constexpr std::string_view kGenesisInfoTypeName =
    "bitcoinsuite_slp::structs::GenesisInfo";

// postcard encoders/decoders of the serde-derived Rust types
void WriteDbToken(postcard::Writer &w, const DbToken &token);
DbToken ReadDbToken(postcard::Reader &r);
void WriteTokenType(postcard::Writer &w, const token::TokenType &token_type);
token::TokenType ReadTokenType(postcard::Reader &r);
void WriteTokenMeta(postcard::Writer &w, const token::TokenMeta &meta);
token::TokenMeta ReadTokenMeta(postcard::Reader &r);
void WriteGenesisInfo(postcard::Writer &w, const token::GenesisInfo &info);
token::GenesisInfo ReadGenesisInfo(postcard::Reader &r);
void WriteDbTokenTx(postcard::Writer &w, const DbTokenTx &tx);
DbTokenTx ReadDbTokenTx(postcard::Reader &r);

/** db_serialize / db_deserialize of the table values. */
Bytes SerializeDbTokenTx(const DbTokenTx &tx);
DbTokenTx DeserializeDbTokenTx(ByteView bytes);
Bytes SerializeTokenMeta(const token::TokenMeta &meta);
token::TokenMeta DeserializeTokenMeta(ByteView bytes);
Bytes SerializeGenesisInfo(const token::GenesisInfo &info);
token::GenesisInfo DeserializeGenesisInfo(ByteView bytes);

// ---- template implementation ----

template <typename FnMeta>
std::optional<token::SpentToken>
DbTokenTx::SpentToken(const DbToken &db_token, FnMeta &&fn_meta) const {
    using namespace token;
    TokenIdx token_num_idx{};
    TokenVariant variant;
    switch (db_token.kind) {
    case DbToken::Kind::NoToken:
        return std::nullopt;
    case DbToken::Kind::Atoms:
        token_num_idx = db_token.idx;
        variant = TokenVariant::MakeAtoms(db_token.atoms);
        break;
    case DbToken::Kind::MintBaton:
        token_num_idx = db_token.idx;
        variant = TokenVariant::MintBaton();
        break;
    case DbToken::Kind::UnknownSlp:
    case DbToken::Kind::UnknownAlp: {
        const TokenType token_type =
            db_token.kind == DbToken::Kind::UnknownSlp
                ? TokenType::Slp(SlpTokenType::Unknown(db_token.token_type))
                : TokenType::Alp(AlpTokenType::Unknown(db_token.token_type));
        return token::SpentToken{
            Token{TokenMeta{TokenId{}, token_type},
                  TokenVariant::Unknown(db_token.token_type)},
            std::nullopt};
    }
    }
    std::optional<TxNum> group_token_tx_num;
    if (const auto it = group_token_indices.find(token_num_idx);
        it != group_token_indices.end()) {
        group_token_tx_num = token_tx_nums.at(it->second);
    }
    token::SpentToken spent{Token{fn_meta(token_tx_nums.at(token_num_idx)),
                                  variant},
                            std::nullopt};
    if (group_token_tx_num) {
        spent.group_token_meta = fn_meta(*group_token_tx_num);
    }
    return spent;
}

} // namespace chronik::native::token_io

#endif // CHRONIK_NATIVE_TOKEN_IO_DATA_H
