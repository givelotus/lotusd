// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_STRUCTS_H
#define CHRONIK_NATIVE_TOKEN_STRUCTS_H

#include <chronik/native/script/script.h>
#include <chronik/native/types.h>

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

/**
 * Port of bitcoinsuite-slp: token ids/types, structs and parsed data
 * (token_id.rs, token_type.rs, structs.rs, parsed.rs, consts.rs).
 */
namespace chronik::native::token {

using Atoms = uint64_t;
using uint128 = unsigned __int128;
using LokadId = std::array<uint8_t, 4>;

/** Decimal representation of a u128 */
std::string U128ToString(uint128 v);

inline const Bytes GENESIS{'G', 'E', 'N', 'E', 'S', 'I', 'S'};
inline const Bytes MINT{'M', 'I', 'N', 'T'};
inline const Bytes SEND{'S', 'E', 'N', 'D'};
inline const Bytes BURN{'B', 'U', 'R', 'N'};

namespace slp_consts {
inline constexpr LokadId SLP_LOKAD_ID{'S', 'L', 'P', 0};
inline constexpr uint8_t TOKEN_TYPE_V1 = 1;
inline constexpr uint8_t TOKEN_TYPE_V2 = 2;
inline constexpr uint8_t TOKEN_TYPE_V1_NFT1_GROUP = 0x81;
inline constexpr uint8_t TOKEN_TYPE_V1_NFT1_CHILD = 0x41;
inline constexpr std::array<uint8_t, 4> ALL_TOKEN_TYPES{
    TOKEN_TYPE_V1, TOKEN_TYPE_V2, TOKEN_TYPE_V1_NFT1_GROUP,
    TOKEN_TYPE_V1_NFT1_CHILD};
} // namespace slp_consts

namespace alp_consts {
inline constexpr LokadId ALP_LOKAD_ID{'S', 'L', 'P', '2'};
inline constexpr uint8_t STANDARD_TOKEN_TYPE = 0;
inline constexpr size_t MAX_TX_INPUTS = 32767;
} // namespace alp_consts

/** Token ID: the txid of the GENESIS tx (internal byte order). */
struct TokenId {
    TxId txid;

    static TokenId FromBeBytes(const std::array<uint8_t, 32> &be) {
        return TokenId{Hash32::FromReversed(be)};
    }
    std::array<uint8_t, 32> ToBeBytes() const { return txid.Reversed(); }
    /** Hex in big-endian (display) order, like Rust's Display. */
    std::string ToString() const;
    auto operator<=>(const TokenId &) const = default;
    bool operator==(const TokenId &) const = default;
};

/** SLP token types; ordering follows the Rust enum (derive Ord). */
struct SlpTokenType {
    enum class Kind : uint8_t { Fungible, MintVault, Nft1Group, Nft1Child, Unknown };
    Kind kind = Kind::Fungible;
    uint8_t unknown{};

    static constexpr SlpTokenType Fungible() { return {Kind::Fungible, 0}; }
    static constexpr SlpTokenType MintVault() { return {Kind::MintVault, 0}; }
    static constexpr SlpTokenType Nft1Group() { return {Kind::Nft1Group, 0}; }
    static constexpr SlpTokenType Nft1Child() { return {Kind::Nft1Child, 0}; }
    static constexpr SlpTokenType Unknown(uint8_t t) {
        return {Kind::Unknown, t};
    }
    uint8_t ToU8() const;
    /** e.g. "FUNGIBLE (V1)" */
    std::string ToString() const;
    auto operator<=>(const SlpTokenType &) const = default;
    bool operator==(const SlpTokenType &) const = default;
};

struct AlpTokenType {
    enum class Kind : uint8_t { Standard, Unknown };
    Kind kind = Kind::Standard;
    uint8_t unknown{};

    static constexpr AlpTokenType Standard() { return {Kind::Standard, 0}; }
    static constexpr AlpTokenType Unknown(uint8_t t) {
        return {Kind::Unknown, t};
    }
    uint8_t ToU8() const;
    std::string ToString() const;
    auto operator<=>(const AlpTokenType &) const = default;
    bool operator==(const AlpTokenType &) const = default;
};

/** TokenType::Slp(..) or TokenType::Alp(..); Slp < Alp as in Rust. */
struct TokenType {
    enum class Protocol : uint8_t { Slp, Alp };
    Protocol protocol = Protocol::Slp;
    SlpTokenType slp;
    AlpTokenType alp;

    static TokenType Slp(SlpTokenType t) {
        return {Protocol::Slp, t, AlpTokenType{}};
    }
    static TokenType Alp(AlpTokenType t) {
        return {Protocol::Alp, SlpTokenType{}, t};
    }
    bool IsSlp() const { return protocol == Protocol::Slp; }
    bool IsAlp() const { return protocol == Protocol::Alp; }
    uint8_t ToU8() const { return IsSlp() ? slp.ToU8() : alp.ToU8(); }
    /** e.g. "SLP FUNGIBLE (V1)" */
    std::string ToString() const;
    auto operator<=>(const TokenType &) const = default;
    bool operator==(const TokenType &) const = default;
};

struct TokenMeta {
    TokenId token_id;
    TokenType token_type;
    auto operator<=>(const TokenMeta &) const = default;
    bool operator==(const TokenMeta &) const = default;
};

enum class TxType : uint8_t { GENESIS, MINT, SEND, BURN, UNKNOWN };

struct TokenVariant {
    enum class Kind : uint8_t { Atoms, MintBaton, Unknown };
    Kind kind = Kind::Atoms;
    Atoms atoms_value{};
    uint8_t unknown{};

    static TokenVariant MakeAtoms(Atoms a) { return {Kind::Atoms, a, 0}; }
    static TokenVariant MintBaton() { return {Kind::MintBaton, 0, 0}; }
    static TokenVariant Unknown(uint8_t t) { return {Kind::Unknown, 0, t}; }

    Atoms atoms() const { return kind == Kind::Atoms ? atoms_value : 0; }
    bool IsMintBaton() const { return kind == Kind::MintBaton; }
    bool operator==(const TokenVariant &) const = default;
};

struct TokenOutput {
    size_t token_idx{};
    TokenVariant variant;
    bool operator==(const TokenOutput &) const = default;
};

struct Token {
    TokenMeta meta;
    TokenVariant variant;
    bool operator==(const Token &) const = default;
    /** Display, e.g. "1234 of <token_id> (SLP FUNGIBLE (V1))" */
    std::string ToString() const;
};

struct GenesisInfo {
    Bytes token_ticker;
    Bytes token_name;
    std::optional<script::ShaRmd160> mint_vault_scripthash;
    Bytes url;
    std::optional<std::array<uint8_t, 32>> hash;
    std::optional<Bytes> data;
    std::optional<Bytes> auth_pubkey;
    uint8_t decimals{};

    static GenesisInfo EmptySlp() { return GenesisInfo{}; }
    static GenesisInfo EmptyAlp() {
        GenesisInfo info;
        info.data = Bytes{};
        info.auth_pubkey = Bytes{};
        return info;
    }
    bool operator==(const GenesisInfo &) const = default;
};

struct ParsedMintData {
    std::vector<Atoms> atoms_vec;
    size_t num_batons{};

    /** Output range [first, last) of the atoms */
    size_t AtomsBegin() const { return 1; }
    size_t AtomsEnd() const { return 1 + atoms_vec.size(); }
    size_t BatonsBegin() const { return 1 + atoms_vec.size(); }
    size_t BatonsEnd() const { return 1 + atoms_vec.size() + num_batons; }
    bool operator==(const ParsedMintData &) const = default;
};

struct ParsedGenesis {
    GenesisInfo info;
    ParsedMintData mint_data;
    bool operator==(const ParsedGenesis &) const = default;
};

/** ParsedTxType: Genesis / Mint / Send / Burn / Unknown */
struct ParsedTxType {
    struct Unknown {
        bool operator==(const Unknown &) const = default;
    };
    struct Send {
        std::vector<Atoms> atoms;
        bool operator==(const Send &) const = default;
    };
    struct Burn {
        Atoms atoms{};
        bool operator==(const Burn &) const = default;
    };
    std::variant<ParsedGenesis, ParsedMintData, Send, Burn, Unknown> v;

    static ParsedTxType MakeGenesis(ParsedGenesis g) { return {std::move(g)}; }
    static ParsedTxType MakeMint(ParsedMintData m) { return {std::move(m)}; }
    static ParsedTxType MakeSend(std::vector<Atoms> a) {
        return {Send{std::move(a)}};
    }
    static ParsedTxType MakeBurn(Atoms a) { return {Burn{a}}; }
    static ParsedTxType MakeUnknown() { return {Unknown{}}; }

    TxType tx_type() const;
    const ParsedGenesis *genesis() const {
        return std::get_if<ParsedGenesis>(&v);
    }
    bool operator==(const ParsedTxType &) const = default;
};

struct ParsedData {
    TokenMeta meta;
    ParsedTxType tx_type;
    bool operator==(const ParsedData &) const = default;
};

} // namespace chronik::native::token

#endif // CHRONIK_NATIVE_TOKEN_STRUCTS_H
