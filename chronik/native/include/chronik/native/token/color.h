// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_COLOR_H
#define CHRONIK_NATIVE_TOKEN_COLOR_H

#include <chronik/native/token/parse.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/types.h>

#include <optional>
#include <string>
#include <variant>
#include <vector>

/** Port of bitcoinsuite-slp color.rs */
namespace chronik::native::token {

/** Parse error of one of the protocols (color::ParseError). */
struct ColorParseError {
    std::variant<empp::ParseError, slp::ParseError, alp::ParseError> v;
    bool operator==(const ColorParseError &) const = default;
    /** "eMPP error: ...", "SLP error: ...", "ALP error: ..." */
    std::string ToString() const;
};

struct FailedParsing {
    std::optional<size_t> pushdata_idx;
    Bytes bytes;
    ColorParseError error;
    bool operator==(const FailedParsing &) const = default;
    /** "Parsing failed[ at pushdata idx N]: <error>" */
    std::string ToString() const;
};

struct ColorError {
    enum class Kind {
        TooFewOutputs,
        GenesisMustBeFirst,
        DescendingTokenType,
        DuplicateTokenId,
        DuplicateIntentionalBurnTokenId,
        OverlappingAtoms,
        OverlappingMintBaton,
    };
    Kind kind = Kind::GenesisMustBeFirst;
    size_t expected{};
    size_t actual{};
    uint8_t before{};
    uint8_t after{};
    size_t prev_section_idx{};
    size_t prev_burn_idx{};
    size_t burn_idx{};
    TokenId token_id;
    std::optional<Token> prev_token;
    size_t output_idx{};
    Atoms atoms{};

    static ColorError TooFewOutputs(size_t expected, size_t actual);
    static ColorError GenesisMustBeFirst();
    static ColorError DescendingTokenType(uint8_t before, uint8_t after);
    static ColorError DuplicateTokenId(size_t prev_section_idx,
                                       TokenId token_id);
    static ColorError DuplicateIntentionalBurnTokenId(size_t prev_burn_idx,
                                                      size_t burn_idx,
                                                      TokenId token_id);
    static ColorError OverlappingAtoms(Token prev_token, size_t output_idx,
                                       Atoms atoms);
    static ColorError OverlappingMintBaton(Token prev_token,
                                           size_t output_idx);

    bool operator==(const ColorError &) const = default;
    std::string ToString() const;
};

struct FailedColoring {
    size_t pushdata_idx{};
    ParsedData parsed;
    ColorError error;
    bool operator==(const FailedColoring &) const = default;
};

struct IntentionalBurn {
    TokenMeta meta;
    Atoms atoms{};
    bool operator==(const IntentionalBurn &) const = default;
};

struct ColoredTxSection {
    TokenMeta meta;
    TxType tx_type = TxType::GENESIS;
    uint128 required_input_sum{};
    bool has_colored_out_of_range = false;
    std::optional<GenesisInfo> genesis_info;

    bool IsMintVaultMint() const;
    bool operator==(const ColoredTxSection &) const = default;
};

class ColoredTx {
public:
    std::vector<ColoredTxSection> sections;
    std::vector<IntentionalBurn> intentional_burns;
    std::vector<std::optional<TokenOutput>> outputs;
    std::vector<FailedParsing> failed_parsings;
    std::vector<FailedColoring> failed_colorings;

    /** nullopt if the tx has nothing to do with SLP/ALP. */
    static std::optional<ColoredTx> ColorTx(const Tx &tx);

    Token GetToken(const TokenOutput &token_output) const;
    bool operator==(const ColoredTx &) const = default;

private:
    bool ColorAllAlpPushdata(std::vector<Bytes> pushdata, const TxId &txid);
    std::optional<ColorError> ColorSection(size_t pushdata_idx,
                                           const ParsedData &parsed,
                                           uint8_t &max_token_type);
    std::optional<ColorError> ColorGenesis(size_t pushdata_idx,
                                           const TokenMeta &meta,
                                           const ParsedGenesis &genesis);
    std::optional<ColorError> ColorMint(const TokenMeta &meta,
                                        const ParsedMintData &mint);
    Result<bool, ColorError> ColorMintData(const TokenMeta &meta,
                                           const ParsedMintData &mint_data);
    std::optional<ColorError> ColorSend(const TokenMeta &meta,
                                        const std::vector<Atoms> &atoms);
    std::optional<ColorError> ColorBurn(const TokenMeta &meta, Atoms atoms);
    std::optional<ColorError> ColorUnknown(const TokenMeta &meta);
};

} // namespace chronik::native::token

#endif // CHRONIK_NATIVE_TOKEN_COLOR_H
