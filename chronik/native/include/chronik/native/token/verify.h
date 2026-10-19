// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_VERIFY_H
#define CHRONIK_NATIVE_TOKEN_VERIFY_H

#include <chronik/native/token/color.h>
#include <chronik/native/token/structs.h>

#include <optional>
#include <span>
#include <string>
#include <vector>

/** Port of bitcoinsuite-slp verify.rs, token_tx.rs and burn_summary.rs */
namespace chronik::native::token {

struct BurnError {
    enum class Kind : uint8_t {
        TooManyTxInputs,
        MissingNft1Group,
        MissingMintBaton,
        MissingMintVault,
        InsufficientInputSum,
    };
    Kind kind = Kind::MissingNft1Group;
    /** TooManyTxInputs */
    size_t num_inputs{};
    uint128 required{};
    uint128 actual{};

    static BurnError TooManyTxInputs(size_t n) {
        return {Kind::TooManyTxInputs, n, 0, 0};
    }
    static BurnError MissingNft1Group() {
        return {Kind::MissingNft1Group, 0, 0, 0};
    }
    static BurnError MissingMintBaton() {
        return {Kind::MissingMintBaton, 0, 0, 0};
    }
    static BurnError MissingMintVault() {
        return {Kind::MissingMintVault, 0, 0, 0};
    }
    static BurnError InsufficientInputSum(uint128 required, uint128 actual) {
        return {Kind::InsufficientInputSum, 0, required, actual};
    }
    bool operator==(const BurnError &) const = default;
    std::string ToString() const;
};

struct SpentToken {
    Token token;
    std::optional<TokenMeta> group_token_meta;
    bool operator==(const SpentToken &) const = default;
};

struct TokenTxEntry {
    TokenMeta meta;
    std::optional<TxType> tx_type;
    std::optional<GenesisInfo> genesis_info;
    std::optional<TokenMeta> group_token_meta;
    bool is_invalid = false;
    std::optional<Atoms> intentional_burn_atoms;
    uint128 actual_burn_atoms{};
    bool burns_mint_batons = false;
    std::optional<BurnError> burn_error;
    bool has_colored_out_of_range = false;
    std::vector<FailedColoring> failed_colorings;

    bool operator==(const TokenTxEntry &) const = default;

    bool HasUnintentionalBurn() const;
    bool IsNormal() const;
    /** Human-readable burn summary, exactly as in Rust (wire-visible). */
    std::string BurnSummary() const;
};

struct TokenTx {
    std::vector<TokenTxEntry> entries;
    std::vector<std::optional<TokenOutput>> outputs;
    std::vector<FailedParsing> failed_parsings;

    Token GetToken(const TokenOutput &token_output) const;
    SpentToken GetSpentToken(const TokenOutput &token_output) const;
    bool operator==(const TokenTx &) const = default;
};

struct VerifyContext {
    std::span<const std::optional<SpentToken>> spent_tokens;
    /** Must be set for SLP V2 Mint Vault token types (unless overridden). */
    const std::vector<script::Script> *spent_scripts = nullptr;
    const GenesisInfo *genesis_info = nullptr;
    std::optional<bool> override_has_mint_vault;

    TokenTx Verify(ColoredTx tx) const;

private:
    TokenTxEntry VerifySection(const ColoredTx &tx,
                               const ColoredTxSection &section) const;
    bool HasMintBaton(const TokenMeta &meta) const;
    bool HasMintVault() const;
    uint128 CalcInputSum(const TokenMeta &meta) const;
    uint128 CalcOutputSum(const ColoredTx &tx, const TokenMeta &meta) const;
    std::optional<TokenMeta> InheritedGroupTokenMeta(const TokenMeta &) const;
    std::optional<Atoms> IntentionalBurnAtoms(const ColoredTx &tx,
                                              const TokenMeta &meta) const;
};

} // namespace chronik::native::token

#endif // CHRONIK_NATIVE_TOKEN_VERIFY_H
