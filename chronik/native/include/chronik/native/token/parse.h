// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_PARSE_H
#define CHRONIK_NATIVE_TOKEN_PARSE_H

#include <chronik/native/script/result.h>
#include <chronik/native/script/script.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/types.h>

#include <optional>
#include <string>
#include <vector>

/** Ports of bitcoinsuite-slp's empp, slp and alp parsers. */
namespace chronik::native::token {

namespace empp {

using EmppData = std::vector<Bytes>;

struct ParseError {
    enum class Kind {
        DataError,
        EmptyScript,
        MissingOpReturn,
        EmptyOpReturn,
        MissingOpReserved,
        InvalidPushOpcode,
        InvalidNonPushOpcode,
        EmptyPushdata,
    };
    Kind kind = Kind::EmptyScript;
    script::DataError data_error;
    script::Opcode opcode;

    static ParseError Make(Kind kind, script::Opcode opcode = {}) {
        return {kind, {}, opcode};
    }
    static ParseError FromDataError(script::DataError err) {
        return {Kind::DataError, std::move(err), {}};
    }
    bool operator==(const ParseError &) const = default;
    std::string ToString() const;
};

/** Ok(nullopt) if the script is not eMPP at all. */
Result<std::optional<EmppData>, ParseError> Parse(ByteView script);
/** Like Parse, but returns the errors Parse ignores. */
Result<EmppData, ParseError> ParseWithIgnoredErr(ByteView script);

} // namespace empp

namespace slp {

struct ParseError {
    enum class Kind {
        DataError,
        EmptyScript,
        MissingOpReturn,
        MissingLokadId,
        WrongLokadId,
        InvalidLokadIdOpcode,
        InvalidAlpLokadId,
        NonPushOp,
        DisallowedPush,
        InvalidFieldSize,
        InvalidDecimals,
        InvalidMintBatonIdx,
        Nft1ChildCannotHaveMintBaton,
        Nft1ChildInvalidInitialQuantity,
        Nft1ChildInvalidDecimals,
        TooFewPushes,
        UnexpectedNumPushes,
        SuperfluousPushes,
        InvalidTokenType,
        InvalidTxType,
    };
    Kind kind = Kind::EmptyScript;
    script::DataError data_error;
    script::Opcode opcode;
    /** WrongLokadId, InvalidTokenType, InvalidTxType */
    Bytes bytes;
    size_t op_idx{};
    std::string field_name;
    /** InvalidFieldSize */
    std::vector<size_t> expected_sizes;
    /** TooFewPushes, UnexpectedNumPushes, SuperfluousPushes */
    size_t expected{};
    /** actual sizes/counts, InvalidDecimals */
    size_t actual{};
    /** InvalidMintBatonIdx, Nft1ChildInvalidDecimals */
    uint8_t byte{};
    /** Nft1ChildInvalidInitialQuantity */
    Atoms atoms{};

    static ParseError Make(Kind kind) {
        ParseError err;
        err.kind = kind;
        return err;
    }
    static ParseError FromDataError(script::DataError err);
    static ParseError MissingOpReturn(script::Opcode opcode);
    static ParseError WrongLokadId(Bytes bytes);
    static ParseError InvalidLokadIdOpcode(script::Opcode opcode);
    static ParseError NonPushOp(script::Opcode opcode, size_t op_idx);
    static ParseError DisallowedPush(script::Opcode opcode, size_t op_idx);
    static ParseError InvalidFieldSize(std::string field_name,
                                       std::vector<size_t> expected,
                                       size_t actual);
    static ParseError InvalidDecimals(size_t actual);
    static ParseError InvalidMintBatonIdx(uint8_t idx);
    static ParseError Nft1ChildInvalidInitialQuantity(Atoms atoms);
    static ParseError Nft1ChildInvalidDecimals(uint8_t decimals);
    static ParseError TooFewPushes(size_t expected, size_t actual);
    static ParseError UnexpectedNumPushes(size_t expected, size_t actual);
    static ParseError SuperfluousPushes(size_t expected, size_t actual);
    static ParseError InvalidTokenType(Bytes bytes);
    static ParseError InvalidTxType(Bytes bytes);

    bool operator==(const ParseError &) const = default;
    std::string ToString() const;
};

/** Parse the first output of a tx; Ok(nullopt) if not SLP. */
Result<std::optional<ParsedData>, ParseError> ParseTx(const Tx &tx);
Result<std::optional<ParsedData>, ParseError> Parse(const TxId &txid,
                                                    ByteView script);
Result<ParsedData, ParseError> ParseWithIgnoredErr(const TxId &txid,
                                                   ByteView script);

// Builders (slp/build.rs)
script::Script GenesisOpreturn(const GenesisInfo &genesis_info,
                               SlpTokenType token_type,
                               std::optional<uint8_t> mint_baton_out_idx,
                               Atoms initial_quantity);
script::Script MintOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            std::optional<uint8_t> mint_baton_out_idx,
                            Atoms additional_quantity);
script::Script MintVaultOpreturn(const TokenId &token_id,
                                 const std::vector<Atoms> &quantities);
script::Script SendOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            const std::vector<Atoms> &send_atoms);
script::Script BurnOpreturn(const TokenId &token_id, SlpTokenType token_type,
                            Atoms burn_atoms);

extern const char *const ADDITIONAL_QUANTITY_FIELD_NAMES[19];
extern const char *const TOKEN_OUTPUT_QUANTITY_FIELD_NAMES[19];

} // namespace slp

namespace alp {

struct ParseError {
    enum class Kind {
        DataError,
        NotEnoughBytes,
        SizeOutOfRange,
        MissingLokadId,
        InvalidLokadId,
        InvalidSlpLokadId,
        UnknownTxType,
        DecimalsOutOfRange,
        LeftoverBytes,
    };
    Kind kind = Kind::DataError;
    script::DataError data_error;
    std::string field_name;
    size_t expected{};
    size_t actual{};
    /** SizeOutOfRange size, DecimalsOutOfRange */
    uint8_t byte{};
    /** MissingLokadId, UnknownTxType, LeftoverBytes */
    Bytes bytes;
    LokadId lokad_id{};

    static ParseError FromDataError(script::DataError err);
    static ParseError NotEnoughBytes(std::string field_name, size_t expected,
                                     size_t actual);
    static ParseError SizeOutOfRange(std::string field_name, uint8_t size);
    static ParseError MissingLokadId(Bytes bytes);
    static ParseError InvalidLokadId(LokadId lokad_id);
    static ParseError InvalidSlpLokadId();
    static ParseError UnknownTxType(Bytes bytes);
    static ParseError DecimalsOutOfRange(uint8_t decimals);
    static ParseError LeftoverBytes(Bytes bytes);

    bool operator==(const ParseError &) const = default;
    std::string ToString() const;
};

/** Ok(nullopt) for sections of other protocols (missing/other LOKAD ID). */
Result<std::optional<ParsedData>, ParseError> ParseSection(const TxId &txid,
                                                           Bytes pushdata);
Result<ParsedData, ParseError> ParseSectionWithIgnoredErr(const TxId &txid,
                                                          Bytes pushdata);

// Builders (alp/build.rs)
script::Script SectionsOpreturn(const std::vector<Bytes> &sections);
Bytes GenesisSection(AlpTokenType token_type, const GenesisInfo &genesis_info,
                     const ParsedMintData &mint_data);
Bytes MintSection(const TokenId &token_id, AlpTokenType token_type,
                  const ParsedMintData &mint_data);
Bytes BurnSection(const TokenId &token_id, AlpTokenType token_type,
                  Atoms atoms);
Bytes SendSection(const TokenId &token_id, AlpTokenType token_type,
                  const std::vector<Atoms> &send_amounts);

} // namespace alp

} // namespace chronik::native::token

#endif // CHRONIK_NATIVE_TOKEN_PARSE_H
