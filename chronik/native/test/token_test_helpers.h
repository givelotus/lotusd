// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_TOKEN_TEST_HELPERS_H
#define CHRONIK_NATIVE_TEST_TOKEN_TEST_HELPERS_H

// Port of bitcoinsuite-slp's test_helpers.rs, plus small byte helpers used by
// the translated Rust tests.

#include <chronik/native/token/color.h>
#include <chronik/native/token/parse.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token/verify.h>

#include <boost/test/unit_test.hpp>

#include <initializer_list>
#include <ostream>
#include <string>
#include <vector>

/** BOOST_CHECK accepting expressions with top-level commas (braced inits). */
#define TOKEN_CHECK(...) BOOST_CHECK((__VA_ARGS__))

namespace chronik::native::token::test {

/** Concatenate byte vectors, like Rust's [a, b, c].concat(). */
inline Bytes Cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto &p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

/** Bytes of a string literal (without the trailing NUL). */
template <size_t N> inline Bytes B(const char (&s)[N]) {
    return Bytes(s, s + N - 1);
}

inline Bytes Rep(uint8_t byte, size_t n) {
    return Bytes(n, byte);
}

inline TxId MakeTxId(uint8_t byte) {
    TxId txid;
    txid.b.fill(byte);
    return txid;
}

inline const TxId TXID = MakeTxId(1);
inline const TokenId TOKEN_ID1{MakeTxId(1)};
inline const TokenId TOKEN_ID2{MakeTxId(2)};
inline const TokenId TOKEN_ID3{MakeTxId(3)};
inline const TokenId TOKEN_ID4{MakeTxId(4)};
inline const TokenId TOKEN_ID5{MakeTxId(5)};
inline const TokenId TOKEN_ID6{MakeTxId(6)};
inline const TokenId TOKEN_ID7{MakeTxId(7)};
inline const TokenId TOKEN_ID8{MakeTxId(8)};
inline const TxId EMPTY_TXID{};
inline const TokenId EMPTY_TOKEN_ID{};

inline const GenesisInfo INFO_SLP = GenesisInfo::EmptySlp();

/** [Fungible, MintVault, Nft1Child, Nft1Group] */
inline const std::array<SlpTokenType, 4> ALL_SLP_TYPES{
    SlpTokenType::Fungible(), SlpTokenType::MintVault(),
    SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()};

inline TokenMeta meta_slp(TokenId token_id, SlpTokenType token_type) {
    return TokenMeta{token_id, TokenType::Slp(token_type)};
}

inline TokenMeta meta_alp(TokenId token_id) {
    return TokenMeta{token_id, TokenType::Alp(AlpTokenType::Standard())};
}

inline TokenMeta meta_alp_unknown(TokenId token_id, uint8_t token_type) {
    return TokenMeta{token_id,
                     TokenType::Alp(AlpTokenType::Unknown(token_type))};
}

inline std::optional<SpentToken> spent_atoms(TokenMeta meta, uint64_t atoms) {
    return SpentToken{Token{meta, TokenVariant::MakeAtoms(atoms)},
                      std::nullopt};
}

inline std::optional<SpentToken>
spent_atoms_group(TokenMeta meta, uint64_t atoms, TokenMeta group_token_meta) {
    return SpentToken{Token{meta, TokenVariant::MakeAtoms(atoms)},
                      group_token_meta};
}

inline std::optional<SpentToken> spent_baton(TokenMeta meta) {
    return SpentToken{Token{meta, TokenVariant::MintBaton()}, std::nullopt};
}

template <size_t N> std::optional<TokenOutput> token_atoms(uint64_t atoms) {
    return TokenOutput{N, TokenVariant::MakeAtoms(atoms)};
}

template <size_t N> std::optional<TokenOutput> token_baton() {
    return TokenOutput{N, TokenVariant::MintBaton()};
}

template <size_t N>
std::optional<TokenOutput> token_unknown(uint8_t token_type) {
    return TokenOutput{N, TokenVariant::Unknown(token_type)};
}

inline ParsedData parse_alp(Bytes section) {
    return *alp::ParseSection(TXID, std::move(section)).value();
}

inline TokenTxEntry empty_entry() {
    TokenTxEntry entry;
    entry.meta = meta_slp(EMPTY_TOKEN_ID, SlpTokenType::Fungible());
    return entry;
}

inline Bytes alp_mint(const TokenId &token_id, std::vector<Atoms> atoms,
                      size_t num_batons) {
    return alp::MintSection(token_id, AlpTokenType::Standard(),
                            ParsedMintData{std::move(atoms), num_batons});
}

/** Tx with OP_RETURN output `script` followed by n empty outputs */
inline Tx MakeTx(const script::Script &script, size_t n,
                 const TxId &txid = TXID) {
    Tx tx;
    tx.txid = txid;
    tx.outputs.push_back(TxOutput{0, script.bytecode()});
    for (size_t i = 0; i < n; ++i) {
        tx.outputs.push_back(TxOutput{});
    }
    return tx;
}

template <size_t N>
TokenTx verify(const script::Script &script,
               std::vector<std::optional<SpentToken>> spent_tokens) {
    const Tx tx = MakeTx(script, N);
    auto colored_tx = ColoredTx::ColorTx(tx);
    BOOST_REQUIRE(colored_tx);
    VerifyContext context;
    context.spent_tokens = spent_tokens;
    return context.Verify(std::move(*colored_tx));
}

using SlpParseResult = Result<std::optional<ParsedData>, slp::ParseError>;
using AlpParseResult = Result<std::optional<ParsedData>, alp::ParseError>;

/** Checks `script` fails to parse as SLP and whether parse() ignores it. */
inline void slp_check_script(const Bytes &script,
                             const slp::ParseError &expected_err,
                             bool should_ignore) {
    auto actual = slp::ParseWithIgnoredErr(EMPTY_TXID, script);
    BOOST_REQUIRE_MESSAGE(!actual.ok(), "Expected SLP parse to fail");
    BOOST_CHECK_MESSAGE(actual.error() == expected_err,
                        "got: " << actual.error().ToString()
                                << ", expected: " << expected_err.ToString());
    auto parsed = slp::Parse(EMPTY_TXID, script);
    const bool ignored = parsed.ok() && !parsed.value();
    BOOST_CHECK_EQUAL(ignored, should_ignore);
}

inline SlpParseResult slp_parse(const Bytes &script) {
    return slp::Parse(EMPTY_TXID, script);
}

inline SlpParseResult slp_parse(const script::Script &script) {
    return slp::Parse(EMPTY_TXID, script.bytecode());
}

/** OP_RETURN "SLP\0" <token_type> <tx_type> */
inline Bytes SlpPrefix(uint8_t token_type, const Bytes &tx_type) {
    return Cat({{0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01, token_type},
                {uint8_t(tx_type.size())},
                tx_type});
}

inline TokenId TokenIdBe(uint8_t byte) {
    std::array<uint8_t, 32> be;
    be.fill(byte);
    return TokenId::FromBeBytes(be);
}

inline Bytes BeBytes(uint64_t v) {
    Bytes out(8);
    for (size_t i = 0; i < 8; ++i) {
        out[7 - i] = uint8_t(v >> (8 * i));
    }
    return out;
}

/** Checks parse(script) == Err(expected_err) */
inline void slp_check_err(const Bytes &script,
                          const slp::ParseError &expected_err) {
    auto actual = slp::Parse(EMPTY_TXID, script);
    BOOST_REQUIRE_MESSAGE(!actual.ok(), "Expected SLP parse to fail");
    BOOST_CHECK_MESSAGE(actual.error() == expected_err,
                        "got: " << actual.error().ToString()
                                << ", expected: " << expected_err.ToString());
}

inline void slp_check_err(const script::Script &script,
                          const slp::ParseError &expected_err) {
    slp_check_err(script.bytecode(), expected_err);
}

/** Ok(Some(parsed)) */
inline SlpParseResult SlpOk(ParsedData parsed) {
    return SlpParseResult{std::optional<ParsedData>{std::move(parsed)}};
}

inline AlpParseResult AlpOk(ParsedData parsed) {
    return AlpParseResult{std::optional<ParsedData>{std::move(parsed)}};
}

/** Field-wise TokenTx comparison, so failures point at the differing part. */
inline void check_token_tx(const TokenTx &actual, const TokenTx &expected) {
    BOOST_CHECK_EQUAL(actual.entries.size(), expected.entries.size());
    for (size_t i = 0;
         i < std::min(actual.entries.size(), expected.entries.size()); ++i) {
        const TokenTxEntry &a = actual.entries[i];
        const TokenTxEntry &e = expected.entries[i];
        BOOST_CHECK_MESSAGE(a.meta == e.meta, "entry " << i << " meta");
        BOOST_CHECK_MESSAGE(a.tx_type == e.tx_type, "entry " << i
                                                             << " tx_type");
        BOOST_CHECK_MESSAGE(a.genesis_info == e.genesis_info,
                            "entry " << i << " genesis_info");
        BOOST_CHECK_MESSAGE(a.group_token_meta == e.group_token_meta,
                            "entry " << i << " group_token_meta");
        BOOST_CHECK_MESSAGE(a.is_invalid == e.is_invalid,
                            "entry " << i << " is_invalid");
        BOOST_CHECK_MESSAGE(a.intentional_burn_atoms ==
                                e.intentional_burn_atoms,
                            "entry " << i << " intentional_burn_atoms");
        BOOST_CHECK_MESSAGE(a.actual_burn_atoms == e.actual_burn_atoms,
                            "entry " << i << " actual_burn_atoms: "
                                     << U128ToString(a.actual_burn_atoms)
                                     << " != "
                                     << U128ToString(e.actual_burn_atoms));
        BOOST_CHECK_MESSAGE(a.burns_mint_batons == e.burns_mint_batons,
                            "entry " << i << " burns_mint_batons");
        BOOST_CHECK_MESSAGE(
            a.burn_error == e.burn_error,
            "entry " << i << " burn_error: "
                     << (a.burn_error ? a.burn_error->ToString() : "None"));
        BOOST_CHECK_MESSAGE(a.has_colored_out_of_range ==
                                e.has_colored_out_of_range,
                            "entry " << i << " has_colored_out_of_range");
        BOOST_CHECK_MESSAGE(a.failed_colorings == e.failed_colorings,
                            "entry " << i << " failed_colorings");
    }
    BOOST_CHECK_MESSAGE(actual.outputs == expected.outputs, "outputs");
    BOOST_CHECK_MESSAGE(actual.failed_parsings == expected.failed_parsings,
                        "failed_parsings");
    BOOST_CHECK(actual == expected);
}

using AlpSectionResult = Result<ParsedData, alp::ParseError>;

inline const Bytes SLP2{'S', 'L', 'P', '2'};

/** parse_section_with_ignored_err */
inline AlpSectionResult alp_parse(Bytes data, const TxId &txid = EMPTY_TXID) {
    return alp::ParseSectionWithIgnoredErr(txid, std::move(data));
}

inline AlpSectionResult not_enough(const char *field_name, size_t expected,
                                   size_t actual) {
    return Err(alp::ParseError::NotEnoughBytes(field_name, expected, actual));
}

inline AlpSectionResult AlpErr(alp::ParseError err) {
    return Err(std::move(err));
}

/** META of the ALP parse tests: token id all 0x76, Standard */
inline TokenMeta AlpTestMeta() {
    return meta_alp(TokenId{MakeTxId(0x76)});
}

} // namespace chronik::native::token::test

#endif // CHRONIK_NATIVE_TEST_TOKEN_TEST_HELPERS_H
