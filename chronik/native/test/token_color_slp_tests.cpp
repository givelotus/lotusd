// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_color_slp.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const TxId COLOR_TXID = MakeTxId(4);
const TokenId TOKEN_ID{COLOR_TXID};

Tx MakeColorTx(const Script &script, size_t n_extra_outputs) {
    return MakeTx(script, n_extra_outputs, COLOR_TXID);
}

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

std::optional<TokenOutput> atoms(Atoms amount) {
    return token_atoms<0>(amount);
}

const std::optional<TokenOutput> MINT_BATON = token_baton<0>();
const std::optional<TokenOutput> NONE;

ColoredTxSection Section(TokenMeta meta, TxType tx_type,
                         uint128 required_input_sum = 0,
                         bool has_colored_out_of_range = false,
                         std::optional<GenesisInfo> genesis_info = {}) {
    return ColoredTxSection{meta, tx_type, required_input_sum,
                            has_colored_out_of_range, std::move(genesis_info)};
}

ColoredTx Colored(std::vector<std::optional<TokenOutput>> outputs,
                  std::vector<ColoredTxSection> sections) {
    return ColoredTx{.sections = std::move(sections),
                     .outputs = std::move(outputs)};
}

std::optional<ColoredTx> Color(const Script &script, size_t n_extra_outputs) {
    return ColoredTx::ColorTx(MakeColorTx(script, n_extra_outputs));
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_color_slp_tests)

BOOST_AUTO_TEST_CASE(test_color_slp_error) {
    {
        const Script script(Bytes{OP_RETURN.number(), 4, 'S', 'L', 'P', 0});
        TOKEN_CHECK(Color(script, 0) ==
                    ColoredTx{
                        .outputs = {NONE},
                        .failed_parsings = {FailedParsing{
                            std::nullopt, script.bytecode(),
                            ColorParseError{slp::ParseError::TooFewPushes(3, 1)},
                        }},
                    });
    }
    {
        const Script script(Bytes{OP_RETURN.number(), 4, 'S', 'L', 'P', '2'});
        TOKEN_CHECK(
            Color(script, 0) ==
            ColoredTx{
                .outputs = {NONE},
                .failed_parsings = {FailedParsing{
                    std::nullopt, script.bytecode(),
                    ColorParseError{slp::ParseError::Make(
                        slp::ParseError::Kind::InvalidAlpLokadId)},
                }},
            });
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_genesis_no_baton) {
    ShaRmd160 vault_hash;
    vault_hash.fill(4);
    for (const auto &[token_type, amt, mint_vault_scripthash] :
         std::vector<std::tuple<SlpTokenType, Atoms, std::optional<ShaRmd160>>>{
             {SlpTokenType::Fungible(), 1234, std::nullopt},
             {SlpTokenType::MintVault(), 2345, vault_hash},
             {SlpTokenType::Nft1Child(), 1, std::nullopt},
             {SlpTokenType::Nft1Group(), 3456, std::nullopt},
         }) {
        GenesisInfo info;
        info.mint_vault_scripthash = mint_vault_scripthash;
        TOKEN_CHECK(
            Color(slp::GenesisOpreturn(info, token_type, std::nullopt, amt),
                  4) ==
            Colored({NONE, atoms(amt), NONE, NONE, NONE},
                    {Section(meta(TOKEN_ID, token_type), TxType::GENESIS, 0,
                             false, info)}));
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_genesis_mint_baton_out_idx) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Group()}) {
        for (size_t out_idx = 2; out_idx <= 255; ++out_idx) {
            std::vector<std::optional<TokenOutput>> outputs(out_idx + 1);
            outputs[1] = atoms(1234567);
            outputs[out_idx] = MINT_BATON;
            TOKEN_CHECK(
                Color(slp::GenesisOpreturn(GenesisInfo{}, token_type,
                                           uint8_t(out_idx), 1234567),
                      out_idx) ==
                Colored(outputs,
                        {Section(meta(TOKEN_ID, token_type), TxType::GENESIS,
                                 0, false, GenesisInfo{})}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_genesis_has_colored_out_of_range) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Group()}) {
        const GenesisInfo info;
        const ColoredTxSection section = Section(
            meta(TOKEN_ID, token_type), TxType::GENESIS, 0, false, info);
        ColoredTxSection section_oor = section;
        section_oor.has_colored_out_of_range = true;

        // Initial quantity colored out of range
        TOKEN_CHECK(
            Color(slp::GenesisOpreturn(info, token_type, std::nullopt, 7777),
                  0) == Colored({NONE}, {section_oor}));

        // 0 initial quantity doesn't color out-of-range
        TOKEN_CHECK(
            Color(slp::GenesisOpreturn(info, token_type, std::nullopt, 0),
                  0) == Colored({NONE}, {section}));

        // Test all the possible mint_baton_out_idx
        for (int out_idx = 2; out_idx <= 255; ++out_idx) {
            TOKEN_CHECK(Color(slp::GenesisOpreturn(info, token_type,
                                                   uint8_t(out_idx), 7777),
                              1) ==
                        Colored({NONE, atoms(7777)}, {section_oor}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_mint_no_baton) {
    for (const auto &[token_type, amt] :
         std::vector<std::pair<SlpTokenType, Atoms>>{
             {SlpTokenType::Fungible(), 1234},
             {SlpTokenType::Nft1Child(), 2345},
             {SlpTokenType::Nft1Group(), 3456},
         }) {
        TOKEN_CHECK(
            Color(slp::MintOpreturn(TOKEN_ID1, token_type, std::nullopt, amt),
                  4) ==
            Colored({NONE, atoms(amt), NONE, NONE, NONE},
                    {Section(meta(TOKEN_ID1, token_type), TxType::MINT)}));
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_mint_vault) {
    for (Atoms num_amounts = 1; num_amounts <= 19; ++num_amounts) {
        std::vector<Atoms> amounts;
        for (Atoms i = 0; i < num_amounts; ++i) {
            amounts.push_back(i);
        }
        // Zero amounts are colored as None
        std::vector<std::optional<TokenOutput>> outputs{NONE, NONE};
        for (Atoms i = 1; i < num_amounts; ++i) {
            outputs.push_back(atoms(i));
        }
        TOKEN_CHECK(
            Color(slp::MintVaultOpreturn(TOKEN_ID1, amounts), num_amounts) ==
            Colored(outputs,
                    {Section(meta(TOKEN_ID1, SlpTokenType::MintVault()),
                             TxType::MINT)}));
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_mint_has_colored_out_of_range) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Child(),
          SlpTokenType::Nft1Group()}) {
        const ColoredTxSection section =
            Section(meta(TOKEN_ID1, token_type), TxType::MINT);
        ColoredTxSection section_oor = section;
        section_oor.has_colored_out_of_range = true;

        // Additional quantity colored out of range
        TOKEN_CHECK(Color(slp::MintOpreturn(TOKEN_ID1, token_type,
                                            std::nullopt, 7777),
                          0) == Colored({NONE}, {section_oor}));

        // 0 initial quantity doesn't color out-of-range
        TOKEN_CHECK(
            Color(slp::MintOpreturn(TOKEN_ID1, token_type, std::nullopt, 0),
                  0) == Colored({NONE}, {section}));

        // Test all the possible mint_baton_out_idx
        for (int out_idx = 2; out_idx <= 255; ++out_idx) {
            TOKEN_CHECK(Color(slp::MintOpreturn(TOKEN_ID1, token_type,
                                                uint8_t(out_idx), 7777),
                              1) ==
                        Colored({NONE, atoms(7777)}, {section_oor}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_mint_vault_has_colored_out_of_range) {
    for (size_t num_amounts = 1; num_amounts <= 19; ++num_amounts) {
        const ColoredTxSection section =
            Section(meta(TOKEN_ID1, SlpTokenType::MintVault()), TxType::MINT);
        ColoredTxSection section_oor = section;
        section_oor.has_colored_out_of_range = true;

        // 0 additional amounts don't color out of range
        TOKEN_CHECK(Color(slp::MintVaultOpreturn(
                              TOKEN_ID1, std::vector<Atoms>(num_amounts, 0)),
                          0) == Colored({NONE}, {section}));

        // Amounts color out of range
        std::vector<Atoms> amounts(num_amounts - 1, 0);
        amounts.push_back(7777);
        TOKEN_CHECK(Color(slp::MintVaultOpreturn(TOKEN_ID1, amounts), 0) ==
                    Colored({NONE}, {section_oor}));
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_send) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()}) {
        TOKEN_CHECK(
            Color(slp::SendOpreturn(TOKEN_ID1, token_type, {4444}), 2) ==
            Colored({NONE, atoms(4444), NONE},
                    {Section(meta(TOKEN_ID1, token_type), TxType::SEND,
                             4444)}));

        for (Atoms num_amounts = 1; num_amounts <= 19; ++num_amounts) {
            std::vector<Atoms> amounts;
            uint128 required_input_sum = 0;
            for (Atoms i = 0; i < num_amounts; ++i) {
                amounts.push_back(i);
                required_input_sum += i;
            }
            // Zero amounts are colored as None
            std::vector<std::optional<TokenOutput>> outputs{NONE, NONE};
            for (Atoms i = 1; i < num_amounts; ++i) {
                outputs.push_back(atoms(i));
            }
            TOKEN_CHECK(
                Color(slp::SendOpreturn(TOKEN_ID1, token_type, amounts),
                      num_amounts) ==
                Colored(outputs,
                        {Section(meta(TOKEN_ID1, token_type), TxType::SEND,
                                 required_input_sum)}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_send_vault_has_colored_out_of_range) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()}) {
        for (size_t num_amounts = 1; num_amounts <= 19; ++num_amounts) {
            const ColoredTxSection section =
                Section(meta(TOKEN_ID1, token_type), TxType::SEND);

            // 0 additional amounts don't color out of range
            TOKEN_CHECK(Color(slp::SendOpreturn(
                                  TOKEN_ID1, token_type,
                                  std::vector<Atoms>(num_amounts, 0)),
                              0) == Colored({NONE}, {section}));

            // Amounts color out of range
            std::vector<Atoms> amounts(num_amounts - 1, 0);
            amounts.push_back(7777);
            ColoredTxSection section_oor = section;
            section_oor.required_input_sum = 7777;
            section_oor.has_colored_out_of_range = true;
            TOKEN_CHECK(
                Color(slp::SendOpreturn(TOKEN_ID1, token_type, amounts), 0) ==
                Colored({NONE}, {section_oor}));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_color_slp_burn) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Child(), SlpTokenType::Nft1Group()}) {
        TOKEN_CHECK(
            Color(slp::BurnOpreturn(TOKEN_ID1, token_type, 3333), 2) ==
            ColoredTx{
                .intentional_burns = {IntentionalBurn{
                    meta(TOKEN_ID1, token_type), 3333}},
                .outputs = {NONE, NONE, NONE},
            });
    }
}

BOOST_AUTO_TEST_SUITE_END()
