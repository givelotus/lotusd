// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_verify_slp_mint_vault.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

const std::optional<TokenOutput> NONE;
const SlpTokenType MintVault = SlpTokenType::MintVault();
const SlpTokenType Fungible = SlpTokenType::Fungible();

TokenMeta meta(const TokenId &token_id, SlpTokenType token_type) {
    return meta_slp(token_id, token_type);
}

ShaRmd160 Hash(uint8_t byte) {
    ShaRmd160 hash;
    hash.fill(byte);
    return hash;
}

template <size_t N>
TokenTx verify_vault(const Script &script,
                     std::vector<std::optional<SpentToken>> spent_tokens,
                     const std::vector<Script> &spent_scripts,
                     std::optional<ShaRmd160> mint_vault_scripthash) {
    const Tx tx = MakeTx(script, N);
    auto colored_tx = ColoredTx::ColorTx(tx);
    BOOST_REQUIRE(colored_tx);
    GenesisInfo genesis_info;
    genesis_info.mint_vault_scripthash = mint_vault_scripthash;
    VerifyContext context;
    context.spent_tokens = spent_tokens;
    context.spent_scripts = &spent_scripts;
    context.genesis_info = &genesis_info;
    return context.Verify(std::move(*colored_tx));
}

TokenTxEntry MissingVaultEntry() {
    return TokenTxEntry{
        .meta = meta(TOKEN_ID2, MintVault),
        .tx_type = TxType::MINT,
        .is_invalid = true,
        .burn_error = BurnError::MissingMintVault(),
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_verify_slp_mint_vault_tests)

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_no_genesis_no_scripts) {
    check_token_tx(verify_vault<1>(slp::MintVaultOpreturn(TOKEN_ID2, {77}), {},
                                   {}, std::nullopt),
                   TokenTx{
                       .entries = {MissingVaultEntry()},
                       .outputs = {NONE, NONE},
                       .failed_parsings = {},
                   });
}

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_no_scritps) {
    check_token_tx(verify_vault<1>(slp::MintVaultOpreturn(TOKEN_ID2, {77}), {},
                                   {}, Hash(1)),
                   TokenTx{
                       .entries = {MissingVaultEntry()},
                       .outputs = {NONE, NONE},
                       .failed_parsings = {},
                   });
}

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_missing_vault_script) {
    check_token_tx(
        verify_vault<1>(slp::MintVaultOpreturn(TOKEN_ID2, {77}), {},
                        {
                            Script::P2sh(Hash(0)),
                            Script::P2sh(Hash(1)),
                            Script::P2sh(Hash(3)),
                        },
                        Hash(2)),
        TokenTx{
            .entries = {MissingVaultEntry()},
            .outputs = {NONE, NONE},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_success_simple) {
    check_token_tx(
        verify_vault<3>(slp::MintVaultOpreturn(TOKEN_ID2, {30, 0, 50}), {},
                        {Script::P2sh(Hash(1))}, Hash(1)),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2, MintVault),
                .tx_type = TxType::MINT,
            }},
            .outputs = {NONE, token_atoms<0>(30), NONE, token_atoms<0>(50)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_success_multiple_scripts) {
    check_token_tx(
        verify_vault<3>(slp::MintVaultOpreturn(TOKEN_ID2, {30, 0, 50}), {},
                        {
                            Script::P2sh(Hash(0)),
                            Script::P2sh(Hash(1)),
                            Script::P2sh(Hash(2)),
                        },
                        Hash(1)),
        TokenTx{
            .entries = {TokenTxEntry{
                .meta = meta(TOKEN_ID2, MintVault),
                .tx_type = TxType::MINT,
            }},
            .outputs = {NONE, token_atoms<0>(30), NONE, token_atoms<0>(50)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_CASE(test_verify_mint_vault_success_with_burns) {
    check_token_tx(
        verify_vault<3>(slp::MintVaultOpreturn(TOKEN_ID2, {10, 0, 20}),
                        {
                            spent_atoms(meta(TOKEN_ID2, MintVault), 80),
                            spent_baton(meta(TOKEN_ID3, Fungible)),
                            spent_atoms(meta(TOKEN_ID3, Fungible), 800),
                            spent_baton(meta_alp(TOKEN_ID4)),
                        },
                        {
                            Script::P2sh(Hash(0)),
                            Script::P2sh(Hash(1)),
                            Script::P2sh(Hash(2)),
                        },
                        Hash(1)),
        TokenTx{
            .entries =
                {
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID2, MintVault),
                        .tx_type = TxType::MINT,
                        .actual_burn_atoms = 80,
                    },
                    TokenTxEntry{
                        .meta = meta(TOKEN_ID3, Fungible),
                        .tx_type = std::nullopt,
                        .is_invalid = true,
                        .actual_burn_atoms = 800,
                        .burns_mint_batons = true,
                    },
                    TokenTxEntry{
                        .meta = meta_alp(TOKEN_ID4),
                        .tx_type = std::nullopt,
                        .is_invalid = true,
                        .burns_mint_batons = true,
                    },
                },
            .outputs = {NONE, token_atoms<0>(10), NONE, token_atoms<0>(20)},
            .failed_parsings = {},
        });
}

BOOST_AUTO_TEST_SUITE_END()
