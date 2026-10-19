// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_slp_parse_mint.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using slp::ParseError;

BOOST_AUTO_TEST_SUITE(token_slp_parse_mint_tests)

BOOST_AUTO_TEST_CASE(test_parse_mint_invalid_pushes) {
    for (uint8_t token_type : {1, 0x41, 0x81}) {
        for (size_t pushes = 0; pushes < 100; ++pushes) {
            if (pushes == 3) {
                continue;
            }
            // Invalid MINT, too few pushes
            slp_check_err(Cat({SlpPrefix(token_type, MINT),
                               // repeat 0x0101, which pushes 0x01
                               Rep(0x01, pushes * 2)}),
                          ParseError::UnexpectedNumPushes(6, 3 + pushes));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_invalid_token_id) {
    for (uint8_t token_type : slp_consts::ALL_TOKEN_TYPES) {
        for (int size = 0; size <= 0xff; ++size) {
            if (size == 32) {
                continue;
            }
            slp_check_err(Cat({SlpPrefix(token_type, MINT),
                               {0x4c, uint8_t(size)},
                               Rep(0x33, size),
                               {0x4c, 0x00, 0x01, 0x00}}),
                          ParseError::InvalidFieldSize("token_id", {32}, size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_invalid_mint_baton_size) {
    for (uint8_t token_type : {1, 0x41, 0x81}) {
        for (int size = 2; size <= 0xff; ++size) {
            slp_check_err(
                Cat({SlpPrefix(token_type, MINT),
                     {32},
                     Rep(0x22, 32),
                     {0x4c, uint8_t(size)},
                     Rep(0x01, size),
                     {0x01, 0x00}}),
                ParseError::InvalidFieldSize("mint_baton_out_idx", {0, 1},
                                             size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_invalid_mint_baton) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Child(),
          SlpTokenType::Nft1Group()}) {
        for (uint8_t mint_baton_out_idx = 0; mint_baton_out_idx <= 1;
             ++mint_baton_out_idx) {
            slp_check_err(slp::MintOpreturn(TokenIdBe(2), token_type,
                                            mint_baton_out_idx, 0),
                          ParseError::InvalidMintBatonIdx(mint_baton_out_idx));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_additional_quantity_size) {
    for (uint8_t token_type : {1, 0x41, 0x81}) {
        for (int size = 0; size <= 0xff; ++size) {
            if (size == 8) {
                continue;
            }
            slp_check_err(Cat({SlpPrefix(token_type, MINT),
                               {32},
                               Rep(0x22, 32),
                               {0x4c, 0x00},
                               {0x4c, uint8_t(size)},
                               Rep(0x01, size)}),
                          ParseError::InvalidFieldSize("additional_quantity",
                                                       {8}, size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_valid_mint_baton_simple) {
    const TokenId token_id = TokenIdBe(0x22);
    const Atoms additional_quantity = 0x987654321abcdef2;
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Child(),
          SlpTokenType::Nft1Group()}) {
        BOOST_CHECK(
            slp_parse(slp::MintOpreturn(token_id, token_type, 4,
                                        additional_quantity)) ==
            SlpOk(ParsedData{
                TokenMeta{token_id, TokenType::Slp(token_type)},
                ParsedTxType::MakeMint(
                    ParsedMintData{{additional_quantity, 0, 0}, 1}),
            }));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_valid_mint_baton) {
    // Valid MINT
    const std::vector<std::pair<uint8_t, SlpTokenType>> token_types{
        {1, SlpTokenType::Fungible()},
        {0x41, SlpTokenType::Nft1Child()},
        {0x81, SlpTokenType::Nft1Group()},
    };
    const std::vector<std::pair<std::optional<uint8_t>, std::vector<Atoms>>>
        mint_baton_indices{
            {std::nullopt, {}},
            {2, {}},
            {4, {0, 0}},
            {0xff, std::vector<Atoms>(0xfd, 0)},
        };
    std::array<uint8_t, 32> token_id_be{};
    token_id_be[0] = 44;

    for (const auto &[type_byte, token_type] : token_types) {
        for (const auto &[mint_baton_out_idx, amounts_pad] :
             mint_baton_indices) {
            const Bytes script = Cat({
                SlpPrefix(type_byte, MINT),
                {0x20},
                Bytes(token_id_be.begin(), token_id_be.end()),
                mint_baton_out_idx ? Bytes{0x01, *mint_baton_out_idx}
                                   : Bytes{0x4c, 0},
                {0x08, 0x98, 0x76, 0x54, 0x32, 0x1a, 0xbc, 0xde, 0xf2},
            });
            std::vector<Atoms> atoms_vec{0x987654321abcdef2};
            atoms_vec.insert(atoms_vec.end(), amounts_pad.begin(),
                             amounts_pad.end());
            BOOST_CHECK(
                slp_parse(script) ==
                SlpOk(ParsedData{
                    TokenMeta{TokenId::FromBeBytes(token_id_be),
                              TokenType::Slp(token_type)},
                    ParsedTxType::MakeMint(ParsedMintData{
                        atoms_vec, mint_baton_out_idx ? size_t(1) : 0}),
                }));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_vault_invalid_pushes) {
    for (size_t pushes = 0; pushes < 2; ++pushes) {
        // Invalid MINT Vault, too few pushes
        slp_check_err(Cat({SlpPrefix(2, MINT),
                           // repeat 0x0101, which pushes 0x01
                           Rep(0x01, pushes * 2)}),
                      ParseError::TooFewPushes(5, 3 + pushes));
    }

    for (size_t pushes = 21; pushes < 100; ++pushes) {
        // Invalid MINT Vault, too many pushes
        slp_check_err(Cat({SlpPrefix(2, MINT),
                           // repeat 0x0101, which pushes 0x01
                           Rep(0x01, pushes * 2)}),
                      ParseError::SuperfluousPushes(23, 3 + pushes));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_mint_vault_invalid_amount_size) {
    // Test all possible MINT outputs with one amount having 2 bytes
    for (size_t num_outputs = 1; num_outputs <= 19; ++num_outputs) {
        const Bytes script_intro =
            Cat({SlpPrefix(2, MINT), {0x20}, Rep(0x22, 32)});
        for (size_t invalid_idx = 0; invalid_idx < num_outputs;
             ++invalid_idx) {
            Bytes script = script_intro;
            for (size_t idx = 0; idx < num_outputs; ++idx) {
                const Bytes part =
                    invalid_idx == idx
                        ? Bytes{0x02, 0x00, 0x00}
                        : Bytes{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00};
                script.insert(script.end(), part.begin(), part.end());
            }
            slp_check_err(
                script,
                ParseError::InvalidFieldSize(
                    slp::ADDITIONAL_QUANTITY_FIELD_NAMES[invalid_idx], {8},
                    2));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_valid_mint_vault_simple) {
    const TokenId token_id = TokenIdBe(0x22);
    const std::vector<Atoms> additional_quantities{
        77, 0x987654321abcdef2, 0, 0xffffffffffffffff, 1};
    BOOST_CHECK(slp_parse(slp::MintVaultOpreturn(token_id,
                                                 additional_quantities)) ==
                SlpOk(ParsedData{
                    TokenMeta{token_id,
                              TokenType::Slp(SlpTokenType::MintVault())},
                    ParsedTxType::MakeMint(
                        ParsedMintData{additional_quantities, 0}),
                }));
}

BOOST_AUTO_TEST_CASE(test_parse_valid_mint_vault) {
    // Valid MINT Vault, test all valid number of amounts
    const Bytes script_intro =
        Cat({SlpPrefix(2, MINT), {0x20}, Rep(0x22, 32)});
    for (size_t num_amounts = 1; num_amounts <= 19; ++num_amounts) {
        Bytes script = script_intro;
        std::vector<Atoms> atoms_vec;
        for (size_t idx = 0; idx < num_amounts; ++idx) {
            const Atoms amount = idx;
            script.push_back(0x08);
            const Bytes be = BeBytes(amount);
            script.insert(script.end(), be.begin(), be.end());
            atoms_vec.push_back(amount);
        }
        BOOST_CHECK(slp_parse(script) ==
                    SlpOk(ParsedData{
                        TokenMeta{TokenIdBe(0x22),
                                  TokenType::Slp(SlpTokenType::MintVault())},
                        ParsedTxType::MakeMint(ParsedMintData{atoms_vec, 0}),
                    }));
    }
}

BOOST_AUTO_TEST_SUITE_END()
