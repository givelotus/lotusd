// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/tests/test_slp_parse_genesis.rs.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::script;
using namespace chronik::native::token;
using namespace chronik::native::token::test;
using slp::ParseError;
using Kind = slp::ParseError::Kind;

namespace {

Bytes GenesisPrefix(uint8_t token_type) {
    return Cat({{0x6a, 0x04}, B("SLP\0"), {0x01, token_type}, {0x07},
                B("GENESIS")});
}

GenesisInfo InfoWithDecimals(uint8_t decimals) {
    GenesisInfo info;
    info.decimals = decimals;
    return info;
}

} // namespace

BOOST_AUTO_TEST_SUITE(token_slp_parse_genesis_tests)

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_pushes) {
    for (size_t pushes = 0; pushes < 100; ++pushes) {
        if (pushes == 7) {
            continue;
        }
        // Invalid GENESIS, too few pushes
        slp_check_err(Cat({GenesisPrefix(1),
                           // repeat 0x0101, which pushes 0x01
                           Rep(0x01, pushes * 2)}),
                      ParseError::UnexpectedNumPushes(10, 3 + pushes));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_token_document_hash) {
    for (int size = 1; size <= 0xff; ++size) {
        if (size == 32) {
            continue;
        }
        slp_check_err(
            Cat({GenesisPrefix(1),
                 {0x01, 0x00, 0x01, 0x00, 0x01, 0x00},
                 {0x4c, uint8_t(size)},
                 Rep(0x33, size),
                 {0x01, 0x00, 0x01, 0x00, 0x01, 0x00}}),
            ParseError::InvalidFieldSize("token_document_hash", {0, 32},
                                         size));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_decimals_size) {
    for (int size = 0; size <= 0xff; ++size) {
        if (size == 1) {
            continue;
        }
        slp_check_err(
            Cat({GenesisPrefix(1),
                 {0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4c, 0x00},
                 {0x4c, uint8_t(size)},
                 Rep(0x06, size),
                 {0x01, 0x00, 0x01, 0x00}}),
            ParseError::InvalidFieldSize("decimals", {1}, size));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_decimals) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::MintVault(),
          SlpTokenType::Nft1Group()}) {
        for (int decimals = 10; decimals <= 0xff; ++decimals) {
            GenesisInfo info = InfoWithDecimals(uint8_t(decimals));
            if (token_type == SlpTokenType::MintVault()) {
                info.mint_vault_scripthash = ShaRmd160{};
            }
            slp_check_err(
                slp::GenesisOpreturn(info, token_type, std::nullopt, 0),
                ParseError::InvalidDecimals(decimals));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_mint_baton_size) {
    for (uint8_t token_type : {1, 0x41, 0x81}) {
        for (int size = 2; size <= 0xff; ++size) {
            slp_check_err(
                Cat({GenesisPrefix(token_type),
                     {0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x01,
                      0x00},
                     {0x4c, uint8_t(size)},
                     Rep(0x01, size),
                     {0x01, 0x00}}),
                ParseError::InvalidFieldSize("mint_baton_out_idx", {0, 1},
                                             size));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_mint_baton) {
    for (SlpTokenType token_type :
         {SlpTokenType::Fungible(), SlpTokenType::Nft1Child(),
          SlpTokenType::Nft1Group()}) {
        for (uint8_t mint_baton_out_idx = 0; mint_baton_out_idx <= 1;
             ++mint_baton_out_idx) {
            slp_check_err(slp::GenesisOpreturn(GenesisInfo{}, token_type,
                                               mint_baton_out_idx, 0),
                          ParseError::InvalidMintBatonIdx(mint_baton_out_idx));
        }
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_nft_child_mint_baton_disallowed) {
    for (int mint_baton_out_idx = 2; mint_baton_out_idx <= 0xff;
         ++mint_baton_out_idx) {
        slp_check_err(slp::GenesisOpreturn(GenesisInfo{},
                                           SlpTokenType::Nft1Child(),
                                           uint8_t(mint_baton_out_idx), 0),
                      ParseError::Make(Kind::Nft1ChildCannotHaveMintBaton));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_invalid_mint_vault_scripthash) {
    for (int size = 0; size <= 0xff; ++size) {
        if (size == 20) {
            continue;
        }
        slp_check_err(
            Cat({GenesisPrefix(2),
                 {0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x01, 0x00},
                 {0x4c, uint8_t(size)},
                 Rep(0x01, size),
                 {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}),
            ParseError::InvalidFieldSize("mint_vault_scripthash", {20}, size));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_initial_quantity_size) {
    for (int size = 0; size <= 0xff; ++size) {
        if (size == 8) {
            continue;
        }
        slp_check_err(
            Cat({GenesisPrefix(1),
                 {0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x01, 0x00},
                 {0x4c, 0x00},
                 {0x4c, uint8_t(size)},
                 Rep(0x01, size)}),
            ParseError::InvalidFieldSize("initial_quantity", {8}, size));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_nft_child_invalid_initial_quantity) {
    for (Atoms initial_quantity = 0; initial_quantity < 1000;
         ++initial_quantity) {
        if (initial_quantity == 1) {
            continue;
        }
        slp_check_err(
            slp::GenesisOpreturn(GenesisInfo{}, SlpTokenType::Nft1Child(),
                                 std::nullopt, initial_quantity),
            ParseError::Nft1ChildInvalidInitialQuantity(initial_quantity));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_genesis_nft_child_invalid_decimals) {
    for (uint8_t decimals = 1; decimals <= 9; ++decimals) {
        slp_check_err(slp::GenesisOpreturn(InfoWithDecimals(decimals),
                                           SlpTokenType::Nft1Child(),
                                           std::nullopt, 1),
                      ParseError::Nft1ChildInvalidDecimals(decimals));
    }
}

BOOST_AUTO_TEST_CASE(test_parse_valid_genesis) {
    const std::vector<std::pair<uint8_t, SlpTokenType>> token_types{
        {1, SlpTokenType::Fungible()},
        {2, SlpTokenType::MintVault()},
        {0x41, SlpTokenType::Nft1Child()},
        {0x81, SlpTokenType::Nft1Group()},
    };

    std::array<uint8_t, 32> counting;
    for (size_t i = 0; i < 32; ++i) {
        counting[i] = uint8_t(i % 10);
    }
    std::array<uint8_t, 32> zeros{};
    std::array<uint8_t, 32> ffs;
    ffs.fill(0xff);
    const std::vector<std::optional<std::array<uint8_t, 32>>>
        token_document_hashes{std::nullopt, zeros, ffs, counting};

    const TxId txid = MakeTxId(100);
    for (const auto &[type_byte, token_type] : token_types) {
        for (const auto &token_document_hash : token_document_hashes) {
            const bool is_child = token_type == SlpTokenType::Nft1Child();
            const bool is_vault = token_type == SlpTokenType::MintVault();
            const uint8_t qty = is_child ? 1 : 123;
            const uint8_t decimals = is_child ? 0 : 9;
            const Bytes hash_push =
                token_document_hash
                    ? Cat({{32},
                           Bytes(token_document_hash->begin(),
                                 token_document_hash->end())})
                    : Bytes{0x4c, 0x00};
            const Bytes baton_push = is_vault   ? Rep(0x14, 21)
                                     : is_child ? Bytes{0x4c, 0x00}
                                                : Bytes{0x01, 0x04};
            const Bytes script =
                Cat({GenesisPrefix(type_byte),
                     {0x01, 0x44, 0x01, 0x55, 0x01, 0x66},
                     hash_push,
                     {0x01, decimals},
                     baton_push,
                     {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, qty}});

            GenesisInfo info;
            info.token_ticker = {0x44};
            info.token_name = {0x55};
            info.url = {0x66};
            info.hash = token_document_hash;
            if (is_vault) {
                ShaRmd160 scripthash;
                scripthash.fill(0x14);
                info.mint_vault_scripthash = scripthash;
            }
            info.decimals = decimals;
            const ParsedMintData mint_data =
                is_vault || is_child
                    ? ParsedMintData{{qty}, 0}
                    : ParsedMintData{{qty, 0, 0}, 1};
            BOOST_CHECK(slp::Parse(txid, script) ==
                        SlpOk(ParsedData{
                            TokenMeta{TokenId{txid}, TokenType::Slp(token_type)},
                            ParsedTxType::MakeGenesis(
                                ParsedGenesis{info, mint_data}),
                        }));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
