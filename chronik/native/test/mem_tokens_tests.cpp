// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db mem/tokens.rs tests, plus the Mempool driven through
// MempoolTokens as its MempoolTokenHook (token ID history/UTXOs).

#include <chronik/native/codec/hex.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/mem/tokens.h>
#include <chronik/native/schema.h>
#include <chronik/native/token/parse.h>

#include <test/index_test_util.h>
#include <test/token_io_mock.h>
#include <test/token_test_helpers.h>

#include <boost/test/unit_test.hpp>

#include <map>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::mem;
using chronik::native::test::ErrorMsg;
using chronik::native::test::make_tx;
using chronik::native::test::make_tx_with_scripts;
using chronik::native::test::MockTokenDb;
using chronik::native::test::TestDb;
using chronik::native::test::TxIdNum;
using token::test::check_token_tx;
using token::test::empty_entry;
using token::test::meta_slp;
using token::test::spent_atoms;
using token::test::spent_atoms_group;
using token::test::spent_baton;
using token::test::TOKEN_ID1;
using token::test::TOKEN_ID3;
using token::test::TOKEN_ID4;
using token::test::TOKEN_ID5;
using token::test::TOKEN_ID8;
using token::test::token_atoms;
using token::test::token_baton;

namespace {

OutPoint outpoint(uint8_t txid_num, uint32_t out_idx) {
    return OutPoint{TxIdNum(txid_num), out_idx};
}

Bytes Slp(const script::Script &script) {
    return script.bytecode();
}

using SpentResult = Result<std::optional<SpentToken>, MempoolTokensError>;

SpentResult Ok(std::optional<SpentToken> token) {
    return SpentResult(std::move(token));
}

TokenTxEntry Entry(TokenMeta meta, std::optional<TxType> tx_type) {
    TokenTxEntry entry = empty_entry();
    entry.meta = meta;
    entry.tx_type = tx_type;
    return entry;
}

struct MempoolFixture {
    TestDb db{"mem_tokens"};
    MockTokenDb mock_db{*db};
    std::map<TxId, TxRef> mempool_txs;
    MempoolTokens mempool_tokens;
    IsMempoolTxFn is_mempool_tx = [this](const TxId &txid) {
        return mempool_txs.count(txid) > 0;
    };

    void add_to_mempool(Tx tx) {
        const MempoolTx mempool_tx{std::make_shared<const Tx>(std::move(tx)),
                                   0};
        mempool_tokens.Insert(*db, mempool_tx, is_mempool_tx);
        mempool_txs.emplace(mempool_tx.tx->txid, mempool_tx.tx);
    }

    void remove_from_mempool(const TxId &txid) {
        mempool_tokens.Remove(txid);
        mempool_txs.erase(txid);
    }

    void generate() {
        std::vector<Tx> txs;
        for (const auto &[txid, tx] : mempool_txs) {
            txs.push_back(*tx);
        }
        mempool_txs.clear();
        mock_db.Connect(txs);
        mempool_tokens.Clear();
    }

    SpentTokensResult fetch(const Tx &tx) {
        auto txn = db->BeginRead();
        return mempool_tokens.FetchTxSpentTokens(*db, *txn, tx,
                                                 is_mempool_tx);
    }

    const TokenTx &token_tx(uint8_t num) {
        const TokenTx *tx = mempool_tokens.TokenTx(TxIdNum(num));
        BOOST_REQUIRE(tx);
        return *tx;
    }
};

void CheckInputs(const SpentTokens *actual,
                 const std::optional<SpentTokens> &expected) {
    if (!expected) {
        BOOST_CHECK(actual == nullptr);
        return;
    }
    BOOST_REQUIRE(actual != nullptr);
    BOOST_CHECK(*actual == *expected);
}

} // namespace

BOOST_AUTO_TEST_SUITE(mem_tokens_tests)

BOOST_AUTO_TEST_CASE(test_mempool_tokens) {
    MempoolFixture f;
    const SlpTokenType FUNGIBLE = SlpTokenType::Fungible();
    const SlpTokenType MINT_VAULT = SlpTokenType::MintVault();
    const SlpTokenType GROUP = SlpTokenType::Nft1Group();
    const SlpTokenType CHILD = SlpTokenType::Nft1Child();

    // Tx 0: Adding a non-token tx to the mempool indexes nothing
    f.add_to_mempool(make_tx(0, {}, 1, {}));
    BOOST_CHECK(!f.mempool_tokens.TokenTx(TxIdNum(0)));
    BOOST_CHECK(!f.mempool_tokens.TxTokenInputs(TxIdNum(0)));
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(0, 1)) == Ok({}));
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(0, 9999)) == Ok({}));

    // Tx 1: Invalid BURN indexed in mempool
    f.add_to_mempool(
        make_tx(1, {}, 1, Slp(slp::BurnOpreturn(TOKEN_ID1, FUNGIBLE, 1000))));
    {
        TokenTxEntry entry = Entry(meta_slp(TOKEN_ID1, FUNGIBLE), TxType::BURN);
        entry.intentional_burn_atoms = 1000;
        check_token_tx(f.token_tx(1), TokenTx{{entry}, {std::nullopt,
                                                        std::nullopt}, {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(1)), std::nullopt);
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(1, 1)) == Ok({}));

    // Tx 2: Valid empty SEND indexed in mempool
    f.add_to_mempool(make_tx(
        2, {}, 1, Slp(slp::SendOpreturn(TOKEN_ID1, FUNGIBLE, {0, 0}))));
    check_token_tx(f.token_tx(2),
                   TokenTx{{Entry(meta_slp(TOKEN_ID1, FUNGIBLE), TxType::SEND)},
                           {std::nullopt, std::nullopt},
                           {}});
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(2)), std::nullopt);
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(2, 1)) == Ok({}));
    {
        const auto result = f.mempool_tokens.SpentToken(outpoint(2, 9999));
        BOOST_REQUIRE(!result.ok());
        BOOST_CHECK(result.error() ==
                    MempoolTokensError::InputTxNoSuchOutput(outpoint(2, 9999)));
    }

    // Tx 3: Add SLP Fungible GENESIS
    GenesisInfo genesis_info3;
    genesis_info3.token_ticker = token::test::B("SLP FUNGIBLE");
    genesis_info3.token_name = token::test::B("Fungible SLP token");
    genesis_info3.url = token::test::B("https://fungible.slp/");
    genesis_info3.hash.emplace();
    genesis_info3.hash->fill(44);
    genesis_info3.decimals = 4;
    f.add_to_mempool(make_tx(
        3, {}, 2,
        Slp(slp::GenesisOpreturn(genesis_info3, FUNGIBLE, 2, 1234))));
    BOOST_REQUIRE(f.mempool_tokens.GenesisInfo(TxIdNum(3)));
    BOOST_CHECK(*f.mempool_tokens.GenesisInfo(TxIdNum(3)) == genesis_info3);
    {
        TokenTxEntry entry =
            Entry(meta_slp(TOKEN_ID3, FUNGIBLE), TxType::GENESIS);
        entry.genesis_info = genesis_info3;
        check_token_tx(f.token_tx(3),
                       TokenTx{{entry},
                               {
                                   std::nullopt, // OP_RETURN never has tokens
                                   token_atoms<0>(1234),
                                   token_baton<0>(),
                               },
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(3)), std::nullopt);
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(3, 1)) ==
                Ok(spent_atoms(meta_slp(TOKEN_ID3, FUNGIBLE), 1234)));
    BOOST_CHECK(f.mempool_tokens.SpentToken(outpoint(3, 2)) ==
                Ok(spent_baton(meta_slp(TOKEN_ID3, FUNGIBLE))));

    // Tx 4: Add SLP V2 Mint Vault GENESIS
    script::ShaRmd160 mint_vault_scripthash;
    mint_vault_scripthash.fill(2);
    GenesisInfo genesis_info4;
    genesis_info4.token_ticker = token::test::B("SLP Mint Vault");
    genesis_info4.token_name = token::test::B("Mint Vault SLP token");
    genesis_info4.url = token::test::B("https://mintvault.slp/");
    genesis_info4.mint_vault_scripthash = mint_vault_scripthash;
    genesis_info4.hash.emplace();
    genesis_info4.hash->fill(55);
    genesis_info4.decimals = 4;
    f.add_to_mempool(make_tx(
        4, {}, 1,
        Slp(slp::GenesisOpreturn(genesis_info4, MINT_VAULT, std::nullopt,
                                 1000))));
    BOOST_REQUIRE(f.mempool_tokens.GenesisInfo(TxIdNum(4)));
    BOOST_CHECK(*f.mempool_tokens.GenesisInfo(TxIdNum(4)) == genesis_info4);
    {
        TokenTxEntry entry =
            Entry(meta_slp(TOKEN_ID4, MINT_VAULT), TxType::GENESIS);
        entry.genesis_info = genesis_info4;
        check_token_tx(f.token_tx(4),
                       TokenTx{{entry},
                               {std::nullopt, token_atoms<0>(1000)},
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(4)), std::nullopt);

    // Tx 5: Add SLP NFT1 GROUP GENESIS
    f.add_to_mempool(make_tx(
        5, {}, 2,
        Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(), GROUP, 2, 10))));
    BOOST_REQUIRE(f.mempool_tokens.GenesisInfo(TxIdNum(5)));
    BOOST_CHECK(*f.mempool_tokens.GenesisInfo(TxIdNum(5)) ==
                GenesisInfo::EmptySlp());
    {
        TokenTxEntry entry = Entry(meta_slp(TOKEN_ID5, GROUP), TxType::GENESIS);
        entry.genesis_info = GenesisInfo::EmptySlp();
        check_token_tx(f.token_tx(5),
                       TokenTx{{entry},
                               {std::nullopt, token_atoms<0>(10),
                                token_baton<0>()},
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(5)), std::nullopt);

    // Tx 6: Invalid mempool SLP V2 Mint Vault MINT: GENESIS still in
    // mempool, but needs at least 1 confirmation
    const Bytes p2sh_vault =
        script::Script::P2sh(mint_vault_scripthash).bytecode();
    f.add_to_mempool(make_tx_with_scripts(
        6, {{4, 0, p2sh_vault}}, 3,
        Slp(slp::MintVaultOpreturn(TOKEN_ID4, {1, 2, 3}))));
    {
        TokenTxEntry entry = Entry(meta_slp(TOKEN_ID4, MINT_VAULT), TxType::MINT);
        entry.is_invalid = true;
        entry.burn_error = BurnError::MissingMintVault();
        check_token_tx(f.token_tx(6),
                       TokenTx{{entry},
                               {std::nullopt, std::nullopt, std::nullopt,
                                std::nullopt},
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(6)), std::nullopt);

    // Tx 7: Valid SEND of mempool GENESIS output (NftGroup)
    f.add_to_mempool(make_tx(
        7, {{5, 1}}, 4, Slp(slp::SendOpreturn(TOKEN_ID5, GROUP, {1, 2, 3, 4}))));
    check_token_tx(f.token_tx(7),
                   TokenTx{{Entry(meta_slp(TOKEN_ID5, GROUP), TxType::SEND)},
                           {std::nullopt, token_atoms<0>(1), token_atoms<0>(2),
                            token_atoms<0>(3), token_atoms<0>(4)},
                           {}});
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(7)),
                SpentTokens{spent_atoms(meta_slp(TOKEN_ID5, GROUP), 10)});

    // Tx 8: Valid NFT1 CHILD GENESIS using mempool SEND output, also burn
    // some SLP V2 Mint Vault tokens
    f.add_to_mempool(make_tx(
        8, {{7, 1}, {4, 1}}, 1,
        Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(), CHILD, std::nullopt,
                                 1))));
    BOOST_REQUIRE(f.mempool_tokens.GenesisInfo(TxIdNum(8)));
    BOOST_CHECK(*f.mempool_tokens.GenesisInfo(TxIdNum(8)) ==
                GenesisInfo::EmptySlp());
    {
        TokenTxEntry e0 = Entry(meta_slp(TOKEN_ID8, CHILD), TxType::GENESIS);
        e0.group_token_meta = meta_slp(TOKEN_ID5, GROUP);
        e0.genesis_info = GenesisInfo::EmptySlp();
        TokenTxEntry e1 = Entry(meta_slp(TOKEN_ID4, MINT_VAULT), std::nullopt);
        e1.is_invalid = true;
        e1.actual_burn_atoms = 1000;
        TokenTxEntry e2 = Entry(meta_slp(TOKEN_ID5, GROUP), std::nullopt);
        check_token_tx(f.token_tx(8),
                       TokenTx{{e0, e1, e2},
                               {std::nullopt, token_atoms<0>(1)},
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(8)),
                SpentTokens{spent_atoms(meta_slp(TOKEN_ID5, GROUP), 1),
                            spent_atoms(meta_slp(TOKEN_ID4, MINT_VAULT),
                                        1000)});

    // Mine all txs in the mempool
    f.generate();

    // Tx 9: Invalid SLP V2 Mint Vault MINT: GENESIS now confirmed, but
    // wrong mint_vault_scriphash
    script::ShaRmd160 wrong_hash;
    wrong_hash.fill(99);
    f.add_to_mempool(make_tx_with_scripts(
        9, {{4, 0, script::Script::P2sh(wrong_hash).bytecode()}}, 1,
        Slp(slp::MintVaultOpreturn(TOKEN_ID4, {123}))));
    {
        TokenTxEntry entry = Entry(meta_slp(TOKEN_ID4, MINT_VAULT), TxType::MINT);
        entry.is_invalid = true;
        entry.burn_error = BurnError::MissingMintVault();
        check_token_tx(f.token_tx(9),
                       TokenTx{{entry}, {std::nullopt, std::nullopt}, {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(9)), std::nullopt);

    // Tx 10: Valid SLP V2 Mint Vault MINT: GENESIS now confirmed
    f.add_to_mempool(make_tx_with_scripts(
        10, {{4, 0, p2sh_vault}}, 1,
        Slp(slp::MintVaultOpreturn(TOKEN_ID4, {123}))));
    check_token_tx(
        f.token_tx(10),
        TokenTx{{Entry(meta_slp(TOKEN_ID4, MINT_VAULT), TxType::MINT)},
                {std::nullopt, token_atoms<0>(123)},
                {}});
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(10)), std::nullopt);

    // Valid SEND using both mempool and DB inputs
    f.add_to_mempool(make_tx(
        11, {{3, 1}, {8, 1}, {10, 1}}, 4,
        Slp(slp::SendOpreturn(TOKEN_ID3, FUNGIBLE, {100, 200, 300, 400}))));
    {
        TokenTxEntry e0 = Entry(meta_slp(TOKEN_ID3, FUNGIBLE), TxType::SEND);
        e0.actual_burn_atoms = 234;
        TokenTxEntry e1 = Entry(meta_slp(TOKEN_ID4, MINT_VAULT), std::nullopt);
        e1.is_invalid = true;
        e1.actual_burn_atoms = 123;
        TokenTxEntry e2 = Entry(meta_slp(TOKEN_ID8, CHILD), std::nullopt);
        e2.group_token_meta = meta_slp(TOKEN_ID5, GROUP);
        e2.is_invalid = true;
        e2.actual_burn_atoms = 1;
        check_token_tx(f.token_tx(11),
                       TokenTx{{e0, e1, e2},
                               {std::nullopt, token_atoms<0>(100),
                                token_atoms<0>(200), token_atoms<0>(300),
                                token_atoms<0>(400)},
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(11)),
                SpentTokens{spent_atoms(meta_slp(TOKEN_ID3, FUNGIBLE), 1234),
                            spent_atoms_group(meta_slp(TOKEN_ID8, CHILD), 1,
                                              meta_slp(TOKEN_ID5, GROUP)),
                            spent_atoms(meta_slp(TOKEN_ID4, MINT_VAULT),
                                        123)});

    // Bare burn
    f.add_to_mempool(make_tx(12, {{11, 2}}, 2, {}));
    {
        TokenTxEntry entry = Entry(meta_slp(TOKEN_ID3, FUNGIBLE), std::nullopt);
        entry.is_invalid = true;
        entry.actual_burn_atoms = 200;
        check_token_tx(f.token_tx(12),
                       TokenTx{{entry},
                               std::vector<std::optional<TokenOutput>>(3),
                               {}});
    }
    CheckInputs(f.mempool_tokens.TxTokenInputs(TxIdNum(12)),
                SpentTokens{spent_atoms(meta_slp(TOKEN_ID3, FUNGIBLE), 200)});

    // Test fetch_tx_spent_tokens

    // Tx fff...fff not found
    {
        const auto result = f.fetch(make_tx(1, {{0xff, 0}}, 0, {}));
        BOOST_REQUIRE(!result.ok());
        BOOST_CHECK(result.error() ==
                    MempoolTokensError::InputTxNotFound(TxIdNum(0xff)));
        BOOST_CHECK_EQUAL(
            result.error().ToString(),
            "Failed indexing mempool token tx: Tx is spending "
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff "
            "which is found neither in the mempool nor DB");
    }

    // Tx 11 in the mempool but no such output
    {
        const auto result = f.fetch(make_tx(1, {{11, 9999}}, 0, {}));
        BOOST_REQUIRE(!result.ok());
        BOOST_CHECK(result.error() ==
                    MempoolTokensError::InputTxNoSuchOutput(outpoint(11, 9999)));
        BOOST_CHECK_EQUAL(
            result.error().ToString(),
            "Failed indexing mempool token tx: Tx spends non-existent token "
            "output OutPoint { txid: TxId(" +
                HashToHex(TxIdNum(11)) + "), out_idx: 9999 }");
    }

    // Tx 3 in the DB but no such output
    {
        const auto result = f.fetch(make_tx(1, {{3, 9999}}, 0, {}));
        BOOST_REQUIRE(!result.ok());
        BOOST_CHECK(result.error() ==
                    MempoolTokensError::InputTxNoSuchOutput(outpoint(3, 9999)));
    }

    // Force-delete TokenMeta for TOKEN_ID4 (MintVault), simulate corruption
    {
        auto txn = f.db->BeginWrite();
        const auto key = index::TxNumToBytes(4);
        txn->Del(f.db->Table(schema::kTokenMeta), ByteView(key));
        txn->Commit();
    }

    // Now the TokenMeta for an input with that token ID fails to load
    BOOST_CHECK_EQUAL(ErrorMsg([&] { f.fetch(make_tx(1, {{4, 1}}, 0, {})); }),
                      "Inconsistent DB: Token TxNum 4 not found in DB");
    BOOST_CHECK_THROW(f.fetch(make_tx(1, {{4, 1}}, 0, {})),
                      token_io::TokenIndexError);

    // However, if the output doesn't have a token assigned, we don't even
    // query that TokenMeta, so this will work fine:
    {
        const auto result = f.fetch(make_tx(1, {{4, 0}}, 0, {}));
        BOOST_REQUIRE(result.ok());
        BOOST_CHECK(result.value() == SpentTokens{std::nullopt});
    }

    // Tx 8 burns some (force-deleted) Token 4, but this is not queried
    // either, so this succeeds, too:
    {
        const auto result = f.fetch(make_tx(1, {{8, 1}}, 0, {}));
        BOOST_REQUIRE(result.ok());
        BOOST_CHECK(result.value() ==
                    SpentTokens{spent_atoms_group(meta_slp(TOKEN_ID8, CHILD), 1,
                                                  meta_slp(TOKEN_ID5, GROUP))});
    }

    // Remove tx 12 from mempool
    f.remove_from_mempool(TxIdNum(12));
    BOOST_CHECK(!f.mempool_tokens.TokenTx(TxIdNum(12)));
    BOOST_CHECK(!f.mempool_tokens.TxTokenInputs(TxIdNum(12)));

    // Remove tx 11 from mempool
    f.remove_from_mempool(TxIdNum(11));
    BOOST_CHECK(!f.mempool_tokens.TokenTx(TxIdNum(11)));
    BOOST_CHECK(!f.mempool_tokens.TxTokenInputs(TxIdNum(11)));

    // Remove tx 10 from mempool
    f.remove_from_mempool(TxIdNum(10));
    BOOST_CHECK(!f.mempool_tokens.TokenTx(TxIdNum(10)));
    BOOST_CHECK(!f.mempool_tokens.TxTokenInputs(TxIdNum(10)));
}

// ---- Additional: MempoolTokens as the Mempool's token hook ----

BOOST_AUTO_TEST_CASE(test_mempool_token_hook_indexes_token_ids) {
    TestDb db("mem_tokens_hook");
    Mempool mempool(
        std::make_shared<groups::ScriptGroup>(
            [](ByteView data, uint8_t out[32]) {
                chronik::native::test::TestSha256(data, out);
            }),
        /*enable_token_index=*/true, /*is_lokad_id_index_enabled=*/false,
        std::make_unique<MempoolTokens>());
    const MempoolTokens *tokens = MempoolTokens::FromHook(mempool.Tokens());
    BOOST_REQUIRE(tokens);

    const auto make = [](Tx tx) {
        return MempoolTx{std::make_shared<const Tx>(std::move(tx)), 100};
    };
    // GENESIS in the mempool (no inputs needed for the token index)
    auto result = mempool.Insert(
        *db, make(make_tx(3, {}, 2,
                          Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                                   SlpTokenType::Fungible(),
                                                   2, 1234)))));
    BOOST_REQUIRE(result.token_id_aux);
    const auto *aux =
        dynamic_cast<const groups::TokenIdGroupAux *>(result.token_id_aux.get());
    BOOST_REQUIRE(aux);
    BOOST_REQUIRE_EQUAL(aux->txs.count(TxIdNum(3)), 1u);
    const auto &[inputs, outputs] = aux->txs.at(TxIdNum(3));
    BOOST_CHECK(inputs.empty());
    BOOST_REQUIRE_EQUAL(outputs.size(), 3u);
    BOOST_CHECK(!outputs[0]);
    BOOST_CHECK(outputs[1] == TOKEN_ID3);
    BOOST_CHECK(outputs[2] == TOKEN_ID3);

    const auto be = TOKEN_ID3.ToBeBytes();
    const Bytes member_ser(be.begin(), be.end());
    const auto *history = mempool.TokenIdHistory()->MemberHistory(member_ser);
    BOOST_REQUIRE(history);
    BOOST_CHECK_EQUAL(history->size(), 1u);
    const auto *utxos = mempool.TokenIdUtxos()->GetUtxos(member_ser);
    BOOST_REQUIRE(utxos);
    BOOST_CHECK(*utxos == (std::set<OutPoint>{outpoint(3, 1), outpoint(3, 2)}));

    // SEND spending the mempool GENESIS
    result = mempool.Insert(
        *db,
        make(make_tx(4, {{3, 1}}, 1,
                     Slp(slp::SendOpreturn(TOKEN_ID3, SlpTokenType::Fungible(),
                                           {1234})))));
    BOOST_CHECK(tokens->TxTokenInputs(TxIdNum(4)));
    utxos = mempool.TokenIdUtxos()->GetUtxos(member_ser);
    BOOST_REQUIRE(utxos);
    BOOST_CHECK(*utxos == (std::set<OutPoint>{outpoint(3, 2), outpoint(4, 1)}));
    BOOST_CHECK_EQUAL(mempool.TokenIdHistory()->MemberHistory(member_ser)->size(),
                      2u);

    // Probe (not added)
    const auto probed = mempool.ProbeTx(
        *db, make(make_tx(5, {{4, 1}}, 1, {})));
    BOOST_REQUIRE(probed.token_id_aux);
    const auto *probe_aux =
        dynamic_cast<const groups::TokenIdGroupAux *>(probed.token_id_aux.get());
    BOOST_REQUIRE(probe_aux);
    BOOST_CHECK(probe_aux->txs.at(TxIdNum(5)).first ==
                TokenIdSubsAux::MaybeTokenIds{TOKEN_ID3});
    BOOST_CHECK(!tokens->TokenTx(TxIdNum(5)));
    // Probe of a tx without any token data
    BOOST_CHECK(!mempool.ProbeTx(*db, make(make_tx(6, {{4, 0}}, 1, {})))
                     .token_id_aux);

    // Inserting a tx spending an unknown tx fails with the Rust text
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] {
            mempool.Insert(*db, make(make_tx(7, {{0xee, 0}}, 1, {})));
        }),
        "Failed indexing mempool token tx: Tx is spending " +
            HashToHex(TxIdNum(0xee)) +
            " which is found neither in the mempool nor DB");

    // Remove the SEND: tokens of its inputs are back
    mempool.Remove(TxIdNum(4));
    BOOST_CHECK(!tokens->TokenTx(TxIdNum(4)));
    utxos = mempool.TokenIdUtxos()->GetUtxos(member_ser);
    BOOST_REQUIRE(utxos);
    BOOST_CHECK(*utxos == (std::set<OutPoint>{outpoint(3, 1), outpoint(3, 2)}));

    // Remove mined GENESIS
    BOOST_CHECK(mempool.RemoveMined(TxIdNum(3)).has_value());
    BOOST_CHECK(!tokens->TokenTx(TxIdNum(3)));
    BOOST_CHECK(!mempool.TokenIdUtxos()->GetUtxos(member_ser));
}

BOOST_AUTO_TEST_SUITE_END()
