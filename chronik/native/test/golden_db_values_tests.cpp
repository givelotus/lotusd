// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Golden DB value tests. Vectors come from the Rust exporter
// chronik/chronik-db/tests/export_native_db_values.rs, run against the
// eCash-tier chronik-db (fixtures/db_values.json). Each case is checked both
// ways: the value is built natively (mirroring the Rust exporter) and encoded,
// which must give the Rust bytes; and the Rust bytes are decoded natively,
// which must give the same value and re-encode to the same bytes.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/extension.h>
#include <chronik/native/index/block_stats.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/index/data.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/index/reverse_lookup.h>
#include <chronik/native/index/spent_by.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token_io/data.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::token::AlpTokenType;
using chronik::native::token::GenesisInfo;
using chronik::native::token::SlpTokenType;
using chronik::native::token::TokenId;
using chronik::native::token::TokenMeta;
using chronik::native::token::TokenType;
using chronik::native::token_io::DbToken;
using chronik::native::token_io::DbTokenTx;

namespace {

/** Loads the flat {"name": "hex"} JSON object written by the exporter. */
std::map<std::string, Bytes> LoadFixtures() {
    std::ifstream in(std::string(CHRONIK_NATIVE_FIXTURES_DIR) +
                     "/db_values.json");
    BOOST_REQUIRE_MESSAGE(in, "missing fixtures/db_values.json");
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string s = ss.str();
    std::map<std::string, Bytes> out;
    size_t pos = 0;
    while (true) {
        const size_t k0 = s.find('"', pos);
        if (k0 == std::string::npos) {
            break;
        }
        const size_t k1 = s.find('"', k0 + 1);
        const size_t v0 = s.find('"', k1 + 1);
        const size_t v1 = s.find('"', v0 + 1);
        BOOST_REQUIRE(k1 != std::string::npos && v1 != std::string::npos);
        auto bytes = HexDecode(s.substr(v0 + 1, v1 - v0 - 1));
        BOOST_REQUIRE(bytes);
        out[s.substr(k0 + 1, k1 - k0 - 1)] = *bytes;
        pos = v1 + 1;
    }
    BOOST_REQUIRE(!out.empty());
    return out;
}

const std::map<std::string, Bytes> &Fixtures() {
    static const std::map<std::string, Bytes> fixtures = LoadFixtures();
    return fixtures;
}

/** Names of the fixtures checked so far (to require full coverage). */
std::set<std::string> &Used() {
    static std::set<std::string> used;
    return used;
}

const Bytes &Fx(const std::string &name) {
    auto it = Fixtures().find(name);
    BOOST_REQUIRE_MESSAGE(it != Fixtures().end(), "missing fixture " + name);
    Used().insert(name);
    return it->second;
}

void CheckBytes(const std::string &name, const Bytes &actual) {
    BOOST_CHECK_MESSAGE(actual == Fx(name), name + ": native " +
                                                HexEncode(actual) + " != rust " +
                                                HexEncode(Fx(name)));
}

/**
 * Both directions: Enc(value) == rust bytes; Dec(rust bytes) == value and
 * Enc(Dec(rust bytes)) == rust bytes.
 */
template <typename T, typename Enc, typename Dec>
void RoundTrip(const std::string &name, const T &value, Enc &&enc, Dec &&dec) {
    CheckBytes(name, enc(value));
    const T decoded = dec(ByteView(Fx(name)));
    BOOST_CHECK_MESSAGE(decoded == value, name + ": decoded value differs");
    CheckBytes(name, enc(decoded));
}

Bytes Seq(size_t n, uint8_t mul, uint8_t add) {
    Bytes out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = uint8_t(uint8_t(i) * mul + add);
    }
    return out;
}

std::array<uint8_t, 32> Arr32(uint8_t mul, uint8_t add) {
    std::array<uint8_t, 32> a;
    const Bytes s = Seq(32, mul, add);
    std::copy(s.begin(), s.end(), a.begin());
    return a;
}

std::array<uint8_t, 32> Fill32(uint8_t v) {
    std::array<uint8_t, 32> a;
    a.fill(v);
    return a;
}

Bytes Str(std::string_view s) { return Bytes(s.begin(), s.end()); }

TokenId MakeTokenId(uint8_t mul, uint8_t add) {
    return TokenId{Hash32{Arr32(mul, add)}};
}

/** Test column type for ReverseLookup<L>::SerSerials/DeserSerials. */
struct TxNumSerial {
    using SerialNum = TxNum;
    using Data = SerTx;
    static constexpr std::string_view kSerialTypeName = "u64";
    static constexpr std::string_view kSerialVecTypeName =
        "alloc::vec::Vec<u64>";
    static void SerSerial(postcard::Writer &w, TxNum n) { w.U64(n); }
    static TxNum DeserSerial(postcard::Reader &r) { return r.U64(); }
};

struct HeightSerial {
    using SerialNum = BlockHeight;
    using Data = SerBlock;
    static constexpr std::string_view kSerialTypeName = "i32";
    static constexpr std::string_view kSerialVecTypeName =
        "alloc::vec::Vec<i32>";
    static void SerSerial(postcard::Writer &w, BlockHeight h) { w.I32(h); }
    static BlockHeight DeserSerial(postcard::Reader &r) { return r.I32(); }
};

/** db_serialize_vec::<TxNum> (history pages and CONCAT operands). */
Bytes SerTxNums(const std::vector<TxNum> &tx_nums) {
    Bytes out;
    postcard::Writer w(out);
    for (const TxNum n : tx_nums) {
        w.U64(n);
    }
    return out;
}

std::vector<TxNum> DeserTxNums(ByteView bytes) {
    return postcard::DbDeserializeVec(
        bytes, "u64", [](postcard::Reader &r) { return r.U64(); });
}

template <typename T, size_t N> Bytes ToBytes(const std::array<T, N> &a) {
    return Bytes(a.begin(), a.end());
}

} // namespace

BOOST_AUTO_TEST_SUITE(golden_db_values_tests)

BOOST_AUTO_TEST_CASE(ser_block) {
    const auto enc = [](const SerBlock &b) { return SerializeSerBlock(b); };
    const auto dec = [](ByteView b) { return DeserializeSerBlock(b); };
    RoundTrip("SerBlock/genesis",
              SerBlock{Arr32(1, 0), 0x207fffff, 1296688602, 0, 8}, enc, dec);
    RoundTrip("SerBlock/max",
              SerBlock{Fill32(0xff), UINT32_MAX,
                       std::numeric_limits<int64_t>::max(), UINT32_MAX,
                       UINT32_MAX},
              enc, dec);
    RoundTrip("SerBlock/neg_ts",
              SerBlock{Arr32(3, 7), 0x1d00ffff,
                       std::numeric_limits<int64_t>::min(), 127, 128},
              enc, dec);
}

BOOST_AUTO_TEST_CASE(be_keys_and_values) {
    for (const BlockHeight h : {0, 1, 1000000, INT32_MAX}) {
        RoundTrip(
            "BlockHeightBe/" + std::to_string(h), h,
            [](BlockHeight v) { return ToBytes(BhToBytes(v)); },
            [](ByteView b) { return BytesToBh(b); });
    }
    for (const TxNum n :
         {TxNum(0), TxNum(1), TxNum(1) << 40, std::numeric_limits<TxNum>::max()}) {
        RoundTrip(
            "TxNumBe/" + std::to_string(n), n,
            [](TxNum v) { return ToBytes(TxNumToBytes(v)); },
            [](ByteView b) { return BytesToTxNum(b); });
    }
    for (const NumTxs n : {NumTxs(0), NumTxs(1), NumTxs(1000), UINT32_MAX}) {
        RoundTrip(
            "NumTxsBe/" + std::to_string(n), n,
            [](NumTxs v) { return ToBytes(ToBe<NumTxs>(v)); },
            [](ByteView b) { return BytesToNumTxs(b); });
    }
    const Bytes member{0x01, 0x02, 0x03};
    for (const PageNum page : {PageNum(0), PageNum(1), PageNum(0x01020304)}) {
        CheckBytes("HistoryPageKey/" + std::to_string(page),
                   KeyForMemberPage(member, page));
    }
}

BOOST_AUTO_TEST_CASE(block_stats) {
    const auto enc = [](const BlockStats &s) { return SerializeBlockStats(s); };
    const auto dec = [](ByteView b) { return DeserializeBlockStats(b); };
    RoundTrip("BlockStats/zero", BlockStats{}, enc, dec);
    RoundTrip("BlockStats/typical",
              BlockStats{285, 1, 1, 2, 0, 5000000000, 0, 0}, enc, dec);
    RoundTrip("BlockStats/extremes",
              BlockStats{std::numeric_limits<uint64_t>::max(), 128,
                         uint64_t(1) << 35, 0x3fff,
                         std::numeric_limits<int64_t>::max(),
                         std::numeric_limits<int64_t>::min(), -1, 64},
              enc, dec);
}

BOOST_AUTO_TEST_CASE(ser_tx) {
    const auto enc = [](const SerTx &t) { return SerializeSerTx(t); };
    const auto dec = [](ByteView b) { return DeserializeSerTx(b); };
    RoundTrip("SerTx/coinbase", SerTx{Arr32(2, 9), 81, 0, 0}, enc, dec);
    RoundTrip("SerTx/normal", SerTx{Arr32(5, 7), 0x00ffff00, 0x1234, 1699999999},
              enc, dec);
    RoundTrip("SerTx/max", SerTx{Fill32(0xee), UINT32_MAX, UINT32_MAX, -1},
              enc, dec);
    // TxEntry <-> SerTx (undo_pos == 0 <==> coinbase)
    const SerTx coinbase = DeserializeSerTx(Fx("SerTx/coinbase"));
    BOOST_CHECK(FromSerTx(coinbase).is_coinbase);
    BOOST_CHECK(ToSerTx(FromSerTx(coinbase)) == coinbase);
    BOOST_CHECK(!FromSerTx(DeserializeSerTx(Fx("SerTx/normal"))).is_coinbase);
}

BOOST_AUTO_TEST_CASE(reverse_lookup_values) {
    using TxLookup = ReverseLookup<TxNumSerial>;
    using BlkLookup = ReverseLookup<HeightSerial>;
    const auto enc_tx = [](const std::vector<TxNum> &v) {
        return TxLookup::SerSerials(v);
    };
    const auto dec_tx = [](ByteView b) { return TxLookup::DeserSerials(b); };
    RoundTrip("LookupTxNums/one", std::vector<TxNum>{5}, enc_tx, dec_tx);
    RoundTrip("LookupTxNums/many",
              std::vector<TxNum>{0, 127, 128, TxNum(1) << 40,
                                 std::numeric_limits<TxNum>::max()},
              enc_tx, dec_tx);
    RoundTrip("LookupTxNums/empty", std::vector<TxNum>{}, enc_tx, dec_tx);
    const auto enc_bh = [](const std::vector<BlockHeight> &v) {
        return BlkLookup::SerSerials(v);
    };
    const auto dec_bh = [](ByteView b) { return BlkLookup::DeserSerials(b); };
    RoundTrip("LookupHeights/one", std::vector<BlockHeight>{0}, enc_bh, dec_bh);
    RoundTrip("LookupHeights/many",
              std::vector<BlockHeight>{1, 63, 64, 1000000, INT32_MAX}, enc_bh,
              dec_bh);
    // Merge operands: one postcard serial.
    RoundTrip(
        "LookupTxNumOperand/300", TxNum(300),
        [](TxNum n) {
            Bytes out;
            postcard::Writer w(out);
            TxNumSerial::SerSerial(w, n);
            return out;
        },
        [](ByteView b) {
            return postcard::DbDeserialize(b, "u64", [](postcard::Reader &r) {
                return TxNumSerial::DeserSerial(r);
            });
        });
    RoundTrip(
        "LookupHeightOperand/700000", BlockHeight(700000),
        [](BlockHeight h) {
            Bytes out;
            postcard::Writer w(out);
            HeightSerial::SerSerial(w, h);
            return out;
        },
        [](ByteView b) {
            return postcard::DbDeserialize(b, "i32", [](postcard::Reader &r) {
                return HeightSerial::DeserSerial(r);
            });
        });
}

BOOST_AUTO_TEST_CASE(spent_by_entries) {
    const auto enc = [](const std::vector<SpentByEntry> &v) {
        return SerializeSpentByEntries(v);
    };
    const auto dec = [](ByteView b) { return DeserializeSpentByEntries(b); };
    RoundTrip("SpentByEntries/one", std::vector<SpentByEntry>{{0, 0, 0}}, enc,
              dec);
    RoundTrip("SpentByEntries/three",
              std::vector<SpentByEntry>{
                  {0, 1, 0},
                  {1, 300, 2},
                  {200, std::numeric_limits<TxNum>::max(), 70000}},
              enc, dec);
    RoundTrip("SpentByEntries/max",
              std::vector<SpentByEntry>{
                  {UINT32_MAX, std::numeric_limits<TxNum>::max(), UINT32_MAX}},
              enc, dec);
}

BOOST_AUTO_TEST_CASE(group_history_pages) {
    RoundTrip("HistoryPage/one", std::vector<TxNum>{0}, SerTxNums,
              DeserTxNums);
    RoundTrip("HistoryPage/many",
              std::vector<TxNum>{1, 127, 128, 16383, 16384, TxNum(1) << 40,
                                 std::numeric_limits<TxNum>::max()},
              SerTxNums, DeserTxNums);
    std::vector<TxNum> full;
    for (TxNum i = 0; i < 1000; ++i) {
        full.push_back(i * 997);
    }
    RoundTrip("HistoryPage/full_1000", full, SerTxNums, DeserTxNums);
    // Merge operands: b'C' || db_serialize_vec(tx_nums); b'T' || NumTxs BE4.
    Bytes concat{'C'};
    Append(concat, SerTxNums({42, 128}));
    CheckBytes("HistoryOperand/concat", concat);
    BOOST_CHECK(DeserTxNums(ByteView(Fx("HistoryOperand/concat")).subspan(1)) ==
                (std::vector<TxNum>{42, 128}));
    Bytes trim{'T'};
    Append(trim, ToBe<NumTxs>(9));
    CheckBytes("HistoryOperand/trim", trim);
    BOOST_CHECK_EQUAL(
        BytesToNumTxs(ByteView(Fx("HistoryOperand/trim")).subspan(1)), 9u);
}

BOOST_AUTO_TEST_CASE(utxo_dups) {
    const auto value = [](TxNum tx_num, uint32_t out_idx, int64_t sats) {
        return UtxoEntry{DbOutpoint{tx_num, out_idx}, sats, {}};
    };
    const auto enc_value = [](const UtxoEntry &e) {
        return EncodeUtxoDup(UtxoDataKind::Value, e);
    };
    const auto dec_value = [](ByteView b) {
        return DecodeUtxoDup(UtxoDataKind::Value, b);
    };
    RoundTrip("UtxoDupValue/zero", value(0, 0, 0), enc_value, dec_value);
    RoundTrip("UtxoDupValue/typical", value(12345, 1, 5000000000), enc_value,
              dec_value);
    RoundTrip("UtxoDupValue/negative", value(TxNum(1) << 40, 0xffff, -1),
              enc_value, dec_value);
    RoundTrip("UtxoDupValue/max",
              value(std::numeric_limits<TxNum>::max(), UINT32_MAX,
                    std::numeric_limits<int64_t>::max()),
              enc_value, dec_value);
    for (const char *name : {"UtxoDupValue/zero", "UtxoDupValue/max"}) {
        BOOST_CHECK_EQUAL(Fx(name).size(),
                          *UtxoFixedDupSize(UtxoDataKind::Value));
    }

    Bytes p2pkh{0x76, 0xa9, 20};
    Append(p2pkh, Seq(20, 3, 1));
    Append(p2pkh, Bytes{0x88, 0xac});
    const auto enc_output = [](const UtxoEntry &e) {
        return EncodeUtxoDup(UtxoDataKind::Output, e);
    };
    const auto dec_output = [](ByteView b) {
        return DecodeUtxoDup(UtxoDataKind::Output, b);
    };
    RoundTrip("UtxoDupOutput/empty_script",
              UtxoEntry{DbOutpoint{0, 0}, 546, {}}, enc_output, dec_output);
    RoundTrip("UtxoDupOutput/p2pkh", UtxoEntry{DbOutpoint{77, 2}, 546, p2pkh},
              enc_output, dec_output);
    RoundTrip("UtxoDupOutput/op_return",
              UtxoEntry{DbOutpoint{TxNum(1) << 33, 0}, 0,
                        Bytes{0x6a, 4, 'S', 'L', 'P', 0}},
              enc_output, dec_output);
    RoundTrip("UtxoDupOutput/long_script",
              UtxoEntry{DbOutpoint{std::numeric_limits<TxNum>::max(),
                                   UINT32_MAX},
                        std::numeric_limits<int64_t>::min(), Seq(300, 7, 1)},
              enc_output, dec_output);
}

BOOST_AUTO_TEST_CASE(metadata_values) {
    for (const uint64_t v : {uint64_t(0), uint64_t(13), uint64_t(300)}) {
        RoundTrip(
            "MetaSchemaVersion/" + std::to_string(v), v,
            [](uint64_t x) {
                Bytes out;
                postcard::Writer(out).U64(x);
                return out;
            },
            [](ByteView b) {
                return postcard::DbDeserialize(
                    b, "u64", [](postcard::Reader &r) { return r.U64(); });
            });
    }
    for (const bool v : {false, true}) {
        RoundTrip(
            std::string("MetaBool/") + (v ? "true" : "false"), v,
            [](bool x) {
                Bytes out;
                postcard::Writer(out).Bool(x);
                return out;
            },
            [](ByteView b) {
                return postcard::DbDeserialize(
                    b, "bool", [](postcard::Reader &r) { return r.Bool(); });
            });
    }
}

BOOST_AUTO_TEST_CASE(token_meta) {
    const std::vector<std::pair<std::string, TokenType>> types = {
        {"slp_fungible", TokenType::Slp(SlpTokenType::Fungible())},
        {"slp_mint_vault", TokenType::Slp(SlpTokenType::MintVault())},
        {"slp_nft1_group", TokenType::Slp(SlpTokenType::Nft1Group())},
        {"slp_nft1_child", TokenType::Slp(SlpTokenType::Nft1Child())},
        {"slp_unknown_0", TokenType::Slp(SlpTokenType::Unknown(0))},
        {"slp_unknown_7", TokenType::Slp(SlpTokenType::Unknown(7))},
        {"slp_unknown_255", TokenType::Slp(SlpTokenType::Unknown(255))},
        {"alp_standard", TokenType::Alp(AlpTokenType::Standard())},
        {"alp_unknown_1", TokenType::Alp(AlpTokenType::Unknown(1))},
        {"alp_unknown_255", TokenType::Alp(AlpTokenType::Unknown(255))},
    };
    for (size_t i = 0; i < types.size(); ++i) {
        RoundTrip(
            "TokenMeta/" + types[i].first,
            TokenMeta{MakeTokenId(7, uint8_t(i)), types[i].second},
            [](const TokenMeta &m) { return token_io::SerializeTokenMeta(m); },
            [](ByteView b) { return token_io::DeserializeTokenMeta(b); });
    }
}

BOOST_AUTO_TEST_CASE(genesis_info) {
    const auto enc = [](const GenesisInfo &g) {
        return token_io::SerializeGenesisInfo(g);
    };
    const auto dec = [](ByteView b) {
        return token_io::DeserializeGenesisInfo(b);
    };
    RoundTrip("GenesisInfo/slp_empty", GenesisInfo::EmptySlp(), enc, dec);
    RoundTrip("GenesisInfo/alp_empty", GenesisInfo::EmptyAlp(), enc, dec);

    GenesisInfo slp_fungible;
    slp_fungible.token_ticker = Str("SLPT");
    slp_fungible.token_name = Str("SLP Test Token");
    slp_fungible.url = Str("https://example.com/slp");
    slp_fungible.hash = Arr32(4, 4);
    slp_fungible.decimals = 4;
    RoundTrip("GenesisInfo/slp_fungible", slp_fungible, enc, dec);

    GenesisInfo slp_no_hash;
    slp_no_hash.token_ticker = Str("N");
    slp_no_hash.decimals = 9;
    RoundTrip("GenesisInfo/slp_no_hash", slp_no_hash, enc, dec);

    GenesisInfo slp_mint_vault;
    slp_mint_vault.token_ticker = Str("MV");
    slp_mint_vault.token_name = Str("Mint vault");
    script::ShaRmd160 scripthash;
    const Bytes sh = Seq(20, 2, 1);
    std::copy(sh.begin(), sh.end(), scripthash.begin());
    slp_mint_vault.mint_vault_scripthash = scripthash;
    slp_mint_vault.url = Str("x");
    slp_mint_vault.hash = Fill32(0);
    RoundTrip("GenesisInfo/slp_mint_vault", slp_mint_vault, enc, dec);

    GenesisInfo alp_full;
    alp_full.token_ticker = Str("ALP");
    alp_full.token_name = Str("ALP Token");
    alp_full.url = Str("https://example.com/alp");
    alp_full.data = Seq(200, 5, 3);
    alp_full.auth_pubkey = Seq(33, 1, 2);
    alp_full.decimals = 8;
    RoundTrip("GenesisInfo/alp_full", alp_full, enc, dec);

    GenesisInfo alp_empty_data;
    alp_empty_data.token_ticker = Str("A");
    alp_empty_data.token_name = Str("B");
    alp_empty_data.data = Bytes{};
    alp_empty_data.auth_pubkey = Seq(33, 3, 2);
    alp_empty_data.decimals = 255;
    RoundTrip("GenesisInfo/alp_empty_data_pubkey", alp_empty_data, enc, dec);

    GenesisInfo long_fields;
    long_fields.token_ticker = Seq(130, 1, 0);
    long_fields.token_name = Seq(300, 3, 1);
    script::ShaRmd160 ff;
    ff.fill(0xff);
    long_fields.mint_vault_scripthash = ff;
    long_fields.url = Seq(17000, 1, 1);
    long_fields.hash = Fill32(0xff);
    long_fields.data = Seq(128, 9, 9);
    long_fields.auth_pubkey = Bytes{};
    long_fields.decimals = 1;
    RoundTrip("GenesisInfo/long_fields", long_fields, enc, dec);
}

BOOST_AUTO_TEST_CASE(db_token_tx) {
    const auto enc = [](const DbTokenTx &t) {
        return token_io::SerializeDbTokenTx(t);
    };
    const auto dec = [](ByteView b) {
        return token_io::DeserializeDbTokenTx(b);
    };
    constexpr uint64_t kU64Max = std::numeric_limits<uint64_t>::max();
    RoundTrip("DbTokenTx/default", DbTokenTx{}, enc, dec);

    DbTokenTx slp_send;
    slp_send.token_tx_nums = {5};
    slp_send.inputs = {DbToken::MakeAtoms(0, 1000), DbToken::NoToken()};
    slp_send.outputs = {DbToken::NoToken(), DbToken::MakeAtoms(0, 600),
                        DbToken::MakeAtoms(0, 400)};
    RoundTrip("DbTokenTx/slp_send", slp_send, enc, dec);

    DbTokenTx mint_vault;
    mint_vault.token_tx_nums = {TxNum(1) << 33};
    mint_vault.inputs = {DbToken::NoToken()};
    mint_vault.outputs = {DbToken::NoToken(), DbToken::MakeAtoms(0, kU64Max)};
    mint_vault.flags = token_io::FLAGS_HAS_MINT_VAULT;
    RoundTrip("DbTokenTx/mint_vault_flag", mint_vault, enc, dec);
    BOOST_CHECK(dec(Fx("DbTokenTx/mint_vault_flag")).HasMintVault());
    BOOST_CHECK(!dec(Fx("DbTokenTx/slp_send")).HasMintVault());

    DbTokenTx flags_ff;
    flags_ff.flags = 0xff;
    RoundTrip("DbTokenTx/flags_ff", flags_ff, enc, dec);

    DbTokenTx nft1_child;
    nft1_child.token_tx_nums = {700, 300, 701};
    nft1_child.group_token_indices = {{0, 1}, {2, 1}};
    nft1_child.inputs = {DbToken::MakeAtoms(1, 1), DbToken::MakeAtoms(0, 1)};
    nft1_child.outputs = {DbToken::NoToken(), DbToken::MakeAtoms(0, 1),
                          DbToken::MakeAtoms(2, 1)};
    RoundTrip("DbTokenTx/nft1_child_group", nft1_child, enc, dec);
    const DbTokenTx nft1_dec = dec(Fx("DbTokenTx/nft1_child_group"));
    BOOST_CHECK_EQUAL(*nft1_dec.GroupTokenTxNum(nft1_dec.outputs[2]), 300u);
    BOOST_CHECK_EQUAL(*nft1_dec.TokenTxNum(nft1_dec.outputs[2]), 701u);

    DbTokenTx all;
    all.token_tx_nums = {5, TxNum(1) << 33, kU64Max};
    all.group_token_indices = {{1, 0}, {UINT32_MAX, 128}};
    all.inputs = {DbToken::NoToken(), DbToken::MakeAtoms(0, 1000),
                  DbToken::MintBaton(1), DbToken::UnknownSlp(0x88),
                  DbToken::UnknownAlp(0xff)};
    all.outputs = {DbToken::NoToken(),
                   DbToken::MakeAtoms(1, 0xffffffffffffULL),
                   DbToken::MintBaton(UINT32_MAX),
                   DbToken::UnknownSlp(0),
                   DbToken::UnknownAlp(3),
                   DbToken::MakeAtoms(UINT32_MAX, kU64Max)};
    all.flags = 1;
    RoundTrip("DbTokenTx/all_variants", all, enc, dec);

    DbTokenTx many;
    for (uint64_t i = 0; i < 130; ++i) {
        many.token_tx_nums.push_back(i * 1000003);
        many.group_token_indices[uint32_t(i)] = uint32_t(129 - i);
    }
    for (uint32_t i = 0; i < 200; ++i) {
        DbToken token;
        switch (i % 5) {
        case 0:
            token = DbToken::NoToken();
            break;
        case 1:
            token = DbToken::MakeAtoms(i % 3, uint64_t(i) << 20);
            break;
        case 2:
            token = DbToken::MintBaton(i % 3);
            break;
        case 3:
            token = DbToken::UnknownSlp(uint8_t(i));
            break;
        default:
            token = DbToken::UnknownAlp(uint8_t(i));
            break;
        }
        many.inputs.push_back(token);
        many.outputs.push_back(token);
    }
    RoundTrip("DbTokenTx/many_200", many, enc, dec);
}

// Runs last (Boost.Test runs cases in declaration order): every fixture the
// exporter wrote must have been checked by a case above.
BOOST_AUTO_TEST_CASE(all_fixtures_covered) {
    std::vector<std::string> unchecked;
    for (const auto &[name, bytes] : Fixtures()) {
        if (!Used().count(name)) {
            unchecked.push_back(name);
        }
    }
    std::string list;
    for (const auto &name : unchecked) {
        list += " " + name;
    }
    BOOST_CHECK_MESSAGE(unchecked.empty(), "unchecked fixtures:" + list);
}

BOOST_AUTO_TEST_SUITE_END()
