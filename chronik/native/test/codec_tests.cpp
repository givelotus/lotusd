// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Codec tests. Golden vectors come from the Rust exporter
// chronik/chronik-db/tests/export_native_golden.rs (fixtures/codec.json); every
// case is re-encoded natively and must match byte for byte, then decoded back.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/codec/script_compress.h>
#include <chronik/native/codec/seahash.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <map>
#include <sstream>
#include <string>

using namespace chronik::native;

namespace {

/** Loads the flat {"name": "hex"} JSON object written by the exporter. */
std::map<std::string, Bytes> LoadFixtures() {
    std::ifstream in(std::string(CHRONIK_NATIVE_FIXTURES_DIR) + "/codec.json");
    BOOST_REQUIRE_MESSAGE(in, "missing fixtures/codec.json");
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

const Bytes &Fx(const std::string &name) {
    auto it = Fixtures().find(name);
    BOOST_REQUIRE_MESSAGE(it != Fixtures().end(), "missing fixture " + name);
    return it->second;
}

template <typename F> Bytes Enc(F &&f) {
    Bytes out;
    postcard::Writer w(out);
    f(w);
    return out;
}

void CheckBytes(const std::string &name, const Bytes &actual) {
    BOOST_CHECK_MESSAGE(actual == Fx(name), name + ": native " +
                                                HexEncode(actual) + " != rust " +
                                                HexEncode(Fx(name)));
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
    for (size_t i = 0; i < 32; ++i) {
        a[i] = uint8_t(uint8_t(i) * mul + add);
    }
    return a;
}

} // namespace

BOOST_AUTO_TEST_SUITE(codec_tests)

BOOST_AUTO_TEST_CASE(postcard_unsigned_golden) {
    for (uint16_t v : {0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff}) {
        const std::string name = "u16/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.U16(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.U16(), v);
        BOOST_CHECK(r.AtEnd());
    }
    for (uint32_t v : {0u, 1u, 0x7fu, 0x80u, 0x3fffu, 0x4000u, 0x1fffffu,
                       0x200000u, 0x0fffffffu, 0x10000000u, 0xffffffffu}) {
        const std::string name = "u32/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.U32(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.U32(), v);
        BOOST_CHECK(r.AtEnd());
    }
    for (uint64_t v :
         {uint64_t(0), uint64_t(1), uint64_t(0x7f), uint64_t(0x80),
          uint64_t(0xffffffff), uint64_t(1) << 35, uint64_t(1) << 56,
          (uint64_t(1) << 63) - 1, uint64_t(1) << 63, UINT64_MAX}) {
        const std::string name = "u64/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.U64(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.U64(), v);
        BOOST_CHECK(r.AtEnd());
    }
    // u128 (decimal names written by Rust)
    const std::pair<const char *, unsigned __int128> u128s[] = {
        {"u128/0", 0},
        {"u128/1", 1},
        {"u128/18446744073709551615", UINT64_MAX},
        {"u128/340282366920938463463374607431768211455",
         ~(unsigned __int128)0}};
    for (const auto &[name, v] : u128s) {
        CheckBytes(name, Enc([&](auto &w) { w.U128(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK(r.U128() == v);
        BOOST_CHECK(r.AtEnd());
    }
    CheckBytes("u8/0", Enc([](auto &w) { w.U8(0); }));
    CheckBytes("u8/255", Enc([](auto &w) { w.U8(255); }));
}

BOOST_AUTO_TEST_CASE(postcard_signed_golden) {
    for (int32_t v : {0, 1, -1, 63, -64, 64, -65, INT32_MAX, INT32_MIN}) {
        const std::string name = "i32/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.I32(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.I32(), v);
        BOOST_CHECK(r.AtEnd());
    }
    for (int64_t v : {int64_t(0), int64_t(1), int64_t(-1), int64_t(63),
                      int64_t(-64), int64_t(64), int64_t(-65),
                      int64_t(INT32_MAX), int64_t(INT32_MIN), INT64_MAX,
                      INT64_MIN}) {
        const std::string name = "i64/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.I64(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.I64(), v);
        BOOST_CHECK(r.AtEnd());
    }
    for (int16_t v : {int16_t(0), int16_t(-1), int16_t(INT16_MAX), int16_t(INT16_MIN)}) {
        const std::string name = "i16/" + std::to_string(v);
        CheckBytes(name, Enc([&](auto &w) { w.I16(v); }));
        postcard::Reader r(Fx(name));
        BOOST_CHECK_EQUAL(r.I16(), v);
    }
}

BOOST_AUTO_TEST_CASE(postcard_compound_golden) {
    CheckBytes("bool/false", Enc([](auto &w) { w.Bool(false); }));
    CheckBytes("bool/true", Enc([](auto &w) { w.Bool(true); }));
    CheckBytes("option_u32/none", Enc([](auto &w) { w.OptionTag(false); }));
    CheckBytes("option_u32/some_300", Enc([](auto &w) {
                   w.OptionTag(true);
                   w.U32(300);
               }));
    CheckBytes("option_bytes/some", Enc([](auto &w) {
                   w.OptionTag(true);
                   w.ByteVec(Bytes{1, 2, 3});
               }));
    CheckBytes("string/empty", Enc([](auto &w) { w.Str(""); }));
    CheckBytes("string/native", Enc([](auto &w) { w.Str("native/v0.34.1"); }));
    CheckBytes("string/unicode",
               Enc([](auto &w) { w.Str("\xc3\xbcn\xc3\xaf \xe2\x9c\x93"); }));
    {
        postcard::Reader r(Fx("string/unicode"));
        BOOST_CHECK_EQUAL(r.Str(), "\xc3\xbcn\xc3\xaf \xe2\x9c\x93");
    }
    CheckBytes("vec_u8/empty", Enc([](auto &w) { w.ByteVec(Bytes{}); }));
    CheckBytes("vec_u8/200", Enc([](auto &w) { w.ByteVec(Seq(200, 7, 3)); }));
    {
        postcard::Reader r(Fx("vec_u8/200"));
        BOOST_CHECK(r.ByteVec() == Seq(200, 7, 3));
        BOOST_CHECK(r.AtEnd());
    }
    const std::vector<int32_t> heights{0, 1, 1000, 1000000, INT32_MAX};
    CheckBytes("vec_i32/heights", Enc([&](auto &w) {
                   w.SeqLen(heights.size());
                   for (int32_t h : heights) {
                       w.I32(h);
                   }
               }));
    const std::vector<uint64_t> nums{0, 127, 128, uint64_t(1) << 40,
                                     UINT64_MAX};
    CheckBytes("vec_u64/tx_nums", Enc([&](auto &w) {
                   w.SeqLen(nums.size());
                   for (uint64_t n : nums) {
                       w.U64(n);
                   }
               }));
    // BTreeMap: sorted by key
    CheckBytes("btreemap_u32_u32", Enc([](auto &w) {
                   w.SeqLen(3);
                   w.U32(0);
                   w.U32(300);
                   w.U32(5);
                   w.U32(1);
                   w.U32(1000);
                   w.U32(0);
               }));
}

BOOST_AUTO_TEST_CASE(postcard_decode_errors) {
    // Truncated
    {
        const Bytes b{0x80};
        postcard::Reader r(b);
        BOOST_CHECK_EXCEPTION(r.U32(), postcard::Error, [](const auto &e) {
            return std::string(e.what()) == postcard::kUnexpectedEnd;
        });
    }
    // u16 varint too large: last byte > 3
    {
        const Bytes b{0xff, 0xff, 0x04};
        postcard::Reader r(b);
        BOOST_CHECK_THROW(r.U16(), postcard::Error);
    }
    {
        const Bytes b{0xff, 0xff, 0x03};
        postcard::Reader r(b);
        BOOST_CHECK_EQUAL(r.U16(), 0xffff);
    }
    // u32 never terminating within 5 bytes
    {
        const Bytes b{0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
        postcard::Reader r(b);
        BOOST_CHECK_EXCEPTION(r.U32(), postcard::Error, [](const auto &e) {
            return std::string(e.what()) == postcard::kBadVarint;
        });
    }
    // u64: 10th byte may be at most 1
    {
        const Bytes b{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02};
        postcard::Reader r(b);
        BOOST_CHECK_THROW(r.U64(), postcard::Error);
    }
    {
        const Bytes b{0x02};
        postcard::Reader r(b);
        BOOST_CHECK_EXCEPTION(r.Bool(), postcard::Error, [](const auto &e) {
            return std::string(e.what()) == postcard::kBadBool;
        });
    }
    {
        const Bytes b{0x02};
        postcard::Reader r(b);
        BOOST_CHECK_THROW(r.OptionTag(), postcard::Error);
    }
    {
        const Bytes b{0x02, 0xc3, 0x28}; // invalid utf-8
        postcard::Reader r(b);
        BOOST_CHECK_EXCEPTION(r.Str(), postcard::Error, [](const auto &e) {
            return std::string(e.what()) == postcard::kBadUtf8;
        });
    }
    {
        const Bytes b{0x05, 0x01}; // length past the end
        postcard::Reader r(b);
        BOOST_CHECK_THROW(r.ByteVec(), postcard::Error);
    }
}

BOOST_AUTO_TEST_CASE(db_deserialize_messages) {
    // Same texts as chronik-db ser.rs SerError (ser.rs tests)
    const Bytes ok{0x05};
    BOOST_CHECK_EQUAL(postcard::DbDeserialize(
                          ok, "u32", [](postcard::Reader &r) { return r.U32(); }),
                      5u);
    const Bytes leftover{0x05, 0x06, 0x07};
    BOOST_CHECK_EXCEPTION(
        postcard::DbDeserialize(leftover, "u32",
                                [](postcard::Reader &r) { return r.U32(); }),
        ChronikError, [](const auto &e) {
            return std::string(e.what()) ==
                   "Inconsistent DB: Deserializing as u32 has leftover data: "
                   "05[0607]";
        });
    const Bytes bad{0x80};
    BOOST_CHECK_EXCEPTION(
        postcard::DbDeserialize(bad, "u32",
                                [](postcard::Reader &r) { return r.U32(); }),
        ChronikError, [](const auto &e) {
            return std::string(e.what()) ==
                   "Inconsistent DB: Cannot deserialize byte sequence as u32: "
                   "Hit the end of buffer, expected more data. Byte sequence: "
                   "80";
        });
    // pc* list
    const Bytes list{0x01, 0x80, 0x01, 0x00};
    const auto items = postcard::DbDeserializeVec(
        list, "u32", [](postcard::Reader &r) { return r.U32(); });
    BOOST_CHECK(items == (std::vector<uint32_t>{1, 128, 0}));
}

BOOST_AUTO_TEST_CASE(seahash_golden) {
    for (size_t n : {0, 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 63, 64,
                     65, 100, 1000}) {
        const Bytes data = Seq(n, 13, 5);
        Bytes out;
        PutBe<uint64_t>(out, SeaHash(data));
        CheckBytes("seahash/" + std::to_string(n), out);
    }
    Bytes out;
    PutBe<uint64_t>(out, SeaHash(AsView(Arr32(3, 1))));
    CheckBytes("seahash/txid", out);
}

BOOST_AUTO_TEST_CASE(script_compression_golden) {
    size_t n_cases = 0;
    for (const auto &[name, script] : Fixtures()) {
        if (name.rfind("script/", 0) != 0) {
            continue;
        }
        const std::string variant = name.substr(7);
        const Bytes compressed = CompressScript(script);
        CheckBytes("compress/" + variant, compressed);
        // Round trip, except uncompressed pubkeys which need EC decompression
        if (variant.rfind("p2pk_uncompressed", 0) != 0) {
            const auto decompressed = DecompressScript(compressed);
            BOOST_CHECK_MESSAGE(decompressed && *decompressed == script,
                                "decompress " + variant);
        } else {
            BOOST_CHECK(!DecompressScript(compressed));
            // With a host hook, the 65-byte key is rebuilt.
            const Bytes pk(script.begin() + 1, script.begin() + 66);
            const auto decompressed = DecompressScript(
                compressed, [&](ByteView c) -> std::optional<Bytes> {
                    BOOST_CHECK_EQUAL(c.size(), 33u);
                    return pk;
                });
            BOOST_CHECK(decompressed && *decompressed == script);
        }
        ++n_cases;
    }
    BOOST_CHECK_EQUAL(n_cases, 13u);
}

BOOST_AUTO_TEST_CASE(core_varint) {
    // bitcoinsuite-core compress.rs test_var_int
    auto varint_hex = [](uint64_t n) {
        Bytes out;
        WriteCoreVarInt(out, n);
        size_t pos = 0;
        uint64_t back;
        BOOST_CHECK(ReadCoreVarInt(out, pos, back));
        BOOST_CHECK_EQUAL(back, n);
        BOOST_CHECK_EQUAL(pos, out.size());
        return HexEncode(out);
    };
    BOOST_CHECK_EQUAL(varint_hex(0), "00");
    BOOST_CHECK_EQUAL(varint_hex(0x7f), "7f");
    BOOST_CHECK_EQUAL(varint_hex(0x80), "8000");
    BOOST_CHECK_EQUAL(varint_hex(0x1234), "a334");
    BOOST_CHECK_EQUAL(varint_hex(0xffff), "82fe7f");
    BOOST_CHECK_EQUAL(varint_hex(0x123456), "c7e756");
    BOOST_CHECK_EQUAL(varint_hex(0x80123456), "86ffc7e756");
    BOOST_CHECK_EQUAL(varint_hex(0xffffffff), "8efefefe7f");
    BOOST_CHECK_EQUAL(varint_hex(0x7fffffffffffffff), "fefefefefefefefe7f");
    BOOST_CHECK_EQUAL(varint_hex(0xffffffffffffffff), "80fefefefefefefefe7f");
}

BOOST_AUTO_TEST_CASE(compress_script_variant_rust_cases) {
    // bitcoinsuite-core compress.rs test_compress_script_variant
    const Bytes hash(20, 4);
    Bytes p2pkh{0x76, 0xa9, 20};
    p2pkh.insert(p2pkh.end(), hash.begin(), hash.end());
    p2pkh.push_back(0x88);
    p2pkh.push_back(0xac);
    Bytes expected{0x00};
    expected.insert(expected.end(), hash.begin(), hash.end());
    BOOST_CHECK(CompressScript(p2pkh) == expected);

    auto pk = *HexDecode(
        "027c5bde5a66a0fbcfe89c394f406ab88a245beb66af6a25216b1415ac945142ea");
    Bytes p2pk{33};
    p2pk.insert(p2pk.end(), pk.begin(), pk.end());
    p2pk.push_back(0xac);
    BOOST_CHECK(CompressScript(p2pk) == pk);

    auto upk_even = *HexDecode(
        "04b7490a14c2266e6e12f474158121e322d1660643721af48256a5a0f8f7eeb230af06"
        "7256dcd144310ab866101af284f4499eae73ec308e1c8946101d85949b8a");
    Bytes s{65};
    s.insert(s.end(), upk_even.begin(), upk_even.end());
    s.push_back(0xac);
    BOOST_CHECK(CompressScript(s) == Bytes(upk_even.begin(), upk_even.begin() + 33));

    auto upk_odd = *HexDecode(
        "04eefdb19ef67210ca651c5b466c5fc4e5183b71ae7a3524f11090a0ebd1707e674f3d"
        "673c461162a3862277fdd422a20486b3b536232eef48fad179ddff4a93ed");
    s = {65};
    s.insert(s.end(), upk_odd.begin(), upk_odd.end());
    s.push_back(0xac);
    Bytes exp_odd{0x05};
    exp_odd.insert(exp_odd.end(), upk_odd.begin() + 1, upk_odd.begin() + 33);
    BOOST_CHECK(CompressScript(s) == exp_odd);

    BOOST_CHECK(CompressScript(Bytes{}) == Bytes{0x06});
    Bytes other121(121, 4);
    Bytes exp121{0x7f};
    exp121.insert(exp121.end(), other121.begin(), other121.end());
    BOOST_CHECK(CompressScript(other121) == exp121);
    Bytes other122(122, 4);
    Bytes exp122{0x80, 0x00};
    exp122.insert(exp122.end(), other122.begin(), other122.end());
    BOOST_CHECK(CompressScript(other122) == exp122);
}

BOOST_AUTO_TEST_CASE(db_value_structs_golden) {
    // SerBlock {hash, n_bits u32, timestamp i64, file_num u32, data_pos u32}
    CheckBytes("SerBlock/a", Enc([](auto &w) {
                   w.Raw(AsView(Arr32(1, 0)));
                   w.U32(0x1d00ffff);
                   w.I64(1700000000);
                   w.U32(3);
                   w.U32(0x01020304);
               }));
    CheckBytes("SerBlock/neg_ts", Enc([](auto &w) {
                   w.Raw(Bytes(32, 0xff));
                   w.U32(0xffffffff);
                   w.I64(-1);
                   w.U32(0);
                   w.U32(8);
               }));
    CheckBytes("BlockStats/a", Enc([](auto &w) {
                   w.U64(1000000);
                   w.U64(2);
                   w.U64(3);
                   w.U64(4);
                   w.I64(5000000000);
                   w.I64(625000000);
                   w.I64(-7);
                   w.I64(0);
               }));
    // SerTx {txid, data_pos u32, undo_pos u32, time_first_seen i64}
    CheckBytes("SerTx/coinbase", Enc([](auto &w) {
                   w.Raw(AsView(Arr32(2, 9)));
                   w.U32(81);
                   w.U32(0);
                   w.I64(0);
               }));
    CheckBytes("SerTx/normal", Enc([](auto &w) {
                   w.Raw(AsView(Arr32(5, 7)));
                   w.U32(0x00ffff00);
                   w.U32(0x1234);
                   w.I64(1699999999);
               }));
    // SpentByEntry {out_idx u32, tx_num u64, input_idx u32}, concatenated
    CheckBytes("SpentByEntries/three", Enc([](auto &w) {
                   w.U32(0);
                   w.U64(1);
                   w.U32(0);
                   w.U32(1);
                   w.U64(300);
                   w.U32(2);
                   w.U32(200);
                   w.U64(UINT64_MAX);
                   w.U32(70000);
               }));
    CheckBytes("SpentByKey/0", Enc([](auto &w) { w.U64(0); }));
    CheckBytes("SpentByKey/1000000", Enc([](auto &w) { w.U64(1000000); }));

    // TokenMeta {token_id [u8;32], token_type enum}
    struct TT {
        const char *name;
        uint32_t protocol; // 0 Slp, 1 Alp
        uint32_t variant;
        std::optional<uint8_t> unknown;
    };
    const TT types[] = {{"slp_fungible", 0, 0, {}},
                        {"slp_mint_vault", 0, 1, {}},
                        {"slp_nft1_group", 0, 2, {}},
                        {"slp_nft1_child", 0, 3, {}},
                        {"slp_unknown_7", 0, 4, 7},
                        {"alp_standard", 1, 0, {}},
                        {"alp_unknown_255", 1, 1, 255}};
    for (const TT &t : types) {
        CheckBytes(std::string("TokenMeta/") + t.name, Enc([&](auto &w) {
                       w.Raw(AsView(Arr32(7, 3)));
                       w.EnumIndex(t.protocol);
                       w.EnumIndex(t.variant);
                       if (t.unknown) {
                           w.U8(*t.unknown);
                       }
                   }));
    }

    // GenesisInfo {ticker Bytes, name Bytes, mint_vault_scripthash
    // Option<[u8;20]>, url Bytes, hash Option<[u8;32]>, data Option<Bytes>,
    // auth_pubkey Option<Bytes>, decimals u8}
    CheckBytes("GenesisInfo/default", Enc([](auto &w) {
                   w.ByteVec(Bytes{});
                   w.ByteVec(Bytes{});
                   w.OptionTag(false);
                   w.ByteVec(Bytes{});
                   w.OptionTag(false);
                   w.OptionTag(false);
                   w.OptionTag(false);
                   w.U8(0);
               }));
    CheckBytes("GenesisInfo/full", Enc([](auto &w) {
                   w.ByteVec(AsView(std::string_view("TKN")));
                   w.ByteVec(AsView(std::string_view("Token name")));
                   w.OptionTag(true);
                   w.Raw(Seq(20, 2, 1));
                   w.ByteVec(AsView(std::string_view("https://example.com")));
                   w.OptionTag(true);
                   w.Raw(AsView(Arr32(4, 4)));
                   w.OptionTag(true);
                   w.ByteVec(Bytes{});
                   w.OptionTag(true);
                   w.ByteVec(Seq(33, 1, 2));
                   w.U8(9);
               }));

    // DbTokenTx {token_tx_nums Vec<u64>, group_token_indices BTreeMap<u32,
    // u32>, inputs Vec<DbToken>, outputs Vec<DbToken>, flags u8}
    // DbToken: 0 NoToken, 1 Atoms(u32, u64), 2 MintBaton(u32),
    // 3 UnknownSlp(u8), 4 UnknownAlp(u8)
    CheckBytes("DbTokenTx/default", Enc([](auto &w) {
                   w.SeqLen(0);
                   w.SeqLen(0);
                   w.SeqLen(0);
                   w.SeqLen(0);
                   w.U8(0);
               }));
    CheckBytes("DbTokenTx/full", Enc([](auto &w) {
                   w.SeqLen(2);
                   w.U64(5);
                   w.U64(uint64_t(1) << 33);
                   w.SeqLen(1);
                   w.U32(1);
                   w.U32(0);
                   w.SeqLen(3);
                   w.EnumIndex(0);
                   w.EnumIndex(1);
                   w.U32(0);
                   w.U64(1000);
                   w.EnumIndex(2);
                   w.U32(1);
                   w.SeqLen(4);
                   w.EnumIndex(0);
                   w.EnumIndex(1);
                   w.U32(1);
                   w.U64(0xffffffffffffULL);
                   w.EnumIndex(3);
                   w.U8(0x88);
                   w.EnumIndex(4);
                   w.U8(3);
                   w.U8(1);
               }));
}

BOOST_AUTO_TEST_CASE(hex_and_bytes) {
    BOOST_CHECK_EQUAL(HexEncode(Bytes{0x00, 0xab, 0xff}), "00abff");
    BOOST_CHECK(*HexDecode("00ABff") == (Bytes{0x00, 0xab, 0xff}));
    BOOST_CHECK(!HexDecode("abc"));
    BOOST_CHECK(!HexDecode("zz"));
    Hash32 h;
    h.b[0] = 0x01;
    h.b[31] = 0xfe;
    BOOST_CHECK_EQUAL(HashToHex(h).substr(0, 2), "fe");
    BOOST_CHECK_EQUAL(HashToHex(h).substr(62, 2), "01");
    BOOST_CHECK(ToBe<uint32_t>(0x01020304) ==
                (std::array<uint8_t, 4>{1, 2, 3, 4}));
    BOOST_CHECK(ToLe<int64_t>(-2) ==
                (std::array<uint8_t, 8>{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff}));
    const Bytes be{0, 0, 0, 0, 0, 0, 1, 2};
    BOOST_CHECK_EQUAL(FromBe<uint64_t>(be), 0x0102u);
    BOOST_CHECK_EQUAL(FromLe<int64_t>(ToLe<int64_t>(-12345)), -12345);
}

BOOST_AUTO_TEST_SUITE_END()
