// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// serde_json compatibility of the V2 HTTP JSON layer: output bytes (sorted
// keys, escapes) and which request documents serde_json + serde derive accept.

#include <ext/lotus_v2/http/json.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace chronik::native;
using namespace chronik::native::lotus_v2::http;

namespace {

std::optional<JsonNode> Parse(std::string_view s) {
    return ParseJson(
        ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size()));
}

/** A derived struct { a: String, #[serde(default)] b: u8, c: Option<bool> } */
bool DecodeAbc(std::string_view s, std::string *a = nullptr,
               uint64_t *b = nullptr) {
    std::optional<JsonNode> doc = Parse(s);
    if (!doc) {
        return false;
    }
    std::string av;
    uint64_t bv = 0;
    std::optional<bool> cv;
    const std::vector<JsonField> fields = {
        {"a", false, false, [&](const JsonNode *n) { return DecodeString(n, av); }},
        {"b", true, false,
         [&](const JsonNode *n) {
             if (!n) {
                 bv = 0;
                 return true;
             }
             return DecodeUnsigned(n, 255, bv);
         }},
        {"c", false, true, [&](const JsonNode *n) { return DecodeOptBool(n, cv); }},
    };
    if (!DecodeStruct(*doc, fields)) {
        return false;
    }
    if (a) {
        *a = av;
    }
    if (b) {
        *b = bv;
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_http_json_tests)

BOOST_AUTO_TEST_CASE(serialization_matches_serde_json) {
    Json v = Json::Object({{"zeta", Json::U(18446744073709551615ULL)},
                           {"alpha", Json::Array({true, false, Json()})},
                           {"Beta", "q\"\\\b\f\n\r\t\x01\x1f\x7f\xc3\xa9/"},
                           {"_", Json::Object({})}});
    BOOST_CHECK_EQUAL(v.Dump(),
                      "{\"Beta\":\"q\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\x7f"
                      "\xc3\xa9/\",\"_\":{},\"alpha\":[true,false,null],"
                      "\"zeta\":18446744073709551615}");
    v.Set("alpha", Json::U(0));
    v.Extend(Json::Object({{"b", "x"}}));
    BOOST_CHECK_EQUAL(v.Dump(), "{\"Beta\":\"q\\\"\\\\\\b\\f\\n\\r\\t\\u0001"
                                "\\u001f\x7f\xc3\xa9/\",\"_\":{},\"alpha\":0,"
                                "\"b\":\"x\",\"zeta\":18446744073709551615}");
    BOOST_CHECK_EQUAL(Json::Array().Dump(), "[]");
}

BOOST_AUTO_TEST_CASE(parser_syntax) {
    for (const char *ok :
         {" {\"a\" : [1, -2, 3.5e-1, true, null, \"x\"]}\n\t\r",
          "[]", "{}", "0", "-0", "1E+2", "\"\\u00e9\\ud83d\\ude00\\/\"",
          "\"\\u0000\"", "[[[[]]]]"}) {
        BOOST_CHECK_MESSAGE(Parse(ok), ok);
    }
    for (const char *bad :
         {"", " ", "{", "[1,]", "{\"a\":1,}", "01", "-", "1.", "1e", "+1",
          ".5", "nul", "True", "\"\\ud800\"", "\"\\udc00\"",
          "\"\\ud800\\u0041\"", "\"\\x\"", "\"a\nb\"", "\"\xff\"",
          "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "{\"a\" 1}", "{1:2}", "1 2",
          "\xef\xbb\xbf{}", "[1] x"}) {
        BOOST_CHECK_MESSAGE(!Parse(bad), bad);
    }
    // serde_json's recursion limit: 127 nested containers parse, 128 don't.
    std::string deep(128, '[');
    deep += std::string(128, ']');
    BOOST_CHECK(!Parse(deep));
    std::string ok_depth(127, '[');
    ok_depth += std::string(127, ']');
    BOOST_CHECK(Parse(ok_depth));

    const std::optional<JsonNode> n =
        Parse("[18446744073709551615, 18446744073709551616, -1, 1.0, 0]");
    BOOST_REQUIRE(n);
    BOOST_CHECK(n->arr[0].u && *n->arr[0].u == UINT64_MAX);
    BOOST_CHECK(!n->arr[1].u);
    BOOST_CHECK(!n->arr[2].u);
    BOOST_CHECK(!n->arr[3].u);
    BOOST_CHECK(n->arr[4].u && *n->arr[4].u == 0);
    const std::optional<JsonNode> s = Parse("\"\\u00e9\\ud83d\\ude00\"");
    BOOST_REQUIRE(s);
    BOOST_CHECK_EQUAL(s->s, "\xc3\xa9\xf0\x9f\x98\x80");
}

BOOST_AUTO_TEST_CASE(derived_struct_semantics) {
    std::string a;
    uint64_t b = 99;
    // Maps: any order, defaults and Option for missing fields.
    BOOST_CHECK(DecodeAbc("{\"c\":null,\"a\":\"x\"}", &a, &b));
    BOOST_CHECK_EQUAL(a, "x");
    BOOST_CHECK_EQUAL(b, 0u);
    BOOST_CHECK(DecodeAbc("{\"a\":\"\\u0079\",\"b\":255,\"c\":true}", &a, &b));
    BOOST_CHECK_EQUAL(a, "y");
    BOOST_CHECK_EQUAL(b, 255u);
    // Escaped keys name the same field.
    BOOST_CHECK(DecodeAbc("{\"\\u0061\":\"x\"}"));
    // deny_unknown_fields, duplicates, missing required, types and ranges.
    for (const char *bad :
         {"{}", "{\"a\":\"x\",\"d\":1}", "{\"a\":\"x\",\"a\":\"y\"}",
          "{\"a\":1}", "{\"a\":null}", "{\"a\":\"x\",\"b\":256}",
          "{\"a\":\"x\",\"b\":-1}", "{\"a\":\"x\",\"b\":1.0}",
          "{\"a\":\"x\",\"b\":null}", "{\"a\":\"x\",\"c\":1}", "\"x\"",
          "null", "1"}) {
        BOOST_CHECK_MESSAGE(!DecodeAbc(bad), bad);
    }
    // Sequences: fields in order; only #[serde(default)] fields may be
    // missing (Option fields may not); no extra elements.
    BOOST_CHECK(DecodeAbc("[\"x\",7,true]", &a, &b));
    BOOST_CHECK_EQUAL(b, 7u);
    BOOST_CHECK(DecodeAbc("[\"x\",7,null]"));
    BOOST_CHECK(!DecodeAbc("[\"x\",7]"));
    BOOST_CHECK(!DecodeAbc("[\"x\"]"));
    BOOST_CHECK(!DecodeAbc("[]"));
    BOOST_CHECK(!DecodeAbc("[\"x\",7,true,1]"));
}

BOOST_AUTO_TEST_SUITE_END()
