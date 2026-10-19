// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_TEST_V2_HTTP_TEST_UTIL_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_TEST_V2_HTTP_TEST_UTIL_H

#include <chronik/native/http.h>

#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/http/json.h>
#include <ext/lotus_v2/http/v2_http.h>
#include <ext/lotus_v2/service/service.h>
#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

/** In-process router calls over the actual V2 DB (Rust tower oneshot). */
namespace chronik::native::lotus_v2::http::test {

using namespace chronik::native::lotus_v2::test;

/** A router over a mutable state (tests swap node_anchor etc.). */
struct RouterFixture {
    std::shared_ptr<V2HttpState> state = std::make_shared<V2HttpState>();
    /** When false the provider reports a closed service. */
    std::shared_ptr<bool> open = std::make_shared<bool>(true);

    Router MakeRouter() const {
        Router router;
        RegisterV2Routes(router, [s = state, o = open]()
                                     -> std::optional<V2HttpState> {
            if (!*o) {
                return std::nullopt;
            }
            return *s;
        });
        return router;
    }
};

inline AuthoritativeState Stamp(uint64_t observation, uint64_t generation,
                                std::optional<Anchor> anchor) {
    return AuthoritativeState{observation, generation, anchor};
}

inline std::function<AuthoritativeState()>
FixedAnchor(AuthoritativeState stamp) {
    return [stamp] { return stamp; };
}

inline V2HttpState MakeState(std::shared_ptr<SharedV2Db> db,
                             std::array<uint8_t, 16> epoch) {
    V2HttpState s;
    s.index_error = std::make_shared<std::atomic<bool>>(false);
    s.service_epoch = epoch;
    s.db = std::move(db);
    s.sha256 = chronik::native::test::TestSha256;
    return s;
}

inline HttpResponse Call(const Router &router, std::string method,
                         std::string target, std::string body = {}) {
    HttpRequest req;
    req.method = std::move(method);
    const size_t q = target.find('?');
    if (q != std::string::npos) {
        req.path = target.substr(0, q);
        req.query_string = target.substr(q + 1);
        req.has_query = true;
    } else {
        req.path = target;
    }
    req.body.assign(body.begin(), body.end());
    return router.Handle(req);
}

inline std::string BodyStr(const HttpResponse &r) {
    return std::string(r.body.begin(), r.body.end());
}

/** The parsed response body (fails the test if it is not JSON). */
inline JsonNode Value(const HttpResponse &r) {
    std::optional<JsonNode> v = ParseJson(r.body);
    BOOST_REQUIRE_MESSAGE(v, "response is not JSON: " + BodyStr(r));
    return *v;
}

/** Object member or array element lookups; nullptr if absent. */
inline const JsonNode *Get(const JsonNode *n, std::string_view key) {
    if (!n || n->kind != JsonNode::Kind::Obj) {
        return nullptr;
    }
    for (const auto &[k, v] : n->obj) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}
inline const JsonNode *Get(const JsonNode *n, size_t index) {
    if (!n || n->kind != JsonNode::Kind::Arr || index >= n->arr.size()) {
        return nullptr;
    }
    return &n->arr[index];
}
template <typename K, typename... Ks>
const JsonNode *At(const JsonNode &n, K key, Ks... keys) {
    const JsonNode *cur = Get(&n, key);
    ((cur = Get(cur, keys)), ...);
    return cur;
}

inline std::string Str(const JsonNode *n) {
    BOOST_REQUIRE(n && n->kind == JsonNode::Kind::Str);
    return n->s;
}
inline bool IsNull(const JsonNode *n) {
    return n && n->kind == JsonNode::Kind::Null;
}
inline bool Bool(const JsonNode *n) {
    BOOST_REQUIRE(n && n->kind == JsonNode::Kind::Bool);
    return n->b;
}
inline uint64_t Num(const JsonNode *n) {
    BOOST_REQUIRE(n && n->kind == JsonNode::Kind::Num && n->u);
    return *n->u;
}
inline size_t Len(const JsonNode *n) {
    BOOST_REQUIRE(n && n->kind == JsonNode::Kind::Arr);
    return n->arr.size();
}

inline std::string HexFill(uint8_t b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 32; ++i) {
        out += kHex[b >> 4];
        out += kHex[b & 0xf];
    }
    return out;
}

} // namespace chronik::native::lotus_v2::http::test

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_TEST_V2_HTTP_TEST_UTIL_H
