// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletpwa/serve.h>
#include <walletpwa/session.h>

#include <util/fs.h>
#include <util/string.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace walletpwa;

namespace {
std::optional<std::string> HeaderValue(const AssetReply &reply,
                                       const std::string &name) {
    for (const auto &[n, v] : reply.headers) {
        if (n == name) {
            return v;
        }
    }
    return std::nullopt;
}

// Sorted by path, as the generator emits them.
const EmbeddedAsset TEST_ASSETS[]{
    {"a.js", "text/javascript; charset=utf-8",
     "\"0123456789abcdef0123456789abcdef\"", "console.log(1);", "GZ-JS"},
    {"icons/i.png", "image/png", "\"fedcba9876543210fedcba9876543210\"", "PNG",
     ""},
    {"index.html", "text/html; charset=utf-8",
     "\"00112233445566778899aabbccddeeff\"", "<html></html>", "GZ-HTML"},
};

bool Allows(const OriginPolicy &policy, const std::string &scheme,
            std::optional<std::string> host, std::optional<std::string> origin,
            bool require_origin = true) {
    std::string reason;
    const bool ok{policy.Allows(scheme, host, origin, require_origin, reason)};
    // A refusal always says why; an acceptance never does.
    BOOST_CHECK_EQUAL(ok, reason.empty());
    return ok;
}

std::string Secret(char c) {
    return std::string(64, c);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(walletpwa_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(asset_paths) {
    BOOST_CHECK_EQUAL(*NormalizeAssetPath(""), "index.html");
    BOOST_CHECK_EQUAL(*NormalizeAssetPath("?x=1"), "index.html");
    BOOST_CHECK_EQUAL(*NormalizeAssetPath("a.js"), "a.js");
    BOOST_CHECK_EQUAL(*NormalizeAssetPath("views/send.js?v=2"),
                      "views/send.js");
    BOOST_CHECK_EQUAL(*NormalizeAssetPath("a%20b.js"), "a b.js");
    // Decoded once only: "%252e" is the file "%2e..."
    BOOST_CHECK_EQUAL(*NormalizeAssetPath("%252e%252e"), "%2e%2e");
    for (const std::string &bad :
         std::vector<std::string>{"..",
                                  "../x",
                                  "a/../b",
                                  "a/./b",
                                  ".",
                                  "%2e%2e",
                                  "%2E%2e/x",
                                  "a%2f..%2fb",
                                  "%2fetc",
                                  "a%2Fb",
                                  "a\\b",
                                  "a%5cb",
                                  "a%00.js",
                                  std::string{"a\0b", 3},
                                  "/abs",
                                  "a//b",
                                  "a/",
                                  ".hidden",
                                  "dir/.git/config",
                                  "%2ehidden",
                                  "%",
                                  "%4",
                                  "%zz",
                                  std::string(257, 'a')}) {
        BOOST_CHECK_MESSAGE(!NormalizeAssetPath(bad), bad);
    }
    BOOST_CHECK(NormalizeAssetPath(std::string(256, 'a')));
}

BOOST_AUTO_TEST_CASE(mime_types) {
    BOOST_CHECK_EQUAL(*MimeType("index.html"), "text/html; charset=utf-8");
    BOOST_CHECK_EQUAL(*MimeType("a.JS"), "text/javascript; charset=utf-8");
    BOOST_CHECK_EQUAL(*MimeType("m.mjs"), "text/javascript; charset=utf-8");
    BOOST_CHECK_EQUAL(*MimeType("app.css"), "text/css; charset=utf-8");
    BOOST_CHECK_EQUAL(*MimeType("BUNDLE.json"), "application/json");
    BOOST_CHECK_EQUAL(*MimeType("manifest.webmanifest"),
                      "application/manifest+json");
    BOOST_CHECK_EQUAL(*MimeType("i.svg"), "image/svg+xml");
    BOOST_CHECK_EQUAL(*MimeType("icons/i.png"), "image/png");
    BOOST_CHECK_EQUAL(*MimeType("favicon.ico"), "image/x-icon");
    BOOST_CHECK_EQUAL(*MimeType("f.woff2"), "font/woff2");
    BOOST_CHECK_EQUAL(*MimeType("x.wasm"), "application/wasm");
    BOOST_CHECK_EQUAL(*MimeType("mining/sha256d.WGSL"),
                      "text/plain; charset=utf-8");
    BOOST_CHECK_EQUAL(*MimeType("LICENSE.txt"), "text/plain; charset=utf-8");
    for (const std::string unknown :
         {"a.gz", "a.js.gz", "a.exe", "README", "dir.js/file", "a.htm"}) {
        BOOST_CHECK_MESSAGE(!MimeType(unknown), unknown);
    }
    // Unknown types are not served, even if present.
    BOOST_CHECK_EQUAL(
        ServeAsset(TEST_ASSETS, "a.exe", std::nullopt, std::nullopt).status,
        404);
}

BOOST_AUTO_TEST_CASE(etags) {
    const std::string tag{"\"0123456789abcdef0123456789abcdef\""};
    BOOST_CHECK(IfNoneMatchMatches(tag, tag));
    BOOST_CHECK(IfNoneMatchMatches("*", tag));
    BOOST_CHECK(IfNoneMatchMatches("W/" + tag, tag));
    BOOST_CHECK(IfNoneMatchMatches("\"x\", W/\"y\" ," + tag, tag));
    BOOST_CHECK(IfNoneMatchMatches("\"x\",*", tag));
    BOOST_CHECK(!IfNoneMatchMatches("", tag));
    BOOST_CHECK(!IfNoneMatchMatches("\"x\", W/\"y\"", tag));
    BOOST_CHECK(!IfNoneMatchMatches("0123456789abcdef0123456789abcdef", tag));

    auto reply{ServeAsset(TEST_ASSETS, "a.js", std::nullopt, std::nullopt)};
    BOOST_CHECK_EQUAL(reply.status, 200);
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "ETag"), tag);
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Cache-Control"), "no-cache");
    BOOST_CHECK_EQUAL(reply.body, "console.log(1);");

    reply = ServeAsset(TEST_ASSETS, "a.js", std::nullopt, "W/" + tag);
    BOOST_CHECK_EQUAL(reply.status, 304);
    BOOST_CHECK(reply.body.empty());
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "ETag"), tag);
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Cache-Control"), "no-cache");

    // The gzip representation has its own tag.
    const std::string gz_tag{"\"0123456789abcdef0123456789abcdef-gz\""};
    reply = ServeAsset(TEST_ASSETS, "a.js", "gzip", tag);
    BOOST_CHECK_EQUAL(reply.status, 200);
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "ETag"), gz_tag);
    reply = ServeAsset(TEST_ASSETS, "a.js", "gzip", gz_tag);
    BOOST_CHECK_EQUAL(reply.status, 304);
    BOOST_CHECK(!HeaderValue(reply, "Content-Encoding"));
}

BOOST_AUTO_TEST_CASE(encodings) {
    BOOST_CHECK(AcceptsGzip("gzip"));
    BOOST_CHECK(AcceptsGzip("gzip, deflate, br, zstd"));
    BOOST_CHECK(AcceptsGzip("GZIP;q=1"));
    BOOST_CHECK(AcceptsGzip("gzip;q=0.5"));
    BOOST_CHECK(AcceptsGzip("deflate, *"));
    BOOST_CHECK(AcceptsGzip("x-gzip"));
    BOOST_CHECK(!AcceptsGzip(""));
    BOOST_CHECK(!AcceptsGzip("identity"));
    BOOST_CHECK(!AcceptsGzip("gzip;q=0"));
    BOOST_CHECK(!AcceptsGzip("gzip; q=0.000"));
    BOOST_CHECK(!AcceptsGzip("*;q=0"));
    BOOST_CHECK(!AcceptsGzip("gzip;q=0, *"));

    auto reply{ServeAsset(TEST_ASSETS, "", "gzip, br", std::nullopt)};
    BOOST_CHECK_EQUAL(reply.status, 200);
    BOOST_CHECK_EQUAL(reply.body, "GZ-HTML");
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Content-Encoding"), "gzip");
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Vary"), "Accept-Encoding");
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Content-Type"),
                      "text/html; charset=utf-8");

    reply = ServeAsset(TEST_ASSETS, "index.html", "gzip;q=0", std::nullopt);
    BOOST_CHECK_EQUAL(reply.body, "<html></html>");
    BOOST_CHECK(!HeaderValue(reply, "Content-Encoding"));
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Vary"), "Accept-Encoding");

    // No .gz variant: the plain body, still with Vary.
    reply = ServeAsset(TEST_ASSETS, "icons/i.png", "gzip", std::nullopt);
    BOOST_CHECK_EQUAL(reply.status, 200);
    BOOST_CHECK_EQUAL(reply.body, "PNG");
    BOOST_CHECK(!HeaderValue(reply, "Content-Encoding"));
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Vary"), "Accept-Encoding");

    // Security headers on every reply, including 404s.
    for (const auto &r :
         {ServeAsset(TEST_ASSETS, "a.js", std::nullopt, std::nullopt),
          ServeAsset(TEST_ASSETS, "missing.js", std::nullopt, std::nullopt),
          ServeAsset(TEST_ASSETS, "../a.js", std::nullopt, std::nullopt),
          NoBundleReply()}) {
        for (const auto &[name, value] : SecurityHeaders()) {
            BOOST_CHECK_EQUAL(HeaderValue(r, name).value_or(""), value);
        }
    }
    BOOST_CHECK_EQUAL(
        ServeAsset(TEST_ASSETS, "missing.js", std::nullopt, std::nullopt)
            .status,
        404);
    BOOST_CHECK_EQUAL(ServeAsset({}, "", std::nullopt, std::nullopt).status,
                      404);
    BOOST_CHECK_EQUAL(NoBundleReply().status, 404);
}

BOOST_AUTO_TEST_CASE(serve_from_directory) {
    const fs::path dir{m_args.GetDataDirBase() / "pwa"};
    fs::create_directories(dir / "views");
    const auto write = [](const fs::path &p, const std::string &content) {
        std::ofstream f{p, std::ios::binary | std::ios::trunc};
        f << content;
    };
    write(dir / "index.html", "v1");
    write(dir / "views" / "a.js", "js");
    write(dir / "views" / "hash.wgsl", "@compute @workgroup_size(1) fn main() {}");
    write(dir / ".secret.txt", "no");
    write(m_args.GetDataDirBase() / "outside.txt", "no");

    auto reply{ServeFromDirectory(dir, "")};
    BOOST_CHECK_EQUAL(reply.status, 200);
    BOOST_CHECK_EQUAL(reply.body, "v1");
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Cache-Control"), "no-store");
    BOOST_CHECK(!HeaderValue(reply, "ETag"));
    BOOST_CHECK_EQUAL(*HeaderValue(reply, "Content-Security-Policy"),
                      SecurityHeaders()[0].second);
    // Read on every request.
    write(dir / "index.html", "v2");
    BOOST_CHECK_EQUAL(ServeFromDirectory(dir, "index.html").body, "v2");
    auto shader{ServeFromDirectory(dir, "views/hash.wgsl")};
    BOOST_CHECK_EQUAL(shader.status, 200);
    BOOST_CHECK_EQUAL(*HeaderValue(shader, "Content-Type"),
                      "text/plain; charset=utf-8");
    BOOST_CHECK_EQUAL(shader.body, "@compute @workgroup_size(1) fn main() {}");
    // A trailing separator on the directory makes no difference.
    BOOST_CHECK_EQUAL(ServeFromDirectory(dir / "", "views/a.js").body, "js");

    for (const std::string bad :
         {"../outside.txt", "%2e%2e/outside.txt", ".secret.txt", "views",
          "views/", "missing.js", "views/a.exe"}) {
        BOOST_CHECK_MESSAGE(ServeFromDirectory(dir, bad).status == 404, bad);
    }
#ifndef WIN32
    // A symlink may not lead out of the directory.
    std::filesystem::create_symlink(m_args.GetDataDirBase() / "outside.txt",
                                    dir / "link.txt");
    BOOST_CHECK_EQUAL(ServeFromDirectory(dir, "link.txt").status, 404);
#endif
}

BOOST_AUTO_TEST_CASE(authorities_and_origins) {
    auto a{ParseAuthority("LocalHost:12604")};
    BOOST_CHECK_EQUAL(a->host, "localhost");
    BOOST_CHECK_EQUAL(*a->port, 12604);
    a = ParseAuthority("[::1]:80");
    BOOST_CHECK_EQUAL(a->host, "[::1]");
    BOOST_CHECK_EQUAL(a->Normalized("http"), "[::1]");
    BOOST_CHECK_EQUAL(a->Normalized("https"), "[::1]:80");
    BOOST_CHECK(!ParseAuthority(""));
    BOOST_CHECK(!ParseAuthority(":80"));
    BOOST_CHECK(!ParseAuthority("a:0"));
    BOOST_CHECK(!ParseAuthority("a:65536"));
    BOOST_CHECK(!ParseAuthority("a:+1"));
    BOOST_CHECK(!ParseAuthority("a b"));
    BOOST_CHECK(!ParseAuthority("user@host"));
    BOOST_CHECK(!ParseAuthority("[::1"));
    BOOST_CHECK(!ParseAuthority("host/path"));

    auto o{ParseOrigin("HTTPS://Node.Example.org:443")};
    BOOST_CHECK_EQUAL(o->Normalized(), "https://node.example.org");
    BOOST_CHECK_EQUAL(ParseOrigin("http://127.0.0.1:12604")->Normalized(),
                      "http://127.0.0.1:12604");
    BOOST_CHECK(!ParseOrigin("ftp://x"));
    BOOST_CHECK(!ParseOrigin("null"));
    BOOST_CHECK(!ParseOrigin("https://x/"));
    BOOST_CHECK(!ParseOrigin("https://x/path"));
    BOOST_CHECK(!ParseOrigin("https://u:p@x"));
    BOOST_CHECK(!ParseOrigin("https://x?q"));

    BOOST_CHECK(IsLoopbackHost("127.0.0.1"));
    BOOST_CHECK(IsLoopbackHost("127.255.3.4"));
    BOOST_CHECK(IsLoopbackHost("localhost"));
    BOOST_CHECK(IsLoopbackHost("[::1]"));
    BOOST_CHECK(!IsLoopbackHost("127.0.0"));
    BOOST_CHECK(!IsLoopbackHost("127.0.0.1.evil.example"));
    BOOST_CHECK(!IsLoopbackHost("127.0.0.256"));
    BOOST_CHECK(!IsLoopbackHost("128.0.0.1"));
    BOOST_CHECK(!IsLoopbackHost("localhost.evil.example"));
    BOOST_CHECK(!IsLoopbackHost("[::2]"));
    BOOST_CHECK(!IsLoopbackHost("0.0.0.0"));
}

BOOST_AUTO_TEST_CASE(origin_policy) {
    const OriginPolicy local;
    // Loopback with any port, localhost and [::1]; Origin equal to the node's
    // own origin, after normalization.
    BOOST_CHECK(
        Allows(local, "http", "127.0.0.1:12604", "http://127.0.0.1:12604"));
    BOOST_CHECK(Allows(local, "http", "127.0.0.1:12604", std::nullopt,
                       /*require_origin=*/false));
    BOOST_CHECK(Allows(local, "http", "127.1.2.3:9", "http://127.1.2.3:9"));
    BOOST_CHECK(
        Allows(local, "http", "localhost:40000", "http://LOCALHOST:40000"));
    BOOST_CHECK(Allows(local, "http", "[::1]:12604", "http://[::1]:12604"));
    BOOST_CHECK(Allows(local, "http", "127.0.0.1", "http://127.0.0.1:80"));
    BOOST_CHECK(Allows(local, "https", "127.0.0.1:443", "https://127.0.0.1"));

    // DNS rebinding: a foreign Host is refused, Origin or not.
    BOOST_CHECK(!Allows(local, "http", "evil.example:12604",
                        "http://evil.example:12604"));
    BOOST_CHECK(!Allows(local, "http", "evil.example:12604", std::nullopt,
                        /*require_origin=*/false));
    BOOST_CHECK(!Allows(local, "http", "127.0.0.1.nip.io:12604",
                        "http://127.0.0.1.nip.io:12604"));
    BOOST_CHECK(!Allows(local, "http", std::nullopt, std::nullopt, false));
    BOOST_CHECK(!Allows(local, "http", "", std::nullopt, false));
    // Scheme mismatch
    BOOST_CHECK(
        !Allows(local, "http", "127.0.0.1:12604", "https://127.0.0.1:12604"));
    BOOST_CHECK(
        !Allows(local, "https", "127.0.0.1:12604", "http://127.0.0.1:12604"));
    // Same site, other port (another local web server)
    BOOST_CHECK(
        !Allows(local, "http", "127.0.0.1:12604", "http://127.0.0.1:3000"));
    BOOST_CHECK(
        !Allows(local, "http", "127.0.0.1:12604", "http://localhost:12604"));
    // Missing Origin where it is required (POST)
    BOOST_CHECK(!Allows(local, "http", "127.0.0.1:12604", std::nullopt));
    BOOST_CHECK(!Allows(local, "http", "127.0.0.1:12604", "null"));

    // Configured origins
    const OriginPolicy proxied{{*ParseOrigin("https://node.example.org"),
                                *ParseOrigin("http://lan.example:8080")}};
    BOOST_CHECK(Allows(proxied, "https", "node.example.org",
                       "https://node.example.org"));
    BOOST_CHECK(Allows(proxied, "https", "Node.Example.org:443",
                       "https://node.example.org:443"));
    BOOST_CHECK(
        Allows(proxied, "http", "lan.example:8080", "http://lan.example:8080"));
    BOOST_CHECK(
        Allows(proxied, "http", "127.0.0.1:12604", "http://127.0.0.1:12604"));
    // Listed host, but the scheme is not the listed one
    BOOST_CHECK(!Allows(proxied, "http", "node.example.org",
                        "http://node.example.org"));
    BOOST_CHECK(!Allows(proxied, "https", "node.example.org:8443",
                        "https://node.example.org:8443"));
    BOOST_CHECK(
        !Allows(proxied, "https", "node.example.org", "https://evil.example"));
    BOOST_CHECK(
        !Allows(proxied, "https", "evil.example:443", "https://evil.example"));
}

BOOST_AUTO_TEST_CASE(cookies) {
    BOOST_CHECK_EQUAL(CookieName(12604), "nodewallet_12604");
    BOOST_CHECK(CookieName(12604) != CookieName(12605));
    const std::string header{"theme=dark; nodewallet_12605=" + Secret('b') +
                             ";nodewallet_12604=" + Secret('a') +
                             "; nodewallet_12604=" + Secret('c') + "; x"};
    BOOST_CHECK_EQUAL(*GetCookie(header, "nodewallet_12604"), Secret('a'));
    BOOST_CHECK_EQUAL(*GetCookie(header, "nodewallet_12605"), Secret('b'));
    BOOST_CHECK_EQUAL(*GetCookie(header, "theme"), "dark");
    BOOST_CHECK_EQUAL(*GetCookie("a=\"quoted\"", "a"), "quoted");
    BOOST_CHECK_EQUAL(*GetCookie("a=", "a"), "");
    BOOST_CHECK(!GetCookie(header, "nodewallet_1260"));
    BOOST_CHECK(!GetCookie(header, "x"));
    BOOST_CHECK(!GetCookie("", "a"));

    BOOST_CHECK(IsJsonContentType("application/json"));
    BOOST_CHECK(IsJsonContentType("Application/JSON; charset=utf-8"));
    BOOST_CHECK(!IsJsonContentType("text/plain"));
    BOOST_CHECK(!IsJsonContentType("application/json-seq"));
    BOOST_CHECK(!IsJsonContentType(""));
}

BOOST_AUTO_TEST_CASE(login_tokens) {
    SetMockTime(1'800'000'000);
    LoginTokens tokens;
    int64_t expires;
    const std::string t1{tokens.Mint("__cookie__", GetTime(), expires)};
    BOOST_CHECK_EQUAL(t1.size(), 64U);
    BOOST_CHECK_EQUAL(expires, GetTime() + TOKEN_LIFETIME_SECONDS);
    // Single use
    BOOST_CHECK_EQUAL(*tokens.Consume(t1, GetTime()), "__cookie__");
    BOOST_CHECK(!tokens.Consume(t1, GetTime()));
    // Only lowercase hex of the right length is a token.
    const std::string t2{tokens.Mint("alice", GetTime(), expires)};
    BOOST_CHECK(!tokens.Consume(ToUpper(t2), GetTime()));
    BOOST_CHECK(!tokens.Consume(t2.substr(1), GetTime()));
    BOOST_CHECK(!tokens.Consume(Secret('0'), GetTime()));
    BOOST_CHECK_EQUAL(*tokens.Consume(t2, GetTime()), "alice");

    // Expiry
    const std::string t3{tokens.Mint("bob", GetTime(), expires)};
    SetMockTime(GetTime() + TOKEN_LIFETIME_SECONDS - 1);
    const std::string t4{tokens.Mint("carol", GetTime(), expires)};
    BOOST_CHECK_EQUAL(*tokens.Consume(t3, GetTime()), "bob");
    SetMockTime(GetTime() + TOKEN_LIFETIME_SECONDS);
    BOOST_CHECK(!tokens.Consume(t4, GetTime()));
    // ...and an expired token is gone, not just refused.
    BOOST_CHECK_EQUAL(tokens.Size(), 0U);

    // At most 16: minting another evicts the oldest.
    std::vector<std::string> minted;
    for (size_t i = 0; i < MAX_LOGIN_TOKENS + 1; ++i) {
        minted.push_back(
            tokens.Mint("user" + util::ToString(i), GetTime(), expires));
    }
    BOOST_CHECK_EQUAL(tokens.Size(), MAX_LOGIN_TOKENS);
    BOOST_CHECK(!tokens.Consume(minted[0], GetTime()));
    BOOST_CHECK_EQUAL(*tokens.Consume(minted[1], GetTime()), "user1");
    BOOST_CHECK_EQUAL(*tokens.Consume(minted.back(), GetTime()),
                      "user" + util::ToString(MAX_LOGIN_TOKENS));
    // Tokens are random.
    BOOST_CHECK_EQUAL(
        std::set<std::string>(minted.begin(), minted.end()).size(),
        minted.size());
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(sessions) {
    SetMockTime(1'800'000'000);
    SessionStore store;
    const auto s1{store.Create("__cookie__", GetTime())};
    BOOST_CHECK_EQUAL(s1.id.size(), 64U);
    BOOST_CHECK_EQUAL(s1.session.csrf.size(), 64U);
    BOOST_CHECK(s1.id != s1.session.csrf);
    BOOST_CHECK_EQUAL(s1.session.Expires(),
                      GetTime() + SESSION_ABSOLUTE_SECONDS);
    auto found{store.Lookup(s1.id, GetTime())};
    BOOST_CHECK_EQUAL(found->user, "__cookie__");
    BOOST_CHECK_EQUAL(found->csrf, s1.session.csrf);

    // CSRF tokens compare in constant time, by value.
    BOOST_CHECK(SecretsEqual(found->csrf, s1.session.csrf));
    std::string wrong{s1.session.csrf};
    wrong.back() = wrong.back() == 'a' ? 'b' : 'a';
    BOOST_CHECK(!SecretsEqual(found->csrf, wrong));
    BOOST_CHECK(!SecretsEqual(found->csrf, ""));
    BOOST_CHECK(!SecretsEqual(found->csrf, s1.session.csrf.substr(1)));

    // Unknown or malformed ids
    BOOST_CHECK(!store.Lookup(Secret('a'), GetTime()));
    BOOST_CHECK(!store.Lookup(ToUpper(s1.id), GetTime()));
    BOOST_CHECK(!store.Lookup("", GetTime()));

    // Idle expiry: used just in time, it lives on; idle too long, it dies.
    SetMockTime(GetTime() + SESSION_IDLE_SECONDS - 1);
    BOOST_CHECK(store.Lookup(s1.id, GetTime()));
    SetMockTime(GetTime() + SESSION_IDLE_SECONDS - 1);
    BOOST_CHECK(store.Lookup(s1.id, GetTime()));
    SetMockTime(GetTime() + SESSION_IDLE_SECONDS);
    BOOST_CHECK(!store.Lookup(s1.id, GetTime()));
    BOOST_CHECK_EQUAL(store.Size(), 0U);

    // Absolute expiry, however busy the session is.
    const int64_t start{GetTime()};
    const auto s2{store.Create("alice", start)};
    while (GetTime() + SESSION_IDLE_SECONDS / 2 <
           start + SESSION_ABSOLUTE_SECONDS) {
        SetMockTime(GetTime() + SESSION_IDLE_SECONDS / 2);
        BOOST_CHECK(store.Lookup(s2.id, GetTime()));
    }
    SetMockTime(start + SESSION_ABSOLUTE_SECONDS);
    BOOST_CHECK(!store.Lookup(s2.id, GetTime()));

    // Logout
    const auto s3{store.Create("bob", GetTime())};
    BOOST_CHECK(store.Remove(s3.id));
    BOOST_CHECK(!store.Remove(s3.id));
    BOOST_CHECK(!store.Lookup(s3.id, GetTime()));

    // At most 64: the least recently used goes.
    std::vector<SessionStore::NewSession> created;
    for (size_t i = 0; i < MAX_SESSIONS; ++i) {
        SetMockTime(GetTime() + 1);
        created.push_back(store.Create("user" + util::ToString(i), GetTime()));
    }
    BOOST_CHECK_EQUAL(store.Size(), MAX_SESSIONS);
    // Touch the oldest, so the second oldest is now the least recently used.
    SetMockTime(GetTime() + 1);
    BOOST_CHECK(store.Lookup(created[0].id, GetTime()));
    SetMockTime(GetTime() + 1);
    const auto extra{store.Create("extra", GetTime())};
    BOOST_CHECK_EQUAL(store.Size(), MAX_SESSIONS);
    BOOST_CHECK(store.Lookup(created[0].id, GetTime()));
    BOOST_CHECK(!store.Lookup(created[1].id, GetTime()));
    BOOST_CHECK(store.Lookup(created[2].id, GetTime()));
    BOOST_CHECK(store.Lookup(extra.id, GetTime()));
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
