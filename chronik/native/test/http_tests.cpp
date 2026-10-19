// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the HTTP framework: ports of the Rust tests in chronik-http
// error.rs and protobuf.rs, plus router/axum/CORS behaviour checks and a
// golden comparison of prost 0.11.9 decode errors.

#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/proto.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <memory>
#include <sstream>
#include <string>

using namespace chronik::native;

namespace {

HttpRequest MakeRequest(std::string method, std::string target) {
    HttpRequest req;
    req.method = std::move(method);
    size_t q = target.find('?');
    if (q == std::string::npos) {
        req.path = target;
    } else {
        req.path = target.substr(0, q);
        req.query_string = target.substr(q + 1);
        req.has_query = true;
    }
    return req;
}

std::string BodyStr(const HttpResponse &resp) {
    return std::string(resp.body.begin(), resp.body.end());
}

proto::Error DecodeError(const HttpResponse &resp) {
    proto::Error err;
    BOOST_REQUIRE(err.ParseFromArray(resp.body.data(), int(resp.body.size())));
    return err;
}

Bytes FromHex(const std::string &hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(uint8_t(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::unique_ptr<google::protobuf::Message> MakeMessage(const std::string &n) {
    if (n == "RawTx") {
        return std::make_unique<proto::RawTx>();
    }
    if (n == "BroadcastTxRequest") {
        return std::make_unique<proto::BroadcastTxRequest>();
    }
    if (n == "BroadcastTxsRequest") {
        return std::make_unique<proto::BroadcastTxsRequest>();
    }
    if (n == "WsSub") {
        return std::make_unique<proto::WsSub>();
    }
    if (n == "ScriptBatchUtxosRequest") {
        return std::make_unique<proto::ScriptBatchUtxosRequest>();
    }
    if (n == "ScriptBatchSummaryRequest") {
        return std::make_unique<proto::ScriptBatchSummaryRequest>();
    }
    if (n == "Tx") {
        return std::make_unique<proto::Tx>();
    }
    return nullptr;
}

} // namespace

BOOST_AUTO_TEST_SUITE(http_tests)

// Port of error.rs test_report_error
BOOST_AUTO_TEST_CASE(report_error) {
    auto check = [](const char *msg, int status, const char *expected) {
        HttpResponse resp = ErrorResponse(msg);
        BOOST_CHECK_EQUAL(resp.status, status);
        BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
        BOOST_CHECK_EQUAL(DecodeError(resp).msg(), expected);
    };
    check("Something obsure", 500, "Unknown error, contact admins");
    check("500: Cable eaten by cat", 500, "500: Cable eaten by cat");
    check("501: Never implemented", 501, "501: Never implemented");
    check("400: Request encoding not code page 65001", 400,
          "400: Request encoding not code page 65001");
}

BOOST_AUTO_TEST_CASE(report_error_logging) {
    std::vector<std::pair<std::string, bool>> logs;
    HttpLogFn log = [&](std::string_view msg, bool debug) {
        logs.emplace_back(std::string(msg), debug);
    };
    ReportStatusError("404: Not found", log);
    BOOST_CHECK(logs.empty());
    ReportStatusError("503: busy", log);
    BOOST_REQUIRE_EQUAL(logs.size(), 2u);
    BOOST_CHECK_EQUAL(logs[1].first,
                      "Chronik HTTP server got an internal server error: "
                      "503: busy\n");
    BOOST_CHECK(!logs[1].second);
    logs.clear();
    ReportStatusError("oops", log);
    BOOST_REQUIRE_EQUAL(logs.size(), 2u);
    BOOST_CHECK_EQUAL(logs[1].first,
                      "Chronik HTTP server got an unknown error: oops\n");
}

// Port of protobuf.rs test_protobuf
BOOST_AUTO_TEST_CASE(protobuf_extractor) {
    Router router;
    router.Get("/", [](const HttpRequest &req, const PathParams &) {
        auto raw = ParseProtobufRequest<proto::RawTx>(req);
        proto::RawTx out;
        out.set_raw_tx(raw.raw_tx() + "!");
        return HttpResponse::Protobuf(out);
    });
    auto call = [&](std::optional<std::string> content_type, Bytes body,
                    bool too_large = false) {
        HttpRequest req = MakeRequest("GET", "/");
        if (content_type) {
            req.headers.emplace_back("Content-Type", *content_type);
        }
        req.body = std::move(body);
        req.body_too_large = too_large;
        return router.Handle(req);
    };

    // No Content-Type
    HttpResponse resp = call(std::nullopt, {});
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(), "400: No Content-Type set");

    // Content-Type invalid UTF-8
    resp = call(std::string("\xff"), {});
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(),
                      "400: Content-Type bad encoding: failed to convert "
                      "header to a str");

    // Content-Type is not application/x-protobuf
    resp = call(std::string("text/not-protobuf"), {});
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(),
                      "400: Content-Type must be application/x-protobuf, got "
                      "text/not-protobuf");

    // Bad protobuf
    resp = call(std::string("application/x-protobuf"), {0xff});
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(),
                      "400: Bad protobuf: failed to decode Protobuf message: "
                      "invalid varint");

    // Oversized body (flagged by the transport, or delivered in full)
    resp = call(std::string("application/x-protobuf"), {}, true);
    BOOST_CHECK_EQUAL(resp.status, 413);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(),
                      "413: Request body exceeds maximum size of 2000000 "
                      "bytes");
    resp = call(std::string("application/x-protobuf"),
                Bytes(MAX_REQUEST_BODY_SIZE + 1));
    BOOST_CHECK_EQUAL(resp.status, 413);

    // Wrong content type wins over size (checked first)
    resp = call(std::string("text/plain"), {}, true);
    BOOST_CHECK_EQUAL(resp.status, 400);

    // Success
    proto::RawTx raw;
    raw.set_raw_tx("abc");
    std::string ser = raw.SerializeAsString();
    resp = call(std::string("application/x-protobuf"),
                Bytes(ser.begin(), ser.end()));
    BOOST_CHECK_EQUAL(resp.status, 200);
    BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
    proto::RawTx out;
    BOOST_REQUIRE(out.ParseFromArray(resp.body.data(), int(resp.body.size())));
    BOOST_CHECK_EQUAL(out.raw_tx(), "abc!");
}

// Every case of the fixture was decoded by prost 0.11.9 (the version the Rust
// Chronik uses) from chronik.proto; the native emulation must produce the same
// DecodeError Display text, or accept exactly the same inputs.
BOOST_AUTO_TEST_CASE(prost_decode_errors_golden) {
    std::ifstream file(std::string(CHRONIK_NATIVE_FIXTURES_DIR) +
                       "/prost_decode_errors.tsv");
    BOOST_REQUIRE(file.good());
    std::string line;
    size_t n_cases = 0, n_ok = 0;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream ss(line);
        std::string name, hex, expected;
        std::getline(ss, name, '\t');
        std::getline(ss, hex, '\t');
        std::getline(ss, expected);
        auto msg = MakeMessage(name);
        BOOST_REQUIRE_MESSAGE(msg, "unknown message " + name);
        const Bytes data = FromHex(hex);
        const auto err = ProstDecodeError(*msg, data);
        const std::string actual = err ? *err : "OK";
        BOOST_CHECK_MESSAGE(actual == expected, name + " " + hex +
                                                    ": expected '" + expected +
                                                    "', got '" + actual + "'");
        if (!err) {
            ++n_ok;
            // libprotobuf must then accept it as well
            BOOST_CHECK_MESSAGE(
                msg->ParseFromArray(data.data(), int(data.size())),
                "libprotobuf rejects prost-valid " + name + " " + hex);
        }
        ++n_cases;
    }
    BOOST_CHECK_GT(n_cases, 2000u);
    BOOST_CHECK_GT(n_ok, 100u);
}

BOOST_AUTO_TEST_CASE(not_found_fallback) {
    Router router;
    router.Get("/blockchain-info", [](const HttpRequest &, const PathParams &) {
        return HttpResponse::Text(200, "ok");
    });
    for (const char *target :
         {"/nope", "/blockchain-info/", "/nope?x=1&y", "/"}) {
        for (const char *method : {"GET", "POST", "DELETE"}) {
            HttpResponse resp = router.Handle(MakeRequest(method, target));
            BOOST_CHECK_EQUAL(resp.status, 404);
            BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
            BOOST_CHECK_EQUAL(DecodeError(resp).msg(),
                              std::string("404: Not found: ") + target);
        }
    }
    // Empty query string still prints the '?'
    BOOST_CHECK_EQUAL(DecodeError(router.Handle(MakeRequest("GET", "/x?")))
                          .msg(),
                      "404: Not found: /x?");
}

BOOST_AUTO_TEST_CASE(method_not_allowed_and_head) {
    Router router;
    router.Get("/info", [](const HttpRequest &, const PathParams &) {
        return HttpResponse::Text(200, "hello");
    });
    router.PostWithOptions("/broadcast-tx",
                           [](const HttpRequest &, const PathParams &) {
                               return HttpResponse::Text(200, "posted");
                           });

    HttpResponse resp = router.Handle(MakeRequest("POST", "/info"));
    BOOST_CHECK_EQUAL(resp.status, 405);
    BOOST_CHECK(resp.body.empty());
    BOOST_CHECK(resp.ContentType().empty());
    BOOST_REQUIRE(resp.Header("allow"));
    BOOST_CHECK_EQUAL(*resp.Header("allow"), "GET,HEAD");

    resp = router.Handle(MakeRequest("GET", "/broadcast-tx"));
    BOOST_CHECK_EQUAL(resp.status, 405);
    BOOST_CHECK_EQUAL(*resp.Header("Allow"), "POST,OPTIONS");

    // OPTIONS on a POST route: handle_post_options
    resp = router.Handle(MakeRequest("OPTIONS", "/broadcast-tx"));
    BOOST_CHECK_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.empty());
    BOOST_CHECK_EQUAL(*resp.Header("Allow"), "OPTIONS, HEAD, POST");

    // OPTIONS on a GET route without CORS: 405
    resp = router.Handle(MakeRequest("OPTIONS", "/info"));
    BOOST_CHECK_EQUAL(resp.status, 405);

    // HEAD is served by GET, without body but with its length
    resp = router.Handle(MakeRequest("HEAD", "/info"));
    BOOST_CHECK_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.empty());
    BOOST_CHECK_EQUAL(*resp.Header("content-length"), "5");
    BOOST_CHECK_EQUAL(resp.ContentType(), "text/plain; charset=utf-8");
}

BOOST_AUTO_TEST_CASE(path_params) {
    Router router;
    router.Get("/script/:type/:payload/utxos",
               [](const HttpRequest &, const PathParams &p) {
                   BOOST_CHECK_EQUAL(p.names.size(), 2u);
                   return HttpResponse::Text(200, "param:" + p[0] + "," + p[1]);
               });
    router.Post("/script/batch/utxos",
                [](const HttpRequest &, const PathParams &) {
                    return HttpResponse::Text(200, "batch");
                });
    router.Get("/script/:type/:payload/history",
               [](const HttpRequest &, const PathParams &p) {
                   return HttpResponse::Text(200, "history:" + p[0]);
               });
    router.Get("/blocks/:start/:end",
               [](const HttpRequest &, const PathParams &p) {
                   const int32_t start = PathI32(p, 0);
                   const int32_t end = PathI32(p, 1);
                   return HttpResponse::Text(200, std::to_string(start) + "-" +
                                                      std::to_string(end));
               });
    router.Get("/single/:h", [](const HttpRequest &, const PathParams &p) {
        return HttpResponse::Text(200, std::to_string(PathSingleI32(p)));
    });

    BOOST_CHECK_EQUAL(BodyStr(router.Handle(
                          MakeRequest("GET", "/script/p2pkh/ab%2Fcd/utxos"))),
                      "param:p2pkh,ab/cd");
    BOOST_CHECK_EQUAL(BodyStr(router.Handle(
                          MakeRequest("GET", "/script/p2pkh/%zz/history"))),
                      "history:p2pkh");
    // like matchit 0.7, an empty middle segment matches a param...
    BOOST_CHECK_EQUAL(
        BodyStr(router.Handle(MakeRequest("GET", "/script/p2pkh//utxos"))),
        "param:p2pkh,");
    // ...but an empty last segment doesn't
    BOOST_CHECK_EQUAL(router.Handle(MakeRequest("GET", "/blocks/1/")).status,
                      404);
    // static route takes priority: GET on /script/batch/utxos isn't the
    // param route but the POST route's 405
    HttpResponse resp = router.Handle(MakeRequest("GET", "/script/batch/utxos"));
    BOOST_CHECK_EQUAL(resp.status, 405);
    BOOST_CHECK_EQUAL(*resp.Header("allow"), "POST");

    BOOST_CHECK_EQUAL(BodyStr(router.Handle(MakeRequest("GET", "/blocks/1/+5"))),
                      "1-5");
    BOOST_CHECK_EQUAL(
        BodyStr(router.Handle(MakeRequest("GET", "/blocks/-3/2147483647"))),
        "-3-2147483647");

    resp = router.Handle(MakeRequest("GET", "/blocks/abc/1"));
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(resp.ContentType(), "text/plain; charset=utf-8");
    BOOST_CHECK_EQUAL(BodyStr(resp),
                      "Invalid URL: Cannot parse value at index 0 with value "
                      "`\"abc\"` to a `i32`");
    resp = router.Handle(MakeRequest("GET", "/blocks/1/2147483648"));
    BOOST_CHECK_EQUAL(BodyStr(resp),
                      "Invalid URL: Cannot parse value at index 1 with value "
                      "`\"2147483648\"` to a `i32`");
    resp = router.Handle(MakeRequest("GET", "/blocks/%22q%5C/1"));
    BOOST_CHECK_EQUAL(BodyStr(resp),
                      "Invalid URL: Cannot parse value at index 0 with value "
                      "`\"\\\"q\\\\\"` to a `i32`");
    resp = router.Handle(MakeRequest("GET", "/single/x"));
    BOOST_CHECK_EQUAL(BodyStr(resp),
                      "Invalid URL: Cannot parse `\"x\"` to a `i32`");

    // Invalid UTF-8 after percent-decoding
    resp = router.Handle(MakeRequest("GET", "/blocks/%ff/1"));
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(BodyStr(resp), "Invalid URL: Invalid UTF-8 in `start`");

    // Raw routes (no Path extractor) get the encoded segments, unchecked.
    router.Get(
        "/raw/:a/:b",
        [](const HttpRequest &, const PathParams &p) {
            BOOST_REQUIRE_EQUAL(p.names.size(), 2u);
            return HttpResponse::Text(200, "raw:" + p[0] + "," + p[1]);
        },
        Router::PathExtraction::Raw);
    BOOST_CHECK_EQUAL(
        BodyStr(router.Handle(MakeRequest("GET", "/raw/%ff/ab%2Fcd"))),
        "raw:%ff,ab%2Fcd");
    BOOST_CHECK_EQUAL(router.Handle(MakeRequest("HEAD", "/raw/x/y")).status,
                      200);
    BOOST_CHECK_THROW(router.Post("/raw/:a/:b",
                                  [](const HttpRequest &, const PathParams &) {
                                      return HttpResponse::Empty(200);
                                  }),
                      std::logic_error);
}

BOOST_AUTO_TEST_CASE(handler_errors) {
    Router router;
    router.Get("/err/:kind", [](const HttpRequest &, const PathParams &p)
                                 -> HttpResponse {
        if (p[0] == "404") {
            throw ChronikError("404: Block not found: 99");
        }
        if (p[0] == "plain") {
            throw std::runtime_error("disk exploded");
        }
        throw HttpRejection(400, "Invalid URL: x");
    });
    HttpResponse resp = router.Handle(MakeRequest("GET", "/err/404"));
    BOOST_CHECK_EQUAL(resp.status, 404);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(), "404: Block not found: 99");
    resp = router.Handle(MakeRequest("GET", "/err/plain"));
    BOOST_CHECK_EQUAL(resp.status, 500);
    BOOST_CHECK_EQUAL(DecodeError(resp).msg(), "Unknown error, contact admins");
    resp = router.Handle(MakeRequest("GET", "/err/rej"));
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(BodyStr(resp), "Invalid URL: x");
}

BOOST_AUTO_TEST_CASE(cors) {
    Router router(RouterOptions{true, {}});
    router.Get("/info", [](const HttpRequest &, const PathParams &) {
        return HttpResponse::Text(200, "x");
    });
    router.PostWithOptions("/validate-tx",
                           [](const HttpRequest &, const PathParams &) {
                               return HttpResponse::Text(200, "y");
                           });
    // Any OPTIONS is a preflight (tower-http doesn't call the inner service)
    for (const char *target : {"/info", "/validate-tx", "/nope"}) {
        HttpResponse resp = router.Handle(MakeRequest("OPTIONS", target));
        BOOST_CHECK_EQUAL(resp.status, 200);
        BOOST_CHECK(resp.body.empty());
        BOOST_CHECK_EQUAL(*resp.Header("access-control-allow-origin"), "*");
        BOOST_CHECK_EQUAL(*resp.Header("access-control-allow-methods"), "*");
        BOOST_CHECK_EQUAL(*resp.Header("vary"),
                          "origin, access-control-request-method, "
                          "access-control-request-headers");
        BOOST_CHECK(!resp.Header("allow"));
    }
    HttpResponse resp = router.Handle(MakeRequest("GET", "/info"));
    BOOST_CHECK_EQUAL(*resp.Header("access-control-allow-origin"), "*");
    BOOST_CHECK(resp.Header("vary"));
    BOOST_CHECK(!resp.Header("access-control-allow-methods"));
    resp = router.Handle(MakeRequest("GET", "/nope"));
    BOOST_CHECK_EQUAL(resp.status, 404);
    BOOST_CHECK_EQUAL(*resp.Header("access-control-allow-origin"), "*");

    // No CORS headers when disabled
    Router plain;
    plain.Get("/info", [](const HttpRequest &, const PathParams &) {
        return HttpResponse::Text(200, "x");
    });
    BOOST_CHECK(!plain.Handle(MakeRequest("GET", "/info"))
                     .Header("access-control-allow-origin"));
}

BOOST_AUTO_TEST_CASE(websocket_route_rejections) {
    Router router;
    router.AddWebSocket("/ws");
    auto req = MakeRequest("GET", "/ws");
    HttpResponse resp = router.Handle(req);
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK_EQUAL(BodyStr(resp),
                      "Connection header did not include 'upgrade'");
    req.headers.emplace_back("Connection", "keep-alive, Upgrade");
    BOOST_CHECK_EQUAL(BodyStr(router.Handle(req)),
                      "`Upgrade` header did not include 'websocket'");
    req.headers.emplace_back("Upgrade", "WebSocket");
    BOOST_CHECK_EQUAL(BodyStr(router.Handle(req)),
                      "`Sec-WebSocket-Version` header did not include '13'");
    req.headers.emplace_back("Sec-WebSocket-Version", "13");
    BOOST_CHECK_EQUAL(BodyStr(router.Handle(req)),
                      "`Sec-WebSocket-Key` header missing");
    BOOST_CHECK(!router.IsWebSocketUpgrade(req));
    req.headers.emplace_back("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    BOOST_CHECK(router.IsWebSocketUpgrade(req));
    BOOST_CHECK_EQUAL(router.Handle(req).status, 426);

    // POST /ws: method router 405; HEAD /ws: GET handler -> MethodNotGet
    resp = router.Handle(MakeRequest("POST", "/ws"));
    BOOST_CHECK_EQUAL(resp.status, 405);
    BOOST_CHECK_EQUAL(*resp.Header("allow"), "GET,HEAD");
    resp = router.Handle(MakeRequest("HEAD", "/ws"));
    BOOST_CHECK_EQUAL(resp.status, 405);
    BOOST_CHECK(resp.body.empty());
    auto head_ws = MakeRequest("HEAD", "/ws");
    head_ws.headers = req.headers;
    BOOST_CHECK(!router.IsWebSocketUpgrade(head_ws));
}

BOOST_AUTO_TEST_CASE(query_params) {
    auto req = MakeRequest("GET", "/x?page=1&page_size=25&page=3&a+b=c%20d&"
                                  "e&=f&g=%zz&h=%ff");
    auto params = req.QueryParams();
    BOOST_CHECK_EQUAL(params["page"], "3");
    BOOST_CHECK_EQUAL(params["page_size"], "25");
    BOOST_CHECK_EQUAL(params["a b"], "c d");
    BOOST_CHECK_EQUAL(params["e"], "");
    BOOST_CHECK_EQUAL(params[""], "f");
    BOOST_CHECK_EQUAL(params["g"], "%zz");
    BOOST_CHECK_EQUAL(params["h"], "\xEF\xBF\xBD");
}

// Port of parse.rs behaviour (hex::FromHexError messages)
BOOST_AUTO_TEST_CASE(parse_hex_and_lokad) {
    BOOST_CHECK(ParseHex("00ffAB") == (Bytes{0x00, 0xff, 0xab}));
    auto msg = [](auto fn) {
        try {
            fn();
        } catch (const ChronikError &err) {
            return std::string(err.what());
        }
        return std::string("no error");
    };
    BOOST_CHECK_EQUAL(msg([] { ParseHex("abc"); }),
                      "400: Invalid hex: Odd number of digits");
    BOOST_CHECK_EQUAL(msg([] { ParseHex("zz"); }),
                      "400: Invalid hex: Invalid character 'z' at position 0");
    BOOST_CHECK_EQUAL(msg([] { ParseHex("0g"); }),
                      "400: Invalid hex: Invalid character 'g' at position 1");
    BOOST_CHECK_EQUAL(msg([] { ParseHex("0'"); }),
                      "400: Invalid hex: Invalid character '\\'' at position "
                      "1");
    BOOST_CHECK_EQUAL(msg([] { ParseHex("\n0"); }),
                      "400: Invalid hex: Invalid character '\\n' at position "
                      "0");
    BOOST_CHECK_EQUAL(msg([] { ParseHex("\x01" "0"); }),
                      "400: Invalid hex: Invalid character '\\u{1}' at "
                      "position 0");
    // Non-ASCII bytes are cast to (Latin-1) chars by hex 0.4
    BOOST_CHECK_EQUAL(msg([] { ParseHex("\xc3\xa9"); }),
                      "400: Invalid hex: Invalid character '\xc3\x83' at "
                      "position 0");
    BOOST_CHECK_EQUAL(msg([] { ParseLokadIdHex("0102"); }),
                      "400: Invalid LOKAD ID length: expected 4 but got 2");
    BOOST_CHECK(ParseLokadIdHex("534c5032") ==
                (std::array<uint8_t, 4>{0x53, 0x4c, 0x50, 0x32}));
    BOOST_CHECK_EQUAL(RustDebugStr("a\"b\\c\td\x7f"),
                      "\"a\\\"b\\\\c\\td\\u{7f}\"");
}

BOOST_AUTO_TEST_CASE(optional_observer_cannot_change_http_outcome) {
    size_t calls = 0;
    uint16_t status = 0;
    RouterOptions options;
    options.observe_request = [&](std::string_view path, uint16_t code, uint64_t) {
        BOOST_CHECK_EQUAL(path, "/observed");
        ++calls;
        status = code;
        throw 1;
    };
    Router router(std::move(options));
    router.Get("/observed", [](const HttpRequest &, const PathParams &) {
        return HttpResponse::Text(200, "unchanged");
    });
    auto response = router.Handle(MakeRequest("GET", "/observed"));
    BOOST_CHECK_EQUAL(response.status, 200);
    BOOST_CHECK_EQUAL(BodyStr(response), "unchanged");
    BOOST_CHECK_EQUAL(calls, 1U);
    BOOST_CHECK_EQUAL(status, 200);
}

BOOST_AUTO_TEST_SUITE_END()
