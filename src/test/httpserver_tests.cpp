// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>
#include <test/util/setup_common.h>

#include <netaddress.h>

#include <boost/test/unit_test.hpp>

#include <zstd.h>

BOOST_FIXTURE_TEST_SUITE(httpserver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_query_parameters) {
    std::string uri{};

    // No parameters
    uri = "localhost:8080/rest/headers/someresource.json";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // Single parameter
    uri = "localhost:8080/rest/endpoint/someresource.json?p1=v1";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(),
                      "v1");
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p2").has_value());

    // Multiple parameters
    uri = "/rest/endpoint/someresource.json?p1=v1&p2=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(),
                      "v1");
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p2").value(),
                      "v2");

    // If the query string contains duplicate keys, the first value is returned
    uri = "/rest/endpoint/someresource.json?p1=v1&p1=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(),
                      "v1");

    // Invalid query string syntax is the same as not having parameters
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // URI with invalid characters (%) raises a runtime error regardless of
    // which query parameter is queried
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2%";
    BOOST_CHECK_EXCEPTION(GetQueryParameterFromUri(uri.c_str(), "p1"),
                          std::runtime_error,
                          HasReason("URI parsing failed, it likely contained "
                                    "RFC 3986 invalid characters"));

    // Values are percent-decoded and '+' maps to a space
    uri = "/rest/endpoint?p1=a%20b+c&p2=%7e";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(),
                      "a b c");
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p2").value(),
                      "~");

    // A malformed pair invalidates the whole query string, as with libevent
    uri = "/rest/endpoint?p1=v1&p2";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // The fragment is not part of the query
    uri = "/rest/endpoint?p1=v1#frag";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(),
                      "v1");

    // Invalid escapes and characters raise
    for (const char *bad : {"/x?p1=%zz", "/x?p1=%4", "/x y?p1=v1"}) {
        BOOST_CHECK_THROW(GetQueryParameterFromUri(bad, "p1"),
                          std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_parsed_request) {
    BOOST_CHECK(!ParseHTTPRequestForTesting("garbage"));
    // Incomplete body
    BOOST_CHECK(!ParseHTTPRequestForTesting(
        "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"));

    auto req{ParseHTTPRequestForTesting(
        "POST /rest/tx?format=hex HTTP/1.1\r\nHost: localhost\r\n"
        "X-Custom: Value\r\nContent-Length: 5\r\n\r\nhello")};
    BOOST_REQUIRE(req);
    BOOST_CHECK(req->GetRequestMethod() == HTTPRequest::POST);
    BOOST_CHECK_EQUAL(req->GetURI(), "/rest/tx?format=hex");
    BOOST_CHECK_EQUAL(req->GetQueryParameter("format").value(), "hex");
    // Header lookup is case-insensitive
    BOOST_CHECK(req->GetHeader("x-custom") ==
                std::make_pair(true, std::string{"Value"}));
    BOOST_CHECK(!req->GetHeader("Missing").first);
    BOOST_CHECK(!req->IsTLS());
    BOOST_CHECK(req->GetClientCertFingerprint().empty());
    BOOST_CHECK_EQUAL(req->GetPeer().ToStringAddrPort(), "[::]:0");
    BOOST_CHECK_EQUAL(req->ReadBody(), "hello");
    // The body is consumed
    BOOST_CHECK_EQUAL(req->ReadBody(), "");

    auto del{ParseHTTPRequestForTesting("DELETE / HTTP/1.1\r\n\r\n")};
    BOOST_REQUIRE(del);
    BOOST_CHECK(del->GetRequestMethod() == HTTPRequest::UNKNOWN);
}

BOOST_AUTO_TEST_CASE(test_zstd_request_body) {
    const std::string plain(4000, 'a');
    std::string compressed(ZSTD_compressBound(plain.size()), '\0');
    compressed.resize(ZSTD_compress(compressed.data(), compressed.size(),
                                    plain.data(), plain.size(), 1));
    auto req{ParseHTTPRequestForTesting(
        "POST / HTTP/1.1\r\nContent-Encoding: zstd\r\nContent-Length: " +
        std::to_string(compressed.size()) + "\r\n\r\n" + compressed)};
    BOOST_REQUIRE(req);
    BOOST_CHECK_EQUAL(req->ReadBody(), plain);

    // A corrupt zstd body reads as empty
    auto bad{ParseHTTPRequestForTesting(
        "POST / HTTP/1.1\r\nContent-Encoding: zstd\r\nContent-Length: "
        "4\r\n\r\nabcd")};
    BOOST_REQUIRE(bad);
    BOOST_CHECK_EQUAL(bad->ReadBody(), "");
}
BOOST_AUTO_TEST_SUITE_END()
