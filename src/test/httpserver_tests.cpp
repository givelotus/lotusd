// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <http_tls_stream.h>
#include <httpserver.h>
#include <tls_util.h>
#include <test/util/setup_common.h>

#include <netaddress.h>

#include <boost/test/unit_test.hpp>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/beast/core/buffers_suffix.hpp>

#include <array>

#include <openssl/ssl.h>
#include <zstd.h>

#include <thread>

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
BOOST_AUTO_TEST_CASE(ossl_stream_reads_gathers_and_retries) {
    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;
    const auto pem{tls::GenerateSelfSigned("t", {"localhost"}, {},
                                           std::chrono::hours{1})};
    BOOST_REQUIRE(pem);
    auto server_ctx{tls::NewContext(/*server=*/true)};
    auto client_ctx{tls::NewContext(/*server=*/false)};
    BOOST_REQUIRE(
        tls::UseCertificatePem(server_ctx.get(), pem->cert_pem, pem->key_pem));

    asio::io_context io;
    tcp::acceptor acceptor{io, {asio::ip::make_address("127.0.0.1"), 0}};
    tcp::socket client{io};
    client.connect(acceptor.local_endpoint());
    boost::beast::tcp_stream server{acceptor.accept()};
    server.socket().non_blocking(true);
    // Small kernel buffers so writes fill them quickly.
    server.socket().set_option(asio::socket_base::send_buffer_size(16384));

    // Blocking OpenSSL client on its own thread.
    tls::SslPtr cssl{SSL_new(client_ctx.get())};
    SSL_set_fd(cssl.get(), int(client.native_handle()));
    std::string received;
    const std::string request(100, 'q');
    const size_t expected{3 * 1024 * 1024 + 11};
    std::thread client_thread{[&] {
        BOOST_REQUIRE_EQUAL(SSL_connect(cssl.get()), 1);
        BOOST_REQUIRE_EQUAL(SSL_write(cssl.get(), request.data(), 100), 100);
        char buf[65536];
        while (received.size() < expected) {
            const int n{SSL_read(cssl.get(), buf, sizeof(buf))};
            BOOST_REQUIRE(n > 0);
            received.append(buf, n);
        }
        // The server's close_notify reads as an orderly end.
        BOOST_CHECK_LE(SSL_read(cssl.get(), buf, sizeof(buf)), 0);
        BOOST_CHECK_EQUAL(SSL_get_error(cssl.get(), 0), SSL_ERROR_ZERO_RETURN);
    }};

    tls::SslPtr sssl{SSL_new(server_ctx.get())};
    SSL_set_fd(sssl.get(), int(server.socket().native_handle()));
    OsslStream stream{server, std::move(sssl)};
    const std::string head{"head:"}, body(3 * 1024 * 1024 + 6, 'b');
    auto result{asio::co_spawn(
        io,
        [&]() -> asio::awaitable<bool> {
            auto [hec, h] = co_await stream.async_handshake(
                asio::as_tuple(asio::use_awaitable));
            if (hec) {
                co_return false;
            }
            std::string got(100, '\0');
            size_t off{0};
            while (off < got.size()) {
                auto [ec, n] = co_await stream.async_read_some(
                    asio::buffer(got.data() + off, got.size() - off),
                    asio::as_tuple(asio::use_awaitable));
                if (ec) {
                    co_return false;
                }
                off += n;
            }
            if (got != request) {
                co_return false;
            }
            // Non-blocking writes of a two-buffer sequence until the socket
            // is full; the rest asynchronously from the same position
            // (which must repeat the exact retried length).
            const std::array<asio::const_buffer, 2> seq{asio::buffer(head),
                                                        asio::buffer(body)};
            size_t sent{0};
            bool blocked{false};
            const size_t total{head.size() + body.size()};
            while (sent < total) {
                auto rest{boost::beast::buffers_suffix<decltype(seq)>{seq}};
                rest.consume(sent);
                boost::system::error_code ec;
                const size_t n{stream.write_some(rest, ec)};
                if (ec == asio::error::would_block) {
                    blocked = true;
                    auto [aec, an] = co_await stream.async_write_some(
                        rest, asio::as_tuple(asio::use_awaitable));
                    if (aec) {
                        co_return false;
                    }
                    sent += an;
                } else if (ec) {
                    co_return false;
                } else {
                    sent += n;
                }
            }
            // close_notify must get out even though the client is still
            // draining a full socket.
            auto [sec, s] = co_await stream.async_shutdown(
                asio::as_tuple(asio::use_awaitable));
            co_return blocked && !sec;
        },
        asio::use_future)};
    io.run();
    client_thread.join();
    BOOST_CHECK(result.get());
    BOOST_CHECK_EQUAL(received.size(), expected);
    BOOST_CHECK(received == head + body);
}

BOOST_AUTO_TEST_SUITE_END()
