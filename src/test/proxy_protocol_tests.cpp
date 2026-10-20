// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <proxy_protocol.h>

#include <netbase.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

using namespace proxy_protocol;

namespace {
std::vector<uint8_t> V2(uint8_t command, uint8_t family,
                        const std::vector<uint8_t> &addrs) {
    std::vector<uint8_t> h(std::begin(V2_SIGNATURE), std::end(V2_SIGNATURE));
    h.push_back(uint8_t(0x20 | command));
    h.push_back(family);
    h.push_back(uint8_t(addrs.size() >> 8));
    h.push_back(uint8_t(addrs.size() & 0xFF));
    h.insert(h.end(), addrs.begin(), addrs.end());
    return h;
}

CService Addr(const std::string &s) { return LookupNumeric(s, 0); }
} // namespace

BOOST_FIXTURE_TEST_SUITE(proxy_protocol_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(v2_ssl_tlv) {
    const std::vector<uint8_t> tcp4{203, 0, 113,  7,    10,   0,
                                    0,   5, 0xC7, 0x38, 0x29, 0x6D};
    const auto with{[&](const std::vector<uint8_t> &tlvs) {
        auto addrs{tcp4};
        addrs.insert(addrs.end(), tlvs.begin(), tlvs.end());
        return ParseV2(V2(0x1, 0x11, addrs));
    }};
    // No TLV, or other TLVs: the client's TLS use is unknown.
    BOOST_CHECK(!with({})->client_tls);
    BOOST_CHECK(!with({0x03, 0x00, 0x01, 0xAA})->client_tls);
    // PP2_TYPE_SSL with PP2_CLIENT_SSL (client, then a 4-byte verify).
    auto h{with({0x20, 0x00, 0x05, 0x01, 0, 0, 0, 0})};
    BOOST_REQUIRE(h && h->source);
    BOOST_CHECK(h->client_tls);
    BOOST_CHECK_EQUAL(h->source->ToStringAddrPort(), "203.0.113.7:51000");
    // ... after another TLV, and with sub-TLVs (PP2_SUBTYPE_SSL_VERSION).
    BOOST_CHECK(with({0x03, 0x00, 0x01, 0xAA, 0x20, 0x00, 0x0C, 0x05, 0, 0, 0,
                      0, 0x21, 0x00, 0x04, 'T', 'L', 'S', '3'})
                    ->client_tls);
    // PP2_TYPE_SSL without PP2_CLIENT_SSL (e.g. only a certificate flag).
    BOOST_CHECK(!with({0x20, 0x00, 0x05, 0x02, 0, 0, 0, 0})->client_tls);
    // Truncated TLVs are not believed.
    BOOST_CHECK(!with({0x20, 0x00, 0x05, 0x01})->client_tls);
    BOOST_CHECK(!with({0x20})->client_tls);
    // IPv6
    std::vector<uint8_t> a6(36, 0);
    a6[0] = 0x20;
    a6.insert(a6.end(), {0x20, 0x00, 0x01, 0x01});
    BOOST_CHECK(ParseV2(V2(0x1, 0x21, a6))->client_tls);
    // v1 cannot carry it.
    BOOST_CHECK(!ParseV1("PROXY TCP4 203.0.113.7 10.0.0.5 51000 10605\r\n")
                     ->client_tls);
}

BOOST_AUTO_TEST_CASE(v2_headers) {
    // TCP over IPv4: 203.0.113.7:51000 -> 10.0.0.5:10605
    const auto tcp4{V2(0x1, 0x11, {203, 0, 113, 7, 10, 0, 0, 5, 0xC7, 0x38,
                                   0x29, 0x6D})};
    BOOST_CHECK_EQUAL(*V2PayloadSize(tcp4), 12U);
    auto h{ParseV2(tcp4)};
    BOOST_REQUIRE(h && h->source);
    BOOST_CHECK_EQUAL(h->source->ToStringAddrPort(), "203.0.113.7:51000");

    // TCP over IPv6, with a trailing TLV (ignored)
    std::vector<uint8_t> a6(36, 0);
    a6[0] = 0x20;
    a6[1] = 0x01;
    a6[2] = 0x0d;
    a6[3] = 0xb8;
    a6[15] = 0x01;
    a6[32] = 0x01;
    a6[33] = 0xBB;
    a6.insert(a6.end(), {0x03, 0x00, 0x01, 0xAA});
    h = ParseV2(V2(0x1, 0x21, a6));
    BOOST_REQUIRE(h && h->source);
    BOOST_CHECK_EQUAL(h->source->ToStringAddrPort(), "[2001:db8::1]:443");

    // LOCAL (a health check from the balancer) and unsupported families keep
    // the connection's own address.
    h = ParseV2(V2(0x0, 0x00, {}));
    BOOST_CHECK(h && !h->source);
    h = ParseV2(V2(0x1, 0x31, std::vector<uint8_t>(216, 0)));
    BOOST_CHECK(h && !h->source);

    // Malformed
    auto bad{tcp4};
    bad[0] = 0x0C;
    BOOST_CHECK(!V2PayloadSize(bad));
    bad = tcp4;
    bad[12] = 0x11; // version 1 in the v2 format
    BOOST_CHECK(!V2PayloadSize(bad));
    bad = tcp4;
    bad[12] = 0x22; // unknown command
    BOOST_CHECK(!ParseV2(bad));
    bad = V2(0x1, 0x11, std::vector<uint8_t>(V2_MAX_PAYLOAD + 1, 0));
    BOOST_CHECK(!V2PayloadSize(bad));
    // Truncated address block
    BOOST_CHECK(!ParseV2(Span{tcp4}.first(tcp4.size() - 1)));
    h = ParseV2(V2(0x1, 0x11, {1, 2, 3}));
    BOOST_CHECK(h && !h->source);
}

BOOST_AUTO_TEST_CASE(v1_headers) {
    auto h{ParseV1("PROXY TCP4 198.51.100.22 10.0.0.5 35646 10605\r\n")};
    BOOST_REQUIRE(h && h->source);
    BOOST_CHECK_EQUAL(h->source->ToStringAddrPort(), "198.51.100.22:35646");
    h = ParseV1("PROXY TCP6 2001:db8::7 2001:db8::1 1 443\r\n");
    BOOST_REQUIRE(h && h->source);
    BOOST_CHECK_EQUAL(h->source->ToStringAddrPort(), "[2001:db8::7]:1");
    h = ParseV1("PROXY UNKNOWN\r\n");
    BOOST_CHECK(h && !h->source);
    h = ParseV1("PROXY UNKNOWN anything at all\r\n");
    BOOST_CHECK(h && !h->source);
    for (const char *bad :
         {"PROXY TCP4 198.51.100.22 10.0.0.5 35646 10605",  // no CRLF
          "PROXY TCP4 2001:db8::7 10.0.0.5 1 2\r\n",        // family mismatch
          "PROXY TCP4 host.example 10.0.0.5 1 2\r\n",       // not numeric
          "PROXY TCP4 1.2.3.4 10.0.0.5 99999 2\r\n",        // bad port
          "PROXY UDP4 1.2.3.4 10.0.0.5 1 2\r\n", "PROXY\r\n",
          "GET / HTTP/1.1\r\n"}) {
        BOOST_CHECK_MESSAGE(!ParseV1(bad), bad);
    }
    BOOST_CHECK(!ParseV1("PROXY UNKNOWN " + std::string(100, 'x') + "\r\n"));
}

BOOST_AUTO_TEST_CASE(forwarded_client) {
    // Proxies at 10.0.0.0/8 (e.g. two layers of balancers in a VPC).
    CSubNet vpc;
    BOOST_REQUIRE(LookupSubNet("10.0.0.0/8", vpc));
    const auto trusted{[&](const CNetAddr &a) { return vpc.Match(a); }};
    const CService lb{Addr("10.0.1.2")};

    // Client -> ALB 10.0.0.9 -> ALB 10.0.1.2 -> node
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"203.0.113.7, 10.0.0.9"}, trusted)
            .ToStringAddr(),
        "203.0.113.7");
    // Several header fields count as one list, in order.
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"203.0.113.7", "10.0.0.9"}, trusted)
            .ToStringAddr(),
        "203.0.113.7");
    // A client's own (spoofed) entries left of the real client are ignored:
    // walking stops at the first untrusted address.
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"1.1.1.1, 10.9.9.9, 203.0.113.7, 10.0.0.9"},
                               trusted)
            .ToStringAddr(),
        "203.0.113.7");
    // From an untrusted peer nothing is believed.
    BOOST_CHECK_EQUAL(ResolveForwardedClient(Addr("203.0.113.7"), {"1.1.1.1"},
                                             trusted)
                          .ToStringAddr(),
                      "203.0.113.7");
    // Ports and bracketed IPv6 are accepted. (Unusable addresses, such as
    // the 2001:db8::/32 documentation range, stop the walk like garbage.)
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"[2a01:4f8::7]:4711"}, trusted)
            .ToStringAddr(),
        "2a01:4f8::7");
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"2a01:4f8::7"}, trusted).ToStringAddr(),
        "2a01:4f8::7");
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"198.51.100.4:80"}, trusted)
            .ToStringAddr(),
        "198.51.100.4");
    // Every hop trusted (a request from inside the VPC): the last one.
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"10.0.0.3, 10.0.0.9"}, trusted)
            .ToStringAddr(),
        "10.0.0.3");
    // Garbage stops the walk at the last trusted address.
    BOOST_CHECK_EQUAL(
        ResolveForwardedClient(lb, {"203.0.113.7, unknown"}, trusted)
            .ToStringAddr(),
        "10.0.1.2");
    // No header: the peer.
    BOOST_CHECK_EQUAL(ResolveForwardedClient(lb, {}, trusted).ToStringAddr(),
                      "10.0.1.2");
}

BOOST_AUTO_TEST_SUITE_END()
