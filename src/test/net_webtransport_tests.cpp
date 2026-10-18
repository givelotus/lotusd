// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_webtransport.h>

#include <net_websocket.h>
#include <netbase.h>
#include <protocol.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(net_webtransport_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bulk_policy_retains_explicit_and_interactive_peers) {
    const auto block{ServiceFlags(NODE_NETWORK | NODE_WEBTRANSPORT)};
    const auto limited{ServiceFlags(NODE_NETWORK_LIMITED | NODE_WEBTRANSPORT)};
    const auto avalanche{ServiceFlags(block | NODE_AVALANCHE)};
    const auto browser{NODE_WEBTRANSPORT};
    for (auto services : {block, limited}) {
        BOOST_CHECK(ShouldTryWebTransport(
            services, WebTransportDialPolicy::PREFER, true));
        BOOST_CHECK(!ShouldTryWebTransport(
            services, WebTransportDialPolicy::PREFER, false));
        BOOST_CHECK(ShouldTryWebTransport(services,
                                          WebTransportDialPolicy::ONLY, false));
    }
    for (auto services : {avalanche, browser}) {
        BOOST_CHECK(ShouldTryWebTransport(
            services, WebTransportDialPolicy::PREFER, false));
        BOOST_CHECK(!ShouldTryWebTransport(services,
                                           WebTransportDialPolicy::OFF, true));
        BOOST_CHECK(!ShouldTryWebTransport(services,
                                           WebTransportDialPolicy::OFF, false));
    }
    BOOST_CHECK(!ShouldTryWebTransport(NODE_NETWORK,
                                       WebTransportDialPolicy::ONLY, true));
}

BOOST_AUTO_TEST_CASE(current_nucleation_messages_keep_their_stream_class) {
    // Current relay owner 81386ab04d633164a3bf679894906b704b5155ae appends
    // sendinvshort/invshort to getAllNetMessageTypes(). Merklix and short-body
    // names already exist in this base. This pins the union without adding a
    // private wire version or pretending the whole relay stack is merged.
    for (const auto name : {"sendinvshort", "invshort", "merklixsync",
                            "getmerklixbuck", "merklixbuck"}) {
        BOOST_CHECK(HasExplicitStreamClass(name));
        BOOST_CHECK(ClassifyMessage(name, {}) == StreamClass::TX_ANNOUNCE);
    }
    for (const auto name : {"getshorttx", "shorttx"}) {
        BOOST_CHECK(HasExplicitStreamClass(name));
        BOOST_CHECK(ClassifyMessage(name, {}) == StreamClass::TX_BODY);
    }
    BOOST_CHECK(ClassifyMessage("futuremsg", {}) == StreamClass::CONTROL);
    BOOST_CHECK(!HasExplicitStreamClass("futuremsg"));
}

BOOST_AUTO_TEST_CASE(discovery_service_flag_is_optional) {
    BOOST_CHECK_EQUAL(serviceFlagsToStr(NODE_WEBTRANSPORT).front(),
                      "WEBTRANSPORT");
    BOOST_CHECK_EQUAL(GetDesirableServiceFlags(NODE_NETWORK),
                      GetDesirableServiceFlags(
                          ServiceFlags(NODE_NETWORK | NODE_WEBTRANSPORT)));
}

BOOST_AUTO_TEST_CASE(negative_cache_lru_ttl_and_success) {
    const auto a{LookupNumeric("127.0.0.1", 443)};
    const auto b{LookupNumeric("127.0.0.1", 444)};
    const auto c{LookupNumeric("127.0.0.2", 443)};
    const auto t{WebTransportNegativeCache::Clock::time_point{}};
    WebTransportNegativeCache cache{2, std::chrono::seconds{10}};
    cache.Record(a, t);
    cache.Record(b, t);
    BOOST_CHECK(cache.Contains(a, t + std::chrono::seconds{2}));
    cache.Record(c, t + std::chrono::seconds{3});
    BOOST_CHECK(!cache.Contains(b, t + std::chrono::seconds{3}));
    BOOST_CHECK(cache.Contains(c, t + std::chrono::seconds{3}));
    // An LRU lookup must not extend the original failure's TTL.
    BOOST_CHECK(!cache.Contains(a, t + std::chrono::seconds{10}));
    BOOST_CHECK_EQUAL(cache.Size(t + std::chrono::seconds{10}), 1U);
    cache.Erase(c);
    BOOST_CHECK_EQUAL(cache.Size(t + std::chrono::seconds{10}), 0U);
    cache.Record(a, t);
    cache.Record(a, t + std::chrono::seconds{5});
    BOOST_CHECK(cache.Contains(a, t + std::chrono::seconds{10}));
    BOOST_CHECK_EQUAL(cache.Size(t + std::chrono::seconds{15}), 0U);
    cache.Record(a, t);
    cache.SetRetryAfter(std::chrono::seconds{0});
    cache.Record(b, t);
    BOOST_CHECK_EQUAL(cache.Size(t), 0U);
    WebTransportNegativeCache empty{0};
    empty.Record(a, t);
    BOOST_CHECK_EQUAL(empty.Size(t), 0U);
}

static std::vector<uint8_t> SerializeInv(const std::vector<CInv> &inv) {
    DataStream ss{};
    ss << inv;
    return {UCharCast(ss.data()), UCharCast(ss.data()) + ss.size()};
}

static std::vector<CInv> DeserializeInv(const std::vector<uint8_t> &bytes) {
    DataStream ss{bytes};
    std::vector<CInv> inv;
    ss >> inv;
    BOOST_CHECK(ss.empty());
    return inv;
}

static bool Same(const CInv &a, const CInv &b) {
    return a.type == b.type && a.hash == b.hash;
}

static uint256 Hash(uint8_t n) {
    uint256 h;
    *h.begin() = n;
    return h;
}

BOOST_AUTO_TEST_CASE(every_message_type_has_a_class) {
    for (const std::string &type : getAllNetMessageTypes()) {
        BOOST_CHECK_MESSAGE(HasExplicitStreamClass(type),
                            type << " has no explicit stream class");
        // Without entries an inventory message is never MIXED either.
        const StreamClass c{ClassifyMessage(type, {})};
        BOOST_CHECK_MESSAGE(c != StreamClass::MIXED, type);
        BOOST_CHECK(IsValidStreamClass(static_cast<uint8_t>(c)));
    }
    BOOST_CHECK(ClassifyMessage("nosuchmsg", {}) == StreamClass::CONTROL);
    BOOST_CHECK(!HasExplicitStreamClass("nosuchmsg"));
}

BOOST_AUTO_TEST_CASE(request_response_pairs_share_a_class) {
    const std::vector<std::pair<std::string, std::string>> pairs{
        {"version", "verack"},
        {"ping", "pong"},
        {"getheaders", "headers"},
        {"getblocktxn", "blocktxn"},
        {"avapoll", "avaresponse"},
        {"getavaproofs", "avaproofs"},
        {"getmerklixbuck", "merklixbuck"},
        {"getshorttx", "shorttx"},
        {"getutxoshard", "utxoshard"},
        {"getblockundo", "blockundo"},
        {"getcfilters", "cfilter"},
    };
    for (const auto &[req, res] : pairs) {
        BOOST_CHECK_MESSAGE(ClassifyMessage(req, {}) == ClassifyMessage(res, {}),
                            req << "/" << res);
    }
    BOOST_CHECK(ClassifyMessage("block", {}) == StreamClass::BLOCK);
    BOOST_CHECK(ClassifyMessage("tx", {}) == StreamClass::TX_BODY);
    BOOST_CHECK(ClassifyMessage("avapoll", {}) == StreamClass::AVALANCHE);
}

BOOST_AUTO_TEST_CASE(inventory_classification) {
    const auto inv_tx{SerializeInv({CInv{MSG_TX, Hash(1)}})};
    BOOST_CHECK(ClassifyMessage("inv", inv_tx) == StreamClass::TX_ANNOUNCE);
    BOOST_CHECK(ClassifyMessage("getdata", inv_tx) == StreamClass::TX_BODY);
    BOOST_CHECK(ClassifyMessage("notfound", inv_tx) == StreamClass::TX_BODY);

    for (uint32_t t : {uint32_t{MSG_BLOCK}, uint32_t{MSG_FILTERED_BLOCK},
                       uint32_t{MSG_CMPCT_BLOCK}, uint32_t{MSG_MINED_HEADER}}) {
        const auto inv{SerializeInv({CInv{t, Hash(2)}, CInv{t, Hash(3)}})};
        BOOST_CHECK(ClassifyMessage("inv", inv) == StreamClass::BLOCK);
        BOOST_CHECK(ClassifyMessage("getdata", inv) == StreamClass::BLOCK);
    }
    for (uint32_t t :
         {uint32_t{MSG_AVA_PROOF}, uint32_t{MSG_AVA_STAKE_CONTENDER},
          uint32_t{MSG_AVA_TREASURY_CONTENDER}, uint32_t{MSG_AVA_MEMPOOL_BATCH}}) {
        BOOST_CHECK(ClassifyMessage("inv", SerializeInv({CInv{t, Hash(4)}})) ==
                    StreamClass::AVALANCHE);
    }
    // Flag bits above the type mask do not change the kind.
    BOOST_CHECK(ClassifyInventoryType(MSG_BLOCK | (1u << 30), false) ==
                StreamClass::BLOCK);

    // Malformed vectors are delivered whole, on the default class.
    std::vector<uint8_t> truncated{inv_tx.begin(), inv_tx.end() - 1};
    BOOST_CHECK(ClassifyMessage("inv", truncated) == StreamClass::TX_ANNOUNCE);
    std::vector<uint8_t> overlong{0xfe, 0xff, 0xff, 0xff, 0xff};
    BOOST_CHECK(ClassifyMessage("getdata", overlong) == StreamClass::TX_BODY);
    const auto split{SplitByClass("inv", truncated)};
    BOOST_REQUIRE_EQUAL(split.size(), 1U);
    BOOST_CHECK(split[0].second == truncated);
}

BOOST_AUTO_TEST_CASE(split_mixed_inventory) {
    const std::vector<CInv> mixed{
        CInv{MSG_TX, Hash(1)},
        CInv{MSG_BLOCK, Hash(2)},
        CInv{MSG_TX, Hash(3)},
        CInv{MSG_AVA_PROOF, Hash(4)},
        CInv{MSG_BLOCK, Hash(5)},
    };
    const auto bytes{SerializeInv(mixed)};
    BOOST_CHECK(ClassifyMessage("inv", bytes) == StreamClass::MIXED);
    const auto split{SplitByClass("inv", bytes)};
    BOOST_REQUIRE_EQUAL(split.size(), 3U);
    // Ordered by each class's first entry; entries keep their order.
    BOOST_CHECK(split[0].first == StreamClass::TX_ANNOUNCE);
    BOOST_CHECK(split[1].first == StreamClass::BLOCK);
    BOOST_CHECK(split[2].first == StreamClass::AVALANCHE);
    const auto tx{DeserializeInv(split[0].second)};
    BOOST_REQUIRE_EQUAL(tx.size(), 2U);
    BOOST_CHECK(Same(tx[0], mixed[0]));
    BOOST_CHECK(Same(tx[1], mixed[2]));
    const auto blocks{DeserializeInv(split[1].second)};
    BOOST_REQUIRE_EQUAL(blocks.size(), 2U);
    BOOST_CHECK(Same(blocks[0], mixed[1]));
    BOOST_CHECK(Same(blocks[1], mixed[4]));
    const auto proofs{DeserializeInv(split[2].second)};
    BOOST_REQUIRE_EQUAL(proofs.size(), 1U);
    BOOST_CHECK(Same(proofs[0], mixed[3]));

    // Each part classifies as its class, and parts reassemble the entries.
    size_t total{0};
    for (const auto &[c, part] : split) {
        BOOST_CHECK(ClassifyMessage("inv", part) == c);
        total += DeserializeInv(part).size();
    }
    BOOST_CHECK_EQUAL(total, mixed.size());

    // getdata: tx entries are bodies there.
    const auto gd{SplitByClass("getdata", SerializeInv({CInv{MSG_TX, Hash(1)},
                                                        CInv{MSG_BLOCK, Hash(2)},
                                                        CInv{MSG_TX, Hash(3)}}))};
    BOOST_REQUIRE_EQUAL(gd.size(), 2U);
    BOOST_CHECK(gd[0].first == StreamClass::TX_BODY);
    BOOST_CHECK(gd[1].first == StreamClass::BLOCK);
    BOOST_CHECK_EQUAL(DeserializeInv(gd[0].second).size(), 2U);

    // Not mixed: returned unchanged.
    const auto single{SplitByClass("tx", Span<const uint8_t>{bytes})};
    BOOST_REQUIRE_EQUAL(single.size(), 1U);
    BOOST_CHECK(single[0].first == StreamClass::TX_BODY);
    BOOST_CHECK(single[0].second == bytes);
}

BOOST_AUTO_TEST_CASE(stream_class_helpers) {
    BOOST_CHECK_EQUAL(StreamClassName(StreamClass::CONTROL), "control");
    BOOST_CHECK_EQUAL(StreamClassName(StreamClass::BLOCK), "block");
    BOOST_CHECK(!IsValidStreamClass(0));
    BOOST_CHECK(!IsValidStreamClass(6));
    for (size_t i = 0; i < NUM_STREAM_CLASSES; ++i) {
        BOOST_CHECK_EQUAL(StreamClassIndex(ALL_STREAM_CLASSES[i]), i);
    }
    BOOST_CHECK_EQUAL(StreamClassPriority(StreamClass::CONTROL),
                      StreamClassPriority(StreamClass::AVALANCHE));
    BOOST_CHECK_LT(StreamClassPriority(StreamClass::AVALANCHE),
                   StreamClassPriority(StreamClass::TX_ANNOUNCE));
    BOOST_CHECK_LT(StreamClassPriority(StreamClass::TX_ANNOUNCE),
                   StreamClassPriority(StreamClass::TX_BODY));
    BOOST_CHECK_LT(StreamClassPriority(StreamClass::TX_BODY),
                   StreamClassPriority(StreamClass::BLOCK));
}

BOOST_AUTO_TEST_CASE(parse_webtransport_url) {
    BOOST_CHECK(IsWebTransportURL("wt://x"));
    BOOST_CHECK(!IsWebTransportURL("wss://x"));

    auto u{ParseWebTransportURL("wt://node.example")};
    BOOST_REQUIRE(u);
    BOOST_CHECK_EQUAL(u->host, "node.example");
    BOOST_CHECK_EQUAL(u->port, 443);
    BOOST_CHECK_EQUAL(u->authority, "node.example:443");
    BOOST_CHECK_EQUAL(u->path, "/p2p/wt");
    BOOST_CHECK(u->token.empty());
    BOOST_CHECK(!u->spki_pin && !u->cert_sha256);

    u = ParseWebTransportURL("wt://127.0.0.1:18444/custom/path?t=abc-DEF_1.~");
    BOOST_REQUIRE(u);
    BOOST_CHECK_EQUAL(u->host, "127.0.0.1");
    BOOST_CHECK_EQUAL(u->port, 18444);
    BOOST_CHECK_EQUAL(u->path, "/custom/path");
    BOOST_CHECK_EQUAL(u->token, "abc-DEF_1.~");

    u = ParseWebTransportURL("wt://[::1]:9000");
    BOOST_REQUIRE(u);
    BOOST_CHECK_EQUAL(u->host, "::1");
    BOOST_CHECK_EQUAL(u->authority, "[::1]:9000");

    const std::vector<unsigned char> digest(32, 0xab);
    u = ParseWebTransportURL("wt://h:1#spki=" + EncodeSpkiPin(digest));
    BOOST_REQUIRE(u && u->spki_pin);
    BOOST_CHECK(*u->spki_pin == digest);
    u = ParseWebTransportURL("wt://h:1#cert=" + HexStr(digest));
    BOOST_REQUIRE(u && u->cert_sha256);
    BOOST_CHECK(*u->cert_sha256 == digest);

    for (const char *bad : {
             "wss://h:1",
             "wt://",
             "wt://:1",
             "wt://h:0",
             "wt://h:65536",
             "wt://h:x",
             "wt://h?t=",
             "wt://h?t=a b",
             "wt://h?other=1",
             "wt://h#spki=short",
             "wt://h#cert=00",
             "wt://h#pin=abc",
             "wt://h/a b",
         }) {
        BOOST_CHECK_MESSAGE(!ParseWebTransportURL(bad), bad);
    }

    BOOST_CHECK_EQUAL(RedactWebTransportURL("wt://h/p?t=secret#cert=00"),
                      "wt://h/p?t=***#cert=00");
    BOOST_CHECK_EQUAL(RedactWebTransportURL("wt://host/at=1"), "wt://host/at=1");
}

BOOST_AUTO_TEST_CASE(registries) {
    BOOST_CHECK(!GetWebTransportDialer());
    BOOST_CHECK(!GetP2PWebTransportAcceptor());
    int calls{0};
    SetP2PWebTransportAcceptor(
        [&](std::unique_ptr<Sock> &&, const CAddress &, const CAddress &,
            std::shared_ptr<QuicTransportInfo>) { ++calls; });
    GetP2PWebTransportAcceptor()(nullptr, CAddress{}, CAddress{}, nullptr);
    BOOST_CHECK_EQUAL(calls, 1);
    SetP2PWebTransportAcceptor(nullptr);
    BOOST_CHECK(!GetP2PWebTransportAcceptor());
    BOOST_CHECK_EQUAL(WebTransportDialErrorName(WebTransportDialError::TIMEOUT),
                      "timeout");
}

BOOST_AUTO_TEST_SUITE_END()
