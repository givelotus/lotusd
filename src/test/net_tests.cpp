// Copyright (c) 2012-2019 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <net.h>

#include <addrman.h>
#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <avalanche/statistics.h>
#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <config.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <init.h>
#include <net_processing.h>
#include <net_websocket.h>
#include <net_websocket_bridge.h>
#include <net_websocket_dialer.h>
#include <net_zstd_dict.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/protocol_version.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/validation.h>
#include <threadsafety.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h> // for bilingual_str

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <ios>
#include <memory>
#include <string>

using namespace std::literals;
using util::ToString;

static CNetAddr ip(uint32_t ip) {
    struct in_addr s;
    s.s_addr = ip;
    return CNetAddr(s);
}

namespace {
struct CConnmanTest : public CConnman {
    using CConnman::CConnman;

    Mutex cs;
    size_t outboundFullRelayCount GUARDED_BY(cs);
    size_t avalancheOutboundsCount GUARDED_BY(cs);

    std::condition_variable cvar;

    NodeId nodeid = 0;

    ~CConnmanTest() { ClearNodes(); }

    void AddNode(ConnectionType type) {
        CAddress addr(CService(ip(FastRandomContext().rand<uint32_t>()),
                               Params().GetDefaultPort()),
                      NODE_NONE);

        return AddNode(addr, type);
    }

    void AddNode(const CAddress &addr, ConnectionType type) {
        CNode *pnode = new CNode(nodeid++, /*sock=*/nullptr, addr,
                                 CalculateKeyedNetGroup(addr),
                                 /* nLocalHostNonceIn */ 0,
                                 /* nLocalExtraEntropyIn */ 0, addr,
                                 /* pszDest */ "", type,
                                 /* inbound_onion */ false);

        LOCK(m_nodes_mutex);
        m_nodes.push_back(pnode);
        pnode->fSuccessfullyConnected = true;
    }

    void ClearNodes() {
        LOCK(m_nodes_mutex);
        for (CNode *node : m_nodes) {
            delete node;
        }
        m_nodes.clear();
    }

    void SetMaxOutbounds(int maxFullRelayOutbounds, int maxAvalancheOutbounds) {
        Options options;
        options.nMaxConnections = DEFAULT_MAX_PEER_CONNECTIONS;
        options.m_max_outbound_full_relay = maxFullRelayOutbounds;
        options.m_max_avalanche_outbound = maxAvalancheOutbounds;
        Init(options);
    };

    void Init(const Options &connOptions) {
        CConnman::Init(connOptions);

        if (semOutbound == nullptr) {
            // initialize semaphore
            semOutbound = std::make_unique<CSemaphore>(
                std::min(m_max_outbound, nMaxConnections));
        }
        if (semAddnode == nullptr) {
            // initialize semaphore
            semAddnode = std::make_unique<CSemaphore>(nMaxAddnode);
        }
    }

    CNode *GetNode(size_t index = 0) EXCLUSIVE_LOCKS_REQUIRED(!m_nodes_mutex) {
        LOCK(m_nodes_mutex);
        assert(index < m_nodes.size());
        return m_nodes[index];
    }

    bool TestInactivityCheck(const CNode &node) const {
        return InactivityCheck(node);
    }

    void openNetworkConnection(const CAddress &addrConnect,
                               ConnectionType connType)
        EXCLUSIVE_LOCKS_REQUIRED(!cs) {
        bool newConnection = !AlreadyConnectedToAddress(addrConnect);
        addrman.Attempt(addrConnect, true);

        if (newConnection) {
            {
                LOCK(cs);

                if (connType == ConnectionType::AVALANCHE_OUTBOUND) {
                    avalancheOutboundsCount++;
                }
                if (connType == ConnectionType::OUTBOUND_FULL_RELAY) {
                    outboundFullRelayCount++;
                }
            }

            AddNode(addrConnect, connType);
            BOOST_CHECK(AlreadyConnectedToAddress(addrConnect));
            addrman.Connected(addrConnect);
        }

        cvar.notify_all();
    }

    struct TestAddresses {
        uint32_t group;
        uint32_t services;
        size_t quantity;
    };

    bool checkContiguousAddressesConnection(
        const std::vector<TestAddresses> &testAddresses,
        size_t expectedOutboundFullRelayCount,
        size_t expectedAvalancheOutboundsCount) EXCLUSIVE_LOCKS_REQUIRED(!cs) {
        {
            LOCK(cs);

            // Reset
            outboundFullRelayCount = 0;
            avalancheOutboundsCount = 0;
        }

        ClearNodes();

        struct IpGen {
            uint32_t baseIp;
            uint32_t offset;
        };
        std::vector<IpGen> ipGroups{
            {0x00010101, 1}, {0x00010164, 1}, {0x000101c8, 1}, {0x00010201, 1},
            {0x00010264, 1}, {0x000102c8, 1}, {0x00010301, 1}, {0x00010364, 1},
            {0x000103c8, 1}, {0x00010401, 1}, {0x00010464, 1}, {0x000104c8, 1}};

        {
            // Make sure we produce addresses in different groups as expected
            std::set<std::vector<uint8_t>> groups;
            for (auto &[baseIp, _] : ipGroups) {
                for (uint32_t j = 0; j < 255; j++) {
                    CNetAddr addr = ip(baseIp + (j << 24));
                    groups.insert(addr.GetGroup({}));
                }
            }
            BOOST_CHECK_EQUAL(groups.size(), ipGroups.size());
        }

        // Generate contiguous addresses
        auto getAddrGroup = [&](size_t group, uint64_t services) {
            CNetAddr addr =
                ip(ipGroups[group].baseIp + (ipGroups[group].offset++ << 24));
            return CAddress(CService(addr, Params().GetDefaultPort()),
                            ServiceFlags(services));
        };

        size_t addressCount = 0;
        for (const TestAddresses &addresses : testAddresses) {
            assert(addresses.group < ipGroups.size());

            addressCount += addresses.quantity;
            do {
                addrman.Add({getAddrGroup(addresses.group,
                                          ServiceFlags(addresses.services))},
                            CNetAddr());
            } while (addrman.size() < addressCount);
        }

        interruptNet.reset();
        std::vector<std::string> empty;
        threadOpenConnections = std::thread(
            &CConnman::ThreadOpenConnections, this, empty,
            std::bind(&CConnmanTest::openNetworkConnection, this,
                      std::placeholders::_1, std::placeholders::_2));

        Mutex mutex;
        WAIT_LOCK(mutex, lock);
        bool ret = cvar.wait_for(lock, 60s, [&]() {
            LOCK(cs);
            return outboundFullRelayCount == expectedOutboundFullRelayCount &&
                   avalancheOutboundsCount == expectedAvalancheOutboundsCount;
        });

        interruptNet();
        if (threadOpenConnections.joinable()) {
            threadOpenConnections.join();
        }

        // Check each non avalanche outbound node belongs to a different group
        std::set<std::vector<uint8_t>> groups;
        ForEachNode([&](const CNode *pnode) {
            if (!pnode->IsAvalancheOutboundConnection()) {
                groups.insert(pnode->addr.GetGroup({}));
            }
        });
        BOOST_CHECK_EQUAL(groups.size(), expectedOutboundFullRelayCount);

        return ret;
    }

    bool AlreadyConnectedToAddress(const CAddress &addr) {
        return CConnman::AlreadyConnectedToAddress(addr);
    }
};
} // namespace

class NetTestConfig : public DummyConfig {
public:
    bool SetMaxBlockSize(uint64_t maxBlockSize) override {
        nMaxBlockSize = maxBlockSize;
        return true;
    }
    uint64_t GetMaxBlockSize() const override { return nMaxBlockSize; }

private:
    uint64_t nMaxBlockSize;
};

// Use TestingSetup or a daughter class so that m_node.addrman is non-null
BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port) {
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test) {
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    auto pnode1 =
        std::make_unique<CNode>(id++, /*sock=*/nullptr, addr,
                                /* nKeyedNetGroupIn = */ 0,
                                /* nLocalHostNonceIn = */ 0,
                                /* nLocalExtraEntropyIn */ 0, CAddress(),
                                pszDest, ConnectionType::OUTBOUND_FULL_RELAY,
                                /* inbound_onion = */ false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    auto pnode2 = std::make_unique<CNode>(id++, /*sock=*/nullptr, addr, 1, 1, 1,
                                          CAddress(), pszDest,
                                          ConnectionType::INBOUND, false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    auto pnode3 = std::make_unique<CNode>(
        id++, /*sock=*/nullptr, addr, 0, 0, 0, CAddress(), pszDest,
        ConnectionType::OUTBOUND_FULL_RELAY, false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    auto pnode4 = std::make_unique<CNode>(id++, /*sock=*/nullptr, addr, 1, 1, 1,
                                          CAddress(), pszDest,
                                          ConnectionType::INBOUND, true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(test_getSubVersionEB) {
    BOOST_CHECK_EQUAL(getSubVersionEB(13800000000), "13800.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(3800000000), "3800.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(14000000), "14.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(1540000), "1.5");
    BOOST_CHECK_EQUAL(getSubVersionEB(1560000), "1.5");
    BOOST_CHECK_EQUAL(getSubVersionEB(210000), "0.2");
    BOOST_CHECK_EQUAL(getSubVersionEB(10000), "0.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(0), "0.0");
}

BOOST_AUTO_TEST_CASE(test_userAgent) {
    NetTestConfig config;

    config.SetMaxBlockSize(8000000);
    const std::string uacomment = "A very nice comment";
    gArgs.ForceSetMultiArg("-uacomment", {uacomment});

    const std::string versionMessage =
        "/Bitcoin ABC:" + ToString(CLIENT_VERSION_MAJOR) + "." +
        ToString(CLIENT_VERSION_MINOR) + "." +
        ToString(CLIENT_VERSION_REVISION) + "(EB8.0; " + uacomment + ")/";

    BOOST_CHECK_EQUAL(userAgent(config), versionMessage);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network) {
    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);
    SetReachable(NET_I2P, false);
    SetReachable(NET_CJDNS, false);

    BOOST_CHECK(!IsReachable(NET_IPV4));
    BOOST_CHECK(!IsReachable(NET_IPV6));
    BOOST_CHECK(!IsReachable(NET_ONION));
    BOOST_CHECK(!IsReachable(NET_I2P));
    BOOST_CHECK(!IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);
    SetReachable(NET_I2P, true);
    SetReachable(NET_CJDNS, true);

    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal) {
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    // Ignored for both networks
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));
}

CNetAddr UtilBuildAddress(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4) {
    uint8_t ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    // initialize the memory block
    memset(&sa, 0, sizeof(sockaddr_in));
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr) {
    // 1.1.1.1
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001);

    SetReachable(NET_IPV4, true);
    BOOST_CHECK(IsReachable(addr));

    SetReachable(NET_IPV4, false);
    BOOST_CHECK(!IsReachable(addr));

    // have to reset this, because this is stateful.
    SetReachable(NET_IPV4, true);
}

BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle) {
    // 2.1.1.1:1000
    CService addr =
        CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000);

    SetReachable(NET_IPV4, true);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic) {
    CNetAddr addr;

    // IPv4, INADDR_ANY
    addr = LookupHost("0.0.0.0", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "0.0.0.0");

    // IPv4, INADDR_NONE
    addr = LookupHost("255.255.255.255", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "255.255.255.255");

    // IPv4, casual
    addr = LookupHost("12.34.56.78", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "12.34.56.78");

    // IPv6, in6addr_any
    addr = LookupHost("::", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "::");

    // IPv6, casual
    addr = LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    addr = LookupHost(scoped_addr, false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for
    // the default scope.
    addr = LookupHost(link_local + "%0", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), link_local);

    // TORv2
    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "6hzph5hv6337r6p2.onion");

    // TORv3
    const char *torv3_addr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion",
        66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char *i2p_addr =
        "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of
    // bytes.
    BOOST_CHECK(!addr.SetSpecial(
        "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial(
        "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial(
        "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(!addr.SetSpecial(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    // "internal" is considered invalid
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1) {
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V1_NETWORK};

    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "fd87d87eeb43f1f2f3f4f5f6f7f8f9fa");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial(
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2) {
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "030af1f2f3f4f5f6f7f8f9fa");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial(
        "kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(
        HexStr(s),
        "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2) {
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr),
                          std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address

    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr),
                          std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02" // network type (IPv6)
                       "10" // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{
        ParseHex("02"                                  // network type (IPv6)
                 "10"                                  // address length
                 "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd +
                                                       // sha256("bitcoin")[0:5]
                                                       // + sha256(name)[0:10]
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02" // network type (IPv6)
                       "10" // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02" // network type (IPv6)
                       "10" // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv2.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "6hzph5hv6337r6p2.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv2, with bogus length.
    s << Span{ParseHex("03"    // network type (TORv2)
                       "07"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 TORv2 address with length 7 (should be 10)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid TORv3.
    s << Span{ParseHex("04" // network type (TORv3)
                       "20" // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f")};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(
        addr.ToStringAddr(),
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(
        addr.ToStringAddr(),
        "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "10" // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "10" // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(
        s >> WithParams(ser_params, addr), std::ios_base::failure,
        HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"         // network type (unknown)
                       "fe00000002" // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr),
                          std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test) {
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(
        0, /*sock=*/nullptr, addr, /* nKeyedNetGroupIn */ 0,
        /* nLocalHostNonceIn */ 0, /* nLocalExtraEntropyIn */ 0, CAddress{},
        /* pszDest */ std::string{}, ConnectionType::OUTBOUND_FULL_RELAY,
        /* inbound_onion = */ false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's
    // -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a
    // sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port) {
    // Test that GetLocalAddrForPeer() properly selects the address to
    // self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address
    // that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has
    // told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the
    // port. 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the
    // above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{
        /*id=*/0,
        /*sock=*/nullptr,
        /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0,
        /*addrBindIn=*/CAddress{},
        /*addrNameIn=*/std::string{},
        /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper
    // peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{
        /*id=*/0,
        /*sock=*/nullptr,
        /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0,
        /*addrBindIn=*/CAddress{},
        /*addrNameIn=*/std::string{},
        /*conn_type_in=*/ConnectionType::INBOUND,
        /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper
    // peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    // An inbound WebSocket peer reached our HTTP/WebSocket port, not our P2P
    // port: only the address it saw may be used, as for outbound peers.
    CNode peer_ws{
        /*id=*/0,
        /*sock=*/nullptr,
        /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0,
        /*addrBindIn=*/CAddress{},
        /*addrNameIn=*/std::string{},
        /*conn_type_in=*/ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        CNodeOptions{.websocket_info =
                         std::make_shared<WebSocketTransportInfo>()}};
    peer_ws.fSuccessfullyConnected = true;
    peer_ws.SetAddrLocal(peer_us);
    chosen_local_addr = GetLocalAddrForPeer(peer_ws);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == expected);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(plain_p2p_off_advertises_no_plain_address) {
    // -p2prawlisten=0: peers cannot reach us with plain P2P, so no IP
    // address (ours, discovered, or as a peer sees us) is ever advertised;
    // a NET_WSS one (-externaldomain) still is.
    g_listen_plain_p2p = false;

    in_addr ip;
    ip.s_addr = htonl(0x03040506);
    const CService plain{ip, 20001};
    BOOST_CHECK(!AddLocal(plain, LOCAL_MANUAL));
    BOOST_CHECK(!AddLocal(plain, LOCAL_BIND));
    BOOST_CHECK(!IsLocal(plain));

    CNetAddr domain;
    BOOST_REQUIRE(domain.SetWSSDomain("node.example.com"));
    const CService wss{domain, 443};
    BOOST_CHECK(AddLocal(wss, LOCAL_MANUAL));

    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    for (const auto conn_type :
         {ConnectionType::OUTBOUND_FULL_RELAY, ConnectionType::INBOUND}) {
        CNode peer{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/
                   CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*nLocalExtraEntropyIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/conn_type,
                   /*inbound_onion=*/false};
        peer.fSuccessfullyConnected = true;
        peer.SetAddrLocal(peer_us);
        BOOST_CHECK(!IsPeerAddrLocalGood(&peer));
        // Repeated: the peer's view of us used to be picked at random.
        for (int i = 0; i < 20; ++i) {
            const auto chosen{GetLocalAddrForPeer(peer)};
            BOOST_REQUIRE(chosen);
            BOOST_CHECK(chosen->IsWSS());
            BOOST_CHECK(*chosen == wss);
        }
        RemoveLocal(wss);
        BOOST_CHECK(!GetLocalAddrForPeer(peer));
        BOOST_CHECK(AddLocal(wss, LOCAL_MANUAL));
    }
    RemoveLocal(wss);

    // Back to the default: plain addresses are learned again.
    g_listen_plain_p2p = true;
    BOOST_CHECK(AddLocal(plain, LOCAL_MANUAL));
    BOOST_CHECK(IsLocal(plain));
    RemoveLocal(plain);
}

BOOST_AUTO_TEST_CASE(p2p_listen_args) {
    const auto check{[](const std::vector<std::pair<std::string, std::string>>
                            &settings,
                        bool interaction = true) {
        ArgsManager args;
        // As bitcoind sets it.
        args.SoftSetBoolArg("-server", true);
        for (const auto &[name, value] : settings) {
            args.ForceSetArg(name, value);
        }
        if (interaction) {
            InitParameterInteraction(args);
        }
        std::vector<bilingual_str> warnings;
        auto error{CheckP2PListenArgs(args, warnings)};
        return std::make_tuple(error ? error->original : std::string{},
                               warnings.size(),
                               GetP2PWebSocketListen(args));
    }};
    const auto ok{[&](const std::vector<std::pair<std::string, std::string>>
                          &settings,
                      size_t n_warnings = 0) {
        const auto [error, warnings, ws]{check(settings)};
        BOOST_CHECK_MESSAGE(error.empty(), error);
        BOOST_CHECK_EQUAL(warnings, n_warnings);
        return ws;
    }};
    const auto fails{
        [&](const std::vector<std::pair<std::string, std::string>> &settings,
            const std::string &needle) {
            const auto [error, warnings, ws]{check(settings)};
            BOOST_CHECK_MESSAGE(error.find(needle) != std::string::npos,
                                "\"" + error + "\" lacks \"" + needle + "\"");
        }};

    // Defaults: both transports, as before these options existed.
    BOOST_CHECK(ok({}));
    BOOST_CHECK(ok({{"-p2prawlisten", "1"}}));

    BOOST_CHECK(!ok({{"-p2pwslisten", "0"}}));
    BOOST_CHECK(ok({{"-p2pwslisten", "1"}}));

    // WebSocket only.
    BOOST_CHECK(ok({{"-p2prawlisten", "0"}}));
    // Neither transport: allowed, with a warning, unless not listening.
    ok({{"-p2prawlisten", "0"}, {"-p2pwslisten", "0"}}, 1);
    ok({{"-listen", "0"}, {"-p2prawlisten", "0"}, {"-p2pwslisten", "0"}}, 0);

    // The P2P port's listeners serve WebSocket too.
    BOOST_CHECK(ok({{"-p2prawlisten", "0"}, {"-bind", "127.0.0.1:1234"}}));
    BOOST_CHECK(
        ok({{"-p2prawlisten", "0"}, {"-whitebind", "noban@127.0.0.1:1234"}}));
    // ... unless nothing would use them.
    fails({{"-p2prawlisten", "0"},
           {"-p2pwslisten", "0"},
           {"-bind", "127.0.0.1:1234"}},
          "-bind");
    fails({{"-p2prawlisten", "0"},
           {"-p2pwslisten", "0"},
           {"-whitebind", "noban@127.0.0.1:1234"}},
          "-whitebind");
    // Options that need raw P2P are refused, not ignored.
    fails({{"-p2prawlisten", "0"}, {"-bind", "127.0.0.1:1234=onion"}},
          "=onion");
    fails({{"-p2prawlisten", "0"}, {"-externalip", "1.2.3.4"}},
          "-externalip");
    fails({{"-p2prawlisten", "0"}, {"-listenonion", "1"}}, "-listenonion");
    fails({{"-p2prawlisten", "0"},
           {"-i2psam", "127.0.0.1:7656"},
           {"-i2pacceptincoming", "1"}},
          "-i2pacceptincoming");
    // ... but only these explicit settings: the defaults are turned off.
    {
        ArgsManager args;
        args.ForceSetArg("-p2prawlisten", "0");
        InitParameterInteraction(args);
        BOOST_CHECK(!args.GetBoolArg("-listenonion", true));
        BOOST_CHECK(!args.GetBoolArg("-i2pacceptincoming", true));
        BOOST_CHECK(!args.GetBoolArg("-discover", true));
        BOOST_CHECK(!args.GetBoolArg("-natpmp", true));
        // -listen keeps its default.
        BOOST_CHECK(args.GetBoolArg("-listen", DEFAULT_LISTEN));
    }
    // -bind still soft-sets -listen=1, as before.
    fails({{"-p2prawlisten", "0"},
           {"-p2pwslisten", "0"},
           {"-proxy", "127.0.0.1:9050"},
           {"-bind", "127.0.0.1:1234"}},
          "-bind");
    // WebSocket peers need the HTTP server.
    {
        const auto [error, warnings,
                    ws]{check({{"-p2prawlisten", "0"}, {"-server", "0"}})};
        BOOST_CHECK_EQUAL(error, "");
        BOOST_CHECK_EQUAL(warnings, 1U);
    }
    // Not listening: -p2prawlisten=0 changes nothing.
    ok({{"-listen", "0"}, {"-p2prawlisten", "0"}, {"-externalip", "1.2.3.4"}});
}

BOOST_AUTO_TEST_CASE(classify_p2p_port_bytes) {
    using P = P2PPortProtocol;
    const auto classify{[](const std::vector<uint8_t> &bytes,
                           const CMessageHeader::MessageMagic &magic) {
        return ClassifyP2PPortBytes(bytes, magic);
    }};
    // Every network's magic: raw P2P from the first byte.
    for (const auto network :
         {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto magic{CreateChainParams(*m_node.args, network)->NetMagic()};
        BOOST_CHECK(classify({magic[0]}, magic) == P::PLAIN);
        BOOST_CHECK(classify({magic.begin(), magic.end()}, magic) == P::PLAIN);
        BOOST_CHECK(classify({}, magic) == P::UNDECIDED);
        // TLS: a handshake record of TLS 1.0-1.3.
        BOOST_CHECK(classify({0x16}, magic) == P::UNDECIDED);
        BOOST_CHECK(classify({0x16, 0x03}, magic) == P::WEBSOCKET);
        BOOST_CHECK(classify({0x16, 0x03, 0x01, 0x02}, magic) == P::WEBSOCKET);
        BOOST_CHECK(classify({0x16, 0x02}, magic) == P::PLAIN);
        // HTTP: only GET, as a WebSocket upgrade needs.
        BOOST_CHECK(classify({'G'}, magic) == P::UNDECIDED);
        BOOST_CHECK(classify({'G', 'E', 'T'}, magic) == P::UNDECIDED);
        BOOST_CHECK(classify({'G', 'E', 'T', ' '}, magic) == P::WEBSOCKET);
        BOOST_CHECK(classify({'G', 'E', 'T', 'x'}, magic) == P::PLAIN);
        BOOST_CHECK(classify({'P', 'O', 'S', 'T'}, magic) == P::PLAIN);
        // Anything else is left to raw P2P, which rejects it.
        BOOST_CHECK(classify({0x00}, magic) == P::PLAIN);
    }
    // A magic that could also start TLS or HTTP waits for 4 bytes.
    const CMessageHeader::MessageMagic tls_like{0x16, 0x03, 0xaa, 0xbb};
    BOOST_CHECK(classify({0x16, 0x03}, tls_like) == P::UNDECIDED);
    BOOST_CHECK(classify({0x16, 0x03, 0xaa, 0xbb}, tls_like) == P::PLAIN);
    BOOST_CHECK(classify({0x16, 0x03, 0x01, 0x00}, tls_like) == P::WEBSOCKET);
    const CMessageHeader::MessageMagic get_like{'G', 'E', 'T', '!'};
    BOOST_CHECK(classify({'G', 'E', 'T'}, get_like) == P::UNDECIDED);
    BOOST_CHECK(classify({'G', 'E', 'T', '!'}, get_like) == P::PLAIN);
    BOOST_CHECK(classify({'G', 'E', 'T', ' '}, get_like) == P::WEBSOCKET);
}

BOOST_AUTO_TEST_CASE(avalanche_statistics) {
    const std::vector<std::tuple<uint32_t, uint32_t, double>> testCases = {
        // {step, tau, decay_factor}
        {10, 100, 1. - std::exp(-1. * 10 / 100)},
        // Current defaults
        {AVALANCHE_STATISTICS_REFRESH_PERIOD.count(),
         AVALANCHE_STATISTICS_TIME_CONSTANT.count(),
         AVALANCHE_STATISTICS_DECAY_FACTOR},
    };
    for (const auto &[step, tau, decayFactor] : testCases) {
        in_addr ipv4Addr;
        ipv4Addr.s_addr = 0xa0b0c001;
        CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
        std::unique_ptr<CNode> pnode = std::make_unique<CNode>(
            0, /*sock=*/nullptr, addr, 0, 0, 0, CAddress(), std::string{},
            ConnectionType::OUTBOUND_FULL_RELAY, false);
        pnode->m_avalanche_enabled = true;

        double previousScore = pnode->getAvailabilityScore();
        BOOST_CHECK_SMALL(previousScore, 1e-6);

        // Check the statistics follow an exponential response for 1 to 10 tau
        for (size_t i = 1; i <= 10; i++) {
            for (uint32_t j = 0; j < tau; j += step) {
                pnode->invsPolled(1);
                // Always respond to everything correctly
                pnode->invsVoted(1);

                pnode->updateAvailabilityScore(decayFactor);

                // Expect a monotonic rise
                double currentScore = pnode->getAvailabilityScore();
                BOOST_CHECK_GE(currentScore, previousScore);
                previousScore = currentScore;
            }

            // We expect (1 - e^-i) after i * tau. The tolerance is expressed
            // as a percentage, and we add a (large) 0.1% margin to account for
            // floating point errors.
            BOOST_CHECK_CLOSE(previousScore, -1 * std::expm1(-1. * i),
                              100.1 / tau);
        }

        // After 10 tau we should be very close to 100% (about 99.995%)
        BOOST_CHECK_CLOSE(previousScore, 1., 0.01);

        for (size_t i = 1; i <= 3; i++) {
            for (uint32_t j = 0; j < tau; j += step) {
                pnode->invsPolled(2);

                // Stop responding to the polls.
                pnode->invsVoted(1);

                pnode->updateAvailabilityScore(decayFactor);

                // Expect a monotonic fall
                double currentScore = pnode->getAvailabilityScore();
                BOOST_CHECK_LE(currentScore, previousScore);
                previousScore = currentScore;
            }

            // There is a slight error in the expected value because we did not
            // start the decay at exactly 100%, but the 0.1% margin is at least
            // an order of magnitude larger than the expected error so it
            // doesn't matter.
            BOOST_CHECK_CLOSE(previousScore, 1. + std::expm1(-1. * i),
                              100.1 / tau);
        }

        // After 3 more tau we should be under 5%
        BOOST_CHECK_LT(previousScore, .05);

        for (size_t i = 1; i <= 100; i++) {
            pnode->invsPolled(10);

            // Completely stop responding to the polls.
            pnode->invsVoted(0);

            pnode->updateAvailabilityScore(decayFactor);

            // It's still a monotonic fall, and the score should turn negative.
            double currentScore = pnode->getAvailabilityScore();
            BOOST_CHECK_LE(currentScore, previousScore);
            BOOST_CHECK_LE(currentScore, 0.);
            previousScore = currentScore;
        }
    }
}

BOOST_AUTO_TEST_CASE(get_extra_full_outbound_count) {
    CConnmanTest connman(m_node.chainman->GetConfig(), 0x1337, 0x1337,
                         *m_node.addrman);

    auto checkExtraFullOutboundCount = [&](size_t fullOutboundCount,
                                           size_t avalancheOutboundCount,
                                           int expectedExtraCount) {
        connman.ClearNodes();
        for (size_t i = 0; i < fullOutboundCount; i++) {
            connman.AddNode(ConnectionType::OUTBOUND_FULL_RELAY);
        }
        for (size_t i = 0; i < avalancheOutboundCount; i++) {
            connman.AddNode(ConnectionType::AVALANCHE_OUTBOUND);
        }
        BOOST_CHECK_EQUAL(connman.GetExtraFullOutboundCount(),
                          expectedExtraCount);
    };

    connman.SetMaxOutbounds(0, 0);
    checkExtraFullOutboundCount(0, 0, 0);
    checkExtraFullOutboundCount(1, 0, 1);
    checkExtraFullOutboundCount(0, 1, 1);
    checkExtraFullOutboundCount(5, 5, 10);

    connman.SetMaxOutbounds(4, 0);
    checkExtraFullOutboundCount(0, 0, 0);
    checkExtraFullOutboundCount(1, 0, 0);
    checkExtraFullOutboundCount(0, 1, 0);
    checkExtraFullOutboundCount(4, 0, 0);
    checkExtraFullOutboundCount(0, 4, 0);
    checkExtraFullOutboundCount(2, 2, 0);
    checkExtraFullOutboundCount(5, 5, 6);

    connman.SetMaxOutbounds(4, 4);
    checkExtraFullOutboundCount(0, 0, 0);
    checkExtraFullOutboundCount(1, 0, 0);
    checkExtraFullOutboundCount(0, 1, 0);
    checkExtraFullOutboundCount(4, 0, 0);
    checkExtraFullOutboundCount(0, 4, 0);
    checkExtraFullOutboundCount(4, 4, 0);
    checkExtraFullOutboundCount(5, 5, 2);
}

BOOST_AUTO_TEST_CASE(net_group_limit) {
    CConnman::Options options;
    auto freshConnman = [&]() {
        m_node.addrman = std::make_unique<AddrMan>(
            /*asmap=*/std::vector<bool>(), /*deterministic=*/true,
            /*consistency_check_ratio=*/0);
        m_node.connman = std::make_unique<CConnmanTest>(
            m_node.chainman->GetConfig(), 0x1337, 0x1337, *m_node.addrman);

        options.nMaxConnections = 200;
        options.m_max_outbound_full_relay = 8;
        options.m_max_avalanche_outbound = 60;

        auto connman = static_cast<CConnmanTest *>(m_node.connman.get());
        connman->Init(options);

        return connman;
    };

    // Single full relay outbound is no problem
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK, 1},
        },
        1, // Expected full-relay outbound count
        0  // Expected avalanche outbound count
        ));

    // Adding more contiguous full relay outbounds fails due to network group
    // limitation
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK, 3},
        },
        1, // Expected full-relay outbound count
        0  // Expected avalanche outbound count
        ));

    // Outbounds from different groups can be connected
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK, 1},
            {1, NODE_NETWORK, 1},
            {2, NODE_NETWORK, 1},
        },
        3, // Expected full-relay outbound count
        0  // Expected avalanche outbound count
        ));

    // Up to the max
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK, 1},
            {1, NODE_NETWORK, 1},
            {2, NODE_NETWORK, 1},
            {3, NODE_NETWORK, 1},
            {4, NODE_NETWORK, 1},
            {5, NODE_NETWORK, 1},
            {6, NODE_NETWORK, 1},
            {7, NODE_NETWORK, 1},
            {8, NODE_NETWORK, 1},
            {9, NODE_NETWORK, 1},
            {10, NODE_NETWORK, 1},
            {11, NODE_NETWORK, 1},
        },
        options.m_max_outbound_full_relay, // Expected full-relay outbound count
        0                                  // Expected avalanche outbound count
        ));

    // Avalanche outbounds are prioritized, so contiguous full relay outbounds
    // will fail due to network group limitation
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK | NODE_AVALANCHE, 1},
            {0, NODE_NETWORK, 3},
        },
        0, // Expected full-relay outbound count
        1  // Expected avalanche outbound count
        ));

    // Adding more avalanche outbounds is fine
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK | NODE_AVALANCHE, 3},
            {0, NODE_NETWORK, 3},
        },
        0, // Expected full-relay outbound count
        3  // Expected avalanche outbound count
        ));

    // Group limit still applies to non avalanche outbounds, which also remain
    // capped to the max from the connman options.
    BOOST_CHECK(freshConnman()->checkContiguousAddressesConnection(
        {
            // group, services, quantity
            {0, NODE_NETWORK | NODE_AVALANCHE, 50},
            {1, NODE_NETWORK, 10},
            {2, NODE_NETWORK, 10},
            {3, NODE_NETWORK, 10},
            {4, NODE_NETWORK, 10},
            {5, NODE_NETWORK, 10},
            {6, NODE_NETWORK, 10},
            {7, NODE_NETWORK, 10},
            {8, NODE_NETWORK, 10},
            {9, NODE_NETWORK, 10},
            {10, NODE_NETWORK, 10},
            {11, NODE_NETWORK, 10},
        },
        options.m_max_outbound_full_relay, // Expected full-relay outbound count
        50                                 // Expected avalanche outbound count
        ));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message) {
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP
    //   connection, we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from
    // the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*nLocalExtraEntropyIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK};
    const int64_t time{Params().GenesisBlock().nTime};

    // Force ChainstateManager::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    auto &chainman = static_cast<TestChainstateManager &>(*m_node.chainman);
    chainman.JumpOutOfIbd();

    const Config &config = m_node.chainman->GetConfig();

    m_node.peerman->InitializeNode(config, peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        NetMsg::Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time,
                     services, WithParams(CAddress::V1_NETWORK, peer_us));
    DataStream msg_version_stream{msg_version.data};

    m_node.peerman->ProcessMessage(config, peer, NetMsgType::VERSION,
                                   msg_version_stream, time_received_dummy,
                                   interrupt_dummy);

    const auto msg_verack = NetMsg::Make(NetMsgType::VERACK);
    DataStream msg_verack_stream{msg_verack.data};

    // Will set peer.fSuccessfullyConnected to true (necessary in
    // SendMessages()).
    m_node.peerman->ProcessMessage(config, peer, NetMsgType::VERACK,
                                   msg_verack_stream, time_received_dummy,
                                   interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage =
        [&sent, &expected](const CAddress &addr, const std::string &msg_type,
                           Span<const uint8_t> data, bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            DataStream s{data};
            std::vector<CAddress> addresses;

            s >> WithParams(CAddress::V1_NETWORK, addresses);

            for (const auto &deserialized_addr : addresses) {
                if (deserialized_addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    m_node.peerman->SendMessages(config, &peer);

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainman.ResetIbd();

    m_node.peerman->FinalizeNode(config, peer);

    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the
    // internal state in timedata.cpp and later confuses the test
    // "timedata_tests/addtimedata". Thus reset that state as it was before our
    // test was run.
    TestOnlyResetTimeData();
}

BOOST_AUTO_TEST_CASE(already_connected_to_address) {
    CConnmanTest connman(m_node.chainman->GetConfig(), 0x1337, 0x1337,
                         *m_node.addrman);

    CNetAddr ip1 = ip(FastRandomContext().rand<uint32_t>());
    CNetAddr ip2 = ip(FastRandomContext().rand<uint32_t>());
    BOOST_CHECK_NE(ip1.ToStringAddr(), ip2.ToStringAddr());

    CAddress ip1port1{{ip1, 2001}, NODE_NETWORK};
    CAddress ip1port2{{ip1, 2002}, NODE_NETWORK};
    CAddress ip2port1{{ip2, 2001}, NODE_NETWORK};

    BOOST_CHECK(!connman.AlreadyConnectedToAddress(ip1port1));
    connman.AddNode(ip1port1, ConnectionType::OUTBOUND_FULL_RELAY);
    BOOST_CHECK(connman.AlreadyConnectedToAddress(ip1port1));

    // Different IP, same port
    BOOST_CHECK(!connman.AlreadyConnectedToAddress(ip2port1));
    connman.AddNode(ip2port1, ConnectionType::OUTBOUND_FULL_RELAY);
    BOOST_CHECK(connman.AlreadyConnectedToAddress(ip2port1));

    // Same IP, different port
    BOOST_CHECK(connman.AlreadyConnectedToAddress(ip1port2));
}

BOOST_AUTO_TEST_CASE(inactivity_check) {
    auto now = GetTime<std::chrono::seconds>();
    SetMockTime(count_seconds(now));

    CConnmanTest connman(m_node.chainman->GetConfig(), 0x1337, 0x1337,
                         *m_node.addrman);
    CConnman::Options options;
    options.m_peer_connect_timeout = DEFAULT_PEER_CONNECT_TIMEOUT;
    connman.Init(options);

    auto addNode = [&]() -> CNode * {
        connman.AddNode(ConnectionType::OUTBOUND_FULL_RELAY);
        return connman.GetNode();
    };

    auto checkInactivity = [&](CNode *node, bool expect_disconnect) {
        BOOST_CHECK_EQUAL(connman.TestInactivityCheck(*node),
                          expect_disconnect);
    };

    auto bumpMockTime = [&](std::chrono::seconds offset) {
        now += offset;
        SetMockTime(count_seconds(now));
    };

    const std::chrono::seconds peer_timeout{DEFAULT_PEER_CONNECT_TIMEOUT};

    // Peer timeout after connect
    {
        CNode *node = addNode();

        bumpMockTime(peer_timeout);
        checkInactivity(node, false);

        bumpMockTime(1s);
        // no message in first <peer_timeout> seconds
        checkInactivity(node, true);

        // We received some data, but did not send any
        node->m_last_recv = now;
        node->m_last_send = 0s;
        checkInactivity(node, true);

        // We sent some data, but did not receive any
        node->m_last_recv = 0s;
        node->m_last_send = now;
        checkInactivity(node, true);

        // No timeout
        node->m_last_recv = now;
        node->m_last_send = now;
        checkInactivity(node, false);
    }

    connman.ClearNodes();

    // Send/receive timeouts
    {
        CNode *node = addNode();
        bumpMockTime(peer_timeout + 1s);
        // Save for later
        auto base_time = now;

        node->m_last_send = now;
        node->m_last_recv = now;

        bumpMockTime(TIMEOUT_INTERVAL);
        checkInactivity(node, false);

        bumpMockTime(1s);

        // Receive timeout
        node->m_last_recv = base_time;
        node->m_last_send = now;
        checkInactivity(node, true);

        // Send timeout
        node->m_last_recv = now;
        node->m_last_send = base_time;
        checkInactivity(node, true);

        // No timeout
        node->m_last_send = now;
        node->m_last_recv = now;
        checkInactivity(node, false);
    }

    connman.ClearNodes();

    // Stalled message timeouts
    {
        CNode *node = addNode();
        bumpMockTime(peer_timeout + 1s);

        // Save for later
        auto base_time = now;
        node->nInflightBytes = 1000;

        node->m_last_msg_start = now;
        node->m_last_recv = now;
        node->m_last_send = now;
        checkInactivity(node, false);

        bumpMockTime(peer_timeout + 1s);

        node->m_last_msg_start = base_time;
        node->m_last_recv = base_time;
        node->m_last_send = now;
        // Message inflight but no data received for <peer_timeout> seconds
        checkInactivity(node, true);

        // Boundary check
        node->m_last_msg_start = base_time;
        node->m_last_recv = base_time + 1s;
        node->m_last_send = now;
        checkInactivity(node, false);

        bumpMockTime(peer_timeout);

        node->m_last_msg_start = base_time;
        node->m_last_recv = now;
        node->m_last_send = now;
        // Message inflight but not completed for <2*peer_timeout> seconds
        checkInactivity(node, true);

        // Boundary check
        node->m_last_msg_start = base_time + 1s;
        node->m_last_recv = now;
        node->m_last_send = now;
        checkInactivity(node, false);
    }

    connman.ClearNodes();

    // Handshake timeout
    {
        CNode *node = addNode();
        bumpMockTime(peer_timeout + 1s);
        node->m_last_recv = now;
        node->m_last_send = now;
        checkInactivity(node, false);

        // No handshake
        node->fSuccessfullyConnected = false;
        checkInactivity(node, true);
    }

    connman.ClearNodes();
}

namespace {
/** A P2P message header (magic + command + length + checksum) and payload */
std::vector<uint8_t> FakeP2PMessage(const std::string &command,
                                    const std::vector<uint8_t> &payload) {
    const auto &magic{Params().NetMagic()};
    std::vector<uint8_t> msg(magic.begin(), magic.end());
    std::string cmd{command};
    cmd.resize(CMessageHeader::MESSAGE_TYPE_SIZE, '\0');
    msg.insert(msg.end(), cmd.begin(), cmd.end());
    const uint32_t len = payload.size();
    for (int i = 0; i < 4; ++i) {
        msg.push_back((len >> (8 * i)) & 0xff);
    }
    const uint256 hash{Hash(payload)};
    msg.insert(msg.end(), hash.begin(), hash.begin() + 4);
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

/** An inv announcing one random transaction */
std::vector<uint8_t> FakeInvTx(FastRandomContext &rng) {
    std::vector<uint8_t> payload{1, 1, 0, 0, 0};
    const uint256 txid{rng.rand256()};
    payload.insert(payload.end(), txid.begin(), txid.end());
    return FakeP2PMessage("inv", payload);
}
} // namespace

BOOST_AUTO_TEST_CASE(p2p_zstd_session_roundtrip) {
    FastRandomContext rng{/*fDeterministic=*/true};
    for (const bool use_dict : {false, true}) {
        P2PZstdSession sender{use_dict};
        P2PZstdSession receiver{use_dict};
        std::vector<uint8_t> all_in, all_out;
        // Messages of many sizes, including empty and > the bridge chunk.
        for (size_t size : {0, 1, 24, 61, 1000, 70000, 300000}) {
            std::vector<uint8_t> in = rng.randbytes<uint8_t>(size);
            if (size > 100) {
                // Make part of it compressible.
                std::fill(in.begin(), in.begin() + size / 2, 0x42);
            }
            std::vector<uint8_t> frame;
            sender.CompressFrame(in, frame);
            std::vector<uint8_t> out;
            receiver.DecompressFrame(frame, out);
            // Each frame decodes completely on its own (ZSTD_e_flush)
            BOOST_CHECK(out == in);
            all_in.insert(all_in.end(), in.begin(), in.end());
            all_out.insert(all_out.end(), out.begin(), out.end());
        }
        BOOST_CHECK(all_out == all_in);
    }
}

BOOST_AUTO_TEST_CASE(p2p_zstd_session_warm_window_and_dict) {
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto inv{FakeInvTx(rng)};
    const auto ping{FakeP2PMessage("ping", rng.randbytes<uint8_t>(8))};

    // The prebaked dictionary helps the very first small message.
    std::vector<uint8_t> plain_frame, dict_frame;
    P2PZstdSession plain{false}, dict{true};
    plain.CompressFrame(ping, plain_frame);
    dict.CompressFrame(ping, dict_frame);
    BOOST_CHECK_LT(dict_frame.size(), plain_frame.size());

    // A message repeated on the same stream compresses to a back-reference.
    std::vector<uint8_t> first, second;
    P2PZstdSession session{false};
    session.CompressFrame(inv, first);
    session.CompressFrame(inv, second);
    BOOST_CHECK_LT(second.size(), first.size() / 3);

    // Both peers must use the dictionary: a plain decoder can't decode it.
    P2PZstdSession wrong{false};
    std::vector<uint8_t> out;
    std::vector<uint8_t> dict_inv;
    P2PZstdSession dict2{true};
    dict2.CompressFrame(inv, dict_inv);
    bool failed{false};
    try {
        wrong.DecompressFrame(dict_inv, out);
    } catch (const std::runtime_error &) {
        failed = true;
    }
    BOOST_CHECK(failed || out != inv);
}

BOOST_AUTO_TEST_CASE(p2p_zstd_session_rejects_garbage) {
    P2PZstdSession session{true};
    std::vector<uint8_t> out;
    const std::vector<uint8_t> garbage{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    BOOST_CHECK_THROW(session.DecompressFrame(garbage, out),
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(p2p_zstd_dict_is_stable) {
    // Changing the v1 dictionary breaks interoperability; see
    // contrib/devtools/gen-p2p-zstd-dict.py.
    BOOST_CHECK_EQUAL(sizeof(P2P_ZSTD_DICT_V1), 9586U);
    CSHA256 hasher;
    hasher.Write(P2P_ZSTD_DICT_V1, sizeof(P2P_ZSTD_DICT_V1));
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    BOOST_CHECK_EQUAL(HexStr(digest), P2P_ZSTD_DICT_V1_SHA256);
}

BOOST_AUTO_TEST_CASE(p2p_websocket_negotiation) {
    using C = P2PWebSocketCompression;
    auto check = [](std::string_view offer, bool deflate,
                    const std::string &token, C mode) {
        const auto [selected, compression] =
            p2pws::NegotiateP2PCompression(offer, deflate);
        BOOST_CHECK_EQUAL(selected, token);
        BOOST_CHECK(compression == mode);
    };
    check("p2p-zstd-v1, p2p-zstd", false, "p2p-zstd-v1", C::ZSTD_DICT);
    check("p2p-zstd,p2p-zstd-v1", false, "p2p-zstd-v1", C::ZSTD_DICT);
    check(" p2p-zstd ", true, "p2p-zstd", C::ZSTD);
    check("chat, superchat", true, "", C::PERMESSAGE_DEFLATE);
    check("", false, "", C::NONE);
    check("p2p-zstd-v10", false, "", C::NONE);

    BOOST_CHECK(p2pws::CompressionFromSelectedProtocol("p2p-zstd-v1", false) ==
                C::ZSTD_DICT);
    BOOST_CHECK(p2pws::CompressionFromSelectedProtocol("", true) ==
                C::PERMESSAGE_DEFLATE);
    BOOST_CHECK_EQUAL(P2PWebSocketCompressionName(C::ZSTD_DICT), "p2p-zstd-v1");

    BOOST_CHECK_EQUAL(WebSocketFrameHeaderSize(125, false), 2U);
    BOOST_CHECK_EQUAL(WebSocketFrameHeaderSize(126, false), 4U);
    BOOST_CHECK_EQUAL(WebSocketFrameHeaderSize(65536, true), 14U);
}

BOOST_AUTO_TEST_CASE(net_wss_address) {
    CNetAddr addr;
    BOOST_CHECK(addr.SetWSSDomain("Node.Example.COM"));
    BOOST_CHECK(addr.IsWSS());
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsRoutable());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.GetNetClass(), NET_WSS);
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "node.example.com");
    BOOST_CHECK_EQUAL(GetNetworkName(NET_WSS), "wss");
    BOOST_CHECK_EQUAL(ParseNetwork("wss"), NET_WSS);
    const CService service{addr, 443};
    BOOST_CHECK_EQUAL(service.ToStringAddrPort(), "node.example.com:443");
    BOOST_CHECK_EQUAL(WebSocketURLForAddress(service),
                      "wss://node.example.com:443/p2p/ws");

    for (const char *bad :
         {"", "-a.com", "a-.com", "a..com", ".a.com", "a.com.", "a_b.com",
          "a b", "x.y/z"}) {
        BOOST_CHECK_MESSAGE(!CNetAddr{}.SetWSSDomain(bad), bad);
    }
    BOOST_CHECK(!CNetAddr{}.SetWSSDomain(std::string(64, 'a') + ".com"));
    BOOST_CHECK(CNetAddr{}.SetWSSDomain(std::string(63, 'a') + ".com"));
    BOOST_CHECK(!CNetAddr{}.SetWSSDomain(std::string(254, 'a')));

    // ADDRv2 round trip with BIP155 network id 0x10: version 1, name only
    // (the default path is never written out)
    BOOST_CHECK_EQUAL(addr.GetWSSVersion(), WSS_ADDR_V1);
    BOOST_CHECK(addr.IsDialableWSS());
    BOOST_CHECK_EQUAL(addr.GetWSSHost(), "node.example.com");
    BOOST_CHECK_EQUAL(addr.GetWSSPath(), "/p2p/ws");
    DataStream s{};
    ParamsStream ps{CAddress::V2_NETWORK, s};
    ps << addr;
    BOOST_CHECK_EQUAL(HexStr(s),
                      "101101" + HexStr(std::string{"node.example.com"}));
    CNetAddr decoded;
    ps >> decoded;
    BOOST_CHECK(decoded == addr);
    CNetAddr explicit_default;
    BOOST_CHECK(explicit_default.SetWSSDomain("node.example.com", "/p2p/ws"));
    BOOST_CHECK(explicit_default == addr);

    // With a path
    CNetAddr with_path;
    BOOST_CHECK(with_path.SetWSSDomain("Node.Example.com", "/Lotus/p2p"));
    BOOST_CHECK(with_path != addr);
    BOOST_CHECK_EQUAL(with_path.ToStringAddr(), "node.example.com");
    BOOST_CHECK_EQUAL(with_path.GetWSSPath(), "/Lotus/p2p");
    BOOST_CHECK(with_path.GetGroup({}) == addr.GetGroup({}));
    BOOST_CHECK_EQUAL(WebSocketURLForAddress(CService{with_path, 8443}),
                      "wss://node.example.com:8443/Lotus/p2p");
    s.clear();
    ps << with_path;
    BOOST_CHECK_EQUAL(HexStr(s), "101b01" + HexStr(std::string{
                                                "node.example.com/Lotus/p2p"}));
    ps >> decoded;
    BOOST_CHECK(decoded == with_path);
    for (const char *bad :
         {"/", "p2p", "/a/", "/a?b", "/a#b", "/a%20", "/a b"}) {
        BOOST_CHECK_MESSAGE(!CNetAddr{}.SetWSSDomain("a.com", bad), bad);
    }
    BOOST_CHECK(!CNetAddr{}.SetWSSDomain("a.com", "/" + std::string(255, 'a')));
    BOOST_CHECK(CNetAddr{}.SetWSSDomain("a.com", "/" + std::string(254, 'a')));

    // A later version is kept and relayed as is, but never dialed, and all
    // such addresses share one addrman group.
    for (const std::string body : {"", "anything \x01\xff at all"}) {
        const std::vector<uint8_t> payload{[&] {
            std::vector<uint8_t> v{0x02};
            v.insert(v.end(), body.begin(), body.end());
            return v;
        }()};
        DataStream later{};
        ParamsStream pl{CAddress::V2_NETWORK, later};
        pl << uint8_t{0x10} << payload;
        const std::string wire{HexStr(later)};
        CNetAddr opaque;
        pl >> opaque;
        BOOST_CHECK(opaque.IsWSS());
        BOOST_CHECK(opaque.IsValid());
        BOOST_CHECK_EQUAL(opaque.GetWSSVersion(), 2);
        BOOST_CHECK(!opaque.IsDialableWSS());
        BOOST_CHECK_EQUAL(opaque.GetWSSPath(), "");
        BOOST_CHECK(opaque.ToStringAddr().starts_with("wss-v2-"));
        BOOST_CHECK(opaque.GetGroup({}) == std::vector<uint8_t>({NET_WSS, 2}));
        pl << opaque;
        BOOST_CHECK_EQUAL(HexStr(later), wire);
    }

    // ADDRv1 cannot carry names: serialized as all-zeros (and never relayed
    // to ADDRv1 peers, see IsAddrV1Compatible).
    DataStream s1{};
    ParamsStream ps1{CAddress::V1_NETWORK, s1};
    ps1 << addr;
    BOOST_CHECK_EQUAL(HexStr(s1), std::string(32, '0'));

    // Malformed payloads (and bad sizes) from peers are ignored, not fatal:
    // a bad name, a bad or explicit default path, the reserved version 0 and
    // an empty payload.
    for (const std::string &hex :
         {std::string{"100501"} + HexStr(std::string{"a b."}),
          std::string{"100a01"} + HexStr(std::string{"a.com/p?q"}),
          std::string{"100d01"} + HexStr(std::string{"a.com/p2p/ws"}),
          std::string{"100700"} + HexStr(std::string{"a.com/"}),
          std::string{"1000"}}) {
        DataStream bad{ParseHex(hex)};
        ParamsStream pbad{CAddress::V2_NETWORK, bad};
        CNetAddr out;
        pbad >> out;
        BOOST_CHECK(!out.IsValid());
        BOOST_CHECK(bad.empty());
    }
}

BOOST_AUTO_TEST_CASE(p2p_websocket_url_parsing) {
    auto url{ParseWebSocketURL("wss://Node.example.com/p2p/ws")};
    BOOST_REQUIRE(url);
    BOOST_CHECK(url->tls);
    BOOST_CHECK_EQUAL(url->host, "Node.example.com");
    BOOST_CHECK_EQUAL(url->port, 443);
    BOOST_CHECK_EQUAL(url->authority, "Node.example.com:443");
    BOOST_CHECK_EQUAL(url->target, "/p2p/ws");

    url = ParseWebSocketURL("ws://127.0.0.1:18443");
    BOOST_REQUIRE(url);
    BOOST_CHECK(!url->tls);
    BOOST_CHECK_EQUAL(url->port, 18443);
    BOOST_CHECK_EQUAL(url->target, "/p2p/ws");

    url = ParseWebSocketURL("wss://[::1]:8443/custom?x=1");
    BOOST_REQUIRE(url);
    BOOST_CHECK_EQUAL(url->host, "::1");
    BOOST_CHECK_EQUAL(url->authority, "[::1]:8443");
    BOOST_CHECK_EQUAL(url->target, "/custom?x=1");

    for (const char *bad :
         {"http://a.com", "wss://", "wss://:443", "ws://a.com:99999", "a.com"}) {
        BOOST_CHECK_MESSAGE(!ParseWebSocketURL(bad), bad);
    }
    // A key pin in the fragment
    const std::vector<unsigned char> key(32, 0xab);
    const std::string pin{EncodeSpkiPin(key)};
    BOOST_CHECK_EQUAL(pin.size(), 43U); // unpadded base64url
    BOOST_CHECK(pin.find_first_of("+/=") == std::string::npos);
    url = ParseWebSocketURL("wss://host/p2p/ws#spki=" + pin);
    BOOST_REQUIRE(url);
    BOOST_CHECK(url->spki_pin == key);
    BOOST_CHECK_EQUAL(url->target, "/p2p/ws");
    // Standard base64 with padding is accepted as well
    BOOST_CHECK(DecodeSpkiPin(EncodeBase64(key)) == key);
    for (const char *bad : {"wss://host/p2p/ws#spki=", "wss://host/p2p/ws#spki=AAAA",
                            "wss://host/p2p/ws#other=x"}) {
        BOOST_CHECK_MESSAGE(!ParseWebSocketURL(bad), bad);
    }

    // An upgrade token leaves the request target and is never logged
    url = ParseWebSocketURL("wss://host/a/b?x=1&token=Ab-9_.~&y=2#spki=" + pin);
    BOOST_REQUIRE(url);
    BOOST_CHECK_EQUAL(url->token, "Ab-9_.~");
    BOOST_CHECK_EQUAL(url->target, "/a/b?x=1&y=2");
    url = ParseWebSocketURL("ws://host/p?token=t");
    BOOST_REQUIRE(url);
    BOOST_CHECK_EQUAL(url->target, "/p");
    BOOST_CHECK(!ParseWebSocketURL("wss://host/p?token="));
    BOOST_CHECK(!ParseWebSocketURL("wss://host/p?token=a%20b"));
    BOOST_CHECK_EQUAL(RedactWebSocketURL("wss://h/p?a=1&token=secret#spki=x"),
                      "wss://h/p?a=1&token=***#spki=x");
    BOOST_CHECK_EQUAL(RedactWebSocketURL("wss://h/p?xtoken=keep"),
                      "wss://h/p?xtoken=keep");

    BOOST_CHECK(IsWebSocketURL("wss://a"));
    BOOST_CHECK(IsWebSocketURL("ws://a"));
    BOOST_CHECK(!IsWebSocketURL("1.2.3.4:8333"));
}

namespace {
/** A Sock that holds received data and a pending write in user space */
class BufferedSock final : public Sock {
public:
    BufferedSock(SOCKET s, std::string data, Event pending)
        : Sock{s}, m_data{std::move(data)}, m_pending{pending} {}
    bool HasBufferedRecv() const override { return !m_data.empty(); }
    Event PendingEvents() const override { return m_pending; }
    bool FlushPending() const override {
        ++m_flushes;
        m_pending = 0;
        return true;
    }
    ssize_t Recv(void *buf, size_t len, int) const override {
        const size_t n{std::min(len, m_data.size())};
        if (n == 0) {
            errno = EAGAIN;
            return -1;
        }
        std::memcpy(buf, m_data.data(), n);
        m_data.erase(0, n);
        return n;
    }
    mutable std::string m_data;
    mutable Event m_pending;
    mutable int m_flushes{0};
};
} // namespace

BOOST_AUTO_TEST_CASE(sock_buffered_data_hooks) {
    int sv[2];
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    const Config &config{m_node.chainman->GetConfig()};
    ConnmanTestMsg connman{config, 0x1337, 0x1337, *m_node.addrman};
    const std::string garbage(100, 'x');
    auto sock{std::make_shared<BufferedSock>(SOCKET(sv[0]), garbage, Sock::SEND)};
    CNode *node = new CNode{/*id=*/0,
                            sock,
                            CAddress{},
                            /*nKeyedNetGroupIn=*/0,
                            /*nLocalHostNonceIn=*/0,
                            /*nLocalExtraEntropyIn=*/0,
                            CAddress{},
                            /*addrNameIn=*/"",
                            ConnectionType::INBOUND,
                            /*inbound_onion=*/false};
    connman.AddTestNode(*node);

    // Nothing queued by CConnman and receiving paused: the socket is still
    // polled for SEND because its implementation has a pending write.
    node->fPauseRecv = true;
    std::vector<CNode *> nodes{node};
    auto events{connman.GenerateWaitSocketsForTest(nodes)};
    BOOST_REQUIRE_EQUAL(events.size(), 1U);
    BOOST_CHECK_EQUAL(events.begin()->second.requested, Sock::SEND);

    // Buffered data is received although the OS socket (sv[1] never writes)
    // is not readable, and the pending write is flushed once writable.
    node->fPauseRecv = false;
    const uint64_t before{connman.GetTotalBytesRecv()};
    connman.SocketHandlerForTest();
    BOOST_CHECK_EQUAL(connman.GetTotalBytesRecv() - before, garbage.size());
    BOOST_CHECK_EQUAL(sock->m_flushes, 1);
    BOOST_CHECK(sock->m_data.empty());

    connman.ClearTestNodes();
    close(sv[1]);
}

BOOST_AUTO_TEST_SUITE_END()
