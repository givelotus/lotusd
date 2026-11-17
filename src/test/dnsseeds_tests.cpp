// Copyright (c) 2020-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dnsseeds.h>

#include <chainparams.h>
#include <common/args.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dnsseeds_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(override_dns_seed) {
    // No override should always provide some DNS seeds
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    BOOST_CHECK(GetRandomizedDNSSeeds(*params).size() > 0);

    // Overriding should only return that DNS seed
    gArgs.ForceSetArg("-overridednsseed", "localhost");
    BOOST_CHECK(GetRandomizedDNSSeeds(*params) ==
                std::vector<std::string>{{"localhost"}});
    gArgs.ClearForcedArg("-overridednsseed");
}

static std::string SeedToString(const SeedSpec6 &seed) {
    // IPv4 addresses are wrapped in ::ffff:a.b.c.d.
    return strprintf("%d.%d.%d.%d:%d", seed.addr[12], seed.addr[13],
                     seed.addr[14], seed.addr[15], seed.port);
}

BOOST_AUTO_TEST_CASE(lotus_seeds) {
    const auto main = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto test = CreateChainParams(*m_node.args, ChainType::TESTNET);

    // The DNS seeders of the Lotus network, not those of eCash.
    BOOST_CHECK(GetRandomizedDNSSeeds(*main) ==
                std::vector<std::string>{{"seed.lotusia.org"}});
    BOOST_CHECK(GetRandomizedDNSSeeds(*test) ==
                std::vector<std::string>{{"testnet.seeds.cash"}});

    std::vector<std::string> fixed;
    for (const SeedSpec6 &seed : main->FixedSeeds()) {
        fixed.push_back(SeedToString(seed));
    }
    BOOST_CHECK(fixed == (std::vector<std::string>{"147.135.88.232:10605",
                                                   "147.135.88.233:10605"}));
    fixed.clear();
    for (const SeedSpec6 &seed : test->FixedSeeds()) {
        fixed.push_back(SeedToString(seed));
    }
    BOOST_CHECK(fixed == std::vector<std::string>{"35.224.106.240:11605"});
}

BOOST_AUTO_TEST_SUITE_END()
