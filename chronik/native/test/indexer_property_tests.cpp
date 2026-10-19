// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Design §8.1.4 property: connecting then disconnecting blocks leaves the DB
// dump identical, and an incrementally maintained index (random chains with
// spends, in-block chains, LOKAD OP_RETURNs and reorgs of depth <= 6) equals
// a fresh sync of the final active chain.

#include <chronik/native/indexer.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/mdbx_store.h>
#include <chronik/native/schema.h>
#include <chronik/native/token_io/token_index.h>

#include <core/db/dump.h>
#include <test/fake_host.h>
#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>

using namespace chronik::native;
namespace th = chronik::native::testhost;
namespace nt = chronik::native::test;

namespace {

std::vector<std::string> Dump(const Indexer &ix) {
    auto snap = ix.Impl().Snapshot();
    return db::DumpLines(snap.Store(), snap.Txn(), schema::EcashTables());
}

struct PropertyConf {
    bool lokad_id_index = true;
    bool scripthash_index = false;
    bool tokens = false;
};

IndexerParams MakeParams(const std::filesystem::path &dir,
                         const PropertyConf &conf) {
    IndexerParams p;
    p.datadir_net = dir;
    p.lokad_id_index = conf.lokad_id_index;
    p.scripthash_index = conf.scripthash_index;
    p.token_index = conf.tokens;
    if (conf.tokens) {
        p.token_index_factory = token_io::MakeEcashTokenIndex;
    }
    return p;
}

/** Returns the number of reorgs performed. */
int RunProperty(uint64_t seed, int steps, const PropertyConf &conf) {
    RegisterMdbxStore();
    std::mt19937_64 rng(seed);
    th::FakeHost host;
    host.Caps().slp_alp_tokens = conf.tokens;
    nt::IndexTempDir dir("indexer-property");
    std::filesystem::create_directories(dir.path);
    host.Extend(host.MakeBlock(-1, {}));
    auto ix = Indexer::Open(host, MakeParams(dir.path, conf));
    ix->Resync();

    // dumps[h] = dump with the active chain at height h
    std::vector<std::vector<std::string>> dumps{Dump(*ix)};
    int reorgs = 0;
    for (int step = 0; step < steps; ++step) {
        const int32_t tip = host.TipHeight();
        const bool reorg = tip >= 1 && rng() % 4 == 0;
        if (reorg) {
            const int32_t depth =
                1 + int32_t(rng() % std::min<uint64_t>(6, uint64_t(tip)));
            for (int32_t h = tip; h > tip - depth; --h) {
                ix->OnBlockDisconnected(host.ActiveBlock(h));
                BOOST_REQUIRE_MESSAGE(Dump(*ix) == dumps[size_t(h - 1)],
                                      "seed " << seed << " step " << step
                                              << ": disconnect of height "
                                              << h << " left a different DB");
            }
            dumps.resize(size_t(tip - depth + 1));
            host.TruncateActive(tip - depth);
            ++reorgs;
            // New branch, one longer than the old one
            for (int32_t i = 0; i <= depth; ++i) {
                Block block = host.RandomBlock(rng, host.TipHeight());
                host.Extend(block);
                ix->OnBlockConnected(block);
                dumps.push_back(Dump(*ix));
            }
        } else {
            Block block = host.RandomBlock(rng, tip);
            host.Extend(block);
            ix->OnBlockConnected(block);
            const auto connected = Dump(*ix);
            BOOST_REQUIRE(connected != dumps.back());
            // connect -> disconnect -> connect round trip
            if (rng() % 3 == 0) {
                ix->OnBlockDisconnected(block);
                BOOST_REQUIRE_MESSAGE(Dump(*ix) == dumps.back(),
                                      "seed " << seed << " step " << step
                                              << ": connect/disconnect of "
                                                 "height "
                                              << block.info.height
                                              << " left a different DB");
                ix->OnBlockConnected(block);
                BOOST_REQUIRE(Dump(*ix) == connected);
            }
            dumps.push_back(connected);
        }
    }

    // Unwinding everything down to genesis retraces every recorded dump
    const auto final_dump = Dump(*ix);
    for (int32_t h = host.TipHeight(); h >= 1; --h) {
        ix->OnBlockDisconnected(host.ActiveBlock(h));
        BOOST_REQUIRE_MESSAGE(Dump(*ix) == dumps[size_t(h - 1)],
                              "seed " << seed << ": unwinding height " << h);
    }
    for (int32_t h = 1; h <= host.TipHeight(); ++h) {
        ix->OnBlockConnected(host.ActiveBlock(h));
    }
    BOOST_REQUIRE(Dump(*ix) == final_dump);
    ix->Close();
    ix.reset();

    // A fresh sync of the final active chain has the same DB
    nt::IndexTempDir fresh("indexer-property-fresh");
    std::filesystem::create_directories(fresh.path);
    auto fresh_ix = Indexer::Open(host, MakeParams(fresh.path, conf));
    fresh_ix->Resync();
    BOOST_REQUIRE_MESSAGE(Dump(*fresh_ix) == final_dump,
                          "seed " << seed << ": fresh sync differs");
    fresh_ix->Close();
    return reorgs;
}

} // namespace

BOOST_AUTO_TEST_SUITE(indexer_property_tests)

BOOST_AUTO_TEST_CASE(connect_disconnect_dump_identical) {
    int reorgs = 0;
    for (uint64_t seed = 1; seed <= 12; ++seed) {
        reorgs += RunProperty(seed, 40, PropertyConf{});
    }
    BOOST_CHECK_GT(reorgs, 12);
}

BOOST_AUTO_TEST_CASE(connect_disconnect_without_lokad_id_index) {
    PropertyConf conf;
    conf.lokad_id_index = false;
    for (uint64_t seed = 100; seed <= 104; ++seed) {
        RunProperty(seed, 30, conf);
    }
}

BOOST_AUTO_TEST_CASE(connect_disconnect_with_scripthash_index) {
    PropertyConf conf;
    conf.scripthash_index = true;
    for (uint64_t seed = 200; seed <= 204; ++seed) {
        RunProperty(seed, 30, conf);
    }
}

BOOST_AUTO_TEST_CASE(connect_disconnect_with_token_index) {
    PropertyConf conf;
    conf.tokens = true;
    for (uint64_t seed = 300; seed <= 304; ++seed) {
        RunProperty(seed, 30, conf);
    }
}

BOOST_AUTO_TEST_SUITE_END()
