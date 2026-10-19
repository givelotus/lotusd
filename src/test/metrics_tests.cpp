// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <config/bitcoin-config.h>
#include <consensus/validation.h>
#include <metrics/metrics.h>
#include <metrics/process.h>
#include <node/metrics.h>
#include <net_websocket.h>
#include <protocol.h>
#include <script/script.h>
#include <txmempool.h>
#include <util/fs.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace metrics;

BOOST_FIXTURE_TEST_SUITE(metrics_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(websocket_v2_compression_label) {
    const auto &labels{node::metric_labels::WebSocketCompressions()};
    const auto v2{size_t(P2PWebSocketCompression::P2P_V2)};
    BOOST_REQUIRE_LT(v2, labels.size());
    BOOST_CHECK_EQUAL(labels[v2], "p2p-v2");
    BOOST_CHECK_EQUAL(
        labels[size_t(P2PWebSocketCompression::ZSTD_DICT)], "zstd-dict");
}

BOOST_AUTO_TEST_CASE(escaping) {
    std::string out;
    AppendLabelValue(out, "a\\b\"c\nd");
    BOOST_CHECK_EQUAL(out, R"(a\\b\"c\nd)");
    out.clear();
    AppendHelp(out, "a\\b\"c\nd");
    BOOST_CHECK_EQUAL(out, R"(a\\b"c\nd)");
    out.clear();
    AppendValue(out, 0.005);
    out += ' ';
    AppendValue(out, 1e21);
    out += ' ';
    AppendValue(out, INFINITY);
    out += ' ';
    AppendValue(out, -INFINITY);
    out += ' ';
    AppendValue(out, NAN);
    out += ' ';
    AppendValue(out, 3);
    BOOST_CHECK_EQUAL(out, "0.005 1e+21 +Inf -Inf NaN 3");
}

BOOST_AUTO_TEST_CASE(render_exposition_format) {
    Registry reg;
    auto &c{reg.Add(std::make_unique<Counter>(
        "test_bytes_total", "Bytes \\ by \"type\"\nand dir.",
        std::vector<LabelDim>{{"dir", {"in", "out"}},
                              {"type", {"a\"b", "c"}}}))};
    auto &g{reg.Add(std::make_unique<Gauge>("test_height", "Height."))};
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "test_seconds", "Durations.", std::vector<double>{0.001, 0.01, 1}, 1e9,
        std::vector<LabelDim>{{"method", {"x", "y"}}}))};

    const std::array<size_t, 2> out_c{1, 1};
    c.Add(c.SeriesIndex(out_c), 7);
    c.Add(0, 2);
    c.Add(0);
    g.Set(42.5);
    h.Record(1'000'000, 1);     // 0.001s: le="0.001" (inclusive)
    h.Record(5'000'000, 1);     // 0.005s
    h.Record(2'000'000'000, 1); // 2s: +Inf
    h.Record(0, 0);

    const std::string expected{
        "# HELP test_bytes_total Bytes \\\\ by \"type\"\\nand dir.\n"
        "# TYPE test_bytes_total counter\n"
        "test_bytes_total{dir=\"in\",type=\"a\\\"b\"} 3\n"
        "test_bytes_total{dir=\"in\",type=\"c\"} 0\n"
        "test_bytes_total{dir=\"out\",type=\"a\\\"b\"} 0\n"
        "test_bytes_total{dir=\"out\",type=\"c\"} 7\n"
        "# HELP test_height Height.\n"
        "# TYPE test_height gauge\n"
        "test_height 42.5\n"
        "# HELP test_seconds Durations.\n"
        "# TYPE test_seconds histogram\n"
        "test_seconds_bucket{method=\"x\",le=\"0.001\"} 1\n"
        "test_seconds_bucket{method=\"x\",le=\"0.01\"} 1\n"
        "test_seconds_bucket{method=\"x\",le=\"1\"} 1\n"
        "test_seconds_bucket{method=\"x\",le=\"+Inf\"} 1\n"
        "test_seconds_sum{method=\"x\"} 0\n"
        "test_seconds_count{method=\"x\"} 1\n"
        "test_seconds_bucket{method=\"y\",le=\"0.001\"} 1\n"
        "test_seconds_bucket{method=\"y\",le=\"0.01\"} 2\n"
        "test_seconds_bucket{method=\"y\",le=\"1\"} 2\n"
        "test_seconds_bucket{method=\"y\",le=\"+Inf\"} 3\n"
        "test_seconds_sum{method=\"y\"} 2.006\n"
        "test_seconds_count{method=\"y\"} 3\n"
        "# HELP metrics_dropped_samples_total Event samples dropped "
        "because a recording thread's buffer was full.\n"
        "# TYPE metrics_dropped_samples_total counter\n"
        "metrics_dropped_samples_total 0\n"};
    BOOST_CHECK_EQUAL(reg.Render(), expected);
}

BOOST_AUTO_TEST_CASE(unlabelled_histogram) {
    Registry reg;
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "h_bytes", "Sizes.", std::vector<double>{10, 100}, 1))};
    h.Record(10);
    h.Record(11);
    const std::string r{reg.Render()};
    BOOST_CHECK(r.find("h_bytes_bucket{le=\"10\"} 1\n"
                       "h_bytes_bucket{le=\"100\"} 2\n"
                       "h_bytes_bucket{le=\"+Inf\"} 2\n"
                       "h_bytes_sum 21\n"
                       "h_bytes_count 2\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(counter_shards_from_many_threads) {
    Registry reg;
    auto &c{reg.Add(std::make_unique<Counter>(
        "c_total", "C.", std::vector<LabelDim>{{"k", {"a", "b", "c"}}}))};
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "e_seconds", "E.", std::vector<double>{1}, 1))};
    reg.Start(std::chrono::milliseconds{1});
    constexpr int THREADS{24}, PER_THREAD{20000};
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < PER_THREAD; ++i) {
                c.Add(2);
                if (i % 20 == 0) {
                    h.Record(0);
                }
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    reg.Stop();
    BOOST_CHECK_EQUAL(c.Value(2), uint64_t{THREADS} * PER_THREAD);
    BOOST_CHECK_EQUAL(c.Value(0), 0U);
    // Every sample is either counted or counted as dropped, and the exited
    // threads' rings were retired.
    const std::string r{reg.Render()};
    const uint64_t dropped{reg.DroppedSamples()};
    const uint64_t total{uint64_t{THREADS} * PER_THREAD / 20};
    BOOST_CHECK(r.find("e_seconds_count " + std::to_string(total - dropped) +
                       "\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(ring_drops_when_full) {
    EventRing ring;
    for (size_t i = 0; i < EventRing::CAPACITY; ++i) {
        BOOST_CHECK(ring.Push({0, 0, i}));
    }
    BOOST_CHECK(!ring.Push({0, 0, 1}));
    BOOST_CHECK(!ring.Push({0, 0, 1}));
    BOOST_CHECK_EQUAL(ring.Dropped(), 2U);
    uint64_t expect{0};
    BOOST_CHECK_EQUAL(ring.Drain([&](const Sample &s) {
        BOOST_CHECK_EQUAL(s.value, expect++);
    }),
                      EventRing::CAPACITY);
    BOOST_CHECK(ring.Empty());
    BOOST_CHECK(ring.Push({0, 0, 9}));

    // Without a drain thread, a registry's ring fills and drops too.
    Registry reg;
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "x", "X.", std::vector<double>{1}, 1))};
    for (size_t i = 0; i < EventRing::CAPACITY + 5; ++i) {
        h.Record(1);
    }
    BOOST_CHECK_EQUAL(reg.DroppedSamples(), 5U);
    BOOST_CHECK(reg.Render().find("metrics_dropped_samples_total 5\n") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(render_cache) {
    Registry reg;
    auto &g{reg.Add(std::make_unique<Gauge>("g", "G."))};
    g.Set(1);
    const std::string first{reg.Render(std::chrono::hours{1})};
    g.Set(2);
    BOOST_CHECK_EQUAL(reg.Render(std::chrono::hours{1}), first);
    BOOST_CHECK(reg.Render().find("\ng 2\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hidden_empty_series_and_collectors) {
    Registry reg;
    auto &h{reg.Add(std::make_unique<EventHistogram>(
                        "rpc_seconds", "R.", std::vector<double>{1}, 1,
                        std::vector<LabelDim>{{"method", {"a", "b", "c"}}}))
                .HideEmptySeries()};
    auto &g{reg.Add(std::make_unique<Gauge>("age", "A."))};
    int collected{0};
    reg.AddCollector([&] { g.Set(++collected); });
    h.Record(1, 1);
    const std::string r{reg.Render()};
    BOOST_CHECK(r.find("method=\"a\"") == std::string::npos);
    BOOST_CHECK(r.find("method=\"c\"") == std::string::npos);
    BOOST_CHECK(r.find("rpc_seconds_count{method=\"b\"} 1\n") !=
                std::string::npos);
    // The HELP/TYPE lines are there even before any series has data.
    BOOST_CHECK(r.find("# TYPE rpc_seconds histogram\n") != std::string::npos);
    BOOST_CHECK(r.find("\nage 1\n") != std::string::npos);
    BOOST_CHECK(reg.Render().find("\nage 2\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rings_prepared_and_reused) {
    Registry reg;
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "x", "X.", std::vector<double>{1}, 1))};
    reg.Start(std::chrono::milliseconds{1}, /*rings=*/2);
    BOOST_CHECK_EQUAL(reg.NumRings(), 2U);
    // Short-lived threads one after the other: each gets a ring at start
    // (as util::ThreadRename does), and exited threads' rings are reused.
    SetThreadRegistry(&reg);
    for (int i = 0; i < 10; ++i) {
        std::thread{[&] {
            PrepareThisThread();
            h.Record(1);
        }}.join();
        reg.Drain();
    }
    SetThreadRegistry(nullptr);
    reg.Stop();
    BOOST_CHECK_LE(reg.NumRings(), 2U);
    BOOST_CHECK(reg.Render().find("\nx_count 10\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(msg_type_index) {
    const size_t other{node::MetricMsgTypeIndex("no-such-type")};
    std::set<size_t> seen;
    for (const std::string &type : getAllNetMessageTypes()) {
        const size_t i{node::MetricMsgTypeIndex(type)};
        BOOST_CHECK(i < other);
        seen.insert(i);
    }
    BOOST_CHECK_EQUAL(seen.size(), getAllNetMessageTypes().size());
    BOOST_CHECK_EQUAL(node::MetricMsgTypeIndex("*other*"), other);
}

BOOST_AUTO_TEST_CASE(label_and_metric_names) {
    BOOST_CHECK(IsValidLabelName("region"));
    BOOST_CHECK(IsValidLabelName("_x9"));
    BOOST_CHECK(!IsValidLabelName(""));
    BOOST_CHECK(!IsValidLabelName("9x"));
    BOOST_CHECK(!IsValidLabelName("a-b"));
    BOOST_CHECK(!IsValidLabelName("a:b"));
    BOOST_CHECK(!IsValidLabelName("__name__"));
    BOOST_CHECK(IsValidMetricName("a:b_total"));
    BOOST_CHECK(!IsValidMetricName("1a"));
    BOOST_CHECK(!IsValidMetricName("a-b"));
}

BOOST_AUTO_TEST_CASE(constant_labels) {
    Registry reg{"ns_"};
    auto &c{reg.Add(std::make_unique<Counter>(
        "ns_c_total", "C.", std::vector<LabelDim>{{"dir", {"in", "out"}}}))};
    auto &g{reg.Add(std::make_unique<Gauge>("ns_g", "G."))};
    auto &h{reg.Add(std::make_unique<EventHistogram>(
        "ns_h_seconds", "H.", std::vector<double>{1}, 1))};
    // Refused: invalid, reserved, a metric's own label, repeated
    BOOST_CHECK(reg.SetConstLabels({{"a-b", "x"}}));
    BOOST_CHECK(reg.SetConstLabels({{"le", "x"}}));
    BOOST_CHECK(reg.SetConstLabels({{"__x", "x"}}));
    BOOST_CHECK(reg.SetConstLabels({{"dir", "x"}}));
    BOOST_CHECK(reg.SetConstLabels({{"a", "x"}, {"a", "y"}}));
    BOOST_REQUIRE(!reg.SetConstLabels({{"client", "d"}, {"q", "a\"b"}}));
    c.Add(1, 2);
    g.Set(3);
    h.Record(1);
    const std::string r{reg.Render()};
    BOOST_CHECK(r.find("\nns_c_total{client=\"d\",q=\"a\\\"b\",dir=\"in\"} "
                       "0\n") != std::string::npos);
    BOOST_CHECK(r.find("\nns_c_total{client=\"d\",q=\"a\\\"b\",dir=\"out\"} "
                       "2\n") != std::string::npos);
    BOOST_CHECK(r.find("\nns_g{client=\"d\",q=\"a\\\"b\"} 3\n") !=
                std::string::npos);
    BOOST_CHECK(r.find("\nns_h_seconds_bucket{client=\"d\",q=\"a\\\"b\",le="
                       "\"1\"} 1\n") != std::string::npos);
    BOOST_CHECK(r.find("\nns_h_seconds_count{client=\"d\",q=\"a\\\"b\"} 1\n") !=
                std::string::npos);
    // The registry's own metric takes its prefix and the labels too
    BOOST_CHECK(r.find("\nns_metrics_dropped_samples_total{client=\"d\",q="
                       "\"a\\\"b\"} 0\n") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(node_metric_names_and_labels) {
    BOOST_CHECK_EQUAL(node::MetricName("x_total"),
                      std::string{METRICS_NAMESPACE} + "x_total");
    BOOST_CHECK_EQUAL(node::MetricsNetworkLabel(ChainType::MAIN),
                      std::string{FULLNODE_CHAIN} + "-mainnet");
    BOOST_CHECK_EQUAL(node::MetricsNetworkLabel(ChainType::TESTNET),
                      std::string{FULLNODE_CHAIN} + "-testnet");
    BOOST_CHECK_EQUAL(node::MetricsNetworkLabel(ChainType::REGTEST),
                      std::string{FULLNODE_CHAIN} + "-regtest");
    BOOST_CHECK_EQUAL(node::MetricsClientLabel(), FULLNODE_CLIENT);

    // Every node metric is namespaced (or a standard process_* metric),
    // and none uses a reserved label.
    node::NodeMetrics m{{"getblockcount"}};
    BOOST_REQUIRE(
        !m.registry.SetConstLabels({{"client", "c"}, {"network", "n"}}));
    const std::string r{m.registry.Render()};
    size_t families{0};
    for (size_t pos{0}; (pos = r.find("# TYPE ", pos)) != std::string::npos;
         ++pos) {
        const std::string name{
            r.substr(pos + 7, r.find(' ', pos + 7) - pos - 7)};
        BOOST_CHECK_MESSAGE(name.starts_with(METRICS_NAMESPACE) ||
                                name.starts_with("process_"),
                            name);
        ++families;
    }
    BOOST_CHECK(families >= 23);
    BOOST_CHECK(r.find("lotus_") == std::string::npos);
    BOOST_CHECK(r.find(node::MetricName("build_info") +
                       "{client=\"c\",network=\"n\",version=\"") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(parse_metrics_labels) {
    const auto ok{node::ParseMetricsLabels({"region=eu-west", "dc=a=b"})};
    BOOST_REQUIRE(ok);
    BOOST_CHECK_EQUAL(ok->size(), 2U);
    BOOST_CHECK_EQUAL((*ok)[0].first, "region");
    BOOST_CHECK_EQUAL((*ok)[0].second, "eu-west");
    BOOST_CHECK_EQUAL((*ok)[1].first, "dc");
    BOOST_CHECK_EQUAL((*ok)[1].second, "a=b");
    BOOST_CHECK(node::ParseMetricsLabels({}));
    for (const std::string &bad : std::vector<std::string>{
             "noequals", "=x", "9a=x", "a-b=x", "__a=x", "le=x", "quantile=x",
             "client=x", "network=x", "a=", "a=x\ny",
             std::string("a=") +
                 std::string(METRICS_LABEL_VALUE_MAX + 1, 'v')}) {
        BOOST_CHECK_MESSAGE(!node::ParseMetricsLabels({bad}), bad);
    }
    BOOST_CHECK(!node::ParseMetricsLabels({"a=x", "a=y"}));
    std::vector<std::string> many;
    for (size_t i = 0; i <= METRICS_LABELS_MAX; ++i) {
        many.push_back("l" + std::to_string(i) + "=v");
    }
    BOOST_CHECK(!node::ParseMetricsLabels(many));
    many.pop_back();
    BOOST_CHECK(node::ParseMetricsLabels(many));
}

BOOST_AUTO_TEST_CASE(collectors_added_and_removed) {
    Registry reg;
    auto &g{reg.Add(std::make_unique<Gauge>("g", "G."))};
    int a{0}, b{0};
    const uint64_t ida{reg.AddCollector([&] { g.Set(++a); })};
    const uint64_t idb{reg.AddCollector([&] { ++b; })};
    BOOST_CHECK(ida != idb);
    reg.Render();
    BOOST_CHECK_EQUAL(a, 1);
    BOOST_CHECK_EQUAL(b, 1);
    reg.RemoveCollector(ida);
    reg.Render();
    BOOST_CHECK_EQUAL(a, 1);
    BOOST_CHECK_EQUAL(b, 2);
    // Added while another thread renders
    std::thread renderer{[&] {
        for (int i = 0; i < 200; ++i) {
            reg.Render();
        }
    }};
    for (int i = 0; i < 200; ++i) {
        reg.RemoveCollector(reg.AddCollector([] {}));
    }
    renderer.join();
    reg.RemoveCollector(idb);
    const int seen{b};
    reg.Render();
    BOOST_CHECK_EQUAL(b, seen);
}

BOOST_AUTO_TEST_CASE(avalanche_vote_series) {
    const auto &labels{node::metric_labels::AvalancheVotes()};
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(0)], "yes");
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(1)], "no"); // invalid
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(2)], "no"); // parked
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(3)], "no"); // fork
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(uint32_t(-1))],
                      "neutral"); // unknown
    BOOST_CHECK_EQUAL(labels[node::AvalancheVoteSeries(uint32_t(-2))],
                      "neutral"); // missing
    BOOST_CHECK_EQUAL(labels.size(), 3U);
    BOOST_CHECK_EQUAL(node::metric_labels::AvalancheItemTypes().size(), 6U);
}

BOOST_AUTO_TEST_CASE(mempool_reason_labels) {
    const auto &reject{node::metric_labels::MempoolRejectReasons()};
    BOOST_CHECK_EQUAL(reject.size(), size_t(TxValidationResult::TX_UNKNOWN));
    const auto label{[&](TxValidationResult r) {
        return reject[node::MempoolRejectSeries(int(r))];
    }};
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_CONSENSUS), "consensus");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_MISSING_INPUTS),
                      "missing_inputs");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_DUPLICATE), "duplicate");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_MEMPOOL_POLICY),
                      "mempool_policy");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_PACKAGE_RECONSIDERABLE),
                      "package_reconsiderable");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_AVALANCHE_RECONSIDERABLE),
                      "avalanche_reconsiderable");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_UNKNOWN), "unknown");
    BOOST_CHECK_EQUAL(label(TxValidationResult::TX_RESULT_UNSET), "unknown");
    BOOST_CHECK_EQUAL(reject[node::MempoolRejectSeries(99)], "unknown");

    const auto &removal{node::metric_labels::MempoolRemovalReasons()};
    for (size_t r = 0; r <= size_t(MemPoolRemovalReason::MANUAL); ++r) {
        BOOST_CHECK_EQUAL(removal.at(r),
                          RemovalReasonToString(MemPoolRemovalReason(r)));
    }
    BOOST_CHECK_EQUAL(removal.size(), size_t(MemPoolRemovalReason::MANUAL) + 1);
}

BOOST_AUTO_TEST_CASE(utxo_cache_lookups) {
    Registry reg;
    auto &lookups{reg.Add(std::make_unique<Counter>(
        "l_total", "L.",
        std::vector<LabelDim>{{"result", {"hit", "miss", "absent"}}}))};
    CCoinsView empty;
    CCoinsViewCache base{&empty};
    const COutPoint present{TxId{uint256::ONE}, 0};
    const COutPoint absent{TxId{uint256::ONE}, 1};
    base.AddCoin(present, Coin{CTxOut{SATOSHI, CScript{} << OP_TRUE}, 1, false},
                 /*possible_overwrite=*/false);
    CCoinsViewCache cache{&base};
    // Uncounted until the metric is set (the node sets it on the chainstate's
    // cache only)
    BOOST_CHECK(cache.HaveCoin(absent) == false);
    BOOST_CHECK_EQUAL(lookups.Value(2), 0U);
    cache.SetLookupMetric(&lookups);
    BOOST_CHECK(cache.HaveCoin(present)); // read from the base
    BOOST_CHECK(cache.HaveCoin(present)); // cached
    BOOST_CHECK(cache.HaveCoin(present));
    BOOST_CHECK(!cache.HaveCoin(absent));
    BOOST_CHECK_EQUAL(lookups.Value(0), 2U);
    BOOST_CHECK_EQUAL(lookups.Value(1), 1U);
    BOOST_CHECK_EQUAL(lookups.Value(2), 1U);
    // The base cache counts nothing
    BOOST_CHECK_EQUAL(lookups.Value(0) + lookups.Value(1) + lookups.Value(2),
                      4U);
}

BOOST_AUTO_TEST_CASE(block_labels) {
    BOOST_CHECK_EQUAL(node::metric_labels::BlockStages().size(),
                      size_t(node::BlockStage::POST_CONNECT) + 1);
    BOOST_CHECK_EQUAL(
        node::metric_labels::BlockStages()[size_t(node::BlockStage::VERIFY)],
        "verify");
    BOOST_CHECK_EQUAL(node::metric_labels::BlockParkReasons().size(),
                      size_t(node::BlockParkReason::REQUESTED) + 1);
}

BOOST_AUTO_TEST_CASE(database_labels) {
    const auto label{[](const std::string &path) {
        return node::metric_labels::Databases()[node::MetricDatabaseIndex(
            path)];
    }};
    BOOST_CHECK_EQUAL(label("/d/regtest/chainstate"), "chainstate");
    BOOST_CHECK_EQUAL(label("/d/regtest/chainstate_snapshot"), "chainstate");
    BOOST_CHECK_EQUAL(label("/d/regtest/blocks/index"), "block_index");
    BOOST_CHECK_EQUAL(label("/d/regtest/indexes/txindex"), "txindex");
    BOOST_CHECK_EQUAL(label("/d/regtest/indexes/blockfilter/basic/db"),
                      "blockfilterindex");
    BOOST_CHECK_EQUAL(label("/d/regtest/indexes/coinstats/db"),
                      "coinstatsindex");
    BOOST_CHECK_EQUAL(label("/tmp/test_x"), "other");
    BOOST_CHECK_EQUAL(label(""), "other");
}

BOOST_AUTO_TEST_CASE(misbehavior_reasons) {
    using R = node::MisbehaviorReason;
    // Every fixed message net_processing passes to Misbehaving()
    const std::vector<std::pair<std::string, R>> cases{
        {"Ignoring invalid timestamp in version message", R::HANDSHAKE},
        {"non-version message before version handshake", R::HANDSHAKE},
        {"non-verack message before version handshake", R::HANDSHAKE},
        {"addr message size = 1001", R::OVERSIZED_MESSAGE},
        {"inv message size = 50001", R::OVERSIZED_MESSAGE},
        {"getdata message size = 50001", R::OVERSIZED_MESSAGE},
        {"too-many-headers: headers message size = 2001", R::OVERSIZED_MESSAGE},
        {"too-many-ava-poll: poll message size = 17", R::OVERSIZED_MESSAGE},
        {"header with invalid proof of work", R::INVALID_HEADER},
        {"non-continuous headers sequence", R::INVALID_HEADER},
        {"mutated block", R::INVALID_BLOCK},
        {"cmpctblock-bad-indexes", R::INVALID_COMPACT_BLOCK},
        {"invalid compact block", R::INVALID_COMPACT_BLOCK},
        {"invalid compact block/non-matching block transactions",
         R::INVALID_COMPACT_BLOCK},
        {"getblocktxn with out-of-bounds tx indices", R::INVALID_COMPACT_BLOCK},
        {"malformed coalesced TX message", R::INVALID_TX},
        {"too-large bloom filter", R::BLOOM_FILTER},
        {"bad filteradd message", R::BLOOM_FILTER},
        {"malformed-ava-response", R::AVALANCHE},
        {"invalid-ava-response-signature", R::AVALANCHE},
        {"unexpected-ava-response", R::AVALANCHE},
        {"invalid-ava-response-size", R::AVALANCHE},
        {"invalid-delegation", R::AVALANCHE},
        {"invalid-avahello-signature", R::AVALANCHE},
        {"avahello-max-elements-too-low", R::AVALANCHE},
        {"avaproofs-bad-indexes", R::AVALANCHE_PROOF},
        {"too-many-invalid-avaproofs", R::AVALANCHE_PROOF},
        {"", R::OTHER},
        {"something new", R::OTHER},
    };
    for (const auto &[message, reason] : cases) {
        BOOST_CHECK_MESSAGE(node::ClassifyMisbehavior(message) == reason,
                            message);
    }
    BOOST_CHECK_EQUAL(node::metric_labels::MisbehaviorReasons().size(),
                      size_t(R::OTHER) + 1);
    const auto &transports{node::metric_labels::Transports()};
    const std::vector<std::string> expected{"tcp", "ws", "wss", "webtransport"};
    BOOST_CHECK_EQUAL_COLLECTIONS(transports.begin(), transports.end(),
                                  expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(chronik_endpoints) {
    const auto label{[](std::string_view route) {
        return node::metric_labels::ChronikEndpoints()
            [node::ChronikEndpointIndex(route)];
    }};
    // Every route of chronik-http's router
    const std::vector<std::pair<std::string, std::string>> routes{
        {"/blockchain-info", "blockchain_info"},
        {"/block/:hash_or_height", "block"},
        {"/block-header/:hash_or_height", "block_header"},
        {"/block-txs/:hash_or_height", "block_txs"},
        {"/blocks/:start/:end", "blocks"},
        {"/block-headers/:start/:end", "block_headers"},
        {"/unconfirmed-txs", "unconfirmed_txs"},
        {"/chronik-info", "chronik_info"},
        {"/tx/:txid", "tx"},
        {"/token/:txid", "token"},
        {"/validate-tx", "validate_tx"},
        {"/broadcast-tx", "broadcast_tx"},
        {"/broadcast-txs", "broadcast_txs"},
        {"/raw-tx/:txid", "raw_tx"},
        {"/script/batch/utxos", "script_batch"},
        {"/script/batch/summary", "script_batch"},
        {"/script/:type/:payload/confirmed-txs", "script"},
        {"/script/:type/:payload/history", "script"},
        {"/script/:type/:payload/unconfirmed-txs", "script"},
        {"/script/:type/:payload/utxos", "script"},
        {"/token-id/:token_id/history", "token_id"},
        {"/lokad-id/:lokad_id/confirmed-txs", "lokad_id"},
        {"/plugin/:plugin_name/:group_hex/utxos", "plugin"},
        {"/plugin/:plugin_name/groups", "plugin"},
        {"/ws", "ws"},
        {"/pause", "pause"},
        {"/resume", "resume"},
        {"", "not_found"},
        {"/something-new/:x", "other"},
        {"/not-found", "other"},
        {"/other", "other"},
    };
    for (const auto &[route, expected] : routes) {
        BOOST_CHECK_EQUAL(label(route), expected);
    }
}

BOOST_AUTO_TEST_CASE(process_stats) {
    const ProcessStats before{ReadProcessStats()};
#if defined(__APPLE__) || defined(__linux__)
    BOOST_REQUIRE(before.resident_bytes && before.virtual_bytes);
    BOOST_CHECK(*before.resident_bytes > 0);
    BOOST_CHECK(*before.virtual_bytes >= *before.resident_bytes);
    BOOST_REQUIRE(before.open_fds);
    // A descriptor more while a file is open
    FILE *f{fsbridge::fopen(m_args.GetDataDirBase() / "fd_test", "wb")};
    BOOST_REQUIRE(f);
    const ProcessStats during{ReadProcessStats()};
    BOOST_REQUIRE(during.open_fds);
    BOOST_CHECK_EQUAL(*during.open_fds, *before.open_fds + 1);
    fclose(f);
#endif
#ifndef WIN32
    BOOST_CHECK(!before.max_fds || *before.max_fds > 0);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
