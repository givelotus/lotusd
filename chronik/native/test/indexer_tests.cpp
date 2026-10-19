// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Ports of chronik-indexer indexer.rs #[test]s (test_indexer,
// test_schema_version; test_plugin_versions is not applicable: no plugins),
// plus resync, mempool, avalanche and failure-path tests on a FakeHost.

#include <chronik/native/avalanche.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/indexer.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/metadata.h>
#include <chronik/native/schema.h>
#include <chronik/native/store.h>
#include <chronik/native/token_index.h>

#include <core/db/dump.h>
#include <core/indexer/indexer_errors.h>
#include <test/fake_host.h>
#include <test/index_test_util.h>
#include <test/test_backend.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace chronik::native;
namespace th = chronik::native::testhost;
namespace nt = chronik::native::test;

namespace {

std::vector<std::string> Dump(const Indexer &ix) {
    auto snap = ix.Impl().Snapshot();
    return db::DumpLines(snap.Store(), snap.Txn(), schema::EcashTables());
}

std::optional<index::DbBlock> Tip(const Indexer &ix) {
    auto snap = ix.Impl().Snapshot();
    return index::BlockReader(snap.Store(), snap.Txn()).Tip();
}

struct Env {
    th::FakeHost host;
    nt::IndexTempDir dir;

    explicit Env(const std::string &name, int num_blocks = 1) : dir(name) {
        nt::RegisterTestStores();
        std::filesystem::create_directories(dir.path);
        for (int i = 0; i < num_blocks; ++i) {
            host.Extend(host.MakeBlock(host.TipHeight(), {}));
        }
    }
    IndexerParams Params() const {
        IndexerParams p;
        p.datadir_net = dir.path;
        p.backend = nt::TestBackend();
        p.token_index = false;
        p.lokad_id_index = true;
        return p;
    }
    std::unique_ptr<Indexer> Open(std::optional<IndexerParams> p = {}) {
        return Indexer::Open(host, p ? *p : Params());
    }
    std::unique_ptr<Indexer> OpenSynced(std::optional<IndexerParams> p = {}) {
        auto ix = Open(p);
        ix->Resync();
        return ix;
    }
    std::filesystem::path DbPath() const {
        return nt::TestIndexDir(dir.path);
    }
    /** Dump of a fresh index of the current active chain (separate dir). */
    std::vector<std::string> FreshDump(std::optional<IndexerParams> p = {}) {
        nt::IndexTempDir fresh("indexer-fresh");
        std::filesystem::create_directories(fresh.path);
        IndexerParams params = p ? *p : Params();
        params.datadir_net = fresh.path;
        params.wipe = false;
        auto ix = Indexer::Open(host, params);
        ix->Resync();
        std::vector<std::string> lines = Dump(*ix);
        ix->Close();
        return lines;
    }
    /** Random blocks on top of the active tip. */
    void Grow(std::mt19937_64 &rng, int n) {
        for (int i = 0; i < n; ++i) {
            host.Extend(host.RandomBlock(rng, host.TipHeight()));
        }
    }
};

/** Open the store of a closed indexer directly (meta manipulation). */
std::unique_ptr<KvStore> OpenRaw(const std::filesystem::path &db_path) {
    StoreOptions opts;
    opts.sha256 = [](ByteView data, uint8_t out[32]) {
        nt::TestSha256(data, out);
    };
    return OpenStore(nt::TestBackend(), db_path, schema::EcashTables(),
                     opts);
}

void SetSchemaVersion(const std::filesystem::path &db_path, uint64_t v) {
    auto store = OpenRaw(db_path);
    auto txn = store->BeginWrite();
    MetadataWriter(*txn, store->Table(schema::kMeta)).UpdateSchemaVersion(v);
    txn->Commit();
}

void PutMeta(const std::filesystem::path &db_path, std::string_view key,
             const Bytes &value) {
    auto store = OpenRaw(db_path);
    auto txn = store->BeginWrite();
    txn->Put(store->Table(schema::kMeta),
             ByteView(reinterpret_cast<const uint8_t *>(key.data()),
                      key.size()),
             value);
    txn->Commit();
}

/** Drain a receiver into a vector of messages. */
template <typename T> std::vector<T> Drain(BroadcastReceiver<T> &rx) {
    std::vector<T> out;
    for (;;) {
        RecvResult<T> r = rx.TryRecv();
        if (r.status != RecvStatus::Message) {
            return out;
        }
        out.push_back(std::move(*r.msg));
    }
}

/** A tx spending output 0 of the coinbase of active block `height`. */
TxRef SpendCoinbase(th::FakeHost &host, int32_t height, uint8_t script_id) {
    const Tx &cb = *host.ActiveBlock(height).txs[0].tx;
    Coin coin{cb.outputs[0], height, true};
    return std::make_shared<const Tx>(host.MakeSpend(
        {{OutPoint{cb.txid, 0}, coin}},
        {TxOutput{4000, th::P2pkh(script_id)}}));
}

TxRef SpendOutput(th::FakeHost &host, const Tx &parent, uint32_t out_idx,
                  int32_t height, uint8_t script_id) {
    Coin coin{parent.outputs[out_idx], height, false};
    return std::make_shared<const Tx>(host.MakeSpend(
        {{OutPoint{parent.txid, out_idx}, coin}},
        {TxOutput{parent.outputs[out_idx].sats - 100,
                  th::P2pkh(script_id)}}));
}

/** Clear (and restore) the global token factory around a test. */
struct TokenFactoryGuard {
    TokenIndexFactory saved = RegisteredTokenIndexFactory();
    TokenFactoryGuard() { RegisterTokenIndexFactory({}); }
    ~TokenFactoryGuard() { RegisterTokenIndexFactory(saved); }
};

} // namespace

BOOST_AUTO_TEST_SUITE(indexer_tests)

// ---------------------------------------------------------------------------
// Ports of indexer.rs tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_indexer) {
    Env env("indexer-indexer");
    IndexerParams params = env.Params();
    params.datadir_net = env.dir.path / "regtest";
    // regtest folder doesn't exist yet -> error
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(params); }),
                      indexer_errors::CreateDirFailed(params.datadir_net /
                                                      "indexes"));
    // create regtest folder, setup will work now
    std::filesystem::create_directory(params.datadir_net);
    auto ix = env.Open(params);
    // indexes and indexes/chronik now exist
    BOOST_CHECK(std::filesystem::exists(params.datadir_net / "indexes"));
    BOOST_CHECK(
        std::filesystem::exists(nt::TestIndexDir(params.datadir_net)));
    BOOST_CHECK(ix->Impl().Config().db_path ==
                nt::TestIndexDir(params.datadir_net));
}

BOOST_AUTO_TEST_CASE(test_schema_version) {
    Env env("indexer-schema");
    const auto path = env.DbPath();
    const uint64_t current = schema::kCurrentIndexerVersion;
    // Setting up DB first time sets the schema version
    env.OpenSynced()->Close();
    {
        auto store = OpenRaw(path);
        auto txn = store->BeginRead();
        BOOST_CHECK(MetadataReader(*txn, store->Table(schema::kMeta))
                        .GetSchemaVersion() == current);
    }
    // Opening DB again works fine
    env.Open()->Close();

    const auto db_outdated = [&](uint64_t v) {
        return "DB outdated: Chronik has version " + std::to_string(current) +
               ", but the database has version " + std::to_string(v) +
               ". -reindex/-chronikreindex to reindex the database to the new "
               "version.";
    };
    // Override DB schema version to 0 -> DB too old
    SetSchemaVersion(path, 0);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(); }), db_outdated(0));
    // CURRENT - 1 -> DB too old
    SetSchemaVersion(path, current - 1);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(); }),
                      db_outdated(current - 1));
    // CURRENT + 1 -> Chronik too old
    SetSchemaVersion(path, current + 1);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(); }),
                      "Chronik outdated: Chronik has version " +
                          std::to_string(current) +
                          ", but the database has version " +
                          std::to_string(current + 1) +
                          ". Upgrade your node to the appropriate version.");
    // Corrupt schema version
    PutMeta(path, "SCHEMA_VERSION", {0xff});
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(); }),
                      "Corrupted schema version in the Chronik database, "
                      "consider running -reindex/-chronikreindex");

    // New db path, but has existing data
    const auto new_dir = env.dir.path / "new";
    std::filesystem::create_directories(new_dir / "indexes");
    IndexerParams new_params = env.Params();
    new_params.datadir_net = new_dir;
    PutMeta(nt::TestIndexDir(new_dir), "FOO", {'B', 'A', 'R'});
    // Error: non-empty DB without schema version
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(new_params); }),
                      "Missing schema version in non-empty Chronik database, "
                      "consider running -reindex/-chronikreindex");
    // with wipe it works
    new_params.wipe = true;
    env.Open(new_params)->Close();
    BOOST_CHECK(env.host.HasLog("Wiping Chronik at " +
                                nt::TestIndexDir(new_dir).string() +
                                "\n"));
}

// ---------------------------------------------------------------------------
// Resync
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(resync_empty_node_and_db) {
    Env env("indexer-empty", 0);
    auto ix = env.OpenSynced();
    BOOST_CHECK(!Tip(*ix));
}

BOOST_AUTO_TEST_CASE(resync_node_without_tip_but_db_has_blocks) {
    Env env("indexer-notip", 2);
    env.OpenSynced()->Close();
    th::FakeHost empty;
    auto ix = Indexer::Open(empty, env.Params());
    const BlockHash tip = env.host.ActiveBlock(1).info.hash;
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->Resync(); }),
                      indexer_errors::CannotRewindChronik(tip));
}

BOOST_AUTO_TEST_CASE(resync_from_empty) {
    Env env("indexer-from-empty");
    std::mt19937_64 rng(1);
    env.Grow(rng, 4);
    auto ix = env.OpenSynced();
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 4);
    BOOST_CHECK(Tip(*ix)->hash == env.host.ActiveBlock(4).info.hash);
    const std::string tip_hex = HashToHex(env.host.ActiveBlock(4).info.hash);
    BOOST_CHECK(env.host.HasLog("Chronik database empty, syncing to block " +
                                tip_hex + " at height 4.\n"));
    BOOST_CHECK(env.host.HasLog("Added block " + tip_hex +
                                ", height 4/4 to Chronik\n"));
    BOOST_CHECK(env.host.HasLog(
        "Chronik completed re-syncing with the node, both are now at block " +
        tip_hex + " at height 4.\n"));
    // Genesis (height 0) is "Synced ... up to" with no rate limit
    bool found = false;
    for (const auto &[level, msg] : env.host.Logs()) {
        if (msg.starts_with("Synced Chronik up to block ")) {
            found = level == LogLevel::InfoNoRateLimit;
        }
    }
    BOOST_CHECK(found);
}

BOOST_AUTO_TEST_CASE(resync_behind) {
    Env env("indexer-behind");
    std::mt19937_64 rng(2);
    env.Grow(rng, 3);
    env.OpenSynced()->Close();
    env.Grow(rng, 4);
    env.host.ClearLogs();
    auto ix = env.OpenSynced();
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 7);
    // Like Rust, a tip that is merely behind also counts as "diverged"; the
    // fork is Chronik's own tip and nothing is reverted.
    BOOST_CHECK(env.host.HasLog("Node and Chronik diverged"));
    BOOST_CHECK(env.host.HasLog("Reverting Chronik blocks 4 to 3.\n"));
    const auto dump = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(resync_ahead) {
    Env env("indexer-ahead");
    std::mt19937_64 rng(3);
    env.Grow(rng, 6);
    const BlockHash old_tip = env.host.ActiveBlock(6).info.hash;
    env.OpenSynced()->Close();
    env.host.TruncateActive(3);
    env.host.ClearLogs();
    auto ix = env.OpenSynced();
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 3);
    const std::string node_tip = HashToHex(env.host.ActiveBlock(3).info.hash);
    BOOST_CHECK(env.host.HasLog("Node and Chronik diverged, node is on block " +
                                node_tip +
                                " at height 3, and Chronik is on block " +
                                HashToHex(old_tip) + " at height 6.\n"));
    BOOST_CHECK(env.host.HasLog("The last common block is " + node_tip +
                                " at height 3.\n"));
    BOOST_CHECK(env.host.HasLog("Reverting Chronik blocks 4 to 6.\n"));
    const auto dump = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(resync_forked) {
    Env env("indexer-forked");
    std::mt19937_64 rng(4);
    env.Grow(rng, 6);
    env.OpenSynced()->Close();
    env.host.TruncateActive(2);
    env.Grow(rng, 6);
    env.host.ClearLogs();
    auto ix = env.OpenSynced();
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 8);
    BOOST_CHECK(Tip(*ix)->hash == env.host.ActiveBlock(8).info.hash);
    BOOST_CHECK(env.host.HasLog("Reverting Chronik blocks 3 to 6.\n"));
    const auto dump = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(resync_unknown_indexer_tip) {
    Env env("indexer-unknown");
    std::mt19937_64 rng(5);
    env.Grow(rng, 2);
    env.OpenSynced()->Close();
    // A node with a different chain: Chronik's tip is unknown to it
    th::FakeHost other;
    other.MakeHash('x'); // shift the hash counter
    other.Extend(other.MakeBlock(-1, {}));
    other.Extend(other.MakeBlock(0, {}));
    auto ix = Indexer::Open(other, env.Params());
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->Resync(); }),
                      indexer_errors::CannotRewindChronik(
                          env.host.ActiveBlock(2).info.hash));
}

BOOST_AUTO_TEST_CASE(resync_shutdown_while_adding) {
    Env env("indexer-shutdown-add");
    std::mt19937_64 rng(6);
    env.Grow(rng, 5);
    env.host.ShutdownAfter(2);
    auto ix = env.OpenSynced();
    BOOST_CHECK(env.host.HasLog("Stopped re-sync adding blocks\n"));
    BOOST_CHECK(!env.host.HasLog("Chronik completed re-syncing"));
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 1);
    ix->Close();
    ix.reset();
    // Resuming later continues where it stopped
    env.host.SetShutdown(false);
    ix = env.OpenSynced();
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 5);
    const auto dump = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(resync_shutdown_while_rewinding) {
    Env env("indexer-shutdown-rewind");
    std::mt19937_64 rng(7);
    env.Grow(rng, 6);
    env.OpenSynced()->Close();
    env.host.TruncateActive(2);
    env.Grow(rng, 2);
    env.host.ShutdownAfter(2);
    auto ix = env.OpenSynced();
    BOOST_CHECK(env.host.HasLog("Stopped re-sync rewinding blocks\n"));
    // Rust returns BlockHeight::MAX; `+ 1` wraps and the add loop stops
    // immediately.
    BOOST_CHECK(env.host.HasLog("Stopped re-sync adding blocks\n"));
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 4);
    ix->Close();
    ix.reset();
    env.host.SetShutdown(false);
    ix = env.OpenSynced();
    BOOST_CHECK(Tip(*ix)->hash == env.host.ActiveBlock(4).info.hash);
    const auto dump = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(resync_perf_stats) {
    Env env("indexer-perf");
    std::mt19937_64 rng(9);
    env.Grow(rng, 2);
    IndexerParams p = env.Params();
    p.perf_stats = true;
    env.OpenSynced(p)->Close();
    const auto path = env.dir.path / "perf" / "resync_stats.txt";
    BOOST_REQUIRE(std::filesystem::exists(path));
    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)), {});
    BOOST_CHECK(content.starts_with("StatsData {\n"));
}

BOOST_AUTO_TEST_CASE(wipe_reindexes) {
    Env env("indexer-wipe");
    std::mt19937_64 rng(10);
    env.Grow(rng, 3);
    auto ix = env.OpenSynced();
    const auto before = Dump(*ix);
    ix->Close();
    ix.reset();
    IndexerParams p = env.Params();
    p.wipe = true;
    ix = env.Open(p);
    BOOST_CHECK(!Tip(*ix));
    ix->Resync();
    BOOST_CHECK(Dump(*ix) == before);
}

// ---------------------------------------------------------------------------
// Index flags
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(lokad_id_reindex) {
    Env env("indexer-lokad");
    std::mt19937_64 rng(11);
    env.Grow(rng, 12);
    IndexerParams off = env.Params();
    off.lokad_id_index = false;
    auto ix = env.OpenSynced(off);
    const auto dump_off = Dump(*ix);
    ix->Close();
    ix.reset();
    BOOST_CHECK(dump_off == env.FreshDump(off));
    // Enabling it reindexes the LOKAD ID index of all blocks
    ix = env.OpenSynced();
    const auto dump_on = Dump(*ix);
    ix->Close();
    ix.reset();
    BOOST_CHECK(dump_on == env.FreshDump());
    BOOST_CHECK(dump_on != dump_off);
    // Rewinding with a pending LOKAD ID reindex (disabled -> enabled while
    // the node reorged) also ends up identical to a fresh index.
    ix = env.OpenSynced(off);
    ix->Close();
    ix.reset();
    env.host.TruncateActive(8);
    env.Grow(rng, 3);
    ix = env.OpenSynced();
    const auto dump_reorg = Dump(*ix);
    ix->Close();
    BOOST_CHECK(dump_reorg == env.FreshDump());
}

BOOST_AUTO_TEST_CASE(token_index_unavailable_fails_closed) {
    TokenFactoryGuard guard;
    Env env("indexer-token-unavailable");
    env.host.Caps().slp_alp_tokens = true;
    IndexerParams p = env.Params();
    p.token_index = true;
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { env.Open(p); }),
                      indexer_errors::TokenIndexUnavailable());
    // Disabled token index, or a host without tokens, works
    p.token_index = false;
    BOOST_CHECK(!env.OpenSynced(p)->Impl().IsTokenIndexEnabled());
    env.host.Caps().slp_alp_tokens = false;
    p.token_index = true;
    BOOST_CHECK(!env.OpenSynced(p)->Impl().IsTokenIndexEnabled());
}

// ---------------------------------------------------------------------------
// Block and mempool events
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(block_events_publish_after_commit) {
    Env env("indexer-block-events");
    auto ix = env.OpenSynced();
    auto block_rx = ix->Impl().Subs().Write()->SubToBlockMsgs();
    auto txs_rx = ix->Impl().Subs().Write()->SubToTxMsgs();
    std::mt19937_64 rng(12);
    Block block = env.host.RandomBlock(rng, 0);
    while (block.txs.size() < 2) {
        block = env.host.RandomBlock(rng, 0);
    }
    env.host.Extend(block);
    // Subscribe to the coinbase's script; the waker must see committed data
    auto script_rx = ix->Impl().Subs().Write()->SubsScript().SubscribeToMember(
        block.txs[0].tx->outputs[0].script);
    std::optional<int32_t> tip_seen_by_waker;
    block_rx.SetWaker([&] { tip_seen_by_waker = Tip(*ix)->height; });
    ix->OnBlockConnected(block);
    BOOST_CHECK(tip_seen_by_waker == 1);
    auto msgs = Drain(block_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == BlockMsgType::Connected);
    BOOST_CHECK(msgs[0].hash == block.info.hash);
    BOOST_CHECK_EQUAL(msgs[0].height, 1);
    BOOST_CHECK_EQUAL(msgs[0].timestamp, block.info.timestamp);
    BOOST_CHECK(!msgs[0].coinbase_tx);
    auto tx_msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(tx_msgs.size(), block.txs.size());
    for (size_t i = 0; i < tx_msgs.size(); ++i) {
        BOOST_CHECK(tx_msgs[i].msg_type == TxMsgType::Confirmed());
        BOOST_CHECK(tx_msgs[i].txid == block.txs[i].tx->txid);
    }
    auto script_msgs = Drain(script_rx);
    BOOST_REQUIRE_GE(script_msgs.size(), 1u);
    BOOST_CHECK(script_msgs[0].txid == block.txs[0].tx->txid);

    block_rx.SetWaker({});
    ix->OnBlockDisconnected(block);
    msgs = Drain(block_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == BlockMsgType::Disconnected);
    BOOST_REQUIRE(msgs[0].coinbase_tx);
    BOOST_CHECK(msgs[0].coinbase_tx->txid == block.txs[0].tx->txid);
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 0);
    // Rust only sends block tx events on connect
    BOOST_CHECK(Drain(txs_rx).empty());

    ix->OnBlockInvalidated(block);
    msgs = Drain(block_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == BlockMsgType::Invalidated);
    BOOST_REQUIRE(msgs[0].coinbase_tx);
}

BOOST_AUTO_TEST_CASE(mempool_add_remove_confirm_conflict) {
    Env env("indexer-mempool", 3);
    auto ix = env.OpenSynced();
    auto txs_rx = ix->Impl().Subs().Write()->SubToTxMsgs();
    // Rust handle_block_tx_events short-circuits without group subscribers:
    // block txs are only broadcast on the txs channel if some group has one.
    auto unrelated_rx = ix->Impl().Subs().Write()->SubsScript().SubscribeToMember(
        th::P2pkh(0xee));
    const auto dump_before = Dump(*ix);

    // Add a tx spending a confirmed coinbase, and a child spending it
    TxRef parent = SpendCoinbase(env.host, 1, 1);
    TxRef child = SpendOutput(env.host, *parent, 0, -1, 2);
    ix->OnTxAddedToMempool(parent, 1000);
    ix->OnTxAddedToMempool(child, 1001);
    {
        auto snap = ix->Impl().Snapshot();
        BOOST_CHECK_EQUAL(snap.Mempool().Txs().size(), 2u);
        BOOST_REQUIRE(snap.Mempool().GetTx(parent->txid));
        BOOST_CHECK_EQUAL(snap.Mempool().GetTx(parent->txid)->time_first_seen,
                          1000);
    }
    auto msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 2u);
    BOOST_CHECK(msgs[0].msg_type == TxMsgType::AddedToMempool());
    BOOST_CHECK(msgs[0].txid == parent->txid);
    // The DB is untouched by mempool txs
    BOOST_CHECK(Dump(*ix) == dump_before);

    // Remove the child
    ix->OnTxRemovedFromMempool(child->txid);
    msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == TxMsgType::RemovedFromMempool());
    BOOST_CHECK(msgs[0].txid == child->txid);

    // Confirm the parent: removed from the mempool on commit (RemoveMined)
    Block block = env.host.MakeBlock(2, {*parent});
    env.host.Extend(block);
    ix->OnBlockConnected(block);
    BOOST_CHECK(ix->Impl().Snapshot().Mempool().Txs().empty());
    msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 2u);
    BOOST_CHECK(msgs[1].msg_type == TxMsgType::Confirmed());
    BOOST_CHECK(msgs[1].txid == parent->txid);
    // Mined tx keeps its time_first_seen: index differs from a fresh sync
    BOOST_CHECK(Dump(*ix) != env.FreshDump());

    // Conflict: a mempool tx spends a coin that a block then spends; the
    // node reports the conflict as a removal.
    TxRef mempool_tx = SpendCoinbase(env.host, 2, 3);
    TxRef conflicting = SpendCoinbase(env.host, 2, 4);
    ix->OnTxAddedToMempool(mempool_tx, 2000);
    Block block2 = env.host.MakeBlock(3, {*conflicting});
    env.host.Extend(block2);
    ix->OnBlockConnected(block2);
    BOOST_CHECK(ix->Impl().Snapshot().Mempool().GetTx(mempool_tx->txid));
    ix->OnTxRemovedFromMempool(mempool_tx->txid);
    BOOST_CHECK(ix->Impl().Snapshot().Mempool().Txs().empty());

    // Disconnecting the blocks restores the DB; the node re-adds the parent
    ix->OnBlockDisconnected(block2);
    ix->OnBlockDisconnected(block);
    BOOST_CHECK(Dump(*ix) == dump_before);
    ix->OnTxAddedToMempool(parent, 1000);
    BOOST_CHECK(ix->Impl().Snapshot().Mempool().GetTx(parent->txid));
}

BOOST_AUTO_TEST_CASE(failed_state) {
    Env env("indexer-failed", 2);
    auto ix = env.OpenSynced();
    const TxId unknown = nt::TxIdNum(0x42);
    const std::string expected = "No such mempool tx: " + HashToHex(unknown);
    BOOST_CHECK_EQUAL(
        nt::ErrorMsg([&] { ix->OnTxRemovedFromMempool(unknown); }), expected);
    BOOST_CHECK(ix->Impl().Failed());
    BOOST_CHECK_EQUAL(ix->Impl().FailureMessage(), expected);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->Impl().Snapshot(); }),
                      "Chronik indexer failed: " + expected);
    // Later events are ignored (no throw, no effect)
    TxRef tx = SpendCoinbase(env.host, 1, 1);
    ix->OnTxAddedToMempool(tx, 1);
    ix->OnTxRemovedFromMempool(unknown);
    ix->Close();
}

BOOST_AUTO_TEST_CASE(closed_state) {
    Env env("indexer-closed");
    auto ix = env.OpenSynced();
    ix->Close();
    ix->Close(); // idempotent
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->Impl().Snapshot(); }),
                      "Chronik indexer is closed");
}

// ---------------------------------------------------------------------------
// Avalanche
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(avalanche_block_finalization) {
    Env env("indexer-avalanche");
    env.host.Caps().avalanche = true;
    std::mt19937_64 rng(13);
    env.Grow(rng, 4);
    auto ix = env.OpenSynced();
    auto block_rx = ix->Impl().Subs().Write()->SubToBlockMsgs();
    auto txs_rx = ix->Impl().Subs().Write()->SubToTxMsgs();
    const Block &b3 = env.host.ActiveBlock(3);
    // Without any group subscriber, block tx events are not broadcast
    ix->OnBlockFinalized(env.host.ActiveBlock(1).info);
    BOOST_CHECK_EQUAL(Drain(block_rx).size(), 1u);
    BOOST_CHECK(Drain(txs_rx).empty());
    auto unrelated_rx = ix->Impl().Subs().Write()->SubsScript().SubscribeToMember(
        th::P2pkh(0xee));
    ix->OnBlockFinalized(b3.info);
    BOOST_CHECK_EQUAL(ix->Impl().Snapshot().GetAvalanche().height, 3);
    auto msgs = Drain(block_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == BlockMsgType::Finalized);
    BOOST_CHECK(msgs[0].hash == b3.info.hash);
    auto tx_msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(tx_msgs.size(), b3.txs.size());
    BOOST_CHECK(tx_msgs[0].msg_type ==
                TxMsgType::Finalized(TxFinalizationReason::PostConsensus));
    BOOST_CHECK(env.host.HasLog("Chronik: block " + HashToHex(b3.info.hash) +
                                " finalized with " +
                                std::to_string(b3.txs.size()) + " txs\n"));
    // Disconnecting the tip above the finalized height keeps it
    ix->OnBlockDisconnected(env.host.ActiveBlock(4));
    BOOST_CHECK_EQUAL(ix->Impl().Snapshot().GetAvalanche().height, 3);
    // Disconnecting the last finalized block lowers it (avalanche.rs)
    ix->OnBlockDisconnected(b3);
    BOOST_CHECK_EQUAL(ix->Impl().Snapshot().GetAvalanche().height, 2);
    BOOST_CHECK(!ix->Impl().Failed());
}

BOOST_AUTO_TEST_CASE(avalanche_decreasing_finalized_height) {
    Env env("indexer-avalanche-dec", 4);
    auto ix = env.OpenSynced();
    ix->OnBlockFinalized(env.host.ActiveBlock(3).info);
    BOOST_CHECK_EQUAL(
        nt::ErrorMsg(
            [&] { ix->OnBlockFinalized(env.host.ActiveBlock(2).info); }),
        AvalancheDecreasingFinalizedHeightMessage(3, 2));
}

BOOST_AUTO_TEST_CASE(avalanche_unknown_block_finalized) {
    Env env("indexer-avalanche-unknown", 2);
    auto ix = env.OpenSynced();
    // A block the node has but Chronik hasn't indexed
    Block block = env.host.MakeBlock(1, {});
    env.host.AddBlock(block);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->OnBlockFinalized(block.info); }),
                      indexer_errors::BlockNotFound(2));
}

BOOST_AUTO_TEST_CASE(avalanche_tx_finalized_and_invalidated) {
    Env env("indexer-avalanche-tx", 3);
    auto ix = env.OpenSynced();
    auto txs_rx = ix->Impl().Subs().Write()->SubToTxMsgs();
    const auto pre = TxMsgType::Finalized(TxFinalizationReason::PreConsensus);

    // From the mempool
    TxRef tx = SpendCoinbase(env.host, 1, 1);
    ix->OnTxAddedToMempool(tx, 5);
    Drain(txs_rx);
    ix->OnTxFinalized(tx->txid);
    auto msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == pre);
    BOOST_CHECK(msgs[0].txid == tx->txid);

    // Invalidated while in the mempool
    ix->OnTxInvalidated(tx);
    msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == TxMsgType::Invalidated());

    // From the DB (mined)
    const Tx &cb = *env.host.ActiveBlock(2).txs[0].tx;
    ix->OnTxFinalized(cb.txid);
    msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == pre);
    BOOST_CHECK(msgs[0].txid == cb.txid);

    // Invalidated, not in the mempool: probed, the mempool is unchanged
    TxRef other = SpendCoinbase(env.host, 2, 2);
    ix->OnTxInvalidated(other);
    msgs = Drain(txs_rx);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].msg_type == TxMsgType::Invalidated());
    BOOST_CHECK(msgs[0].txid == other->txid);
    BOOST_CHECK(!ix->Impl().Snapshot().Mempool().GetTx(other->txid));

    // Unknown txid
    const TxId unknown = nt::TxIdNum(0x77);
    BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ix->OnTxFinalized(unknown); }),
                      indexer_errors::TxIdNotFound(unknown));
}

// ---------------------------------------------------------------------------
// Concurrency: snapshots see a consistent DB + mempool
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(snapshots_consistent_with_writer) {
    Env env("indexer-concurrent", 2);
    auto ix = env.OpenSynced();
    std::atomic<bool> done{false};
    std::atomic<int> violations{0};
    std::atomic<int> reads{0};
    std::thread reader([&] {
        int32_t last = -1;
        while (!done.load()) {
            auto snap = ix->Impl().Snapshot();
            auto tip = index::BlockReader(snap.Store(), snap.Txn()).Tip();
            if (!tip || tip->height < last) {
                ++violations;
            }
            last = tip ? tip->height : -1;
            // Every mempool tx must be unconfirmed in this view
            index::TxReader txs(snap.Store(), snap.Txn());
            for (const auto &[txid, mtx] : snap.Mempool().Txs()) {
                if (txs.TxNumByTxid(txid)) {
                    ++violations;
                }
            }
            ++reads;
        }
    });
    for (int i = 0; i < 30; ++i) {
        TxRef tx = SpendCoinbase(env.host, env.host.TipHeight(), 1);
        ix->OnTxAddedToMempool(tx, i);
        Block block = env.host.MakeBlock(env.host.TipHeight(), {*tx});
        env.host.Extend(block);
        ix->OnBlockConnected(block);
    }
    done = true;
    reader.join();
    BOOST_CHECK_EQUAL(violations.load(), 0);
    BOOST_CHECK_GT(reads.load(), 0);
    BOOST_CHECK_EQUAL(Tip(*ix)->height, 31);
}

BOOST_AUTO_TEST_SUITE_END()
