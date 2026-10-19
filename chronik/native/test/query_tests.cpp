// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// HTTP handler tests for the query routes of chronik-http server.rs
// (core/query/*): every route's success and error paths on a FakeHost-backed
// indexer. The Rust query/*.rs and handlers.rs files have no #[test]s.

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/indexer.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/proto.h>
#include <chronik/native/routes.h>
#include <chronik/native/token_index.h>
#include <chronik/native/token_io/token_index.h>
#include <chronik/native/tx/legacy_tx.h>

#include <test/fake_host.h>
#include <test/index_test_util.h>
#include <test/test_backend.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <functional>
#include <map>
#include <set>

using namespace chronik::native;
namespace th = chronik::native::testhost;
namespace nt = chronik::native::test;

namespace {

/**
 * Host delegating to a FakeHost, adding raw tx decoding/broadcast, coin
 * lookup from the active chain, raw tx loading and preconsensus finality.
 */
class QueryHost final : public Host {
public:
    explicit QueryHost(th::FakeHost &fake) : m_fake(fake) {}

    /** Make `tx` decodable; returns its raw bytes. */
    Bytes AddRawTx(const Tx &tx) {
        Bytes raw = SerializeLegacyTx(tx);
        m_decodable[raw] = tx;
        return raw;
    }
    void SetExtraCoin(const OutPoint &outpoint, const Coin &coin) {
        m_extra_coins[outpoint] = coin;
    }
    void SetBroadcastError(std::optional<std::string> error) {
        m_broadcast_error = std::move(error);
    }
    void SetPreconsensus(const TxId &txid, bool final) {
        m_preconsensus[txid] = final;
    }
    std::function<void()> on_sync;
    mutable int sync_calls = 0;
    mutable std::vector<TxId> broadcast;
    mutable std::vector<OutPoint> uncached;

    const HostCapabilities &Capabilities() const override {
        return m_fake.Capabilities();
    }
    std::optional<BlockInfo> ActiveTip() const override {
        return m_fake.ActiveTip();
    }
    std::optional<BlockInfo> LookupBlock(const BlockHash &h) const override {
        return m_fake.LookupBlock(h);
    }
    std::optional<BlockInfo> ActiveAtHeight(int32_t height) const override {
        return m_fake.ActiveAtHeight(height);
    }
    std::optional<BlockInfo> FindFork(const BlockHash &h) const override {
        return m_fake.FindFork(h);
    }
    BlockHash GenesisHash() const override { return m_fake.GenesisHash(); }
    Bytes RawHeader(const BlockInfo &info) const override {
        return m_fake.RawHeader(info);
    }
    std::vector<Bytes> RawHeadersByRange(int32_t start,
                                         int32_t end) const override {
        return m_fake.RawHeadersByRange(start, end);
    }
    Block LoadBlock(const BlockInfo &info) const override {
        return m_fake.LoadBlock(info);
    }
    Tx LoadTx(uint32_t file_num, uint32_t data_pos,
              uint32_t undo_pos) const override {
        return m_fake.LoadTx(file_num, data_pos, undo_pos);
    }
    Bytes LoadRawTx(uint32_t file_num, uint32_t data_pos) const override {
        return SerializeLegacyTx(m_fake.LoadTx(file_num, data_pos, 0));
    }
    DecodedTx DecodeRawTx(std::span<const uint8_t> raw) const override {
        auto it = m_decodable.find(Bytes(raw.begin(), raw.end()));
        if (it == m_decodable.end()) {
            return DecodedTx{false, {}, "TX decode failed"};
        }
        Tx tx = it->second;
        for (TxInput &input : tx.inputs) {
            input.coin.reset();
        }
        return DecodedTx{true, std::move(tx), {}};
    }
    SpentCoinLookup LookupSpentCoins(Tx &tx) const override {
        SpentCoinLookup lookup;
        const std::map<OutPoint, Coin> utxos =
            m_fake.UtxosAt(m_fake.TipHeight());
        for (TxInput &input : tx.inputs) {
            if (auto it = utxos.find(input.prev_out); it != utxos.end()) {
                input.coin = it->second;
                lookup.to_uncache.push_back(input.prev_out);
            } else if (auto extra = m_extra_coins.find(input.prev_out);
                       extra != m_extra_coins.end()) {
                input.coin = extra->second;
            } else {
                lookup.not_found.push_back(input.prev_out);
            }
        }
        return lookup;
    }
    void UncacheCoins(std::span<const OutPoint> outpoints) const override {
        uncached.insert(uncached.end(), outpoints.begin(), outpoints.end());
    }
    BroadcastResult Broadcast(std::span<const uint8_t> raw,
                              int64_t) const override {
        auto it = m_decodable.find(Bytes(raw.begin(), raw.end()));
        if (it == m_decodable.end()) {
            return BroadcastResult{false, {}, "TX decode failed"};
        }
        if (m_broadcast_error) {
            return BroadcastResult{false, {}, *m_broadcast_error};
        }
        broadcast.push_back(it->second.txid);
        return BroadcastResult{true, it->second.txid, {}};
    }
    int64_t CalcMaxFee(size_t size) const override { return int64_t(size); }
    std::optional<FeeRateInfo> MempoolFeeRate(const TxId &) const override {
        return std::nullopt;
    }
    int64_t EstimateFeeRateSatsPerKb() const override { return 1000; }
    int64_t MinRelayFeeRateSatsPerKb() const override { return 1000; }
    std::optional<bool>
    IsFinalizedPreConsensus(const TxId &txid) const override {
        if (auto it = m_preconsensus.find(txid); it != m_preconsensus.end()) {
            return it->second;
        }
        return false;
    }
    void SyncWithIndexer() const override {
        ++sync_calls;
        if (on_sync) {
            on_sync();
        }
    }
    bool ShutdownRequested() const override {
        return m_fake.ShutdownRequested();
    }
    void FatalError(std::string_view log_msg,
                    std::string_view user_msg) const override {
        m_fake.FatalError(log_msg, user_msg);
    }
    void Log(LogLevel level, std::string_view msg) const override {
        m_fake.Log(level, msg);
    }
    std::string FormatFullVersion() const override {
        return m_fake.FormatFullVersion();
    }
    void Sha256(std::span<const uint8_t> data, uint8_t out[32]) const override {
        m_fake.Sha256(data, out);
    }

private:
    th::FakeHost &m_fake;
    std::map<Bytes, Tx> m_decodable;
    std::map<OutPoint, Coin> m_extra_coins;
    std::optional<std::string> m_broadcast_error;
    std::map<TxId, bool> m_preconsensus;
};

/** Restores the global token index factory. */
struct TokenFactoryGuard {
    TokenIndexFactory saved = RegisteredTokenIndexFactory();
    ~TokenFactoryGuard() { RegisterTokenIndexFactory(saved); }
};

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

std::string Str(ByteView bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
}
std::string Str(const Hash32 &hash) {
    return Str(ByteView(hash.b.data(), hash.b.size()));
}
std::string Hex(const Hash32 &hash) { return HashToHex(hash); }

const std::array<uint8_t, 4> LOKAD = {'T', 'E', 'S', '0'};

/** SLP fungible GENESIS with ticker "TST", 1000 atoms to output 1. */
Bytes SlpGenesisScript() {
    return Bytes{0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01, 0x01, 0x07, 'G',
                 'E',  'N',  'E', 'S', 'I', 'S',  0x03, 'T',  'S',  'T',
                 0x04, 'T',  'e', 's', 't', 0x4c, 0x00, 0x4c, 0x00, 0x01,
                 0x00, 0x4c, 0x00, 0x08, 0,   0,    0,    0,    0,    0,
                 0x03, 0xe8};
}

/**
 * A chain of three blocks and one mempool tx:
 *  block 0: cb0 -> P2PKH(cb)
 *  block 1: cb1, A spends cb0:0 -> [OP_RETURN TES0, P2PKH(1) 4000]
 *  block 2: cb2, B spends A:1 -> [P2PKH(2) 3900]
 *  mempool: C spends B:0 -> [P2PKH(1) 3800]
 */
struct Env {
    th::FakeHost fake;
    QueryHost host{fake};
    nt::IndexTempDir dir;
    std::unique_ptr<Indexer> ix;
    Router router;
    TxRef a, b, c;
    int64_t c_time = 1'700'000'000;

    explicit Env(const std::string &name, bool scripthash = false,
                 bool tokens = false)
        : dir(name) {
        nt::RegisterTestStores();
        std::filesystem::create_directories(dir.path);
        fake.Caps().slp_alp_tokens = tokens;
        fake.Extend(fake.MakeBlock(-1, {}));
        const Tx &cb0 = *fake.ActiveBlock(0).txs[0].tx;
        a = std::make_shared<const Tx>(fake.MakeSpend(
            {{OutPoint{cb0.txid, 0}, Coin{cb0.outputs[0], 0, true}}},
            {TxOutput{0, th::LokadOpReturn(LOKAD)},
             TxOutput{4000, th::P2pkh(1)}}));
        fake.Extend(fake.MakeBlock(0, {*a}));
        b = std::make_shared<const Tx>(fake.MakeSpend(
            {{OutPoint{a->txid, 1}, Coin{a->outputs[1], 1, false}}},
            {TxOutput{3900, th::P2pkh(2)}}));
        fake.Extend(fake.MakeBlock(1, {*b}));
        c = std::make_shared<const Tx>(fake.MakeSpend(
            {{OutPoint{b->txid, 0}, Coin{b->outputs[0], 2, false}}},
            {TxOutput{3800, th::P2pkh(1)}}));
        IndexerParams params;
        params.datadir_net = dir.path;
        params.backend = nt::TestBackend();
        params.token_index = tokens;
        params.lokad_id_index = true;
        params.scripthash_index = scripthash;
        ix = Indexer::Open(host, params);
        ix->Resync();
        ix->OnTxAddedToMempool(c, c_time);
        RegisterCoreRoutes(router, RouteContext{ix->Impl(), host, nullptr});
    }

    const Block &ActiveBlock(int32_t height) {
        return fake.ActiveBlock(height);
    }

    HttpResponse Get(const std::string &target) const {
        return router.Handle(MakeRequest("GET", target));
    }
    HttpResponse Post(const std::string &target,
                      const google::protobuf::Message &msg) const {
        HttpRequest req = MakeRequest("POST", target);
        req.headers.emplace_back("Content-Type", "application/x-protobuf");
        std::string body;
        BOOST_REQUIRE(msg.SerializeToString(&body));
        req.body.assign(body.begin(), body.end());
        return router.Handle(req);
    }
};

template <typename T> T Decode(const HttpResponse &resp) {
    T msg;
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
    BOOST_REQUIRE(msg.ParseFromArray(resp.body.data(), int(resp.body.size())));
    return msg;
}

std::string ErrMsg(const HttpResponse &resp) {
    proto::Error err;
    BOOST_REQUIRE(err.ParseFromArray(resp.body.data(), int(resp.body.size())));
    return err.msg();
}

/** Checks a proto Error response. */
void CheckErr(const HttpResponse &resp, int status, const std::string &msg) {
    BOOST_CHECK_EQUAL(resp.status, status);
    BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
    BOOST_CHECK_EQUAL(ErrMsg(resp), msg);
}

/** Checks an axum plain text rejection. */
void CheckRejection(const HttpResponse &resp, int status,
                    const std::string &body) {
    BOOST_CHECK_EQUAL(resp.status, status);
    BOOST_CHECK_EQUAL(resp.ContentType(), "text/plain; charset=utf-8");
    BOOST_CHECK_EQUAL(Str(ByteView(resp.body.data(), resp.body.size())), body);
}

std::vector<TxId> PageTxids(const proto::TxHistoryPage &page) {
    std::vector<TxId> txids;
    for (const proto::Tx &tx : page.txs()) {
        txids.push_back(Hash32::FromBytes(
            ByteView(reinterpret_cast<const uint8_t *>(tx.txid().data()),
                     tx.txid().size())));
    }
    return txids;
}

std::string P2pkhHex(uint8_t id) { return HexEncode(Bytes(20, id)); }

proto::ScriptRef MakeScriptRef(const std::string &type, const Bytes &payload) {
    proto::ScriptRef ref;
    ref.set_script_type(type);
    ref.set_payload(Str(payload));
    return ref;
}

bool HasTxIdSubs(Env &env) {
    return !env.ix->Impl().Subs().Write()->SubsTxId().IsEmpty();
}

const std::string UNKNOWN_TXID(64, 'a');

} // namespace

BOOST_AUTO_TEST_SUITE(query_tests)

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(block_by_hash_or_height) {
    Env env("query-block");
    const BlockInfo info1 = env.ActiveBlock(1).info;
    for (const std::string &key :
         {std::string("1"), std::string("+1"), Hex(info1.hash)}) {
        auto block = Decode<proto::Block>(env.Get("/block/" + key));
        BOOST_CHECK_EQUAL(block.block_info().hash(), Str(info1.hash));
        BOOST_CHECK_EQUAL(block.block_info().prev_hash(),
                          Str(info1.prev_hash));
        BOOST_CHECK_EQUAL(block.block_info().height(), 1);
        BOOST_CHECK_EQUAL(block.block_info().num_txs(), 2u);
        BOOST_CHECK_EQUAL(block.block_info().timestamp(), info1.timestamp);
        BOOST_CHECK(!block.block_info().is_final());
    }
    CheckErr(env.Get("/block/3"), 404, "404: Block not found: 3");
    CheckErr(env.Get("/block/-1"), 404, "404: Block not found: -1");
    CheckErr(env.Get("/block/" + UNKNOWN_TXID), 404,
             "404: Block not found: " + UNKNOWN_TXID);
    CheckErr(env.Get("/block/01"), 400, "400: Not a hash or height: 01");
    CheckErr(env.Get("/block/abc"), 400, "400: Not a hash or height: abc");
    CheckErr(env.Get("/block/99999999999"), 400,
             "400: Not a hash or height: 99999999999");

    // Avalanche finalization is reflected in is_final
    env.ix->OnBlockFinalized(info1);
    BOOST_CHECK(
        Decode<proto::Block>(env.Get("/block/1")).block_info().is_final());
    BOOST_CHECK(
        !Decode<proto::Block>(env.Get("/block/2")).block_info().is_final());
}

BOOST_AUTO_TEST_CASE(blocks_by_range) {
    Env env("query-blocks");
    auto blocks = Decode<proto::Blocks>(env.Get("/blocks/0/2"));
    BOOST_REQUIRE_EQUAL(blocks.blocks_size(), 3);
    for (int i = 0; i < 3; ++i) {
        BOOST_CHECK_EQUAL(blocks.blocks(i).height(), i);
        BOOST_CHECK_EQUAL(blocks.blocks(i).hash(),
                          Str(env.ActiveBlock(i).info.hash));
    }
    // Beyond the tip: truncated
    BOOST_CHECK_EQUAL(
        Decode<proto::Blocks>(env.Get("/blocks/1/100")).blocks_size(), 2);
    BOOST_CHECK_EQUAL(
        Decode<proto::Blocks>(env.Get("/blocks/5/6")).blocks_size(), 0);
    // Max page size is 500
    BOOST_CHECK_EQUAL(
        Decode<proto::Blocks>(env.Get("/blocks/0/499")).blocks_size(), 3);
    CheckErr(env.Get("/blocks/0/500"), 400,
             "400: Blocks page size too large, may not be above 500 but got "
             "501");
    CheckErr(env.Get("/blocks/-1/2"), 400,
             "400: Invalid block start height: -1");
    CheckErr(env.Get("/blocks/2/1"), 400, "400: Invalid block end height: 1");
    CheckRejection(env.Get("/blocks/x/1"), 400,
                   "Invalid URL: Cannot parse value at index 0 with value "
                   "`\"x\"` to a `i32`");
    CheckRejection(env.Get("/blocks/0/y"), 400,
                   "Invalid URL: Cannot parse value at index 1 with value "
                   "`\"y\"` to a `i32`");
}

BOOST_AUTO_TEST_CASE(block_txs) {
    Env env("query-block-txs");
    const Block &block1 = env.ActiveBlock(1);
    auto page = Decode<proto::TxHistoryPage>(env.Get("/block-txs/1"));
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    BOOST_REQUIRE_EQUAL(page.txs_size(), 2);
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{block1.txs[0].tx->txid, env.a->txid}));
    BOOST_CHECK(page.txs(0).is_coinbase());
    BOOST_CHECK_EQUAL(page.txs(1).block().height(), 1);
    BOOST_CHECK_EQUAL(page.txs(1).block().hash(), Str(block1.info.hash));
    // A:1 is spent by B
    BOOST_CHECK_EQUAL(page.txs(1).outputs(1).spent_by().txid(),
                      Str(env.b->txid));
    BOOST_CHECK_EQUAL(page.txs(1).inputs(0).sats(), 5000);
    // Paging
    page = Decode<proto::TxHistoryPage>(env.Get(
        "/block-txs/" + Hex(block1.info.hash) + "?page=1&page_size=1"));
    BOOST_CHECK_EQUAL(page.num_pages(), 2u);
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.a->txid});
    page = Decode<proto::TxHistoryPage>(env.Get("/block-txs/1?page=5"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    Decode<proto::TxHistoryPage>(env.Get("/block-txs/1?page_size=200"));

    CheckErr(env.Get("/block-txs/1?page_size=0"), 400,
             "400: Requested block tx page size 0 is too small, minimum is 1");
    CheckErr(env.Get("/block-txs/1?page_size=201"), 400,
             "400: Requested block tx page size 201 is too big, maximum is "
             "200");
    CheckErr(env.Get("/block-txs/1?page=abc"), 400,
             "400: Invalid param page: abc, invalid digit found in string");
    CheckErr(env.Get("/block-txs/1?page=-1"), 400,
             "400: Invalid param page: -1, invalid digit found in string");
    CheckErr(env.Get("/block-txs/1?page="), 400,
             "400: Invalid param page: , cannot parse integer from empty "
             "string");
    CheckErr(env.Get("/block-txs/1?page_size=4294967296"), 400,
             "400: Invalid param page_size: 4294967296, number too large to "
             "fit in target type");
    // Params are parsed before the block
    CheckErr(env.Get("/block-txs/zz?page=x"), 400,
             "400: Invalid param page: x, invalid digit found in string");
    CheckErr(env.Get("/block-txs/9"), 404, "404: Block not found: 9");
    CheckErr(env.Get("/block-txs/zz"), 400, "400: Not a hash or height: zz");
}

BOOST_AUTO_TEST_CASE(block_headers) {
    Env env("query-block-headers");
    const BlockInfo info2 = env.ActiveBlock(2).info;
    auto header = Decode<proto::BlockHeader>(env.Get("/block-header/2"));
    BOOST_CHECK_EQUAL(header.raw_header(), Str(env.fake.RawHeader(info2)));
    BOOST_CHECK(header.root().empty());
    BOOST_CHECK_EQUAL(header.branch_size(), 0);
    header = Decode<proto::BlockHeader>(
        env.Get("/block-header/" + Hex(info2.hash) + "?checkpoint_height=2"));
    BOOST_CHECK_EQUAL(header.raw_header(), Str(env.fake.RawHeader(info2)));
    BOOST_CHECK_EQUAL(header.root().size(), 32u);
    const std::string root2 = header.root();
    header = Decode<proto::BlockHeader>(
        env.Get("/block-header/0?checkpoint_height=2"));
    BOOST_CHECK_EQUAL(header.root(), root2);
    BOOST_CHECK_GT(header.branch_size(), 0);

    CheckErr(env.Get("/block-header/2?checkpoint_height=1"), 400,
             "400: Invalid checkpoint height 1, may not be below queried "
             "header height 2");
    CheckErr(env.Get("/block-header/0?checkpoint_height=3"), 400,
             "400: Invalid checkpoint height 3, must be <= chain height 2");
    CheckErr(env.Get("/block-header/0?checkpoint_height=x"), 400,
             "400: Invalid param checkpoint_height: x, invalid digit found "
             "in string");
    CheckErr(env.Get("/block-header/0?checkpoint_height=2147483648"), 400,
             "400: Invalid param checkpoint_height: 2147483648, number too "
             "large to fit in target type");
    CheckErr(env.Get("/block-header/0?checkpoint_height=-2147483649"), 400,
             "400: Invalid param checkpoint_height: -2147483649, number too "
             "small to fit in target type");
    CheckErr(env.Get("/block-header/7"), 404, "404: Block not found: 7");
    CheckErr(env.Get("/block-header/" + UNKNOWN_TXID), 404,
             "404: Block not found: " + UNKNOWN_TXID);
    CheckErr(env.Get("/block-header/q"), 400, "400: Not a hash or height: q");

    auto headers = Decode<proto::BlockHeaders>(env.Get("/block-headers/0/2"));
    BOOST_REQUIRE_EQUAL(headers.headers_size(), 3);
    for (int i = 0; i < 3; ++i) {
        BOOST_CHECK_EQUAL(headers.headers(i).raw_header(),
                          Str(env.fake.RawHeader(env.ActiveBlock(i).info)));
        BOOST_CHECK(headers.headers(i).root().empty());
    }
    headers = Decode<proto::BlockHeaders>(
        env.Get("/block-headers/0/1?checkpoint_height=2"));
    BOOST_REQUIRE_EQUAL(headers.headers_size(), 2);
    BOOST_CHECK(headers.headers(0).root().empty());
    BOOST_CHECK_EQUAL(headers.headers(1).root(), root2);
    // Partial and empty results beyond the tip
    BOOST_CHECK_EQUAL(
        Decode<proto::BlockHeaders>(env.Get("/block-headers/1/9")).headers_size(),
        2);
    BOOST_CHECK_EQUAL(
        Decode<proto::BlockHeaders>(env.Get("/block-headers/5/6")).headers_size(),
        0);
    CheckErr(env.Get("/block-headers/0/2?checkpoint_height=1"), 400,
             "400: Invalid checkpoint height 1, may not be below queried "
             "header height 2");
    CheckErr(env.Get("/block-headers/-1/2"), 400,
             "400: Invalid block start height: -1");
    CheckErr(env.Get("/block-headers/2/1"), 400,
             "400: Invalid block end height: 1");
    CheckErr(env.Get("/block-headers/0/500"), 400,
             "400: Blocks page size too large, may not be above 500 but got "
             "501");
    CheckRejection(env.Get("/block-headers/a/1"), 400,
                   "Invalid URL: Cannot parse value at index 0 with value "
                   "`\"a\"` to a `i32`");
}

// ---------------------------------------------------------------------------
// Txs
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(unconfirmed_txs) {
    Env env("query-unconfirmed");
    auto page = Decode<proto::TxHistoryPage>(env.Get("/unconfirmed-txs"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.c->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    BOOST_CHECK_EQUAL(page.num_txs(), 1u);
    BOOST_CHECK_EQUAL(page.txs(0).time_first_seen(), env.c_time);
    BOOST_CHECK(!page.txs(0).has_block());
    // Sorted by (time_first_seen, txid)
    TxRef d = std::make_shared<const Tx>(env.fake.MakeSpend(
        {{OutPoint{env.c->txid, 0}, Coin{env.c->outputs[0], -1, false}}},
        {TxOutput{3700, th::P2pkh(3)}}));
    env.ix->OnTxAddedToMempool(d, env.c_time - 1);
    page = Decode<proto::TxHistoryPage>(env.Get("/unconfirmed-txs"));
    BOOST_CHECK(PageTxids(page) == (std::vector<TxId>{d->txid, env.c->txid}));
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    // C:0 spent by D in the mempool
    BOOST_CHECK_EQUAL(page.txs(1).outputs(0).spent_by().txid(), Str(d->txid));
}

BOOST_AUTO_TEST_CASE(tx_by_id) {
    Env env("query-tx");
    const Block &block1 = env.ActiveBlock(1);
    auto tx = Decode<proto::Tx>(env.Get("/tx/" + Hex(env.a->txid)));
    BOOST_CHECK_EQUAL(tx.txid(), Str(env.a->txid));
    BOOST_CHECK_EQUAL(tx.version(), 2u);
    BOOST_REQUIRE_EQUAL(tx.inputs_size(), 1);
    BOOST_CHECK_EQUAL(tx.inputs(0).prev_out().txid(),
                      Str(env.ActiveBlock(0).txs[0].tx->txid));
    BOOST_CHECK_EQUAL(tx.inputs(0).sats(), 5000);
    BOOST_CHECK_EQUAL(tx.inputs(0).output_script(), Str(th::P2pkh(0xcb)));
    BOOST_REQUIRE_EQUAL(tx.outputs_size(), 2);
    BOOST_CHECK_EQUAL(tx.outputs(1).sats(), 4000);
    BOOST_CHECK_EQUAL(tx.outputs(1).output_script(), Str(th::P2pkh(1)));
    BOOST_CHECK_EQUAL(tx.outputs(1).spent_by().txid(), Str(env.b->txid));
    BOOST_CHECK_EQUAL(tx.outputs(1).spent_by().input_idx(), 0u);
    BOOST_CHECK(!tx.outputs(0).has_spent_by());
    BOOST_CHECK_EQUAL(tx.block().height(), 1);
    BOOST_CHECK_EQUAL(tx.block().hash(), Str(block1.info.hash));
    BOOST_CHECK_EQUAL(tx.block().timestamp(), block1.info.timestamp);
    BOOST_CHECK(!tx.block().is_final());
    BOOST_CHECK(!tx.is_final());
    BOOST_CHECK_EQUAL(tx.size(), env.a->wire_size);
    BOOST_CHECK_EQUAL(tx.token_status(), proto::TOKEN_STATUS_NON_TOKEN);
    env.ix->OnBlockFinalized(block1.info);
    tx = Decode<proto::Tx>(env.Get("/tx/" + Hex(env.a->txid)));
    BOOST_CHECK(tx.block().is_final());
    BOOST_CHECK(tx.is_final());

    // B:0 spent in the mempool by C
    tx = Decode<proto::Tx>(env.Get("/tx/" + Hex(env.b->txid)));
    BOOST_CHECK_EQUAL(tx.outputs(0).spent_by().txid(), Str(env.c->txid));

    // Mempool tx, with preconsensus finality from the host
    tx = Decode<proto::Tx>(env.Get("/tx/" + Hex(env.c->txid)));
    BOOST_CHECK(!tx.has_block());
    BOOST_CHECK_EQUAL(tx.time_first_seen(), env.c_time);
    BOOST_CHECK(!tx.is_final());
    env.host.SetPreconsensus(env.c->txid, true);
    BOOST_CHECK(
        Decode<proto::Tx>(env.Get("/tx/" + Hex(env.c->txid))).is_final());

    CheckErr(env.Get("/tx/" + UNKNOWN_TXID), 404,
             "404: Transaction " + UNKNOWN_TXID + " not found in the index");
    CheckErr(env.Get("/tx/abc"), 400, "400: Not a txid: abc");
    CheckErr(env.Get("/tx/" + std::string(62, '0')), 400,
             "400: Not a txid: " + std::string(62, '0'));
}

BOOST_AUTO_TEST_CASE(raw_tx_by_id) {
    Env env("query-raw-tx");
    auto raw = Decode<proto::RawTx>(env.Get("/raw-tx/" + Hex(env.a->txid)));
    BOOST_CHECK_EQUAL(raw.raw_tx(), Str(SerializeLegacyTx(*env.a)));
    raw = Decode<proto::RawTx>(env.Get("/raw-tx/" + Hex(env.c->txid)));
    BOOST_CHECK_EQUAL(raw.raw_tx(), Str(SerializeLegacyTx(*env.c)));
    CheckErr(env.Get("/raw-tx/" + UNKNOWN_TXID), 404,
             "404: Transaction " + UNKNOWN_TXID + " not found in the index");
    CheckErr(env.Get("/raw-tx/xyz"), 400, "400: Not a txid: xyz");
}

BOOST_AUTO_TEST_CASE(token_info_without_token) {
    Env env("query-token-none");
    CheckErr(env.Get("/token/" + Hex(env.a->txid)), 404,
             "404: Token " + Hex(env.a->txid) + " not found in the index");
    CheckErr(env.Get("/token/" + UNKNOWN_TXID), 404,
             "404: Token " + UNKNOWN_TXID + " not found in the index");
    CheckErr(env.Get("/token/nope"), 400, "400: Not a txid: nope");
}

// ---------------------------------------------------------------------------
// Script groups
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(script_history_routes) {
    Env env("query-script-history");
    const std::string s1 = "/script/p2pkh/" + P2pkhHex(1);
    const std::string s2 = "/script/p2pkh/" + P2pkhHex(2);

    // Script 1: received in A, spent in B, received in C (mempool)
    auto page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/history"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{env.c->txid, env.b->txid, env.a->txid}));
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    BOOST_CHECK_EQUAL(page.num_txs(), 3u);
    page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/confirmed-txs"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{env.a->txid, env.b->txid}));
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/unconfirmed-txs"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.c->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    BOOST_CHECK_EQUAL(page.num_txs(), 1u);
    // script 2 receives in B and spends in C
    page = Decode<proto::TxHistoryPage>(env.Get(s2 + "/history"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{env.c->txid, env.b->txid}));
    // Paging over mempool + DB
    page = Decode<proto::TxHistoryPage>(
        env.Get(s1 + "/history?page=1&page_size=1"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.b->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 3u);
    page = Decode<proto::TxHistoryPage>(
        env.Get(s1 + "/history?page=1&page_size=2"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.a->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 2u);
    page = Decode<proto::TxHistoryPage>(
        env.Get(s1 + "/history?page=3&page_size=1"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    BOOST_CHECK_EQUAL(page.num_txs(), 3u);
    page = Decode<proto::TxHistoryPage>(
        env.Get(s1 + "/confirmed-txs?page=1&page_size=1"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.b->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 2u);
    page = Decode<proto::TxHistoryPage>(
        env.Get(s1 + "/confirmed-txs?page=1&page_size=200"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    BOOST_CHECK_EQUAL(page.num_txs(), 2u);
    // Unknown script: empty
    page = Decode<proto::TxHistoryPage>(
        env.Get("/script/p2sh/" + P2pkhHex(9) + "/history"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    BOOST_CHECK_EQUAL(page.num_pages(), 0u);
    BOOST_CHECK_EQUAL(page.num_txs(), 0u);

    for (const std::string route : {"/history", "/confirmed-txs"}) {
        CheckErr(env.Get(s1 + route + "?page_size=0"), 400,
                 "400: Requested page size 0 is too small, minimum is 1");
        CheckErr(env.Get(s1 + route + "?page_size=201"), 400,
                 "400: Requested page size 201 is too big, maximum is 200");
        CheckErr(env.Get(s1 + route + "?page=1.5"), 400,
                 "400: Invalid param page: 1.5, invalid digit found in "
                 "string");
        // Params are parsed before the script
        CheckErr(env.Get("/script/foo/zz" + route + "?page_size=x"), 400,
                 "400: Invalid param page_size: x, invalid digit found in "
                 "string");
    }
    for (const std::string route :
         {"/history", "/confirmed-txs", "/unconfirmed-txs", "/utxos"}) {
        CheckErr(env.Get("/script/foo/" + P2pkhHex(1) + route), 400,
                 "400: Unknown script type: foo");
        CheckErr(env.Get("/script/p2pkh/0102" + route), 400,
                 "400: Invalid payload for P2PKH: Invalid length, expected "
                 "20 bytes but got 2 bytes");
        CheckErr(env.Get("/script/p2sh/01" + route), 400,
                 "400: Invalid payload for P2SH: Invalid length, expected 20 "
                 "bytes but got 1 bytes");
        // hex is parsed before the script type
        CheckErr(env.Get("/script/foo/zz" + route), 400,
                 "400: Invalid hex: Invalid character 'z' at position 0");
        CheckErr(env.Get("/script/p2pkh/012" + route), 400,
                 "400: Invalid hex: Odd number of digits");
        CheckErr(env.Get("/script/scripthash/zz" + route), 400,
                 "400: Unable to parse script hash \"zz\"");
        CheckErr(env.Get("/script/scripthash/" + P2pkhHex(1) + route), 400,
                 "400: Unable to parse script hash \"" + P2pkhHex(1) + "\"");
        CheckErr(env.Get("/script/scripthash/" + UNKNOWN_TXID + route), 400,
                 "400: Script hash index disabled");
    }
    // P2PK and other
    page = Decode<proto::TxHistoryPage>(
        env.Get("/script/p2pk/" + HexEncode(Bytes(33, 2)) + "/history"));
    BOOST_CHECK_EQUAL(page.num_txs(), 0u);
    CheckErr(env.Get("/script/p2pk/0102/history"), 400,
             "400: Invalid payload for P2PK: Invalid length, expected one of "
             "[33, 65] but got 2 bytes");
    page = Decode<proto::TxHistoryPage>(env.Get("/script/other/51/history"));
    BOOST_CHECK_EQUAL(page.num_txs(), 0u);
}

BOOST_AUTO_TEST_CASE(script_utxos_route) {
    Env env("query-script-utxos");
    // Script 1: A:1 spent by B, C:0 in the mempool
    auto utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(1) + "/utxos"));
    BOOST_CHECK_EQUAL(utxos.script(), Str(th::P2pkh(1)));
    BOOST_REQUIRE_EQUAL(utxos.utxos_size(), 1);
    BOOST_CHECK_EQUAL(utxos.utxos(0).outpoint().txid(), Str(env.c->txid));
    BOOST_CHECK_EQUAL(utxos.utxos(0).outpoint().out_idx(), 0u);
    BOOST_CHECK_EQUAL(utxos.utxos(0).block_height(), -1);
    BOOST_CHECK_EQUAL(utxos.utxos(0).sats(), 3800);
    BOOST_CHECK(!utxos.utxos(0).is_coinbase());
    BOOST_CHECK(!utxos.utxos(0).is_final());
    BOOST_CHECK(!utxos.utxos(0).has_token());
    env.host.SetPreconsensus(env.c->txid, true);
    utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(1) + "/utxos"));
    BOOST_CHECK(utxos.utxos(0).is_final());

    // Script 2: B:0 is spent in the mempool => skipped
    utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(2) + "/utxos"));
    BOOST_CHECK_EQUAL(utxos.script(), Str(th::P2pkh(2)));
    BOOST_CHECK_EQUAL(utxos.utxos_size(), 0);

    // Coinbase script: cb1:0, cb2:0
    utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(0xcb) + "/utxos"));
    BOOST_REQUIRE_EQUAL(utxos.utxos_size(), 2);
    std::set<std::pair<std::string, int32_t>> got;
    for (const proto::ScriptUtxo &utxo : utxos.utxos()) {
        BOOST_CHECK(utxo.is_coinbase());
        BOOST_CHECK_EQUAL(utxo.sats(), 5000);
        got.emplace(utxo.outpoint().txid(), utxo.block_height());
    }
    BOOST_CHECK(got == (std::set<std::pair<std::string, int32_t>>{
                           {Str(env.ActiveBlock(1).txs[0].tx->txid), 1},
                           {Str(env.ActiveBlock(2).txs[0].tx->txid), 2}}));
    // Finalized heights are final
    env.ix->OnBlockFinalized(env.ActiveBlock(1).info);
    utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(0xcb) + "/utxos"));
    for (const proto::ScriptUtxo &utxo : utxos.utxos()) {
        BOOST_CHECK_EQUAL(utxo.is_final(), utxo.block_height() == 1);
    }

    // Unknown script: empty
    utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(7) + "/utxos"));
    BOOST_CHECK_EQUAL(utxos.script(), Str(th::P2pkh(7)));
    BOOST_CHECK_EQUAL(utxos.utxos_size(), 0);
}

BOOST_AUTO_TEST_CASE(scripthash_routes) {
    Env env("query-scripthash", /*scripthash=*/true);
    const auto ScriptHashHex = [](const Bytes &script) {
        uint8_t digest[32];
        nt::TestSha256(script, digest);
        return HexEncodeRev(ByteView(digest, 32));
    };
    const std::string s1 = "/script/scripthash/" + ScriptHashHex(th::P2pkh(1));
    auto page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/history"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{env.c->txid, env.b->txid, env.a->txid}));
    page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/confirmed-txs"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{env.a->txid, env.b->txid}));
    page = Decode<proto::TxHistoryPage>(env.Get(s1 + "/unconfirmed-txs"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.c->txid});
    auto utxos = Decode<proto::ScriptUtxos>(env.Get(s1 + "/utxos"));
    BOOST_CHECK_EQUAL(utxos.script(), Str(th::P2pkh(1)));
    BOOST_CHECK_EQUAL(utxos.utxos_size(), 1);
    // Uppercase hex works
    std::string upper = ScriptHashHex(th::P2pkh(1));
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char ch) { return char(std::toupper(ch)); });
    Decode<proto::ScriptUtxos>(
        env.Get("/script/scripthash/" + upper + "/utxos"));

    // Only in the mempool: script 3 of a new mempool tx
    TxRef d = std::make_shared<const Tx>(env.fake.MakeSpend(
        {{OutPoint{env.c->txid, 0}, Coin{env.c->outputs[0], -1, false}}},
        {TxOutput{3700, th::P2pkh(3)}}));
    env.ix->OnTxAddedToMempool(d, env.c_time + 1);
    utxos = Decode<proto::ScriptUtxos>(env.Get(
        "/script/scripthash/" + ScriptHashHex(th::P2pkh(3)) + "/utxos"));
    BOOST_CHECK_EQUAL(utxos.script(), Str(th::P2pkh(3)));
    BOOST_CHECK_EQUAL(utxos.utxos_size(), 1);

    // Unknown script hash
    page = Decode<proto::TxHistoryPage>(
        env.Get("/script/scripthash/" + UNKNOWN_TXID + "/history"));
    BOOST_CHECK_EQUAL(page.num_txs(), 0u);
    page = Decode<proto::TxHistoryPage>(
        env.Get("/script/scripthash/" + UNKNOWN_TXID + "/unconfirmed-txs"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    CheckErr(env.Get("/script/scripthash/" + UNKNOWN_TXID + "/utxos"), 404,
             "404: Script hash \"" + UNKNOWN_TXID + "\" not found");
}

// ---------------------------------------------------------------------------
// Script batch routes
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(script_batch_utxos) {
    Env env("query-batch-utxos");
    proto::ScriptBatchUtxosRequest req;
    auto *scripts = req.mutable_params()->mutable_scripts();
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 1));
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 0xcb));
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 2));
    auto resp = Decode<proto::ScriptBatchUtxosResponse>(
        env.Post("/script/batch/utxos", req));
    BOOST_REQUIRE_EQUAL(resp.rows_size(), 3);
    for (int i = 0; i < 3; ++i) {
        BOOST_CHECK_EQUAL(resp.rows(i).script().script_type(), "p2pkh");
        BOOST_CHECK_EQUAL(resp.rows(i).script().payload(),
                          req.params().scripts(i).payload());
    }
    BOOST_CHECK_EQUAL(resp.rows(0).utxos().script(), Str(th::P2pkh(1)));
    BOOST_CHECK_EQUAL(resp.rows(0).utxos().utxos_size(), 1);
    BOOST_CHECK_EQUAL(resp.rows(1).utxos().utxos_size(), 2);
    BOOST_CHECK_EQUAL(resp.rows(2).utxos().utxos_size(), 0);
    env.host.SetPreconsensus(env.c->txid, true);
    resp = Decode<proto::ScriptBatchUtxosResponse>(
        env.Post("/script/batch/utxos", req));
    BOOST_CHECK(resp.rows(0).utxos().utxos(0).is_final());

    // Errors
    CheckErr(env.Post("/script/batch/utxos", proto::ScriptBatchUtxosRequest{}),
             400, "400: Batch script request must include at least one script");
    proto::ScriptBatchUtxosRequest dup = req;
    *dup.mutable_params()->add_scripts() = MakeScriptRef("p2pkh", Bytes(20, 1));
    CheckErr(env.Post("/script/batch/utxos", dup), 400,
             "400: Duplicate script entries in batch request");
    proto::ScriptBatchUtxosRequest big;
    for (int i = 0; i < 501; ++i) {
        *big.mutable_params()->add_scripts() =
            MakeScriptRef("other", Bytes{uint8_t(i), uint8_t(i >> 8)});
    }
    CheckErr(env.Post("/script/batch/utxos", big), 400,
             "400: Too many scripts in batch: max is 500, got 501");
    big.mutable_params()->mutable_scripts()->RemoveLast();
    BOOST_CHECK_EQUAL(Decode<proto::ScriptBatchUtxosResponse>(
                          env.Post("/script/batch/utxos", big))
                          .rows_size(),
                      500);
    proto::ScriptBatchUtxosRequest bad = req;
    *bad.mutable_params()->add_scripts() = MakeScriptRef("foo", Bytes(20, 5));
    CheckErr(env.Post("/script/batch/utxos", bad), 400,
             "400: Unknown script type: foo");
    bad = req;
    *bad.mutable_params()->add_scripts() = MakeScriptRef("p2sh", Bytes(3, 5));
    CheckErr(env.Post("/script/batch/utxos", bad), 400,
             "400: Invalid payload for P2SH: Invalid length, expected 20 "
             "bytes but got 3 bytes");
    bad = req;
    *bad.mutable_params()->add_scripts() =
        MakeScriptRef("scripthash", Bytes(31, 5));
    CheckErr(env.Post("/script/batch/utxos", bad), 400,
             "400: Unable to parse script hash \"" + HexEncode(Bytes(31, 5)) +
                 "\"");
    bad = req;
    *bad.mutable_params()->add_scripts() =
        MakeScriptRef("scripthash", Bytes(32, 5));
    CheckErr(env.Post("/script/batch/utxos", bad), 400,
             "400: Script hash index disabled");
    // Not protobuf
    HttpRequest raw = MakeRequest("POST", "/script/batch/utxos");
    raw.headers.emplace_back("Content-Type", "application/x-protobuf");
    raw.body = {0xff};
    CheckErr(env.router.Handle(raw), 400,
             "400: Bad protobuf: failed to decode Protobuf message: invalid "
             "varint");
    raw.headers.clear();
    CheckErr(env.router.Handle(raw), 400, "400: No Content-Type set");
}

BOOST_AUTO_TEST_CASE(script_batch_summary) {
    Env env("query-batch-summary");
    proto::ScriptBatchSummaryRequest req;
    auto *scripts = req.mutable_params()->mutable_scripts();
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 1));
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 2));
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 0xcb));
    *scripts->Add() = MakeScriptRef("p2pkh", Bytes(20, 9));
    auto resp = Decode<proto::ScriptBatchSummaryResponse>(
        env.Post("/script/batch/summary", req));
    BOOST_REQUIRE_EQUAL(resp.rows_size(), 4);
    BOOST_CHECK_EQUAL(resp.rows(0).script().payload(), Str(Bytes(20, 1)));
    BOOST_CHECK_EQUAL(resp.rows(0).script().script_type(), "p2pkh");
    BOOST_CHECK_EQUAL(resp.rows(0).num_txs(), 3u);
    BOOST_CHECK_EQUAL(resp.rows(0).num_utxos(), 1u);
    BOOST_CHECK_EQUAL(resp.rows(0).latest_tx().txid(), Str(env.c->txid));
    BOOST_CHECK_EQUAL(resp.rows(1).num_txs(), 2u);
    BOOST_CHECK_EQUAL(resp.rows(1).num_utxos(), 0u);
    BOOST_CHECK_EQUAL(resp.rows(1).latest_tx().txid(), Str(env.c->txid));
    BOOST_CHECK_EQUAL(resp.rows(2).num_txs(), 4u);
    BOOST_CHECK_EQUAL(resp.rows(2).num_utxos(), 2u);
    BOOST_CHECK_EQUAL(resp.rows(2).latest_tx().block().height(), 2);
    BOOST_CHECK_EQUAL(resp.rows(3).num_txs(), 0u);
    BOOST_CHECK_EQUAL(resp.rows(3).num_utxos(), 0u);
    BOOST_CHECK(!resp.rows(3).has_latest_tx());

    CheckErr(
        env.Post("/script/batch/summary", proto::ScriptBatchSummaryRequest{}),
        400, "400: Batch script request must include at least one script");
    proto::ScriptBatchSummaryRequest dup = req;
    *dup.mutable_params()->add_scripts() = MakeScriptRef("p2pkh", Bytes(20, 2));
    CheckErr(env.Post("/script/batch/summary", dup), 400,
             "400: Duplicate script entries in batch request");
    proto::ScriptBatchSummaryRequest big;
    for (int i = 0; i < 501; ++i) {
        *big.mutable_params()->add_scripts() =
            MakeScriptRef("other", Bytes{uint8_t(i), uint8_t(i >> 8)});
    }
    CheckErr(env.Post("/script/batch/summary", big), 400,
             "400: Too many scripts in batch: max is 500, got 501");
    proto::ScriptBatchSummaryRequest bad = req;
    *bad.mutable_params()->add_scripts() = MakeScriptRef("bar", Bytes(20, 5));
    CheckErr(env.Post("/script/batch/summary", bad), 400,
             "400: Unknown script type: bar");
    bad = req;
    *bad.mutable_params()->add_scripts() =
        MakeScriptRef("scripthash", Bytes(32, 5));
    CheckErr(env.Post("/script/batch/summary", bad), 400,
             "400: Script hash index disabled");
}

// ---------------------------------------------------------------------------
// LOKAD ID and token ID groups
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(lokad_id_routes) {
    Env env("query-lokad");
    const std::string base =
        "/lokad-id/" + HexEncode(ByteView(LOKAD.data(), LOKAD.size()));
    auto page = Decode<proto::TxHistoryPage>(env.Get(base + "/history"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.a->txid});
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/confirmed-txs"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{env.a->txid});
    BOOST_CHECK_EQUAL(page.num_pages(), 1u);
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/unconfirmed-txs"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    BOOST_CHECK_EQUAL(page.num_pages(), 0u);
    page = Decode<proto::TxHistoryPage>(env.Get("/lokad-id/00000000/history"));
    BOOST_CHECK_EQUAL(page.num_txs(), 0u);

    for (const std::string route :
         {"/history", "/confirmed-txs", "/unconfirmed-txs"}) {
        CheckErr(env.Get("/lokad-id/0102" + route), 400,
                 "400: Invalid LOKAD ID length: expected 4 but got 2");
        CheckErr(env.Get("/lokad-id/zz" + route), 400,
                 "400: Invalid hex: Invalid character 'z' at position 0");
    }
    CheckErr(env.Get(base + "/history?page_size=0"), 400,
             "400: Requested page size 0 is too small, minimum is 1");
    CheckErr(env.Get(base + "/confirmed-txs?page_size=1000"), 400,
             "400: Requested page size 1000 is too big, maximum is 200");
    // LOKAD ID is parsed before the params
    CheckErr(env.Get("/lokad-id/01/history?page=x"), 400,
             "400: Invalid LOKAD ID length: expected 4 but got 1");
    CheckErr(env.Get(base + "/history?page=x"), 400,
             "400: Invalid param page: x, invalid digit found in string");
    // No utxos route for LOKAD IDs
    CheckErr(env.Get(base + "/utxos"), 404,
             "404: Not found: " + base + "/utxos");
}

BOOST_AUTO_TEST_CASE(token_id_routes_without_tokens) {
    Env env("query-token-id-none");
    const std::string base = "/token-id/" + UNKNOWN_TXID;
    for (const std::string route :
         {"/history", "/confirmed-txs", "/unconfirmed-txs"}) {
        auto page = Decode<proto::TxHistoryPage>(env.Get(base + route));
        BOOST_CHECK_EQUAL(page.txs_size(), 0);
        BOOST_CHECK_EQUAL(page.num_txs(), 0u);
    }
    BOOST_CHECK_EQUAL(
        Decode<proto::Utxos>(env.Get(base + "/utxos")).utxos_size(), 0);
    // TokenId parse errors are unprefixed (500)
    for (const std::string route :
         {"/history", "/confirmed-txs", "/unconfirmed-txs", "/utxos"}) {
        CheckErr(env.Get("/token-id/zz" + route), 500,
                 "Unknown error, contact admins");
        CheckErr(env.Get("/token-id/0102" + route), 500,
                 "Unknown error, contact admins");
    }
    // Token ID is parsed before the params
    CheckErr(env.Get("/token-id/zz/history?page=x"), 500,
             "Unknown error, contact admins");
    CheckErr(env.Get(base + "/history?page=x"), 400,
             "400: Invalid param page: x, invalid digit found in string");
    CheckErr(env.Get(base + "/confirmed-txs?page_size=0"), 400,
             "400: Requested page size 0 is too small, minimum is 1");
}

BOOST_AUTO_TEST_CASE(token_routes) {
    TokenFactoryGuard guard;
    token_io::RegisterEcashTokenIndex();
    Env env("query-tokens", false, /*tokens=*/true);
    BOOST_REQUIRE(env.ix->Impl().IsTokenIndexEnabled());
    // GENESIS in block 3, with C confirmed
    const Tx &cb2 = *env.ActiveBlock(2).txs[0].tx;
    TxRef genesis = std::make_shared<const Tx>(env.fake.MakeSpend(
        {{OutPoint{cb2.txid, 0}, Coin{cb2.outputs[0], 2, true}}},
        {TxOutput{0, SlpGenesisScript()}, TxOutput{546, th::P2pkh(4)},
         TxOutput{4000, th::P2pkh(4)}}));
    Block block3 = env.fake.MakeBlock(2, {*env.c, *genesis});
    env.fake.Extend(block3);
    env.ix->OnBlockConnected(block3);
    const std::string token_id = Hex(genesis->txid);

    auto info = Decode<proto::TokenInfo>(env.Get("/token/" + token_id));
    BOOST_CHECK_EQUAL(info.token_id(), token_id);
    BOOST_CHECK_EQUAL(info.token_type().slp(), proto::SLP_TOKEN_TYPE_FUNGIBLE);
    BOOST_CHECK_EQUAL(info.genesis_info().token_ticker(), "TST");
    BOOST_CHECK_EQUAL(info.genesis_info().token_name(), "Test");
    BOOST_CHECK_EQUAL(info.genesis_info().decimals(), 0u);
    BOOST_CHECK_EQUAL(info.block().height(), 3);
    BOOST_CHECK_EQUAL(info.block().hash(), Str(block3.info.hash));
    CheckErr(env.Get("/token/" + Hex(env.a->txid)), 404,
             "404: Token " + Hex(env.a->txid) + " not found in the index");

    auto tx = Decode<proto::Tx>(env.Get("/tx/" + token_id));
    BOOST_CHECK_EQUAL(tx.token_status(), proto::TOKEN_STATUS_NORMAL);
    BOOST_REQUIRE_EQUAL(tx.token_entries_size(), 1);
    BOOST_CHECK_EQUAL(tx.token_entries(0).token_id(), token_id);
    BOOST_CHECK_EQUAL(tx.token_entries(0).tx_type(), proto::GENESIS);
    BOOST_CHECK_EQUAL(tx.outputs(1).token().atoms(), 1000u);
    BOOST_CHECK_EQUAL(tx.outputs(1).token().token_id(), token_id);
    BOOST_CHECK(!tx.outputs(2).has_token());

    const std::string base = "/token-id/" + token_id;
    auto page = Decode<proto::TxHistoryPage>(env.Get(base + "/history"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{genesis->txid});
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/confirmed-txs"));
    BOOST_CHECK(PageTxids(page) == std::vector<TxId>{genesis->txid});
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/unconfirmed-txs"));
    BOOST_CHECK_EQUAL(page.txs_size(), 0);
    auto utxos = Decode<proto::Utxos>(env.Get(base + "/utxos"));
    BOOST_REQUIRE_EQUAL(utxos.utxos_size(), 1);
    BOOST_CHECK_EQUAL(utxos.utxos(0).outpoint().txid(), Str(genesis->txid));
    BOOST_CHECK_EQUAL(utxos.utxos(0).outpoint().out_idx(), 1u);
    BOOST_CHECK_EQUAL(utxos.utxos(0).script(), Str(th::P2pkh(4)));
    BOOST_CHECK_EQUAL(utxos.utxos(0).block_height(), 3);
    BOOST_CHECK_EQUAL(utxos.utxos(0).token().atoms(), 1000u);
    auto script_utxos = Decode<proto::ScriptUtxos>(
        env.Get("/script/p2pkh/" + P2pkhHex(4) + "/utxos"));
    BOOST_REQUIRE_EQUAL(script_utxos.utxos_size(), 2);

    // Mempool token tx: SEND of 1000 atoms to output 1
    Bytes send_script = {0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01, 0x01,
                         0x04, 'S',  'E', 'N', 'D', 0x20};
    const auto token_id_be = genesis->txid.Reversed();
    send_script.insert(send_script.end(), token_id_be.begin(),
                       token_id_be.end());
    for (uint8_t byte : {0x08, 0, 0, 0, 0, 0, 0, 0x03, 0xe8}) {
        send_script.push_back(byte);
    }
    TxRef send = std::make_shared<const Tx>(env.fake.MakeSpend(
        {{OutPoint{genesis->txid, 1}, Coin{genesis->outputs[1], 3, false}}},
        {TxOutput{0, send_script}, TxOutput{500, th::P2pkh(5)}}));
    env.ix->OnTxAddedToMempool(send, env.c_time + 10);
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/history"));
    BOOST_CHECK(PageTxids(page) ==
                (std::vector<TxId>{send->txid, genesis->txid}));
    page = Decode<proto::TxHistoryPage>(env.Get(base + "/unconfirmed-txs"));
    BOOST_REQUIRE(PageTxids(page) == std::vector<TxId>{send->txid});
    BOOST_CHECK_EQUAL(page.txs(0).inputs(0).token().atoms(), 1000u);
    BOOST_CHECK_EQUAL(page.txs(0).outputs(1).token().atoms(), 1000u);
    BOOST_CHECK_EQUAL(page.txs(0).token_status(), proto::TOKEN_STATUS_NORMAL);
    utxos = Decode<proto::Utxos>(env.Get(base + "/utxos"));
    BOOST_REQUIRE_EQUAL(utxos.utxos_size(), 1);
    BOOST_CHECK_EQUAL(utxos.utxos(0).outpoint().txid(), Str(send->txid));
    BOOST_CHECK_EQUAL(utxos.utxos(0).block_height(), -1);
    BOOST_CHECK_EQUAL(utxos.utxos(0).token().atoms(), 1000u);
    // The genesis output is spent in the mempool
    tx = Decode<proto::Tx>(env.Get("/tx/" + token_id));
    BOOST_CHECK_EQUAL(tx.outputs(1).spent_by().txid(), Str(send->txid));

    // validate-tx of a burn: token data, not normal
    Tx burn = env.fake.MakeSpend(
        {{OutPoint{send->txid, 1}, Coin{send->outputs[1], -1, false}}},
        {TxOutput{400, th::P2pkh(6)}});
    env.host.SetExtraCoin(OutPoint{send->txid, 1},
                          Coin{send->outputs[1], -1, false});
    const Bytes burn_raw = env.host.AddRawTx(burn);
    proto::RawTx raw_req;
    raw_req.set_raw_tx(Str(burn_raw));
    auto validated = Decode<proto::Tx>(env.Post("/validate-tx", raw_req));
    BOOST_CHECK_EQUAL(validated.txid(), Str(burn.txid));
    BOOST_CHECK_EQUAL(validated.token_status(),
                      proto::TOKEN_STATUS_NOT_NORMAL);
    BOOST_CHECK_EQUAL(validated.inputs(0).token().atoms(), 1000u);
    BOOST_CHECK_EQUAL(validated.inputs(0).sats(), 500);

    // broadcast of the burn fails the token checks
    proto::BroadcastTxRequest bc;
    bc.set_raw_tx(Str(burn_raw));
    const std::string burn_err = "400: Tx " + Hex(burn.txid) +
                                 " failed token checks: Unexpected burn: "
                                 "Burns 1000 atoms.";
    CheckErr(env.Post("/broadcast-tx", bc), 400, burn_err);
    BOOST_CHECK(env.host.broadcast.empty());
    BOOST_CHECK_EQUAL(env.host.sync_calls, 1);
    // ... unless skipped
    bc.set_skip_token_checks(true);
    auto bc_resp =
        Decode<proto::BroadcastTxResponse>(env.Post("/broadcast-tx", bc));
    BOOST_CHECK_EQUAL(bc_resp.txid(), Str(burn.txid));
    BOOST_CHECK_EQUAL(env.host.sync_calls, 2);

    // Token checks decode the txs: decoding errors
    bc.set_skip_token_checks(false);
    bc.set_raw_tx("garbage");
    CheckErr(env.Post("/broadcast-tx", bc), 400,
             "400: Parsing tx failed TX decode failed");
    BOOST_CHECK_EQUAL(env.host.sync_calls, 3);
    // Without token checks the node reports the error
    bc.set_skip_token_checks(true);
    CheckErr(env.Post("/broadcast-tx", bc), 400,
             "400: Broadcast failed: TX decode failed");

    // Two burns in one batch: messages are joined with a space
    Tx burn2 = env.fake.MakeSpend(
        {{OutPoint{genesis->txid, 2}, Coin{genesis->outputs[2], 3, false}},
         {OutPoint{send->txid, 1}, Coin{send->outputs[1], -1, false}}},
        {TxOutput{100, th::P2pkh(6)}});
    proto::BroadcastTxsRequest bcs;
    bcs.add_raw_txs(Str(burn_raw));
    bcs.add_raw_txs(Str(env.host.AddRawTx(burn2)));
    CheckErr(env.Post("/broadcast-txs", bcs), 400,
             burn_err + " Tx " + Hex(burn2.txid) +
                 " failed token checks: Unexpected burn: Burns 1000 atoms.");
    // A decode error at tx 1 is reported after the token checks of tx 0
    bcs.add_raw_txs("garbage");
    CheckErr(env.Post("/broadcast-txs", bcs), 400,
             "400: Parsing tx failed TX decode failed");
}

// ---------------------------------------------------------------------------
// validate-tx / broadcast
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(validate_tx) {
    Env env("query-validate");
    Tx d = env.fake.MakeSpend(
        {{OutPoint{env.c->txid, 0}, Coin{env.c->outputs[0], -1, false}},
         {OutPoint{env.ActiveBlock(1).txs[0].tx->txid, 0}, Coin{}},
         {OutPoint{Hash32{}, 7}, Coin{}}},
        {TxOutput{3000, th::P2pkh(8)}});
    env.host.SetExtraCoin(OutPoint{env.c->txid, 0},
                          Coin{env.c->outputs[0], -1, false});
    proto::RawTx req;
    req.set_raw_tx(Str(env.host.AddRawTx(d)));
    auto tx = Decode<proto::Tx>(env.Post("/validate-tx", req));
    BOOST_CHECK_EQUAL(tx.txid(), Str(d.txid));
    BOOST_REQUIRE_EQUAL(tx.inputs_size(), 3);
    BOOST_CHECK_EQUAL(tx.inputs(0).sats(), 3800);
    BOOST_CHECK_EQUAL(tx.inputs(0).output_script(), Str(th::P2pkh(1)));
    BOOST_CHECK_EQUAL(tx.inputs(1).sats(), 5000);
    // Missing coin => default coin
    BOOST_CHECK_EQUAL(tx.inputs(2).sats(), 0);
    BOOST_CHECK(tx.inputs(2).output_script().empty());
    BOOST_CHECK(!tx.has_block());
    BOOST_CHECK_EQUAL(tx.time_first_seen(), 0);
    BOOST_CHECK(!tx.is_final());
    BOOST_CHECK(!tx.outputs(0).has_spent_by());
    BOOST_CHECK_EQUAL(tx.token_status(), proto::TOKEN_STATUS_NON_TOKEN);
    // Looked-up coins are uncached
    BOOST_CHECK_EQUAL(env.host.uncached.size(), 1u);
    // Decoding errors are unprefixed
    req.set_raw_tx("junk");
    CheckErr(env.Post("/validate-tx", req), 500,
             "Unknown error, contact admins");
}

BOOST_AUTO_TEST_CASE(broadcast_tx) {
    Env env("query-broadcast");
    Tx d = env.fake.MakeSpend(
        {{OutPoint{env.c->txid, 0}, Coin{env.c->outputs[0], -1, false}}},
        {TxOutput{3000, th::P2pkh(8)}});
    Tx e = env.fake.MakeSpend(
        {{OutPoint{d.txid, 0}, Coin{d.outputs[0], -1, false}}},
        {TxOutput{2000, th::P2pkh(9)}});
    const Bytes d_raw = env.host.AddRawTx(d);
    const Bytes e_raw = env.host.AddRawTx(e);

    proto::BroadcastTxRequest req;
    req.set_raw_tx(Str(d_raw));
    auto resp =
        Decode<proto::BroadcastTxResponse>(env.Post("/broadcast-tx", req));
    BOOST_CHECK_EQUAL(resp.txid(), Str(d.txid));
    BOOST_CHECK(env.host.broadcast == std::vector<TxId>{d.txid});
    BOOST_CHECK_EQUAL(env.host.sync_calls, 1);

    proto::BroadcastTxsRequest reqs;
    reqs.add_raw_txs(Str(d_raw));
    reqs.add_raw_txs(Str(e_raw));
    auto resps =
        Decode<proto::BroadcastTxsResponse>(env.Post("/broadcast-txs", reqs));
    BOOST_REQUIRE_EQUAL(resps.txids_size(), 2);
    BOOST_CHECK_EQUAL(resps.txids(0), Str(d.txid));
    BOOST_CHECK_EQUAL(resps.txids(1), Str(e.txid));
    BOOST_CHECK_EQUAL(env.host.sync_calls, 2);
    // Empty batch: no txids
    BOOST_CHECK_EQUAL(
        Decode<proto::BroadcastTxsResponse>(
            env.Post("/broadcast-txs", proto::BroadcastTxsRequest{}))
            .txids_size(),
        0);
    BOOST_CHECK_EQUAL(env.host.sync_calls, 3);

    // Node rejection; sync still happens, coins are uncached
    env.host.SetBroadcastError("bad-txns-inputs-missingorspent");
    CheckErr(env.Post("/broadcast-tx", req), 400,
             "400: Broadcast failed: bad-txns-inputs-missingorspent");
    BOOST_CHECK_EQUAL(env.host.sync_calls, 4);
    CheckErr(env.Post("/broadcast-txs", reqs), 400,
             "400: Broadcast failed: bad-txns-inputs-missingorspent");
    BOOST_CHECK_EQUAL(env.host.sync_calls, 5);
    env.host.SetBroadcastError(std::nullopt);

    // Finalization timeout limits: checked before broadcasting/syncing
    req.set_finalization_timeout_secs(121);
    CheckErr(env.Post("/broadcast-tx", req), 400,
             "400: Finalization timeout of 121s exceeds maximum of 120s");
    reqs.set_finalization_timeout_secs(1000);
    CheckErr(env.Post("/broadcast-txs", reqs), 400,
             "400: Finalization timeout of 1000s exceeds maximum of 120s");
    BOOST_CHECK_EQUAL(env.host.sync_calls, 5);

    // Not finalized within the timeout
    req.set_finalization_timeout_secs(1);
    CheckErr(env.Post("/broadcast-tx", req), 504,
             "504: Transaction(s) failed to finalize within 1s");
    // The txid subscriptions are released afterwards
    BOOST_CHECK(!HasTxIdSubs(env));

    // Finalized while waiting (the node indexes the txs on sync)
    std::vector<TxRef> to_index = {std::make_shared<const Tx>(d),
                                   std::make_shared<const Tx>(e)};
    env.host.on_sync = [&] {
        BOOST_CHECK(HasTxIdSubs(env));
        for (const TxRef &tx : to_index) {
            env.ix->OnTxAddedToMempool(tx, env.c_time + 5);
            env.ix->OnTxFinalized(tx->txid);
        }
        to_index.clear();
    };
    reqs.set_finalization_timeout_secs(120);
    resps =
        Decode<proto::BroadcastTxsResponse>(env.Post("/broadcast-txs", reqs));
    BOOST_CHECK_EQUAL(resps.txids_size(), 2);
    BOOST_CHECK(!HasTxIdSubs(env));
    // Without a timeout nothing is subscribed
    env.host.on_sync = [&] { BOOST_CHECK(!HasTxIdSubs(env)); };
    req.set_finalization_timeout_secs(0);
    Decode<proto::BroadcastTxResponse>(env.Post("/broadcast-tx", req));
}

// ---------------------------------------------------------------------------
// Plugins (none loaded)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(plugin_routes) {
    Env env("query-plugins");
    for (const std::string route :
         {"/utxos", "/confirmed-txs", "/history", "/unconfirmed-txs"}) {
        CheckErr(env.Get("/plugin/foo/00ff" + route), 404,
                 "404: Plugin \"foo\" not loaded");
        CheckErr(env.Get("/plugin/foo/zz" + route), 400,
                 "400: Invalid hex: Invalid character 'z' at position 0");
        CheckErr(env.Get("/plugin/foo/0" + route), 400,
                 "400: Invalid hex: Odd number of digits");
        CheckErr(env.Get("/plugin/fo%22o/00" + route), 404,
                 "404: Plugin \"fo\\\"o\" not loaded");
    }
    // Page params are only parsed by the paged routes, after the group
    CheckErr(env.Get("/plugin/foo/00/history?page=x"), 400,
             "400: Invalid param page: x, invalid digit found in string");
    CheckErr(env.Get("/plugin/foo/00/confirmed-txs?page_size=x"), 400,
             "400: Invalid param page_size: x, invalid digit found in string");
    CheckErr(env.Get("/plugin/foo/zz/history?page=x"), 400,
             "400: Invalid hex: Invalid character 'z' at position 0");
    CheckErr(env.Get("/plugin/foo/00/unconfirmed-txs?page=x"), 404,
             "404: Plugin \"foo\" not loaded");
    CheckErr(env.Get("/plugin/foo/00/utxos?page=x"), 404,
             "404: Plugin \"foo\" not loaded");
    // Page size is not checked before the plugin lookup
    CheckErr(env.Get("/plugin/foo/00/history?page_size=0"), 404,
             "404: Plugin \"foo\" not loaded");

    // groups
    CheckErr(env.Get("/plugin/foo/groups"), 404,
             "404: Plugin \"foo\" not loaded");
    CheckErr(env.Get("/plugin/foo/groups?prefix=01&start=0102"), 404,
             "404: Plugin \"foo\" not loaded");
    auto groups = Decode<proto::PluginGroups>(
        env.Get("/plugin/foo/groups?prefix=01&start=02"));
    BOOST_CHECK_EQUAL(groups.groups_size(), 0);
    BOOST_CHECK(groups.next_start().empty());
    BOOST_CHECK(env.Get("/plugin/foo/groups?prefix=01&start=02").body.empty());
    Decode<proto::PluginGroups>(
        env.Get("/plugin/foo/groups?prefix=0102&start=01"));
    CheckErr(env.Get("/plugin/foo/groups?page_size=0"), 400,
             "400: Requested page size 0 is too small, minimum is 1");
    CheckErr(env.Get("/plugin/foo/groups?page_size=51"), 400,
             "400: Requested page size 51 is too big, maximum is 50");
    CheckErr(env.Get("/plugin/foo/groups?page_size=50"), 404,
             "404: Plugin \"foo\" not loaded");
    CheckErr(env.Get("/plugin/foo/groups?page_size=x"), 400,
             "400: Invalid param page_size: x, invalid digit found in string");
    CheckErr(env.Get("/plugin/foo/groups?prefix=zz"), 400,
             "400: Invalid hex: Invalid character 'z' at position 0");
    CheckErr(env.Get("/plugin/foo/groups?start=1"), 400,
             "400: Invalid hex: Odd number of digits");
    // page_size is parsed first
    CheckErr(env.Get("/plugin/foo/groups?prefix=zz&page_size=x"), 400,
             "400: Invalid param page_size: x, invalid digit found in string");
    // The short-circuit happens before the page size check
    Decode<proto::PluginGroups>(
        env.Get("/plugin/foo/groups?prefix=01&start=02&page_size=0"));
}

// ---------------------------------------------------------------------------
// Route table
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(route_table) {
    Env env("query-route-table");
    // GET routes reject POST with "GET,HEAD"
    for (const std::string target :
         {"/block/0", "/block-header/0", "/block-txs/0", "/blocks/0/1",
          "/block-headers/0/1", "/unconfirmed-txs", "/tx/00", "/token/00",
          "/raw-tx/00", "/script/p2pkh/00/confirmed-txs",
          "/script/p2pkh/00/history", "/script/p2pkh/00/unconfirmed-txs",
          "/script/p2pkh/00/utxos", "/token-id/00/confirmed-txs",
          "/token-id/00/history", "/token-id/00/unconfirmed-txs",
          "/token-id/00/utxos", "/lokad-id/00/confirmed-txs",
          "/lokad-id/00/history", "/lokad-id/00/unconfirmed-txs",
          "/plugin/a/00/utxos", "/plugin/a/00/confirmed-txs",
          "/plugin/a/00/history", "/plugin/a/00/unconfirmed-txs",
          "/plugin/a/groups", "/blockchain-info", "/chronik-info"}) {
        BOOST_TEST_CONTEXT(target) {
            HttpResponse r = env.router.Handle(MakeRequest("POST", target));
            BOOST_CHECK_EQUAL(r.status, 405);
            BOOST_REQUIRE(r.Header("Allow"));
            BOOST_CHECK_EQUAL(*r.Header("Allow"), "GET,HEAD");
            const HttpResponse get = env.Get(target);
            BOOST_CHECK_NE(get.status, 405);
            if (get.status == 404) {
                // Only "not loaded" 404s, never a missing route
                BOOST_CHECK_EQUAL(ErrMsg(get),
                                  "404: Plugin \"a\" not loaded");
            }
        }
    }
    // POST routes: "POST,OPTIONS" and handle_post_options
    for (const std::string target :
         {"/validate-tx", "/broadcast-tx", "/broadcast-txs",
          "/script/batch/utxos", "/script/batch/summary"}) {
        BOOST_TEST_CONTEXT(target) {
            HttpResponse r = env.Get(target);
            BOOST_CHECK_EQUAL(r.status, 405);
            BOOST_REQUIRE(r.Header("Allow"));
            BOOST_CHECK_EQUAL(*r.Header("Allow"), "POST,OPTIONS");
            r = env.router.Handle(MakeRequest("OPTIONS", target));
            BOOST_CHECK_EQUAL(r.status, 200);
            BOOST_REQUIRE(r.Header("Allow"));
            BOOST_CHECK_EQUAL(*r.Header("Allow"), "OPTIONS, HEAD, POST");
        }
    }
    // HEAD on a GET route has the GET's length and no body
    HttpResponse head = env.router.Handle(MakeRequest("HEAD", "/block/0"));
    BOOST_CHECK_EQUAL(head.status, 200);
    BOOST_CHECK(head.body.empty());
    BOOST_CHECK_EQUAL(*head.Header("content-length"),
                      std::to_string(env.Get("/block/0").body.size()));
    // Unknown routes
    CheckErr(env.Get("/script/p2pkh/00"), 404,
             "404: Not found: /script/p2pkh/00");
    CheckErr(env.Get("/blocks/0"), 404, "404: Not found: /blocks/0");
    CheckErr(env.Get("/script/batch/foo"), 404,
             "404: Not found: /script/batch/foo");
    CheckErr(env.Get("/plugin/a/groups/x"), 404,
             "404: Not found: /plugin/a/groups/x");
}

BOOST_AUTO_TEST_SUITE_END()
