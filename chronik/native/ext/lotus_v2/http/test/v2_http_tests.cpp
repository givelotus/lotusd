// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-http/src/v2.rs tests, through the native router.

#include <ext/lotus_v2/http/test/v2_http_test_util.h>
#include <ext/lotus_v2/http/util.h>

#include <boost/test/unit_test.hpp>

#include <condition_variable>
#include <thread>

using chronik::native::Bytes;
using chronik::native::HttpResponse;
using chronik::native::Router;
using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::http;
using namespace chronik::native::lotus_v2::http::test;

namespace {

const Anchor kParent{B32(2), 0};
const Anchor kChild{B32(6), 1};

TxLocation Loc(const Bytes32 &block, uint64_t height, uint8_t id) {
    return TxLocation{H(block), height, 0, TxId{Fill(id)},
                      TxHash{Fill(uint8_t(id + 1))}};
}

Output TestOutputMax() {
    Output o;
    o.value = UINT64_MAX;
    o.branches = {Fill(9)};
    o.paths = {{0}};
    return o;
}

ExplorerTxFacts Facts(const std::vector<OutPoint> &spends) {
    ExplorerTxFacts f;
    f.wire = {0};
    for (const OutPoint &op : spends) {
        InputFact i;
        i.prev_txid = op.txid.hash.b;
        i.prev_index = op.out_idx;
        i.flags = 1;
        i.witnesses = {FixtureWitness()};
        f.inputs.push_back(std::move(i));
    }
    return f;
}

struct Fixture : RouterFixture {
    V2TempDir dir{"http"};
    Fixture() {
        auto db = std::make_shared<SharedV2Db>(dir.path, TestBinding());
        db->db.InitializeGenesis(CommittedBlock{
            kParent,
            kParent,
            {ConfirmedTx{Loc(B32(2), 0, 4),
                         {TestOutputMax(), TestOutputMax()},
                         {},
                         Facts({})}},
            FixtureHeader(kParent, kParent)});
        std::array<uint8_t, 16> epoch;
        epoch.fill(1);
        *state = MakeState(db, epoch);
        state->node_anchor = FixedAnchor(Stamp(2, 1, kParent));
    }
};

std::string Request(size_t page, std::optional<std::string> cursor) {
    return "{\"any_branch\":[\"" + HexFill(9) +
           "\"],\"page_size\":" + std::to_string(page) +
           ",\"cursor\":" + (cursor ? "\"" + *cursor + "\"" : "null") + "}";
}

HttpResponse Branches(const Router &r, const std::string &body,
                      bool history) {
    return Call(r, "POST",
                history ? "/v2/branches/outputs" : "/v2/branches/utxos", body);
}

HttpResponse UtxoCall(const Router &r, const std::string &idx) {
    return Call(r, "GET", "/v2/utxos/" + HexFill(4) + "/" + idx);
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_http_tests)

BOOST_AUTO_TEST_CASE(actual_db_output_paging_spends_reorg_and_stale_cursor) {
    Fixture f;
    const Router r = f.MakeRouter();
    const JsonNode p = Value(Branches(r, Request(1, std::nullopt), true));
    BOOST_CHECK_EQUAL(Len(At(p, "outputs")), 1u);
    BOOST_CHECK_EQUAL(Str(At(p, "outputs", 0, "record", "value")),
                      std::to_string(UINT64_MAX));
    const std::string cursor = Str(At(p, "cursor"));
    const JsonNode second = Value(Branches(r, Request(1, cursor), true));
    BOOST_CHECK_EQUAL(Num(At(second, "outputs", 0, "record", "out_idx")), 1u);

    const OutPoint op{TxId{Fill(4)}, 0};
    f.state->db->db.Connect(CommittedBlock{
        kChild,
        kParent,
        {ConfirmedTx{Loc(B32(6), 1, 7), {}, {SpentInput{op, 0}}, Facts({op})}},
        FixtureHeader(kChild, kParent)});
    f.state->node_anchor = FixedAnchor(Stamp(2, 2, kChild));
    BOOST_CHECK_EQUAL(Branches(r, Request(1, cursor), true).status, 409);
    const JsonNode history = Value(Branches(r, Request(100, std::nullopt), true));
    BOOST_CHECK(At(history, "outputs", 0, "record", "spend")->kind ==
                JsonNode::Kind::Obj);
    const JsonNode coins = Value(Branches(r, Request(100, std::nullopt), false));
    BOOST_CHECK_EQUAL(Len(At(coins, "outputs")), 1u);

    f.state->db->db.Disconnect(kChild);
    f.state->node_anchor = FixedAnchor(Stamp(2, 3, kParent));
    const JsonNode coins2 =
        Value(Branches(r, Request(100, std::nullopt), false));
    BOOST_CHECK_EQUAL(Len(At(coins2, "outputs")), 2u);
    BOOST_CHECK(Bool(At(Value(Call(r, "GET", "/v2/status")), "ready")));
    f.state->node_anchor = FixedAnchor(Stamp(2, 1, kParent));
    BOOST_CHECK(Bool(At(Value(Call(r, "GET", "/v2/status")), "ready")));
    f.state->node_anchor = FixedAnchor(Stamp(2, 2, kChild));
    BOOST_CHECK(!Bool(At(Value(Call(r, "GET", "/v2/status")), "ready")));
}

BOOST_AUTO_TEST_CASE(rejects_malformed_unknown_and_caps_before_queries) {
    Fixture f;
    const Router r = f.MakeRouter();
    for (const std::string s :
         {"{", "{\"unknown\":1}", "{\"any_branch\":[\"zz\"]}",
          "{\"page_size\":101}",
          "{\"positions\":[{\"position\":256,\"roots\":[]}]}",
          "{\"cursor\":\"00\"}"}) {
        BOOST_CHECK_MESSAGE(Branches(r, s, true).status == 400, s);
    }
    const HttpResponse big = Branches(r, std::string(32 * 1024 + 1, ' '), true);
    BOOST_CHECK_EQUAL(big.status, 413);
    BOOST_CHECK_EQUAL(BodyStr(big), "{\"error\":\"request_limit\"}");
    BOOST_CHECK_EQUAL(UtxoCall(r, "4294967296").status, 400);
    BOOST_CHECK_EQUAL(UtxoCall(r, "0").status, 200);
}

BOOST_AUTO_TEST_CASE(error_codes_and_canonical_outpoints) {
    Fixture f;
    const Router r = f.MakeRouter();
    auto code = [&](const HttpResponse &resp) {
        return BodyStr(resp);
    };
    BOOST_CHECK_EQUAL(code(Branches(r, "{\"any_branch\":[\"zz\"]}", true)),
                      "{\"error\":\"invalid_hex\"}");
    BOOST_CHECK_EQUAL(code(Branches(r, "{\"page_size\":0}", true)),
                      "{\"error\":\"invalid_limits\"}");
    BOOST_CHECK_EQUAL(code(Branches(r, "{\"include_burn\":true}", false)),
                      "{\"error\":\"invalid_limits\"}");
    BOOST_CHECK_EQUAL(code(Branches(r, "{\"cursor\":\"00\"}", true)),
                      "{\"error\":\"invalid_cursor\"}");
    BOOST_CHECK_EQUAL(code(Branches(r, "{\"page_size\":1.0}", true)),
                      "{\"error\":\"invalid_request\"}");
    // Uppercase hex is accepted by v2.rs (not by the explorer).
    const std::string upper = "{\"any_branch\":[\"" +
                              std::string(64, 'F') + "\"]}";
    BOOST_CHECK_EQUAL(Branches(r, upper, true).status, 200);
    // Struct sequences are serde-valid requests.
    BOOST_CHECK_EQUAL(
        Branches(r, "[[\"" + HexFill(9) + "\"],[],null,100,false]", true)
            .status,
        200);
    for (const char *idx : {"+0", "00", "-0", "1x"}) {
        BOOST_CHECK_EQUAL(code(UtxoCall(r, idx)),
                          "{\"error\":\"invalid_outpoint\"}");
    }
    const HttpResponse missing = UtxoCall(r, "7");
    BOOST_CHECK_EQUAL(missing.status, 404);
    BOOST_CHECK_EQUAL(code(missing), "{\"error\":\"utxo_not_found\"}");
    BOOST_CHECK_EQUAL(missing.ContentType(), "application/json");
    BOOST_CHECK(!missing.Header("cache-control"));
}

BOOST_AUTO_TEST_CASE(router_uses_versioned_routes_without_network) {
    Fixture f;
    const Router r = f.MakeRouter();
    BOOST_CHECK_EQUAL(Call(r, "GET", "/v2/status").status, 200);
    BOOST_CHECK_EQUAL(UtxoCall(r, "0").status, 200);
    BOOST_CHECK_EQUAL(
        Len(At(Value(Branches(r, Request(100, std::nullopt), true)),
               "outputs")),
        2u);
    // Exact serde_json bytes: sorted keys, decimal strings for heights.
    const std::string snapshot =
        "{\"chain_id\":\"" + HexFill(1) + "\",\"height\":\"0\"," +
        "\"profile_id\":\"" + HexFill(3) + "\",\"tip\":\"" + HexFill(2) +
        "\"}";
    BOOST_CHECK_EQUAL(BodyStr(Call(r, "GET", "/v2/status")),
                      "{\"confirmed_only\":true,\"generation\":\"1\","
                      "\"pool_indexed\":false,\"ready\":true,\"snapshot\":" +
                          snapshot + ",\"version\":2}");
    const std::string location =
        "{\"block_id\":\"" + HexFill(2) + "\",\"height\":\"0\",\"tx_index\":0,"
        "\"txhash\":\"" + HexFill(5) + "\",\"txid\":\"" + HexFill(4) + "\"}";
    BOOST_CHECK_EQUAL(
        BodyStr(UtxoCall(r, "1")),
        "{\"confirmed_only\":true,\"generation\":\"1\",\"record\":{"
        "\"branches\":[\"" + HexFill(9) + "\"],\"creation\":" + location +
            ",\"flags\":0,\"out_idx\":1,\"paths\":[[0]],\"spend\":null,"
            "\"token_id\":\"" + HexFill(0) + "\",\"txid\":\"" + HexFill(4) +
            "\",\"value\":\"18446744073709551615\"},\"snapshot\":" + snapshot +
            ",\"version\":2}");
    // Methods and fallbacks of the shared router.
    BOOST_CHECK_EQUAL(Call(r, "POST", "/v2/status").status, 405);
    BOOST_CHECK_EQUAL(Call(r, "GET", "/v2/branches/utxos").status, 405);
}

BOOST_AUTO_TEST_CASE(readiness_fences_unknown_recovery_behind_and_aba) {
    Fixture f;
    const Router r = f.MakeRouter();
    f.state->node_anchor = nullptr;
    BOOST_CHECK_EQUAL(Branches(r, Request(100, std::nullopt), true).status, 503);
    for (const std::optional<Anchor> &anchor :
         {std::optional<Anchor>(), std::optional<Anchor>(kChild)}) {
        f.state->node_anchor = FixedAnchor(Stamp(2, 2, anchor));
        BOOST_CHECK_EQUAL(Branches(r, Request(100, std::nullopt), false).status,
                          503);
        BOOST_CHECK_EQUAL(UtxoCall(r, "0").status, 503);
    }
    // The third observation occurs after result construction/encoding.
    // Changing generation while retaining the same anchor models an ABA or
    // recovery boundary that bare anchor comparison cannot detect.
    for (const bool point_lookup : {false, true}) {
        for (const std::optional<Anchor> &changed :
             {std::optional<Anchor>(kParent), std::optional<Anchor>(kChild),
              std::optional<Anchor>()}) {
            auto calls = std::make_shared<int>(0);
            f.state->node_anchor = [calls, changed] {
                const bool is_changed = (*calls)++ >= 2;
                return Stamp(2, is_changed ? 5 : 3,
                             is_changed ? changed : kParent);
            };
            const HttpResponse result =
                point_lookup ? UtxoCall(r, "0")
                             : Branches(r, Request(100, std::nullopt), true);
            BOOST_CHECK_EQUAL(result.status, 503);
        }
    }
    f.state->node_anchor = FixedAnchor(Stamp(2, 6, kParent));
    BOOST_CHECK_EQUAL(Branches(r, Request(100, std::nullopt), true).status, 200);
}

BOOST_AUTO_TEST_CASE(held_database_returns_503_on_all_routes_without_waiting) {
    Fixture f;
    const Router r = f.MakeRouter();
    std::mutex m;
    std::condition_variable cv;
    bool locked = false, release = false;
    std::thread owner([&] {
        std::lock_guard<std::mutex> guard(f.state->db->mutex);
        std::unique_lock<std::mutex> lk(m);
        locked = true;
        cv.notify_all();
        // Bounded fallback allows a regression to fail instead of hanging.
        cv.wait_for(lk, std::chrono::seconds(5), [&] { return release; });
    });
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return locked; });
    }
    BOOST_CHECK_EQUAL(Call(r, "GET", "/v2/status").status, 503);
    BOOST_CHECK_EQUAL(UtxoCall(r, "0").status, 503);
    BOOST_CHECK_EQUAL(Branches(r, Request(100, std::nullopt), false).status,
                      503);
    BOOST_CHECK_EQUAL(Branches(r, Request(100, std::nullopt), true).status, 503);
    // The owner has not released the DB: every response was immediate.
    {
        std::lock_guard<std::mutex> lk(m);
        BOOST_CHECK(!release);
        release = true;
    }
    cv.notify_all();
    owner.join();
}

BOOST_AUTO_TEST_CASE(cursor_fixed_encoding_and_binding) {
    Fixture f;
    const Router r = f.MakeRouter();
    const std::string cursor =
        Str(At(Value(Branches(r, Request(1, std::nullopt), true)), "cursor"));
    BOOST_REQUIRE_EQUAL(cursor.size(), 348u);
    // version 01, chain, profile, tip, height LE, digest, present byte 01.
    BOOST_CHECK_EQUAL(cursor.substr(0, 2), "01");
    BOOST_CHECK_EQUAL(cursor.substr(2, 64), HexFill(1));
    BOOST_CHECK_EQUAL(cursor.substr(66, 64), HexFill(3));
    BOOST_CHECK_EQUAL(cursor.substr(130, 64), HexFill(2));
    BOOST_CHECK_EQUAL(cursor.substr(194, 16), "0000000000000000");
    BOOST_CHECK_EQUAL(cursor.substr(274, 2), "01");
    BOOST_CHECK_EQUAL(cursor.substr(276, 64), HexFill(4));
    BOOST_CHECK_EQUAL(cursor.substr(340, 8), "00000000");
    // Uppercase cursors decode too; a bad presence byte or nonzero padding
    // after an absent key is malformed.
    std::string upper = cursor;
    for (char &c : upper) {
        c = char(std::toupper(c));
    }
    BOOST_CHECK_EQUAL(Branches(r, Request(1, upper), true).status, 200);
    std::string bad = cursor;
    bad.replace(274, 2, "02");
    BOOST_CHECK_EQUAL(BodyStr(Branches(r, Request(1, bad), true)),
                      "{\"error\":\"invalid_cursor\"}");
    bad.replace(274, 2, "00");
    BOOST_CHECK_EQUAL(BodyStr(Branches(r, Request(1, bad), true)),
                      "{\"error\":\"invalid_cursor\"}");
}

BOOST_AUTO_TEST_CASE(closed_service_is_unavailable) {
    Fixture f;
    const Router r = f.MakeRouter();
    *f.open = false;
    for (const HttpResponse &resp :
         {Call(r, "GET", "/v2/status"), UtxoCall(r, "0"),
          Branches(r, Request(1, std::nullopt), true)}) {
        BOOST_CHECK_EQUAL(resp.status, 503);
        BOOST_CHECK_EQUAL(BodyStr(resp), "{\"error\":\"index_unavailable\"}");
    }
    // Request validation still precedes the service.
    BOOST_CHECK_EQUAL(UtxoCall(r, "x").status, 400);
}

BOOST_AUTO_TEST_SUITE_END()
