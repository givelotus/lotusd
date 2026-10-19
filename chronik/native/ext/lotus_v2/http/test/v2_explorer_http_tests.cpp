// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http/src/v2_explorer_http_tests.rs and the v2_explorer.rs
// unit tests (through the router, since the helpers are private here).

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

const std::string kPrefix = "/v2/explorer/v1";
const Anchor kAnchor{B32(2), 0};

struct Fixture : RouterFixture {
    V2TempDir dir{"explorer-http"};
    Bytes wire;

    explicit Fixture(size_t count = 2, bool burn = false) {
        auto db = std::make_shared<SharedV2Db>(dir.path, TestBinding());
        ExplorerBlockFacts header;
        for (int i = 0; i < 8; ++i) {
            header.header_wire[54 + i] = uint8_t(uint64_t(134) >> (8 * i));
        }
        for (size_t i = 0; i < 40000; ++i) {
            wire.push_back(uint8_t(i % 251));
        }
        wire[1] = 0; // Native empty argument table CompactSize count.
        InputFact input;
        input.prev_txid = B32(9);
        input.sequence = UINT32_MAX;
        input.flags = 3;
        input.witnesses = {WitnessFact{WireRange{2, 1}, WireRange{0, 1}, 0,
                                       WireRange{1, 1}, 0}};
        Output token;
        token.flags = burn ? 3 : 1;
        token.value = UINT64_MAX;
        token.token_id = Fill(9);
        token.branches = {Fill(8), Fill(7)};
        if (!burn) {
            token.paths = {{0, 1}};
        }
        db->db.InitializeGenesis(CommittedBlock{
            kAnchor,
            kAnchor,
            {ConfirmedTx{TxLocation{Fill(2), 0, 0, TxId{Fill(4)},
                                    TxHash{Fill(5)}},
                         std::vector<Output>(count, token),
                         {},
                         ExplorerTxFacts{wire, UINT64_MAX, {input}}}},
            header});
        std::array<uint8_t, 16> epoch;
        epoch.fill(6);
        *state = MakeState(db, epoch);
        state->node_anchor = FixedAnchor(Stamp(2, 1, kAnchor));
    }
};

HttpResponse Get(const Router &r, const std::string &path) {
    return Call(r, "GET", kPrefix + path);
}
HttpResponse Post(const Router &r, const std::string &path,
                  const std::string &body) {
    return Call(r, "POST", kPrefix + path, body);
}

std::vector<std::string> Routes() {
    const std::string id2 = HexFill(2), id4 = HexFill(4), id5 = HexFill(5),
                      id9 = HexFill(9);
    return {
        "/status",
        "/blocks",
        "/blocks/by-height/0",
        "/blocks/" + id2,
        "/blocks/" + id2 + "/transactions",
        "/transactions/by-id/" + id4,
        "/transactions/by-hash/" + id5,
        "/transactions/by-id/" + id4 + "/inputs",
        "/transactions/by-id/" + id4 + "/outputs",
        "/transactions/by-id/" + id4 + "/witnesses?input_index=0",
        "/transactions/by-id/" + id4 + "/wire",
        "/outputs/" + id4 + "/0",
        "/assets",
        "/assets/" + id9,
        "/assets/" + id9 + "/events",
        "/assets/" + id9 + "/outputs?view=history",
        "/assets/" + id9 + "/outputs?view=unspent",
    };
}

std::string Code(const HttpResponse &r) {
    return Str(At(Value(r), "error", "code"));
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_explorer_http_tests)

BOOST_AUTO_TEST_CASE(every_route_serves_schema_and_exact_native_facts) {
    Fixture f;
    const Router app = f.MakeRouter();
    for (const std::string &path : Routes()) {
        const HttpResponse r = Get(app, path);
        BOOST_CHECK_MESSAGE(r.status == 200, path + ": " + BodyStr(r));
        BOOST_REQUIRE(r.Header("cache-control"));
        BOOST_CHECK_EQUAL(*r.Header("cache-control"), "no-store");
        BOOST_CHECK_EQUAL(r.ContentType(), "application/json");
        const JsonNode v = Value(r);
        BOOST_CHECK_EQUAL(Str(At(v, "api_version")), "1");
        if (path != "/status") {
            BOOST_CHECK_EQUAL(Str(At(v, "snapshot", "genesis")), HexFill(2));
            BOOST_CHECK_EQUAL(Str(At(v, "snapshot", "height")), "0");
            BOOST_CHECK(Bool(At(v, "coverage", "complete")));
            BOOST_CHECK_EQUAL(Str(At(v, "snapshot_token")).size(), 322u);
        }
    }
    for (const std::string kind : {"outputs", "utxos"}) {
        const HttpResponse r =
            Post(app, "/branches/" + kind,
                 "{\"any_branch\":[\"" + HexFill(8) + "\"],\"page_size\":\"1\"}");
        BOOST_CHECK_EQUAL(r.status, 200);
        const JsonNode v = Value(r);
        BOOST_CHECK_EQUAL(
            Str(At(v, "data", "items", 0, "matching_positions", 0)), "0");
        BOOST_CHECK_EQUAL(Str(At(v, "data", "items", 0, "record", "paths", 0, 1)),
                          "1");
    }
    const JsonNode block = Value(Get(app, "/blocks/by-height/0"));
    BOOST_CHECK_EQUAL(Str(At(block, "data", "header_wire")).size(), 268u);
    BOOST_CHECK_EQUAL(Str(At(block, "data", "prev_id")), HexFill(0));
    const JsonNode tx = Value(Get(app, "/transactions/by-id/" + HexFill(4)));
    BOOST_CHECK(Str(At(tx, "data", "txid")) != Str(At(tx, "data", "txhash")));
    BOOST_CHECK_EQUAL(Str(At(tx, "data", "lock")), std::to_string(UINT64_MAX));
    BOOST_CHECK_EQUAL(Str(At(tx, "data", "accounting", "availability")),
                      "unknown");
    const JsonNode input =
        Value(Get(app, "/transactions/by-id/" + HexFill(4) + "/inputs"));
    BOOST_CHECK_EQUAL(Str(At(input, "data", "items", 0, "kind")), "mint");
    BOOST_CHECK(IsNull(At(input, "data", "items", 0, "path_index")));
    BOOST_CHECK_EQUAL(Str(At(input, "data", "items", 0, "sequence")),
                      std::to_string(UINT32_MAX));
    const JsonNode asset =
        Value(Get(app, "/assets/" + HexFill(9) + "/events"));
    // u64::MAX * 2 as u128
    BOOST_CHECK_EQUAL(Str(At(asset, "data", "items", 0, "output_units")),
                      "36893488147419103230");
}

BOOST_AUTO_TEST_CASE(wire_chunks_reconstruct_only_with_pinned_snapshot) {
    Fixture f;
    const Router app = f.MakeRouter();
    const std::string path = "/transactions/by-id/" + HexFill(4) + "/wire";
    const JsonNode first = Value(Get(app, path));
    const std::string token = Str(At(first, "snapshot_token"));
    std::string hex = Str(At(first, "data", "bytes_hex"));
    BOOST_CHECK_EQUAL(hex.size(), 2u * 32768);
    BOOST_CHECK_EQUAL(Get(app, path + "?offset=32768").status, 400);
    const JsonNode next =
        Value(Get(app, path + "?offset=32768&snapshot_token=" + token));
    hex += Str(At(next, "data", "bytes_hex"));
    BOOST_CHECK_EQUAL(hex, http::detail::Hex(f.wire));
    BOOST_CHECK(IsNull(At(next, "data", "next_offset")));
    BOOST_CHECK_EQUAL(Str(At(first, "data", "next_offset")), "32768");
    const JsonNode end =
        Value(Get(app, path + "?offset=40000&snapshot_token=" + token));
    BOOST_CHECK_EQUAL(Str(At(end, "data", "bytes_hex")), "");
    BOOST_CHECK(IsNull(At(end, "data", "next_offset")));
    const HttpResponse range =
        Get(app, path + "?offset=40001&snapshot_token=" + token);
    BOOST_CHECK_EQUAL(range.status, 416);
    BOOST_CHECK_EQUAL(Code(range), "invalid_range");
}

BOOST_AUTO_TEST_CASE(list_continuations_and_restart_fences) {
    Fixture f;
    const Router app = f.MakeRouter();
    const std::string path = "/transactions/by-id/" + HexFill(4) + "/outputs";
    const JsonNode first = Value(Get(app, path + "?page_size=1"));
    const std::string cursor = Str(At(first, "data", "next_cursor"));
    BOOST_CHECK(!Bool(At(first, "data", "exhausted")));
    const JsonNode second = Value(Get(app, path + "?cursor=" + cursor));
    BOOST_CHECK_EQUAL(Str(At(second, "data", "items", 0, "out_idx")), "1");
    BOOST_CHECK(Bool(At(second, "data", "exhausted")));
    BOOST_CHECK(IsNull(At(second, "data", "next_cursor")));
    // A changed explicit parameter does not resume the cursor.
    const HttpResponse changed =
        Get(app, path + "?cursor=" + cursor + "&page_size=2");
    BOOST_CHECK_EQUAL(changed.status, 409);
    BOOST_CHECK_EQUAL(Code(changed), "stale_cursor");

    const std::string token = Str(At(first, "snapshot_token"));
    RouterFixture restarted;
    *restarted.state = *f.state;
    restarted.state->service_epoch[0] ^= 1;
    const Router app2 = restarted.MakeRouter();
    BOOST_CHECK_EQUAL(Get(app2, path + "?cursor=" + cursor).status, 409);
    const HttpResponse r = Get(app2, path + "?snapshot_token=" + token);
    BOOST_CHECK_EQUAL(r.status, 409);
    BOOST_CHECK_EQUAL(Code(r), "stale_snapshot");
    // A new generation also invalidates the token (restart_generation...).
    restarted.state->service_epoch = f.state->service_epoch;
    restarted.state->node_anchor = FixedAnchor(Stamp(2, 2, kAnchor));
    BOOST_CHECK_EQUAL(Code(Get(app2, path + "?snapshot_token=" + token)),
                      "stale_snapshot");
    BOOST_CHECK_EQUAL(Code(Get(app2, path + "?cursor=" + cursor)),
                      "stale_cursor");
}

BOOST_AUTO_TEST_CASE(
    held_owner_unknown_authority_and_aba_never_return_success_or_404) {
    Fixture f;
    const Router app = f.MakeRouter();
    {
        std::mutex m;
        std::condition_variable cv;
        bool locked = false, release = false;
        std::thread owner([&] {
            std::lock_guard<std::mutex> guard(f.state->db->mutex);
            std::unique_lock<std::mutex> lk(m);
            locked = true;
            cv.notify_all();
            cv.wait_for(lk, std::chrono::seconds(5), [&] { return release; });
        });
        {
            std::unique_lock<std::mutex> lk(m);
            cv.wait(lk, [&] { return locked; });
        }
        for (const std::string &path : Routes()) {
            BOOST_CHECK_MESSAGE(Get(app, path).status == 503, path);
        }
        for (const std::string kind : {"outputs", "utxos"}) {
            BOOST_CHECK_EQUAL(
                Post(app, "/branches/" + kind,
                     "{\"any_branch\":[\"" + HexFill(8) + "\"]}")
                    .status,
                503);
        }
        {
            std::lock_guard<std::mutex> lk(m);
            release = true;
        }
        cv.notify_all();
        owner.join();
    }
    f.state->node_anchor = nullptr;
    BOOST_CHECK_EQUAL(Get(app, "/blocks").status, 503);
    auto calls = std::make_shared<int>(0);
    f.state->node_anchor = [calls] {
        return Stamp(2, (*calls)++ >= 2 ? 2 : 1, kAnchor);
    };
    const HttpResponse r = Get(app, "/transactions/by-id/" + HexFill(99));
    BOOST_CHECK_EQUAL(r.status, 503);
    BOOST_CHECK(IsNull(At(Value(r), "snapshot")));
}

BOOST_AUTO_TEST_CASE(malformed_parameters_rejected_before_a_busy_storage_read) {
    Fixture f;
    const Router app = f.MakeRouter();
    std::mutex m;
    std::condition_variable cv;
    bool locked = false, release = false;
    std::thread owner([&] {
        std::lock_guard<std::mutex> g(f.state->db->mutex);
        std::unique_lock<std::mutex> lk(m);
        locked = true;
        cv.notify_all();
        cv.wait_for(lk, std::chrono::seconds(5), [&] { return release; });
    });
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return locked; });
    }
    for (const std::string &path : std::vector<std::string>{
             "/blocks?unknown=1",
             "/blocks?page_size=01",
             "/blocks?page_size=1&page_size=2",
             "/blocks/by-height/01",
             "/assets/" + std::string(64, 'A'),
             "/transactions/by-id/" + HexFill(4) + "/wire?length=0",
             "/transactions/by-id/" + HexFill(4) + "/witnesses",
             // v2_explorer.rs strict_query_encodings_and_duplicates
             "/blocks?a=1&a=2",
             "/blocks?%61=1",
             "/blocks?a=%30",
             "/blocks?a=+1",
             "/blocks?a",
             "/blocks?=1",
             "/blocks?a=",
             "/blocks?",
             "/blocks?before_height=00",
             "/blocks?before_height=+1",
             "/blocks?before_height=-1",
             "/blocks?before_height=18446744073709551616",
             "/status?snapshot_token=" + std::string(322, '0'),
             "/blocks/" + HexFill(2) + "%2f",
         }) {
        BOOST_CHECK_MESSAGE(Get(app, path).status == 400, path);
    }
    {
        std::lock_guard<std::mutex> lk(m);
        release = true;
    }
    cv.notify_all();
    owner.join();
    // u64::MAX is a canonical number.
    BOOST_CHECK_EQUAL(Get(app, "/blocks?before_height=18446744073709551615")
                          .status,
                      200);
    // Raw path parameters: invalid UTF-8 escapes are JSON errors, not axum
    // Path rejections.
    const HttpResponse raw = Get(app, "/blocks/%ff");
    BOOST_CHECK_EQUAL(raw.status, 400);
    BOOST_CHECK_EQUAL(Code(raw), "invalid_request");
    // Request limits.
    const HttpResponse big = Get(app, "/blocks?a=" + std::string(32768, '1'));
    BOOST_CHECK_EQUAL(big.status, 413);
    BOOST_CHECK_EQUAL(Code(big), "request_limit");
    const HttpResponse body = Post(app, "/branches/outputs",
                                   std::string(32768, ' '));
    BOOST_CHECK_EQUAL(body.status, 413);
}

BOOST_AUTO_TEST_CASE(
    empty_work_limited_branch_page_advances_without_claiming_exhaustion) {
    Fixture f(600);
    const Router app = f.MakeRouter();
    const std::string filter = "\"any_branch\":[\"" + HexFill(8) +
                               "\"],\"positions\":[{\"position\":\"0\","
                               "\"roots\":[\"" + HexFill(7) + "\"]}]";
    const JsonNode first =
        Value(Post(app, "/branches/outputs", "{" + filter + "}"));
    BOOST_CHECK_EQUAL(Len(At(first, "data", "items")), 0u);
    BOOST_CHECK(!Bool(At(first, "data", "exhausted")));
    BOOST_CHECK_EQUAL(Str(At(first, "data", "work")), "1024");
    const std::string cursor = Str(At(first, "data", "next_cursor"));
    const JsonNode next = Value(Post(
        app, "/branches/outputs", "{" + filter + ",\"cursor\":\"" + cursor + "\"}"));
    BOOST_CHECK(Bool(At(next, "data", "exhausted")));
    BOOST_CHECK(IsNull(At(next, "data", "next_cursor")));
}

BOOST_AUTO_TEST_CASE(index_failure_and_absence_are_explicit) {
    Fixture f;
    const Router app = f.MakeRouter();
    const JsonNode miss = Value(Get(app, "/assets/" + HexFill(99)));
    BOOST_CHECK_EQUAL(Str(At(miss, "error", "code")), "not_in_covered_chain");
    BOOST_CHECK(At(miss, "snapshot")->kind == JsonNode::Kind::Obj);
    BOOST_CHECK(Bool(At(miss, "coverage", "complete")));
    f.state->index_error->store(true);
    const JsonNode status = Value(Get(app, "/status"));
    BOOST_CHECK(!Bool(At(status, "ready")));
    BOOST_CHECK_EQUAL(Str(At(status, "reason")), "index_error");
    BOOST_CHECK_EQUAL(Get(app, "/blocks").status, 503);
}

BOOST_AUTO_TEST_CASE(burned_only_asset_unspent_scan_is_bounded_and_continues_empty) {
    Fixture f(1100, true);
    const Router app = f.MakeRouter();
    const std::string path = "/assets/" + HexFill(9) + "/outputs?view=unspent";
    const JsonNode first = Value(Get(app, path));
    BOOST_CHECK_EQUAL(Len(At(first, "data", "items")), 0u);
    BOOST_CHECK(!Bool(At(first, "data", "exhausted")));
    const std::string cursor = Str(At(first, "data", "next_cursor"));
    const JsonNode next = Value(Get(app, path + "&cursor=" + cursor));
    BOOST_CHECK_EQUAL(Len(At(next, "data", "items")), 0u);
    BOOST_CHECK(Bool(At(next, "data", "exhausted")));
    const JsonNode asset = Value(Get(app, "/assets/" + HexFill(9)));
    BOOST_CHECK_EQUAL(Str(At(asset, "data", "output_count")), "1100");
}

BOOST_AUTO_TEST_CASE(
    observation_only_idle_boundary_rejects_inflight_success_and_absence) {
    for (const uint8_t id : {4, 99}) {
        Fixture f;
        auto calls = std::make_shared<int>(0);
        f.state->node_anchor = [calls] {
            return Stamp((*calls)++ >= 2 ? 4 : 2, 1, kAnchor);
        };
        const HttpResponse result =
            Get(f.MakeRouter(), "/transactions/by-id/" + HexFill(id));
        BOOST_CHECK_EQUAL(result.status, 503);
        BOOST_CHECK(IsNull(At(Value(result), "snapshot")));
    }
}

BOOST_AUTO_TEST_CASE(status_bytes_and_snapshot_token_layout) {
    Fixture f;
    const Router app = f.MakeRouter();
    const std::string anchor =
        "{\"block_id\":\"" + HexFill(2) + "\",\"height\":\"0\"}";
    BOOST_CHECK_EQUAL(
        BodyStr(Get(app, "/status")),
        "{\"api_version\":\"1\",\"authoritative_anchor\":" + anchor +
            ",\"binding\":{\"chain_id\":\"" + HexFill(1) +
            "\",\"genesis\":\"" + HexFill(2) + "\",\"profile_id\":\"" +
            HexFill(3) +
            "\"},\"capabilities\":{\"accepted_pool\":false,\"asset_events\":"
            "true,\"assets\":true,\"blocks\":true,\"branches\":true,"
            "\"detached_history\":false,\"finality\":false,\"outputs\":true,"
            "\"transaction_wire\":true,\"transactions\":true},\"coverage\":{"
            "\"complete\":true,\"from_height\":\"0\",\"scope\":"
            "\"canonical_confirmed\",\"through_height\":\"0\"},\"generation\":"
            "\"1\",\"indexed_anchor\":" + anchor +
            ",\"limits\":{\"cursor_bytes\":\"2048\",\"examined_records\":"
            "\"1024\",\"key_reads\":\"4096\",\"page_size\":\"100\","
            "\"request_bytes\":\"32768\",\"response_bytes\":\"262144\","
            "\"wire_chunk_bytes\":\"32768\"},\"ready\":true,\"reason\":"
            "\"ready\",\"service_epoch\":\"06060606060606060606060606060606\"}");
    // version, epoch, generation BE, chain, genesis, profile, tip, height BE
    const std::string token =
        Str(At(Value(Get(app, "/blocks")), "snapshot_token"));
    BOOST_CHECK_EQUAL(token, "01"
                             "06060606060606060606060606060606"
                             "0000000000000001" +
                                 HexFill(1) + HexFill(2) + HexFill(3) +
                                 HexFill(2) + "0000000000000000");
    // Unknown authority and missing service.
    f.state->node_anchor = nullptr;
    const JsonNode unknown = Value(Get(app, "/status"));
    BOOST_CHECK_EQUAL(Str(At(unknown, "reason")), "authority_unknown");
    BOOST_CHECK(IsNull(At(unknown, "generation")));
    *f.open = false;
    const HttpResponse closed = Get(app, "/status");
    BOOST_CHECK_EQUAL(closed.status, 503);
    BOOST_CHECK_EQUAL(BodyStr(closed),
                      "{\"api_version\":\"1\",\"coverage\":null,\"error\":{"
                      "\"code\":\"index_unavailable\",\"meaning\":\"A coherent "
                      "complete canonical index is unavailable\"},"
                      "\"snapshot\":null}");
}

BOOST_AUTO_TEST_CASE(cursor_tampering_and_list_pages) {
    Fixture f(3);
    const Router app = f.MakeRouter();
    const JsonNode blocks = Value(Get(app, "/blocks"));
    BOOST_CHECK(Bool(At(blocks, "data", "exhausted")));
    BOOST_CHECK_EQUAL(Len(At(blocks, "data", "items")), 1u);
    BOOST_CHECK_EQUAL(Str(At(blocks, "data", "items", 0, "confirmations")),
                      "1");
    const JsonNode none = Value(Get(app, "/blocks?before_height=0"));
    BOOST_CHECK_EQUAL(Len(At(none, "data", "items")), 0u);
    BOOST_CHECK(Bool(At(none, "data", "exhausted")));

    const std::string path =
        "/assets/" + HexFill(9) + "/outputs?view=history&page_size=1";
    const JsonNode first = Value(Get(app, path));
    const std::string cursor = Str(At(first, "data", "next_cursor"));
    // The cursor is hex of serde_json Cursor (declaration order).
    const std::optional<Bytes> json = http::detail::HexDecode(cursor);
    BOOST_REQUIRE(json);
    const std::string text(json->begin(), json->end());
    BOOST_CHECK(text.starts_with("{\"version\":1,\"token\":\""));
    BOOST_CHECK(text.find(",\"route\":\"/assets/" + HexFill(9) +
                          "/outputs\",\"params\":{\"page_size\":\"1\","
                          "\"view\":\"history\"},\"filter_digest\":\"") !=
                std::string::npos);
    const std::string base = "/assets/" + HexFill(9) + "/outputs?cursor=";
    const JsonNode second = Value(Get(app, base + cursor));
    BOOST_CHECK_EQUAL(Str(At(second, "data", "items", 0, "out_idx")), "1");
    // Edited params no longer match the digest.
    std::string edited = text;
    edited.replace(edited.find("\"page_size\":\"1\""), 15,
                   "\"page_size\":\"2\"");
    BOOST_CHECK_EQUAL(
        Code(Get(app, base + http::detail::Hex(edited))), "invalid_cursor");
    BOOST_CHECK_EQUAL(Code(Get(app, base + "zz")), "invalid_cursor");
    BOOST_CHECK_EQUAL(Code(Get(app, "/blocks/" + HexFill(2) + "?cursor=" +
                                        cursor)),
                      "invalid_request");
}

BOOST_AUTO_TEST_SUITE_END()
