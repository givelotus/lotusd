// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http/src/v2.rs: the opt-in confirmed V2 JSON API. All hex
// uses native wire order, without reversal. Money and heights are decimal
// strings. Responses are fenced by the authoritative node observation.

#include <ext/lotus_v2/http/util.h>
#include <ext/lotus_v2/http/v2_http.h>

#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/service/service.h>

#include <mutex>

namespace chronik::native::lotus_v2::http {

namespace {

using namespace detail;
namespace qb = query_branches;

constexpr size_t BODY_CAP = 32 * 1024;
constexpr size_t JSON_CAP = 256 * 1024;

HttpResponse Response(int status, const Json &value) {
    std::string bytes = value.Dump();
    if (bytes.size() <= JSON_CAP) {
        return JsonResponse(status, std::move(bytes));
    }
    return JsonResponse(413, "{\"error\":\"response_limit\"}");
}

HttpResponse Fail(int status, std::string_view message) {
    return Response(status, Json::Object({{"error", Json(message)}}));
}

HttpResponse Internal() { return Fail(503, "index_unavailable"); }

/** v2.rs hash: exactly 64 hex digits of either case. */
std::optional<Hash32> ParseHash(std::string_view s) {
    if (s.size() != 64) {
        return std::nullopt;
    }
    std::optional<Bytes> bytes = HexDecode(s);
    if (!bytes) {
        return std::nullopt;
    }
    Hash32 h;
    std::copy(bytes->begin(), bytes->end(), h.b.begin());
    return h;
}

qb::Snapshot ToSnapshot(const ReadSnapshot &s) {
    return qb::Snapshot{
        .chain_id = H(s.binding.chain_id),
        .profile_id = H(s.binding.profile),
        .tip = H(s.anchor.block_id),
        .height = s.anchor.height,
    };
}

Json SnapshotJson(const qb::Snapshot &s) {
    return Json::Object({{"chain_id", Hex(s.chain_id.b)},
                         {"profile_id", Hex(s.profile_id.b)},
                         {"tip", Hex(s.tip.b)},
                         {"height", std::to_string(s.height)}});
}

Json Location(const TxLocation &l) {
    return Json::Object({{"block_id", Hex(l.block_id.b)},
                         {"height", std::to_string(l.height)},
                         {"tx_index", Json::U(l.tx_index)},
                         {"txid", Hex(l.txid.hash.b)},
                         {"txhash", Hex(l.txhash.hash.b)}});
}

Json Record(const OutputRecord &r) {
    Json branches = Json::Array();
    for (const Hash32 &b : r.output.branches) {
        branches.Push(Hex(b.b));
    }
    Json paths = Json::Array();
    for (const auto &path : r.output.paths) {
        Json p = Json::Array();
        for (const uint8_t idx : path) {
            p.Push(Json::U(idx));
        }
        paths.Push(std::move(p));
    }
    Json spend;
    if (r.spend) {
        spend = Json::Object({{"transaction", Location(r.spend->transaction)},
                              {"input_index", Json::U(r.spend->input_index)}});
    }
    return Json::Object({{"txid", Hex(r.outpoint.txid.hash.b)},
                         {"out_idx", Json::U(r.outpoint.out_idx)},
                         {"flags", Json::U(r.output.flags)},
                         {"value", std::to_string(r.output.value)},
                         {"token_id", Hex(r.output.token_id.b)},
                         {"branches", std::move(branches)},
                         {"paths", std::move(paths)},
                         {"creation", Location(r.creation)},
                         {"spend", std::move(spend)}});
}

Json Generation(const std::optional<AuthoritativeState> &s) {
    return s ? Json(std::to_string(s->generation)) : Json();
}

// Fixed 174-byte transport: version, chain, profile, tip, height LE, digest,
// key-presence byte, TxID and output ordinal LE. Absent key has zero padding.
std::string EncodeCursor(const qb::Cursor &c) {
    Bytes b{c.version};
    b.insert(b.end(), c.snapshot.chain_id.b.begin(), c.snapshot.chain_id.b.end());
    b.insert(b.end(), c.snapshot.profile_id.b.begin(),
             c.snapshot.profile_id.b.end());
    b.insert(b.end(), c.snapshot.tip.b.begin(), c.snapshot.tip.b.end());
    for (int i = 0; i < 8; ++i) {
        b.push_back(uint8_t(c.snapshot.height >> (8 * i)));
    }
    b.insert(b.end(), c.filter_digest.b.begin(), c.filter_digest.b.end());
    b.push_back(c.last_key ? 1 : 0);
    const OutPoint op = c.last_key.value_or(OutPoint{});
    b.insert(b.end(), op.txid.hash.b.begin(), op.txid.hash.b.end());
    for (int i = 0; i < 4; ++i) {
        b.push_back(uint8_t(op.out_idx >> (8 * i)));
    }
    return Hex(b);
}

std::optional<qb::Cursor> DecodeCursor(std::string_view s) {
    if (s.size() != 348) {
        return std::nullopt;
    }
    std::optional<Bytes> bytes = HexDecode(s);
    if (!bytes) {
        return std::nullopt;
    }
    const Bytes &b = *bytes;
    auto h = [&](size_t i) {
        Hash32 out;
        std::copy_n(b.begin() + i, 32, out.b.begin());
        return out;
    };
    auto le = [&](size_t i, size_t n) {
        uint64_t v = 0;
        for (size_t k = 0; k < n; ++k) {
            v |= uint64_t(b[i + k]) << (8 * k);
        }
        return v;
    };
    qb::Cursor c;
    if (b[137] == 0) {
        for (size_t i = 138; i < b.size(); ++i) {
            if (b[i] != 0) {
                return std::nullopt;
            }
        }
    } else if (b[137] == 1) {
        c.last_key = OutPoint{TxId{h(138)}, uint32_t(le(170, 4))};
    } else {
        return std::nullopt;
    }
    c.version = b[0];
    c.snapshot = qb::Snapshot{.chain_id = h(1),
                              .profile_id = h(33),
                              .tip = h(65),
                              .height = le(97, 8)};
    c.filter_digest = h(105);
    return c;
}

bool Ready(const std::optional<AuthoritativeState> &stamp,
           const Anchor &anchor) {
    return stamp && stamp->anchor == anchor;
}

/** The final observation is the response's linearization point. */
HttpResponse Fenced(const V2HttpState &s,
                    const std::optional<AuthoritativeState> &stamp,
                    HttpResponse result) {
    return Observe(s) == stamp ? std::move(result) : Internal();
}

/** Stable snapshot of a held DB; nullopt if uninitialized or failing. */
std::optional<ReadSnapshot> TrySnapshot(const SharedV2Db &db) {
    try {
        return db.db.Snapshot();
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

HttpResponse Status(const std::optional<V2HttpState> &state) {
    if (!state) {
        return Internal();
    }
    const V2HttpState &s = *state;
    const std::optional<AuthoritativeState> stamp = Observe(s);
    std::unique_lock<std::mutex> lock(s.db->mutex, std::try_to_lock);
    if (!lock) {
        return Internal();
    }
    std::optional<ReadSnapshot> view = TrySnapshot(*s.db);
    if (!view) {
        return Internal();
    }
    const std::optional<AuthoritativeState> current = Observe(s);
    const bool is_ready = stamp == current && Ready(current, view->anchor);
    HttpResponse result = Response(
        200, Json::Object({{"version", Json::U(2)},
                           {"confirmed_only", true},
                           {"pool_indexed", false},
                           {"ready", is_ready},
                           {"generation", Generation(current)},
                           {"snapshot", SnapshotJson(ToSnapshot(*view))}}));
    return Observe(s) == current ? std::move(result) : Internal();
}

struct BranchClause {
    uint64_t position = 0;
    std::vector<std::string> roots;
};

struct BranchRequest {
    std::vector<std::string> any_branch;
    std::vector<BranchClause> positions;
    std::optional<std::string> cursor;
    uint64_t page_size = 100;
    bool include_burn = false;
};

/** serde_json::from_slice::<Request> */
std::optional<BranchRequest> ParseRequest(ByteView body) {
    std::optional<JsonNode> doc = ParseJson(body);
    if (!doc) {
        return std::nullopt;
    }
    BranchRequest r;
    const std::vector<JsonField> fields = {
        {"any_branch", true, false,
         [&](const JsonNode *n) { return DecodeStrings(n, r.any_branch); }},
        {"positions", true, false,
         [&](const JsonNode *n) {
             r.positions.clear();
             if (!n) {
                 return true;
             }
             if (n->kind != JsonNode::Kind::Arr) {
                 return false;
             }
             for (const JsonNode &item : n->arr) {
                 BranchClause c;
                 const std::vector<JsonField> clause = {
                     {"position", false, false,
                      [&](const JsonNode *v) {
                          return DecodeUnsigned(v, 255, c.position);
                      }},
                     {"roots", false, false,
                      [&](const JsonNode *v) {
                          return DecodeStrings(v, c.roots);
                      }},
                 };
                 if (!DecodeStruct(item, clause)) {
                     return false;
                 }
                 r.positions.push_back(std::move(c));
             }
             return true;
         }},
        {"cursor", true, true,
         [&](const JsonNode *n) { return DecodeOptString(n, r.cursor); }},
        {"page_size", true, false,
         [&](const JsonNode *n) {
             if (!n) {
                 r.page_size = 100;
                 return true;
             }
             return DecodeUnsigned(n, UINT64_MAX, r.page_size);
         }},
        {"include_burn", true, false,
         [&](const JsonNode *n) { return DecodeBool(n, r.include_burn); }},
    };
    if (!DecodeStruct(*doc, fields)) {
        return std::nullopt;
    }
    return r;
}

HttpResponse Branches(const std::optional<V2HttpState> &state,
                      const HttpRequest &req, bool history) {
    if (req.body_too_large || req.body.size() > BODY_CAP) {
        return Fail(413, "request_limit");
    }
    std::optional<BranchRequest> r = ParseRequest(req.body);
    if (!r) {
        return Fail(400, "invalid_request");
    }
    size_t count = r->any_branch.size();
    for (const BranchClause &c : r->positions) {
        count += c.roots.size();
    }
    if (r->page_size == 0 || r->page_size > 100 || r->positions.size() > 16 ||
        count > 256 || (!history && r->include_burn)) {
        return Fail(400, "invalid_limits");
    }
    qb::BranchFilter filter;
    for (const std::string &s : r->any_branch) {
        std::optional<Hash32> h = ParseHash(s);
        if (!h) {
            return Fail(400, "invalid_hex");
        }
        filter.any_branch.push_back(*h);
    }
    for (const BranchClause &c : r->positions) {
        qb::PositionClause clause;
        clause.position = uint8_t(c.position);
        for (const std::string &s : c.roots) {
            std::optional<Hash32> h = ParseHash(s);
            if (!h) {
                return Fail(400, "invalid_hex");
            }
            clause.roots.push_back(*h);
        }
        filter.positions.push_back(std::move(clause));
    }
    std::optional<qb::Cursor> cursor;
    if (r->cursor) {
        cursor = DecodeCursor(*r->cursor);
        if (!cursor) {
            return Fail(400, "invalid_cursor");
        }
    }
    if (!state) {
        return Internal();
    }
    const V2HttpState &s = *state;
    const std::optional<AuthoritativeState> stamp = Observe(s);
    if (!stamp || !stamp->anchor) {
        return Internal();
    }
    std::unique_lock<std::mutex> lock(s.db->mutex, std::try_to_lock);
    if (!lock) {
        return Internal();
    }
    std::optional<ReadSnapshot> view = TrySnapshot(*s.db);
    if (!view) {
        return Internal();
    }
    if (Observe(s) != stamp || !Ready(stamp, view->anchor)) {
        return Internal();
    }

    const qb::QueryKind kind = history
                                   ? qb::QueryKind::History(r->include_burn)
                                   : qb::QueryKind::Utxos();
    qb::Limits limits;
    limits.page_size = size_t(r->page_size);
    const qb::SnapshotPostingSource source(*view);
    HttpResponse result;
    try {
        const qb::Page p =
            qb::Query(source, filter, kind, limits, cursor, s.sha256);
        Json outputs = Json::Array();
        for (const qb::Match &m : p.matches) {
            Json positions = Json::Array();
            for (const uint8_t pos : m.matching_positions) {
                positions.Push(Json::U(pos));
            }
            outputs.Push(Json::Object({{"record", Record(m.record)},
                                       {"matching_positions",
                                        std::move(positions)}}));
        }
        result = Response(
            200,
            Json::Object(
                {{"version", Json::U(2)},
                 {"confirmed_only", true},
                 {"snapshot", SnapshotJson(p.snapshot)},
                 {"outputs", std::move(outputs)},
                 {"cursor", p.continuation ? Json(EncodeCursor(*p.continuation))
                                           : Json()},
                 {"generation", Generation(stamp)},
                 {"posting_reads", Json::U(p.posting_reads)},
                 {"work", Json::U(p.work)}}));
    } catch (const qb::QueryError &e) {
        switch (e.kind()) {
            case qb::QueryError::Kind::StaleCursor:
                result = Fail(409, "stale_cursor");
                break;
            case qb::QueryError::Kind::InvalidFilter:
            case qb::QueryError::Kind::InvalidLimits:
                result = Fail(400, "invalid_filter");
                break;
            case qb::QueryError::Kind::RecordTooLarge:
                result = Fail(413, "record_limit");
                break;
            case qb::QueryError::Kind::Source:
                result = Internal();
                break;
        }
    } catch (const std::exception &) {
        result = Internal();
    }
    return Fenced(s, stamp, std::move(result));
}

HttpResponse Utxo(const std::optional<V2HttpState> &state,
                  const PathParams &params) {
    const std::optional<Hash32> txid = ParseHash(params[0]);
    const std::optional<uint64_t> out_idx = CanonicalU64(params[1]);
    if (!txid || !out_idx || *out_idx > UINT32_MAX) {
        return Fail(400, "invalid_outpoint");
    }
    if (!state) {
        return Internal();
    }
    const V2HttpState &s = *state;
    const std::optional<AuthoritativeState> stamp = Observe(s);
    if (!stamp || !stamp->anchor) {
        return Internal();
    }
    std::unique_lock<std::mutex> lock(s.db->mutex, std::try_to_lock);
    if (!lock) {
        return Internal();
    }
    std::optional<ReadSnapshot> view = TrySnapshot(*s.db);
    if (!view) {
        return Internal();
    }
    if (Observe(s) != stamp || !Ready(stamp, view->anchor)) {
        return Internal();
    }
    HttpResponse result;
    try {
        std::optional<OutputRecord> record =
            view->Utxo(OutPoint{TxId{*txid}, uint32_t(*out_idx)});
        if (record) {
            result = Response(
                200, Json::Object({{"version", Json::U(2)},
                                   {"confirmed_only", true},
                                   {"snapshot", SnapshotJson(ToSnapshot(*view))},
                                   {"record", Record(*record)},
                                   {"generation", Generation(stamp)}}));
        } else {
            result = Fail(404, "utxo_not_found");
        }
    } catch (const std::exception &) {
        result = Internal();
    }
    return Fenced(s, stamp, std::move(result));
}

} // namespace

void RegisterV2Routes(Router &router, V2HttpStateProvider provider) {
    router.Get("/v2/status",
               [provider](const HttpRequest &, const PathParams &) {
                   return Status(provider());
               });
    router.Post("/v2/branches/utxos",
                [provider](const HttpRequest &req, const PathParams &) {
                    return Branches(provider(), req, false);
                });
    router.Post("/v2/branches/outputs",
                [provider](const HttpRequest &req, const PathParams &) {
                    return Branches(provider(), req, true);
                });
    router.Get("/v2/utxos/:txid/:out_idx",
               [provider](const HttpRequest &, const PathParams &params) {
                   return Utxo(provider(), params);
               });
    RegisterV2ExplorerRoutes(router, std::move(provider));
}

} // namespace chronik::native::lotus_v2::http
