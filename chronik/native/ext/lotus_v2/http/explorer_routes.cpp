// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http/src/v2_explorer.rs: explorer schema 1 over the single
// V2 owner. Requests are parsed and bounded before any storage observation;
// every success is fenced by the authoritative node observation and carries
// a restart-safe snapshot token. Errors are explicit JSON envelopes.

#include <ext/lotus_v2/http/util.h>
#include <ext/lotus_v2/http/v2_http.h>

#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/query/explorer.h>
#include <ext/lotus_v2/service/service.h>

#include <map>
#include <mutex>
#include <span>

namespace chronik::native::lotus_v2::http {

namespace {

using namespace detail;
namespace qb = query_branches;

constexpr size_t REQUEST_CAP = 32768;
constexpr size_t JSON_CAP = 262144;
constexpr size_t TOKEN_CAP = 2048;
constexpr size_t ITEM_CAP = JSON_CAP - 8192;
constexpr std::string_view PREFIX = "/v2/explorer/v1";

using Params = std::map<std::string, std::string>;

/** v2_explorer.rs Error(StatusCode, code); thrown, never a std::exception. */
struct Error {
    int status;
    const char *code;
};

Error Invalid() { return {400, "invalid_request"}; }
Error Limits() { return {400, "invalid_limits"}; }
Error Unavailable() { return {503, "index_unavailable"}; }
Error Missing() { return {404, "not_in_covered_chain"}; }
Error RecordLimit() { return {413, "record_limit"}; }
Error InvalidCursor() { return {400, "invalid_cursor"}; }
Error StaleCursor() { return {409, "stale_cursor"}; }

/** Storage reads: any failure is index_unavailable. */
template <typename F> auto Db(F &&f) -> decltype(f()) {
    try {
        return f();
    } catch (const std::exception &) {
        throw Unavailable();
    }
}

/** serde_json::to_writer into a capped buffer. */
std::string Encode(const Json &value, size_t cap) {
    std::string bytes = value.Dump();
    if (bytes.size() > cap) {
        throw RecordLimit();
    }
    return bytes;
}

HttpResponse Response(int status, const Json &value) {
    std::string bytes = value.Dump();
    if (bytes.size() > JSON_CAP) {
        return JsonResponse(
            413,
            "{\"api_version\":\"1\",\"error\":{\"code\":\"record_limit\","
            "\"meaning\":\"The complete record exceeds the response "
            "limit\"},"
            "\"snapshot\":null,\"coverage\":null}",
            /*no_store=*/true);
    }
    return JsonResponse(status, std::move(bytes), /*no_store=*/true);
}

std::string_view Meaning(std::string_view code) {
    if (code == "not_in_covered_chain") {
        return "Absent from covered canonical history at this observation";
    }
    if (code == "stale_cursor") {
        return "The continuation belongs to a different observation or "
               "query";
    }
    if (code == "stale_snapshot") {
        return "The requested observation is no longer current";
    }
    if (code == "index_unavailable") {
        return "A coherent complete canonical index is unavailable";
    }
    if (code == "record_limit") {
        return "The complete record exceeds the response limit";
    }
    if (code == "request_limit") {
        return "The request exceeds the request limit";
    }
    if (code == "invalid_range") {
        return "The wire offset exceeds the transaction frame";
    }
    if (code == "invalid_cursor") {
        return "Malformed explorer continuation";
    }
    if (code == "invalid_limits") {
        return "Noncanonical or excessive request limits";
    }
    return "Malformed or unsupported request";
}

/** Lowercase-only 64-digit hash. */
Hash32 ParseHash(std::string_view s) {
    if (s.size() != 64 || !IsLowerHex(s)) {
        throw Invalid();
    }
    Hash32 h;
    for (size_t i = 0; i < 32; ++i) {
        h.b[i] = uint8_t(HexDigit(s[2 * i]) * 16 + HexDigit(s[2 * i + 1]));
    }
    return h;
}

uint64_t Number(std::string_view s) {
    std::optional<uint64_t> n = CanonicalU64(s);
    if (!n) {
        throw Limits();
    }
    return *n;
}

uint32_t Ordinal(std::string_view s) {
    const uint64_t n = Number(s);
    if (n > UINT32_MAX) {
        throw Limits();
    }
    return uint32_t(n);
}

/** Strict query: decimal or lowercase hex values, no escapes/duplicates. */
Params Query(const HttpRequest &req) {
    Params result;
    if (!req.has_query) {
        return result;
    }
    std::string_view raw = req.query_string;
    while (true) {
        const size_t amp = raw.find('&');
        const std::string_view pair = raw.substr(0, amp);
        const size_t eq = pair.find('=');
        if (eq == std::string_view::npos) {
            throw Invalid();
        }
        const std::string_view k = pair.substr(0, eq);
        const std::string_view v = pair.substr(eq + 1);
        if (k.empty() || v.empty() || k.size() > 32 || v.size() > TOKEN_CAP ||
            pair.find('%') != std::string_view::npos ||
            pair.find('+') != std::string_view::npos ||
            !result.emplace(std::string(k), std::string(v)).second) {
            throw Invalid();
        }
        if (amp == std::string_view::npos) {
            break;
        }
        raw = raw.substr(amp + 1);
    }
    return result;
}

Json AnchorJson(const Anchor &a) {
    return Json::Object({{"block_id", Hex(a.block_id)},
                         {"height", std::to_string(a.height)}});
}

struct Context {
    AuthoritativeState stamp;
    std::array<uint8_t, 16> epoch{};
    Binding binding;
    Anchor anchor;

    Json Snapshot() const {
        return Json::Object({{"chain_id", Hex(binding.chain_id)},
                             {"genesis", Hex(binding.genesis)},
                             {"profile_id", Hex(binding.profile)},
                             {"tip", Hex(anchor.block_id)},
                             {"height", std::to_string(anchor.height)},
                             {"service_epoch", Hex(epoch)},
                             {"generation", std::to_string(stamp.generation)}});
    }
    Json Coverage() const {
        return Json::Object({{"from_height", "0"},
                             {"through_height", std::to_string(anchor.height)},
                             {"complete", true},
                             {"scope", "canonical_confirmed"}});
    }
    std::string Token() const {
        Bytes b{1};
        b.insert(b.end(), epoch.begin(), epoch.end());
        for (int i = 7; i >= 0; --i) {
            b.push_back(uint8_t(stamp.generation >> (8 * i)));
        }
        for (const Bytes32 *h : {&binding.chain_id, &binding.genesis,
                                 &binding.profile, &anchor.block_id}) {
            b.insert(b.end(), h->begin(), h->end());
        }
        for (int i = 7; i >= 0; --i) {
            b.push_back(uint8_t(anchor.height >> (8 * i)));
        }
        return Hex(b);
    }
    void CheckToken(std::string_view s) const {
        if (s.size() != 322 || !IsLowerHex(s)) {
            throw Invalid();
        }
        if (s != Token()) {
            throw Error{409, "stale_snapshot"};
        }
    }
    Json Envelope(Json data) const {
        return Json::Object({{"api_version", "1"},
                             {"snapshot_token", Token()},
                             {"snapshot", Snapshot()},
                             {"coverage", Coverage()},
                             {"data", std::move(data)}});
    }
    std::string Confirmations(uint64_t height) const {
        if (height > anchor.height || anchor.height - height == UINT64_MAX) {
            throw Unavailable();
        }
        return std::to_string(anchor.height - height + 1);
    }
};

HttpResponse Failure(const Error &e, const Context *context) {
    return Response(
        e.status,
        Json::Object(
            {{"api_version", "1"},
             {"error", Json::Object({{"code", e.code},
                                     {"meaning", Meaning(e.code)}})},
             {"snapshot", context ? context->Snapshot() : Json()},
             {"coverage", context ? context->Coverage() : Json()}}));
}

// ---- cursors ----

/** Cursor fields in declaration order (derived Serialize). */
struct Cursor {
    uint64_t version = 0;
    std::string token;
    std::string route;
    Params params;
    std::string filter_digest;
    std::string last;
};

void WriteParams(const Params &params, std::string &out) {
    out += '{';
    bool first = true;
    for (const auto &[k, v] : params) {
        if (!first) {
            out += ',';
        }
        first = false;
        WriteJsonString(k, out);
        out += ':';
        WriteJsonString(v, out);
    }
    out += '}';
}

std::string CapJson(std::string bytes, size_t cap) {
    if (bytes.size() > cap) {
        throw RecordLimit();
    }
    return bytes;
}

std::string FilterDigest(const std::string &route, const Params &params,
                         const qb::Sha256Fn &sha256) {
    std::string json = "[";
    WriteJsonString("LotusExplorerCursor/1", json);
    json += ',';
    WriteJsonString(route, json);
    json += ',';
    WriteParams(params, json);
    json += ']';
    const std::string bytes = CapJson(std::move(json), TOKEN_CAP / 2);
    uint8_t digest[32];
    sha256(ByteView(reinterpret_cast<const uint8_t *>(bytes.data()),
                    bytes.size()),
           digest);
    return Hex(digest, 32);
}

std::string CursorEncode(const Cursor &c) {
    std::string json = "{\"version\":" + std::to_string(c.version) +
                       ",\"token\":";
    WriteJsonString(c.token, json);
    json += ",\"route\":";
    WriteJsonString(c.route, json);
    json += ",\"params\":";
    WriteParams(c.params, json);
    json += ",\"filter_digest\":";
    WriteJsonString(c.filter_digest, json);
    json += ",\"last\":";
    WriteJsonString(c.last, json);
    json += '}';
    const std::string bytes = CapJson(std::move(json), TOKEN_CAP / 2);
    return Hex(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size());
}

Cursor CursorDecode(std::string_view s, const qb::Sha256Fn &sha256) {
    if (s.size() > TOKEN_CAP || s.size() % 2 != 0 || !IsLowerHex(s)) {
        throw InvalidCursor();
    }
    const Bytes bytes = *HexDecode(s);
    std::optional<JsonNode> doc = ParseJson(bytes);
    if (!doc) {
        throw InvalidCursor();
    }
    Cursor c;
    const std::vector<JsonField> fields = {
        {"version", false, false,
         [&](const JsonNode *n) { return DecodeUnsigned(n, 255, c.version); }},
        {"token", false, false,
         [&](const JsonNode *n) { return DecodeString(n, c.token); }},
        {"route", false, false,
         [&](const JsonNode *n) { return DecodeString(n, c.route); }},
        {"params", false, false,
         [&](const JsonNode *n) {
             if (!n || n->kind != JsonNode::Kind::Obj) {
                 return false;
             }
             for (const auto &[k, v] : n->obj) {
                 std::string value;
                 if (!DecodeString(&v, value)) {
                     return false;
                 }
                 c.params[k] = std::move(value);
             }
             return true;
         }},
        {"filter_digest", false, false,
         [&](const JsonNode *n) { return DecodeString(n, c.filter_digest); }},
        {"last", false, false,
         [&](const JsonNode *n) { return DecodeString(n, c.last); }},
    };
    if (!DecodeStruct(*doc, fields)) {
        throw InvalidCursor();
    }
    if (c.version != 1 || c.last.size() > 348 || c.route.size() > 192 ||
        c.params.size() > 8 || c.token.size() != 322) {
        throw InvalidCursor();
    }
    if (c.filter_digest != FilterDigest(c.route, c.params, sha256)) {
        throw InvalidCursor();
    }
    return c;
}

bool Allowed(std::span<const std::string_view> allowed, std::string_view k) {
    for (std::string_view a : allowed) {
        if (a == k) {
            return true;
        }
    }
    return false;
}

struct Request {
    std::string route;
    Params params;
    std::optional<Bytes> last;
    size_t page = 25;
    bool pinned = false;

    Request(const std::string &route_, Params params_, const Context &context,
            std::span<const std::string_view> allowed,
            const qb::Sha256Fn &sha256) {
        for (const auto &[k, v] : params_) {
            if (k != "snapshot_token" && k != "cursor" && !Allowed(allowed, k)) {
                throw Invalid();
            }
        }
        pinned = params_.count("snapshot_token") > 0;
        if (auto it = params_.find("snapshot_token"); it != params_.end()) {
            const std::string token = it->second;
            params_.erase(it);
            context.CheckToken(token);
        }
        if (route_.starts_with("/assets/") && route_.ends_with("/outputs") &&
            !params_.count("cursor")) {
            params_.emplace("view", "history");
        }
        std::optional<Cursor> continuation;
        if (auto it = params_.find("cursor"); it != params_.end()) {
            const std::string s = it->second;
            params_.erase(it);
            continuation = CursorDecode(s, sha256);
        }
        if (continuation) {
            if (continuation->token != context.Token() ||
                continuation->route != route_) {
                throw StaleCursor();
            }
            for (const auto &[k, v] : params_) {
                auto it = continuation->params.find(k);
                if (it == continuation->params.end() || it->second != v) {
                    throw StaleCursor();
                }
            }
            params_ = continuation->params;
            for (const auto &[k, v] : params_) {
                if (!Allowed(allowed, k)) {
                    throw InvalidCursor();
                }
            }
            std::optional<Bytes> decoded = HexDecode(continuation->last);
            if (!decoded) {
                throw InvalidCursor();
            }
            last = std::move(decoded);
        }
        uint64_t page_size = 25;
        if (auto it = params_.find("page_size"); it != params_.end()) {
            page_size = Number(it->second);
        }
        if (page_size == 0 || page_size > 100) {
            throw Limits();
        }
        if (Allowed(allowed, "page_size")) {
            params_["page_size"] = std::to_string(page_size);
        }
        route = route_;
        params = std::move(params_);
        page = size_t(page_size);
    }

    std::string Continuation(const Context &context, const Bytes &key,
                             const qb::Sha256Fn &sha256) const {
        Cursor c;
        c.version = 1;
        c.token = context.Token();
        c.route = route;
        c.params = params;
        c.filter_digest = FilterDigest(route, params, sha256);
        c.last = Hex(key);
        return CursorEncode(c);
    }

    std::optional<uint64_t> Integer(const std::string &name) const {
        auto it = params.find(name);
        if (it == params.end()) {
            return std::nullopt;
        }
        return Number(it->second);
    }

    std::optional<uint32_t> Index() const {
        if (!last) {
            return std::nullopt;
        }
        if (last->size() != 4) {
            throw InvalidCursor();
        }
        return uint32_t((*last)[0]) << 24 | uint32_t((*last)[1]) << 16 |
               uint32_t((*last)[2]) << 8 | uint32_t((*last)[3]);
    }
};

Bytes BigEndian(uint64_t v, size_t n) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) {
        b[n - 1 - i] = uint8_t(v >> (8 * i));
    }
    return b;
}

uint64_t ReadBigEndian(const Bytes &b) {
    uint64_t v = 0;
    for (const uint8_t x : b) {
        v = (v << 8) | x;
    }
    return v;
}

struct Page {
    std::vector<Json> items;
    size_t bytes = 0;
    std::optional<Bytes> last;
    bool exhausted = false;
    size_t examined = 0;
    size_t reads = 0;

    void Read() {
        if (reads >= 4096) {
            throw Unavailable();
        }
        ++reads;
    }
    bool Push(Bytes key, Json value) {
        if (examined >= 1024) {
            return false;
        }
        ++examined;
        const size_t n = Encode(value, ITEM_CAP).size();
        if (n > ITEM_CAP - std::min(bytes, ITEM_CAP)) {
            if (items.empty()) {
                throw RecordLimit();
            }
            return false;
        }
        bytes += n;
        items.push_back(std::move(value));
        last = std::move(key);
        return true;
    }
    Json Finish(const Request &r, const Context &c,
                const qb::Sha256Fn &sha256) {
        Json next;
        if (!exhausted) {
            const std::optional<Bytes> &key = last ? last : r.last;
            if (!key) {
                throw Unavailable();
            }
            next = Json(r.Continuation(c, *key, sha256));
        }
        return Json::Object({{"items", Json::Array(std::move(items))},
                             {"next_cursor", std::move(next)},
                             {"exhausted", exhausted}});
    }
};

Json Location(const TxLocation &l) {
    return Json::Object({{"block_id", Hex(l.block_id.b)},
                         {"height", std::to_string(l.height)},
                         {"tx_index", std::to_string(l.tx_index)},
                         {"txid", Hex(l.txid.hash.b)},
                         {"txhash", Hex(l.txhash.hash.b)}});
}

Json OutputFields(const Output &out) {
    if (out.legacy_script) {
        return Json::Object({{"is_legacy", true},
                             {"value", std::to_string(out.value)},
                             {"legacy_script", Hex(*out.legacy_script)},
                             {"branches", Json::Array()},
                             {"paths", Json::Array()},
                             {"is_burn", out.IsBurn()},
                             {"has_token", false},
                             {"has_state", false}});
    }
    Json branches = Json::Array();
    for (const Hash32 &h : out.branches) {
        branches.Push(Hex(h.b));
    }
    Json paths = Json::Array();
    for (const auto &path : out.paths) {
        Json p = Json::Array();
        for (const uint8_t idx : path) {
            p.Push(std::to_string(idx));
        }
        paths.Push(std::move(p));
    }
    return Json::Object({{"flags", std::to_string(out.flags)},
                         {"value", std::to_string(out.value)},
                         {"has_token", out.HasToken()},
                         {"token_id", Hex(out.token_id.b)},
                         {"is_burn", out.IsBurn()},
                         {"has_state", out.HasState()},
                         {"state_root", Hex(out.state_root.b)},
                         {"branches", std::move(branches)},
                         {"paths", std::move(paths)}});
}

Json Record(const OutputRecord &r) {
    Json v = OutputFields(r.output);
    v.Set("txid", Hex(r.outpoint.txid.hash.b));
    v.Set("out_idx", std::to_string(r.outpoint.out_idx));
    v.Set("creation", Location(r.creation));
    v.Set("spend",
          r.spend ? Json::Object(
                        {{"transaction", Location(r.spend->transaction)},
                         {"input_index",
                          std::to_string(r.spend->input_index)}})
                  : Json());
    return v;
}

Json ByteRef(const WireRange &r) {
    return Json::Object({{"offset", std::to_string(r.offset)},
                         {"length", std::to_string(r.length)}});
}

Json TxSummary(const TxMeta &t, const Context &c) {
    return Json::Object(
        {{"txid", Hex(t.location.txid.hash.b)},
         {"txhash", Hex(t.location.txhash.hash.b)},
         {"location",
          Json::Object({{"block_id", Hex(t.location.block_id.b)},
                        {"height", std::to_string(t.location.height)},
                        {"tx_index", std::to_string(t.location.tx_index)}})},
         {"status", "confirmed"},
         {"confirmations", c.Confirmations(t.location.height)},
         {"input_count", std::to_string(t.input_count)},
         {"output_count", std::to_string(t.output_count)},
         {"wire_size", std::to_string(t.wire_size)}});
}

uint64_t ReadLe(const HeaderWire &w, size_t from, size_t to) {
    uint64_t v = 0;
    for (size_t i = from; i < to; ++i) {
        v |= uint64_t(w[i]) << (8 * (i - from));
    }
    return v;
}

std::string HexRange(const HeaderWire &w, size_t from, size_t to) {
    return Hex(w.data() + from, to - from);
}

Json BlockSummary(const BlockMeta &b, const Context &c, bool detail) {
    const HeaderWire &w = b.header_wire;
    Json v = Json::Object(
        {{"block_id", Hex(b.anchor.block_id)},
         {"prev_id", HexRange(w, 0, 32)},
         {"height", std::to_string(b.anchor.height)},
         {"time", std::to_string(ReadLe(w, 36, 42))},
         {"size", std::to_string(ReadLe(w, 54, 62))},
         {"tx_count", std::to_string(b.tx_count)},
         {"status", "confirmed"},
         {"confirmations", c.Confirmations(b.anchor.height)}});
    if (detail) {
        v.Set("header_wire", Hex(w));
        v.Set("body_availability", "complete");
        v.Set("finality", "unknown");
        v.Set("header",
              Json::Object({{"prev_id", HexRange(w, 0, 32)},
                            {"bits", std::to_string(ReadLe(w, 32, 36))},
                            {"time", std::to_string(ReadLe(w, 36, 42))},
                            {"nonce", std::to_string(ReadLe(w, 42, 50))},
                            {"version", std::to_string(ReadLe(w, 50, 54))},
                            {"size", std::to_string(ReadLe(w, 54, 62))},
                            {"height", std::to_string(ReadLe(w, 62, 70))},
                            {"tx_root", HexRange(w, 70, 102)},
                            {"state_root", HexRange(w, 102, 134)}}));
    }
    return v;
}

Json AssetSummaryJson(const AssetSummary &a) {
    return Json::Object(
        {{"token_id", Hex(a.token_id.b)},
         {"first_seen", Location(a.first_seen)},
         {"event_count", std::to_string(a.event_count)},
         {"output_count", std::to_string(a.output_count)},
         {"metadata", Json::Object({{"availability", "unknown"},
                                    {"name", Json()},
                                    {"symbol", Json()},
                                    {"decimals", Json()},
                                    {"issuer", Json()},
                                    {"mint_cap", Json()}})},
         {"supply", Json::Object({{"availability", "unknown"}})}});
}

Json AssetEventJson(const AssetEvent &a) {
    using query_explorer::UnsignedDecimal;
    return Json::Object(
        {{"token_id", Hex(a.token_id.b)},
         {"location", Location(a.location)},
         {"spent_units", UnsignedDecimal(a.spent_units)},
         {"output_units", UnsignedDecimal(a.output_units)},
         {"explicit_burn_units", UnsignedDecimal(a.explicit_burn_units)},
         {"minted_units", UnsignedDecimal(a.minted_units)},
         {"implicit_burn_units", UnsignedDecimal(a.implicit_burn_units)},
         {"has_mint_input", a.has_mint_input}});
}

std::vector<std::string_view> Parts(std::string_view path) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= path.size()) {
        const size_t slash = path.find('/', start);
        const std::string_view part =
            path.substr(start, slash == std::string_view::npos
                                   ? std::string_view::npos
                                   : slash - start);
        if (!part.empty()) {
            parts.push_back(part);
        }
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
    return parts;
}

using Pat = std::vector<std::string_view>;
/** Slice pattern match; "_" matches any part. */
bool Is(const std::vector<std::string_view> &p, const Pat &pat) {
    if (p.size() != pat.size()) {
        return false;
    }
    for (size_t i = 0; i < p.size(); ++i) {
        if (pat[i] != "_" && pat[i] != p[i]) {
            return false;
        }
    }
    return true;
}

void ValidateAssetKey(const std::optional<Bytes> &key,
                      std::string_view prefix,
                      const std::optional<Hash32> &token, size_t len) {
    if (!key) {
        return;
    }
    const Bytes &k = *key;
    if (k.size() != len || !std::equal(prefix.begin(), prefix.end(), k.begin(),
                                       [](char a, uint8_t b) {
                                           return uint8_t(a) == b;
                                       }) ||
        (token && !std::equal(token->b.begin(), token->b.end(),
                              k.begin() + 2))) {
        throw InvalidCursor();
    }
}

void ValidateToken(std::string_view s) {
    if (s.size() != 322 || !s.starts_with("01") || !IsLowerHex(s)) {
        throw Invalid();
    }
}

void ValidateParameter(std::string_view name, std::string_view value) {
    if (name == "page_size") {
        const uint64_t n = Number(value);
        if (n == 0 || n > 100) {
            throw Limits();
        }
    } else if (name == "length") {
        const uint64_t n = Number(value);
        if (n == 0 || n > 32768) {
            throw Limits();
        }
    } else if (name == "input_index") {
        Ordinal(value);
    } else if (name == "before_height" || name == "offset") {
        Number(value);
    } else if (name == "view") {
        if (value != "history" && value != "unspent") {
            throw Invalid();
        }
    } else {
        throw Invalid();
    }
}

struct BranchClause {
    std::string position;
    std::vector<std::string> roots;
};

struct BranchRequest {
    std::vector<std::string> any_branch;
    std::vector<BranchClause> positions;
    std::optional<std::string> page_size;
    std::optional<std::string> cursor;
    std::optional<bool> include_burn;
};

BranchRequest ParseBranchRequest(ByteView body) {
    std::optional<JsonNode> doc = ParseJson(body);
    if (!doc) {
        throw Invalid();
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
                          return DecodeString(v, c.position);
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
        {"page_size", false, true,
         [&](const JsonNode *n) { return DecodeOptString(n, r.page_size); }},
        {"cursor", false, true,
         [&](const JsonNode *n) { return DecodeOptString(n, r.cursor); }},
        {"include_burn", false, true,
         [&](const JsonNode *n) { return DecodeOptBool(n, r.include_burn); }},
    };
    if (!DecodeStruct(*doc, fields)) {
        throw Invalid();
    }
    return r;
}

size_t RootCount(const BranchRequest &r) {
    size_t n = r.any_branch.size();
    for (const BranchClause &c : r.positions) {
        n += c.roots.size();
    }
    return n;
}

/**
 * Parse and bound the request before any storage observation. Snapshot
 * equality is deliberately checked later, on a coherent ready view.
 */
void ValidateRequest(std::string_view path, const Params &params,
                     const Bytes &body, const qb::Sha256Fn &sha256) {
    const std::vector<std::string_view> parts = Parts(path);
    std::vector<std::string_view> allowed;
    std::optional<size_t> key_len;
    if (Is(parts, {"status"})) {
    } else if (Is(parts, {"blocks"})) {
        allowed = {"before_height", "page_size"};
        key_len = 8;
    } else if (Is(parts, {"blocks", "by-height", "_"})) {
        Number(parts[2]);
    } else if (Is(parts, {"blocks", "_"})) {
        ParseHash(parts[1]);
    } else if (Is(parts, {"blocks", "_", "transactions"})) {
        ParseHash(parts[1]);
        allowed = {"page_size"};
        key_len = 4;
    } else if (Is(parts, {"transactions", "by-id", "_"}) ||
               Is(parts, {"transactions", "by-hash", "_"})) {
        ParseHash(parts[2]);
    } else if (Is(parts, {"transactions", "by-id", "_", "inputs"}) ||
               Is(parts, {"transactions", "by-id", "_", "outputs"})) {
        ParseHash(parts[2]);
        allowed = {"page_size"};
        key_len = 4;
    } else if (Is(parts, {"transactions", "by-id", "_", "witnesses"})) {
        ParseHash(parts[2]);
        if (!params.count("input_index") && !params.count("cursor")) {
            throw Invalid();
        }
        allowed = {"input_index", "page_size"};
        key_len = 4;
    } else if (Is(parts, {"transactions", "by-id", "_", "wire"})) {
        ParseHash(parts[2]);
        allowed = {"offset", "length"};
    } else if (Is(parts, {"outputs", "_", "_"})) {
        ParseHash(parts[1]);
        Ordinal(parts[2]);
    } else if (Is(parts, {"assets"})) {
        allowed = {"page_size"};
        key_len = 34;
    } else if (Is(parts, {"assets", "_"})) {
        ParseHash(parts[1]);
    } else if (Is(parts, {"assets", "_", "events"})) {
        ParseHash(parts[1]);
        allowed = {"page_size"};
        key_len = 46;
    } else if (Is(parts, {"assets", "_", "outputs"})) {
        ParseHash(parts[1]);
        allowed = {"view", "page_size"};
        key_len = 50;
    } else if (Is(parts, {"branches", "_"}) &&
               (parts[1] == "outputs" || parts[1] == "utxos")) {
        for (const auto &[k, v] : params) {
            if (k != "snapshot_token") {
                throw Invalid();
            }
        }
        const BranchRequest r = ParseBranchRequest(body);
        if (parts[1] == "utxos" && r.include_burn) {
            throw Invalid();
        }
        if (RootCount(r) > 256 || r.positions.size() > 16) {
            throw Limits();
        }
        for (const std::string &root : r.any_branch) {
            ParseHash(root);
        }
        for (const BranchClause &p : r.positions) {
            if (Number(p.position) >= 16) {
                throw Limits();
            }
            for (const std::string &root : p.roots) {
                ParseHash(root);
            }
        }
        if (r.page_size) {
            const uint64_t n = Number(*r.page_size);
            if (n == 0 || n > 100) {
                throw Limits();
            }
        }
        if (r.cursor) {
            const Cursor c = CursorDecode(*r.cursor, sha256);
            std::optional<Bytes> last = HexDecode(c.last);
            if (!last) {
                throw Invalid();
            }
            if (last->size() != 36) {
                throw InvalidCursor();
            }
        }
        if (auto it = params.find("snapshot_token"); it != params.end()) {
            ValidateToken(it->second);
        }
        return;
    } else {
        throw Invalid();
    }
    if (!body.empty()) {
        throw Invalid();
    }
    for (const auto &[key, value] : params) {
        if (key == "snapshot_token" && path != "/status") {
            ValidateToken(value);
        } else if (key == "cursor" && key_len) {
            const Cursor c = CursorDecode(value, sha256);
            try {
                ValidateToken(c.token);
            } catch (const Error &) {
                throw InvalidCursor();
            }
            std::optional<Bytes> last = HexDecode(c.last);
            if (!last || last->size() != *key_len) {
                throw InvalidCursor();
            }
            for (const auto &[name, val] : c.params) {
                if (!Allowed(allowed, name)) {
                    throw InvalidCursor();
                }
                ValidateParameter(name, val);
            }
            if (Is(parts, {"assets", "_", "events"}) ||
                Is(parts, {"assets", "_", "outputs"})) {
                const Hash32 token = ParseHash(parts[1]);
                const std::string_view prefix =
                    parts[2] == "events" ? "eE" : "eP";
                ValidateAssetKey(last, prefix, token, *key_len);
            }
            if (path == "/assets") {
                ValidateAssetKey(last, "eA", std::nullopt, 34);
            }
        } else if (Allowed(allowed, key)) {
            ValidateParameter(key, value);
        } else {
            throw Invalid();
        }
    }
    if (Is(parts, {"transactions", "by-id", "_", "wire"})) {
        uint64_t offset = 0;
        if (auto it = params.find("offset"); it != params.end()) {
            offset = Number(it->second);
        }
        if (offset > 0 && !params.count("snapshot_token")) {
            throw Invalid();
        }
        uint64_t length = 32768;
        if (auto it = params.find("length"); it != params.end()) {
            length = Number(it->second);
        }
        if (offset > UINT64_MAX - length) {
            throw Limits();
        }
    }
}

qb::Snapshot BranchSnapshot(const ReadSnapshot &v) {
    return qb::Snapshot{.chain_id = H(v.binding.chain_id),
                        .profile_id = H(v.binding.profile),
                        .tip = H(v.anchor.block_id),
                        .height = v.anchor.height};
}

Error BranchError(const qb::QueryError &e) {
    switch (e.kind()) {
        case qb::QueryError::Kind::StaleCursor:
            return StaleCursor();
        case qb::QueryError::Kind::RecordTooLarge:
            return RecordLimit();
        case qb::QueryError::Kind::InvalidLimits:
            return Limits();
        case qb::QueryError::Kind::InvalidFilter:
            return Invalid();
        case qb::QueryError::Kind::Source:
            break;
    }
    return Unavailable();
}

Json Branches(std::string_view path, Params params, const Bytes &body,
              const ReadSnapshot &v, const Context &c,
              const qb::Sha256Fn &sha256) {
    for (const auto &[k, val] : params) {
        if (k != "snapshot_token") {
            throw Invalid();
        }
    }
    BranchRequest req = ParseBranchRequest(body);
    const bool history = path == "/branches/outputs";
    if (!history && req.include_burn) {
        throw Invalid();
    }
    if (req.positions.size() > 16 || RootCount(req) > 256) {
        throw Limits();
    }
    qb::BranchFilter filter;
    for (const std::string &s : req.any_branch) {
        filter.any_branch.push_back(ParseHash(s));
    }
    for (const BranchClause &p : req.positions) {
        qb::PositionClause clause;
        const uint64_t position = Number(p.position);
        if (position > 255) {
            throw Limits();
        }
        clause.position = uint8_t(position);
        for (const std::string &s : p.roots) {
            clause.roots.push_back(ParseHash(s));
        }
        filter.positions.push_back(std::move(clause));
    }
    const qb::QueryKind kind =
        history ? qb::QueryKind::History(req.include_burn.value_or(false))
                : qb::QueryKind::Utxos();
    qb::Limits caps;
    caps.page_size = 25;
    caps.work = 1024;
    caps.posting_reads = 1024;
    caps.result_bytes = 64 * 1024;
    Hash32 digest;
    try {
        digest = filter.Digest(kind, caps, sha256);
    } catch (const qb::QueryError &e) {
        throw BranchError(e);
    }
    params["filter"] = Hex(digest.b);
    if (req.page_size) {
        params["page_size"] = *req.page_size;
    }
    if (req.cursor) {
        params["cursor"] = *req.cursor;
    }
    static constexpr std::string_view kAllowed[] = {"filter", "page_size"};
    const Request r(std::string(path), std::move(params), c, kAllowed, sha256);
    caps.page_size = r.page;
    const qb::SnapshotPostingSource source(v);
    std::optional<qb::Cursor> prior;
    if (r.last) {
        if (r.last->size() != 36) {
            throw InvalidCursor();
        }
        qb::Cursor cursor;
        cursor.version = 1;
        cursor.snapshot = BranchSnapshot(v);
        cursor.filter_digest = digest;
        OutPoint op;
        std::copy_n(r.last->begin(), 32, op.txid.hash.b.begin());
        op.out_idx = uint32_t((*r.last)[32]) << 24 |
                     uint32_t((*r.last)[33]) << 16 |
                     uint32_t((*r.last)[34]) << 8 | uint32_t((*r.last)[35]);
        cursor.last_key = op;
        prior = cursor;
    }
    qb::Page page;
    try {
        page = qb::Query(source, filter, kind, caps, prior, sha256);
    } catch (const qb::QueryError &e) {
        throw BranchError(e);
    } catch (const std::exception &) {
        throw Unavailable();
    }
    Json items = Json::Array();
    for (const qb::Match &m : page.matches) {
        Json positions = Json::Array();
        for (const uint8_t p : m.matching_positions) {
            positions.Push(std::to_string(p));
        }
        items.Push(Json::Object({{"record", Record(m.record)},
                                 {"matching_positions", std::move(positions)}}));
    }
    // Engine results have their own logical budget; the JSON budget is
    // checked before the final authority fence.
    Encode(items, ITEM_CAP);
    Json next;
    if (page.continuation) {
        if (!page.continuation->last_key) {
            throw Unavailable();
        }
        const OutPoint &last = *page.continuation->last_key;
        Bytes key(last.txid.hash.b.begin(), last.txid.hash.b.end());
        const Bytes idx = BigEndian(last.out_idx, 4);
        key.insert(key.end(), idx.begin(), idx.end());
        next = Json(r.Continuation(c, key, sha256));
    }
    const bool exhausted = !page.continuation.has_value();
    return Json::Object({{"items", std::move(items)},
                         {"exhausted", exhausted},
                         {"next_cursor", std::move(next)},
                         {"posting_reads", std::to_string(page.posting_reads)},
                         {"work", std::to_string(page.work)}});
}

template <typename F>
Json IndexPage(const Request &r, const Context &c, uint32_t count, F &&item,
               const qb::Sha256Fn &sha256) {
    uint32_t index = 0;
    if (const std::optional<uint32_t> last = r.Index()) {
        if (*last >= count) {
            throw InvalidCursor();
        }
        if (*last == UINT32_MAX) {
            throw Unavailable();
        }
        index = *last + 1;
    }
    Page page;
    while (index < count && page.items.size() < r.page) {
        page.Read();
        if (!page.Push(BigEndian(index, 4), item(index))) {
            break;
        }
        ++index;
    }
    if (index == count) {
        page.exhausted = true;
    }
    return page.Finish(r, c, sha256);
}

Json Wire(const TxId &id, const Request &r, const ReadSnapshot &v) {
    const uint64_t offset = r.Integer("offset").value_or(0);
    const uint64_t length = r.Integer("length").value_or(32768);
    if (length == 0 || length > 32768) {
        throw Limits();
    }
    // A nonzero chunk requires a token so clients cannot assemble frames
    // across changed canonical membership.
    if (offset > 0 && !r.pinned) {
        throw Invalid();
    }
    const std::optional<TxMeta> t = Db([&] { return v.ExplorerTx(id); });
    if (!t) {
        throw Missing();
    }
    if (offset > t->wire_size) {
        throw Error{416, "invalid_range"};
    }
    if (offset > UINT64_MAX - length) {
        throw Limits();
    }
    const uint64_t end = std::min(offset + length, t->wire_size);
    Bytes bytes;
    bytes.reserve(size_t(end - offset));
    uint64_t pos = offset;
    while (pos < end) {
        if (pos / 32768 > UINT32_MAX) {
            throw Unavailable();
        }
        const auto chunk_index = uint32_t(pos / 32768);
        const std::optional<Bytes> chunk =
            Db([&] { return v.ExplorerWireChunk(id, chunk_index); });
        if (!chunk) {
            throw Unavailable();
        }
        const auto expected = size_t(std::min<uint64_t>(
            t->wire_size - uint64_t(chunk_index) * 32768, 32768));
        if (chunk->size() != expected) {
            throw Unavailable();
        }
        const auto from = size_t(pos % 32768);
        const size_t n = std::min(size_t(end - pos), chunk->size() - from);
        if (n == 0) {
            throw Unavailable();
        }
        bytes.insert(bytes.end(), chunk->begin() + from,
                     chunk->begin() + from + n);
        pos += n;
    }
    return Json::Object(
        {{"txid", Hex(id.hash.b)},
         {"txhash", Hex(t->location.txhash.hash.b)},
         {"total_bytes", std::to_string(t->wire_size)},
         {"offset", std::to_string(offset)},
         {"bytes_hex", Hex(bytes)},
         {"next_offset",
          end < t->wire_size ? Json(std::to_string(end)) : Json()}});
}

Json Dispatch(std::string_view path, Params params, const Bytes &body,
              const ReadSnapshot &v, const Context &c,
              AssetReadBudget &budget, const qb::Sha256Fn &sha256) {
    if (path.starts_with("/branches/")) {
        return Branches(path, std::move(params), body, v, c, sha256);
    }
    if (!body.empty()) {
        throw Invalid();
    }
    const std::vector<std::string_view> p = Parts(path);
    std::vector<std::string_view> allowed;
    if (Is(p, {"blocks"})) {
        allowed = {"before_height", "page_size"};
    } else if (Is(p, {"blocks", "_", "transactions"}) ||
               Is(p, {"transactions", "by-id", "_", "inputs"}) ||
               Is(p, {"transactions", "by-id", "_", "outputs"}) ||
               Is(p, {"assets"}) || Is(p, {"assets", "_", "events"})) {
        allowed = {"page_size"};
    } else if (Is(p, {"transactions", "by-id", "_", "witnesses"})) {
        allowed = {"input_index", "page_size"};
    } else if (Is(p, {"transactions", "by-id", "_", "wire"})) {
        allowed = {"offset", "length"};
    } else if (Is(p, {"assets", "_", "outputs"})) {
        allowed = {"view", "page_size"};
    }
    // Cursor is list-only. Snapshot tokens apply to every data route.
    if (params.count("cursor") && !Allowed(allowed, "page_size")) {
        throw Invalid();
    }
    Request r(std::string(path), std::move(params), c, allowed, sha256);
    if (Is(p, {"assets", "_", "outputs"})) {
        r.params.emplace("view", "history");
    }

    if (Is(p, {"blocks"})) {
        const std::optional<uint64_t> before = r.Integer("before_height");
        if (r.last) {
            if (r.last->size() != 8) {
                throw InvalidCursor();
            }
            const uint64_t last = ReadBigEndian(*r.last);
            if (last > c.anchor.height || (before && last >= *before)) {
                throw InvalidCursor();
            }
        }
        std::optional<uint64_t> height;
        if (r.last) {
            const uint64_t last = ReadBigEndian(*r.last);
            if (last > 0) {
                height = last - 1;
            }
        } else if (before) {
            if (*before > 0) {
                height = std::min(*before - 1, c.anchor.height);
            }
        } else {
            height = c.anchor.height;
        }
        Page page;
        while (page.items.size() < r.page) {
            if (!height) {
                page.exhausted = true;
                break;
            }
            const uint64_t h = *height;
            page.Read();
            const std::optional<BlockMeta> b =
                Db([&] { return v.ExplorerBlockAtHeight(h); });
            if (!b) {
                throw Unavailable();
            }
            if (!page.Push(BigEndian(h, 8), BlockSummary(*b, c, false))) {
                break;
            }
            height = h > 0 ? std::optional<uint64_t>(h - 1) : std::nullopt;
        }
        if (!height) {
            page.exhausted = true;
        }
        return page.Finish(r, c, sha256);
    }
    if (Is(p, {"blocks", "by-height", "_"})) {
        const uint64_t height = Number(p[2]);
        const std::optional<BlockMeta> b =
            Db([&] { return v.ExplorerBlockAtHeight(height); });
        if (!b) {
            throw Missing();
        }
        return BlockSummary(*b, c, true);
    }
    if (Is(p, {"blocks", "_"})) {
        const Hash32 id = ParseHash(p[1]);
        const std::optional<BlockMeta> b =
            Db([&] { return v.ExplorerBlock(id); });
        if (!b) {
            throw Missing();
        }
        return BlockSummary(*b, c, true);
    }
    if (Is(p, {"blocks", "_", "transactions"})) {
        const Hash32 id = ParseHash(p[1]);
        const std::optional<BlockMeta> b =
            Db([&] { return v.ExplorerBlock(id); });
        if (!b) {
            throw Missing();
        }
        return IndexPage(
            r, c, b->tx_count,
            [&](uint32_t index) {
                const auto ids =
                    Db([&] { return v.ExplorerBlockTx(id, index); });
                if (!ids) {
                    throw Unavailable();
                }
                const std::optional<TxMeta> t =
                    Db([&] { return v.ExplorerTx(ids->first); });
                if (!t) {
                    throw Unavailable();
                }
                if (t->location.txhash != ids->second ||
                    t->location.block_id != id ||
                    t->location.tx_index != index) {
                    throw Unavailable();
                }
                return TxSummary(*t, c);
            },
            sha256);
    }
    if (Is(p, {"transactions", "by-id", "_"}) ||
        Is(p, {"transactions", "by-hash", "_"})) {
        const Hash32 h = ParseHash(p[2]);
        const std::optional<TxMeta> t = Db([&] {
            return p[1] == "by-id" ? v.ExplorerTx(TxId{h})
                                   : v.ExplorerTxByHash(TxHash{h});
        });
        if (!t) {
            throw Missing();
        }
        Json value = TxSummary(*t, c);
        value.Extend(Json::Object(
            {{"lock", std::to_string(t->lock)},
             {"core_available", true},
             {"witness_available", true},
             {"wire_available", true},
             {"finality", "unknown"},
             {"accounting", Json::Object({{"availability", "unknown"}})}}));
        return value;
    }
    if (Is(p, {"transactions", "by-id", "_", "inputs"})) {
        const TxId id{ParseHash(p[2])};
        const std::optional<TxMeta> t = Db([&] { return v.ExplorerTx(id); });
        if (!t) {
            throw Missing();
        }
        return IndexPage(
            r, c, t->input_count,
            [&](uint32_t index) {
                const std::optional<InputMeta> i =
                    Db([&] { return v.ExplorerInput(id, index); });
                if (!i) {
                    throw Unavailable();
                }
                std::string kind;
                Json path_index;
                Json resolved;
                switch (i->flags) {
                    case 1:
                    case 4: {
                        if (!i->resolved_creation) {
                            throw Unavailable();
                        }
                        const ResolvedCreation &coin = *i->resolved_creation;
                        Json out = OutputFields(coin.output);
                        out.Extend(Json::Object(
                            {{"txid", Hex(coin.outpoint.txid.hash.b)},
                             {"out_idx", std::to_string(coin.outpoint.out_idx)},
                             {"creation", Location(coin.creation)}}));
                        kind = i->flags == 4 ? "legacy_spend" : "spend";
                        if (i->flags != 4)
                            path_index = Json(std::to_string(i->path_index));
                        resolved = Json::Object({{"availability", "complete"},
                                                 {"output", std::move(out)}});
                        break;
                    }
                    case 2:
                    case 5:
                        kind = i->flags == 5 ? "legacy_coinbase" : "coinbase";
                        resolved =
                            Json::Object({{"availability", "not_applicable"}});
                        break;
                    case 3:
                        kind = "mint";
                        resolved =
                            Json::Object({{"availability", "not_applicable"}});
                        break;
                    default:
                        throw Unavailable();
                }
                return Json::Object(
                    {{"input_index", std::to_string(index)},
                     {"flags", std::to_string(i->flags)},
                     {"kind", kind},
                     {"prev_txid", Hex(i->prev_txid)},
                     {"prev_index", std::to_string(i->prev_index)},
                     {"sequence", std::to_string(i->sequence)},
                     {"path_index", std::move(path_index)},
                     {"witness_count", std::to_string(i->witness_count)},
                     {"coinbase_data",
                      Json::Object({{"present", i->has_coinbase_data},
                                    {"wire_ref", i->has_coinbase_data
                                                     ? ByteRef(i->coinbase_data)
                                                     : Json()}})},
                     {"resolved_coin", std::move(resolved)}});
            },
            sha256);
    }
    if (Is(p, {"transactions", "by-id", "_", "outputs"})) {
        const TxId id{ParseHash(p[2])};
        const std::optional<TxMeta> t = Db([&] { return v.ExplorerTx(id); });
        if (!t) {
            throw Missing();
        }
        return IndexPage(
            r, c, t->output_count,
            [&](uint32_t index) {
                const std::optional<OutputRecord> rec =
                    Db([&] { return v.GetOutput(OutPoint{id, index}); });
                if (!rec) {
                    throw Unavailable();
                }
                return Record(*rec);
            },
            sha256);
    }
    if (Is(p, {"transactions", "by-id", "_", "witnesses"})) {
        const TxId id{ParseHash(p[2])};
        const std::optional<TxMeta> t = Db([&] { return v.ExplorerTx(id); });
        if (!t) {
            throw Missing();
        }
        const std::optional<uint64_t> index64 = r.Integer("input_index");
        if (!index64) {
            throw Invalid();
        }
        if (*index64 > UINT32_MAX) {
            throw Limits();
        }
        const auto index = uint32_t(*index64);
        if (index >= t->input_count) {
            throw Missing();
        }
        const std::optional<InputMeta> input =
            Db([&] { return v.ExplorerInput(id, index); });
        if (!input) {
            throw Unavailable();
        }
        return IndexPage(
            r, c, input->witness_count,
            [&](uint32_t w) {
                const std::optional<WitnessFact> fact =
                    Db([&] { return v.ExplorerWitness(id, index, w); });
                if (!fact) {
                    throw Unavailable();
                }
                return Json::Object(
                    {{"witness_index", std::to_string(w)},
                     {"script", ByteRef(fact->script)},
                     {"siblings",
                      Json::Object(
                          {{"count", std::to_string(fact->siblings_count)},
                           {"table_ref", ByteRef(fact->siblings_table)},
                           {"inline", Json()}})},
                     {"arguments",
                      Json::Object(
                          {{"count", std::to_string(fact->arguments_count)},
                           {"table_ref", ByteRef(fact->arguments_table)},
                           {"inline", Json()}})}});
            },
            sha256);
    }
    if (Is(p, {"transactions", "by-id", "_", "wire"})) {
        return Wire(TxId{ParseHash(p[2])}, r, v);
    }
    if (Is(p, {"outputs", "_", "_"})) {
        const OutPoint op{TxId{ParseHash(p[1])}, Ordinal(p[2])};
        const std::optional<OutputRecord> rec =
            Db([&] { return v.GetOutput(op); });
        if (!rec) {
            throw Missing();
        }
        return Record(*rec);
    }
    if (Is(p, {"assets"})) {
        Page page;
        std::optional<Bytes> after = r.last;
        ValidateAssetKey(after, "eA", std::nullopt, 34);
        while (page.items.size() < r.page && budget.Remaining() >= 4) {
            page.Read();
            auto next = Db([&] {
                return v.NextAssetSummaryCounted(
                    after ? std::optional<ByteView>(*after) : std::nullopt,
                    budget);
            });
            if (!next) {
                page.exhausted = true;
                break;
            }
            if (!page.Push(next->first, AssetSummaryJson(next->second))) {
                break;
            }
            after = next->first;
        }
        return page.Finish(r, c, sha256);
    }
    if (Is(p, {"assets", "_"})) {
        const Hash32 id = ParseHash(p[1]);
        const std::optional<AssetSummary> a =
            Db([&] { return v.AssetSummaryCounted(id, budget); });
        if (!a) {
            throw Missing();
        }
        return AssetSummaryJson(*a);
    }
    if (Is(p, {"assets", "_", "events"})) {
        const Hash32 id = ParseHash(p[1]);
        if (!Db([&] { return v.AssetSummaryCounted(id, budget); })) {
            throw Missing();
        }
        Page page;
        std::optional<Bytes> after = r.last;
        ValidateAssetKey(after, "eE", id, 46);
        while (page.items.size() < r.page && budget.Remaining() >= 4) {
            page.Read();
            auto next = Db([&] {
                return v.NextAssetEventCounted(
                    id, after ? std::optional<ByteView>(*after) : std::nullopt,
                    budget);
            });
            if (!next) {
                page.exhausted = true;
                break;
            }
            if (!page.Push(next->first, AssetEventJson(next->second))) {
                break;
            }
            after = next->first;
        }
        return page.Finish(r, c, sha256);
    }
    if (Is(p, {"assets", "_", "outputs"})) {
        const Hash32 id = ParseHash(p[1]);
        if (!Db([&] { return v.AssetSummaryCounted(id, budget); })) {
            throw Missing();
        }
        std::string view = "history";
        if (auto it = r.params.find("view"); it != r.params.end()) {
            view = it->second;
        }
        if (view != "history" && view != "unspent") {
            throw Invalid();
        }
        Page page;
        std::optional<Bytes> after = r.last;
        ValidateAssetKey(after, "eP", id, 50);
        while (page.items.size() < r.page && page.examined < 1024 &&
               budget.Remaining() >= 7) {
            page.Read();
            auto next = Db([&] {
                return v.NextAssetOutputCounted(
                    id, after ? std::optional<ByteView>(*after) : std::nullopt,
                    budget);
            });
            if (!next) {
                page.exhausted = true;
                break;
            }
            const Bytes key = next->first;
            const OutPoint op = next->second;
            page.Read();
            // The counted helper charges the output and each canonical
            // location join immediately before its storage read.
            const std::optional<OutputRecord> out =
                Db([&] { return v.OutputCounted(op, budget); });
            if (!out) {
                throw Unavailable();
            }
            if (out->outpoint != op || out->creation.txid != op.txid ||
                !out->output.HasToken() || out->output.token_id != id ||
                AssetOutputKey(id, out->creation, op.out_idx) != key) {
                throw Unavailable();
            }
            if (view == "unspent" &&
                (out->output.IsBurn() || out->spend.has_value())) {
                ++page.examined;
                page.last = key;
                after = key;
                continue;
            }
            if (!page.Push(key, Record(*out))) {
                break;
            }
            after = key;
        }
        return page.Finish(r, c, sha256);
    }
    throw Invalid();
}

HttpResponse StatusRoute(const V2HttpState &s,
                         const std::optional<AuthoritativeState> &stamp,
                         SharedV2Db &db) {
    const Binding binding = db.db.GetBinding();
    std::optional<Anchor> indexed;
    try {
        indexed = db.db.Checkpoint();
    } catch (const std::exception &) {
        return Failure(Unavailable(), nullptr);
    }
    if (Observe(s) != stamp) {
        return Failure(Unavailable(), nullptr);
    }
    const std::optional<Anchor> authority =
        stamp ? stamp->anchor : std::nullopt;
    const bool index_error = s.index_error && s.index_error->load();
    const bool ready = !index_error && indexed && indexed == authority;
    std::string_view reason;
    if (index_error) {
        reason = "index_error";
    } else if (!authority) {
        reason = "authority_unknown";
    } else if (!indexed) {
        reason = "initializing";
    } else if (!ready) {
        reason = "catching_up";
    } else {
        reason = "ready";
    }
    Json coverage;
    if (indexed) {
        coverage = Json::Object(
            {{"from_height", "0"},
             {"through_height", std::to_string(indexed->height)},
             {"complete", ready},
             {"scope", "canonical_confirmed"}});
    }
    const Json value = Json::Object(
        {{"api_version", "1"},
         {"ready", ready},
         {"reason", reason},
         {"indexed_anchor", indexed ? AnchorJson(*indexed) : Json()},
         {"authoritative_anchor", authority ? AnchorJson(*authority) : Json()},
         {"service_epoch", Hex(s.service_epoch)},
         {"generation",
          stamp ? Json(std::to_string(stamp->generation)) : Json()},
         {"binding", Json::Object({{"chain_id", Hex(binding.chain_id)},
                                   {"genesis", Hex(binding.genesis)},
                                   {"profile_id", Hex(binding.profile)}})},
         {"coverage", std::move(coverage)},
         {"capabilities", Json::Object({{"blocks", true},
                                        {"transactions", true},
                                        {"transaction_wire", true},
                                        {"outputs", true},
                                        {"assets", true},
                                        {"asset_events", true},
                                        {"branches", true},
                                        {"accepted_pool", false},
                                        {"detached_history", false},
                                        {"finality", false}})},
         {"limits",
          Json::Object({{"request_bytes", std::to_string(REQUEST_CAP)},
                        {"response_bytes", std::to_string(JSON_CAP)},
                        {"page_size", "100"},
                        {"cursor_bytes", std::to_string(TOKEN_CAP)},
                        {"wire_chunk_bytes", "32768"},
                        {"examined_records", "1024"},
                        {"key_reads", "4096"}})}});
    HttpResponse result = Response(200, value);
    return Observe(s) == stamp ? std::move(result)
                               : Failure(Unavailable(), nullptr);
}

HttpResponse Handle(const std::optional<V2HttpState> &state,
                    const HttpRequest &req) {
    const std::string target = req.Target();
    if (target.size() > REQUEST_CAP) {
        return Failure({413, "request_limit"}, nullptr);
    }
    Params params;
    try {
        params = Query(req);
    } catch (const Error &e) {
        return Failure(e, nullptr);
    }
    const std::string_view path =
        std::string_view(req.path).starts_with(PREFIX)
            ? std::string_view(req.path).substr(PREFIX.size())
            : std::string_view();
    if (path.find('%') != std::string_view::npos) {
        return Failure(Invalid(), nullptr);
    }
    if (req.body_too_large || req.body.size() > REQUEST_CAP ||
        target.size() + req.body.size() > REQUEST_CAP) {
        return Failure({413, "request_limit"}, nullptr);
    }
    // The cursor digests need the host SHA-256, which only the service
    // supplies (Rust links its own): without one nothing can be validated.
    static const qb::Sha256Fn kNoSha256 = [](ByteView, uint8_t out[32]) {
        std::fill_n(out, 32, uint8_t{0});
    };
    const qb::Sha256Fn &sha256 =
        state && state->sha256 ? state->sha256 : kNoSha256;
    try {
        ValidateRequest(path, params, req.body, sha256);
    } catch (const Error &e) {
        return Failure(e, nullptr);
    }
    if (!state) {
        return Failure(Unavailable(), nullptr);
    }
    const V2HttpState &s = *state;
    const std::optional<AuthoritativeState> observed = Observe(s);
    std::unique_lock<std::mutex> lock(s.db->mutex, std::try_to_lock);
    if (!lock) {
        return Failure(Unavailable(), nullptr);
    }
    if (path == "/status") {
        if (!params.empty() || !req.body.empty()) {
            return Failure(Invalid(), nullptr);
        }
        return StatusRoute(s, observed, *s.db);
    }
    const auto index_error = [&] {
        return s.index_error && s.index_error->load();
    };
    if (index_error() || !observed || !observed->anchor) {
        return Failure(Unavailable(), nullptr);
    }
    AssetReadBudget budget(4096);
    // Snapshot construction reads the checkpoint key. Reserve it before
    // I/O; asset iteration and all secondary joins share the remaining
    // budget.
    try {
        budget.Charge();
    } catch (const std::exception &) {
        return Failure(Unavailable(), nullptr);
    }
    std::optional<ReadSnapshot> view;
    try {
        view.emplace(s.db->db.Snapshot());
    } catch (const std::exception &) {
        return Failure(Unavailable(), nullptr);
    }
    const AuthoritativeState stamp = *observed;
    if (Observe(s) != stamp || stamp.anchor != view->anchor) {
        return Failure(Unavailable(), nullptr);
    }
    const Context context{stamp, s.service_epoch, view->binding, view->anchor};
    HttpResponse result;
    try {
        const Json value = context.Envelope(Dispatch(
            path, std::move(params), req.body, *view, context, budget, sha256));
        // The capped encoder runs before the final stamp observation.
        Encode(value, JSON_CAP);
        result = Response(200, value);
    } catch (const Error &e) {
        result = Failure(e, &context);
    }
    if (!index_error() && Observe(s) == stamp) {
        return result;
    }
    return Failure(Unavailable(), nullptr);
}

} // namespace

void RegisterV2ExplorerRoutes(Router &router, V2HttpStateProvider provider) {
    auto handler = [provider](const HttpRequest &req, const PathParams &) {
        return Handle(provider(), req);
    };
    for (std::string_view path : {
             "/status",
             "/blocks",
             "/blocks/by-height/:height",
             "/blocks/:block_id",
             "/blocks/:block_id/transactions",
             "/transactions/by-id/:txid",
             "/transactions/by-hash/:txhash",
             "/transactions/by-id/:txid/inputs",
             "/transactions/by-id/:txid/outputs",
             "/transactions/by-id/:txid/witnesses",
             "/transactions/by-id/:txid/wire",
             "/outputs/:txid/:out_idx",
             "/assets",
             "/assets/:token_id",
             "/assets/:token_id/events",
             "/assets/:token_id/outputs",
         }) {
        router.Get(std::string(PREFIX) + std::string(path), handler,
                   Router::PathExtraction::Raw);
    }
    for (std::string_view path : {"/branches/outputs", "/branches/utxos"}) {
        router.Post(std::string(PREFIX) + std::string(path), handler,
                    Router::PathExtraction::Raw);
    }
}

} // namespace chronik::native::lotus_v2::http
