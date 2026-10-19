// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Router with the observable semantics of axum 0.7.9 (matchit routing,
// MethodRouter 405/Allow/HEAD handling, Router::fallback) and tower-http 0.5.2
// CorsLayer::new().allow_origin(any).allow_methods(any), as configured by
// chronik-http/src/server.rs.

#include <chronik/native/error.h>
#include <chronik/native/http.h>

#include <cctype>
#include <chrono>
#include <stdexcept>

namespace chronik::native {

namespace {

constexpr std::string_view CORS_VARY =
    "origin, access-control-request-method, access-control-request-headers";

std::vector<std::string_view> SplitPath(std::string_view path) {
    std::vector<std::string_view> segments;
    // Paths always start with '/'; split the rest on '/', keeping empty
    // segments so "/a/" and "/a" differ, as in matchit.
    if (path.empty() || path[0] != '/') {
        segments.push_back(path);
        return segments;
    }
    std::string_view rest = path.substr(1);
    while (true) {
        size_t slash = rest.find('/');
        segments.push_back(rest.substr(0, slash));
        if (slash == std::string_view::npos) {
            break;
        }
        rest = rest.substr(slash + 1);
    }
    return segments;
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/** percent_encoding::percent_decode */
std::string PercentDecode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size() && HexVal(in[i + 1]) >= 0 &&
            HexVal(in[i + 2]) >= 0) {
            out.push_back(char(HexVal(in[i + 1]) * 16 + HexVal(in[i + 2])));
            i += 2;
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

bool IsValidUtf8(std::string_view s) {
    const auto *p = reinterpret_cast<const uint8_t *>(s.data());
    size_t i = 0, n = s.size();
    while (i < n) {
        uint8_t b = p[i];
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (b < 0x80) {
            ++i;
            continue;
        } else if (b >= 0xC2 && b <= 0xDF) {
            need = 1;
        } else if (b >= 0xE0 && b <= 0xEF) {
            need = 2;
            lo = b == 0xE0 ? 0xA0 : 0x80;
            hi = b == 0xED ? 0x9F : 0xBF;
        } else if (b >= 0xF0 && b <= 0xF4) {
            need = 3;
            lo = b == 0xF0 ? 0x90 : 0x80;
            hi = b == 0xF4 ? 0x8F : 0xBF;
        } else {
            return false;
        }
        if (i + need >= n) {
            return false;
        }
        for (size_t j = 1; j <= need; ++j) {
            uint8_t c = p[i + j];
            uint8_t l = j == 1 ? lo : 0x80, h = j == 1 ? hi : 0xBF;
            if (c < l || c > h) {
                return false;
            }
        }
        i += need + 1;
    }
    return true;
}

bool HeaderEqIgnoreCase(const std::string *value, std::string_view expected) {
    if (!value || value->size() != expected.size()) {
        return false;
    }
    for (size_t i = 0; i < expected.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>((*value)[i])) !=
            std::tolower(static_cast<unsigned char>(expected[i]))) {
            return false;
        }
    }
    return true;
}

bool HeaderContainsLower(const std::string *value, std::string_view needle) {
    if (!value || !IsValidUtf8(*value)) {
        return false;
    }
    std::string lower = *value;
    for (char &c : lower) {
        c = char(std::tolower(static_cast<unsigned char>(c)));
    }
    return lower.find(needle) != std::string::npos;
}

/**
 * axum 0.7 WebSocketUpgrade::from_request_parts checks, in order. Returns
 * nullopt if the request can be upgraded.
 */
std::optional<HttpResponse> WebSocketRejection(const HttpRequest &req) {
    if (req.method != "GET") {
        return HttpResponse::Text(405, "Request method must be `GET`");
    }
    if (!HeaderContainsLower(req.Header("connection"), "upgrade")) {
        return HttpResponse::Text(
            400, "Connection header did not include 'upgrade'");
    }
    if (!HeaderEqIgnoreCase(req.Header("upgrade"), "websocket")) {
        return HttpResponse::Text(
            400, "`Upgrade` header did not include 'websocket'");
    }
    if (!HeaderEqIgnoreCase(req.Header("sec-websocket-version"), "13")) {
        return HttpResponse::Text(
            400, "`Sec-WebSocket-Version` header did not include '13'");
    }
    if (!req.Header("sec-websocket-key")) {
        return HttpResponse::Text(400, "`Sec-WebSocket-Key` header missing");
    }
    return std::nullopt;
}

} // namespace

struct Router::Segment {
    bool is_param;
    std::string text; // literal, or param name
};

struct Router::Route {
    std::string pattern;
    std::vector<Segment> segments;
    std::vector<std::string> param_names;
    // Registration order matters for the Allow header.
    std::vector<std::pair<std::string, HttpHandler>> methods;
    std::string allow;
    bool is_websocket = false;

    const HttpHandler *Find(std::string_view method) const {
        for (const auto &[m, h] : methods) {
            if (m == method) {
                return &h;
            }
        }
        return nullptr;
    }
};

Router::~Router() = default;
Router::Router(Router &&) noexcept = default;
Router &Router::operator=(Router &&) noexcept = default;

Router::Router(RouterOptions opts) : m_opts(std::move(opts)) {
    m_fallback = [](const HttpRequest &req, const PathParams &) {
        // Port of handlers::handle_not_found: RouteNotFound(Uri)
        throw ChronikError("404: Not found: " + req.Target());
        return HttpResponse{};
    };
}

void Router::Add(std::string_view method, std::string_view pattern,
                 HttpHandler handler) {
    Route *route = nullptr;
    for (auto &r : m_routes) {
        if (r->pattern == pattern) {
            route = r.get();
        }
    }
    if (!route) {
        auto new_route = std::make_unique<Route>();
        new_route->pattern = std::string(pattern);
        for (std::string_view seg : SplitPath(pattern)) {
            if (!seg.empty() && seg[0] == ':') {
                new_route->segments.push_back({true, std::string(seg.substr(1))});
                new_route->param_names.emplace_back(seg.substr(1));
            } else {
                new_route->segments.push_back({false, std::string(seg)});
            }
        }
        route = new_route.get();
        m_routes.push_back(std::move(new_route));
    }
    if (route->Find(method)) {
        throw std::logic_error("Overlapping method route for " +
                               std::string(pattern));
    }
    route->methods.emplace_back(std::string(method), std::move(handler));
    // axum append_allow_header: GET registers "GET,HEAD"
    auto append = [&](std::string_view m) {
        if (route->allow.find(m) != std::string::npos) {
            return;
        }
        if (!route->allow.empty()) {
            route->allow += ",";
        }
        route->allow += m;
    };
    append(method);
    if (method == "GET") {
        append("HEAD");
    }
}

void Router::PostWithOptions(std::string_view pattern, HttpHandler h) {
    Add("POST", pattern, std::move(h));
    Add("OPTIONS", pattern, [](const HttpRequest &, const PathParams &) {
        HttpResponse resp = HttpResponse::Empty(200);
        resp.headers.emplace_back("Allow", "OPTIONS, HEAD, POST");
        return resp;
    });
}

void Router::AddWebSocket(std::string_view pattern) {
    Add("GET", pattern, [](const HttpRequest &req, const PathParams &) {
        if (auto rejection = WebSocketRejection(req)) {
            return *rejection;
        }
        // All headers fine but the transport didn't upgrade (e.g. HTTP/1.0
        // or an in-process transport without upgrade support).
        return HttpResponse::Text(426, "WebSocket request couldn't be "
                                       "upgraded since no upgrade state was "
                                       "present");
    });
    for (auto &r : m_routes) {
        if (r->pattern == pattern) {
            r->is_websocket = true;
        }
    }
}

void Router::SetFallback(HttpHandler handler) {
    m_fallback = std::move(handler);
}

const Router::Route *
Router::Match(std::string_view path,
              std::vector<std::string_view> &raw_params) const {
    const std::vector<std::string_view> segs = SplitPath(path);
    const Route *best = nullptr;
    std::vector<std::string_view> best_params;
    // matchit prefers static segments over params at the first segment where
    // candidate routes differ: compare match "shapes" lexicographically with
    // static < param.
    std::vector<bool> best_shape;
    for (const auto &route : m_routes) {
        if (route->segments.size() != segs.size()) {
            continue;
        }
        std::vector<std::string_view> params;
        std::vector<bool> shape;
        bool ok = true;
        for (size_t i = 0; i < segs.size(); ++i) {
            const Segment &seg = route->segments[i];
            if (seg.is_param) {
                // matchit 0.7 (axum 0.7): a param matches an empty segment
                // in the middle of a path ("/script//x/history"), but not an
                // empty last segment (the parent's prefix must be followed
                // by at least one byte).
                if (segs[i].empty() && i + 1 == segs.size()) {
                    ok = false;
                    break;
                }
                params.push_back(segs[i]);
                shape.push_back(true);
            } else {
                if (seg.text != segs[i]) {
                    ok = false;
                    break;
                }
                shape.push_back(false);
            }
        }
        if (!ok) {
            continue;
        }
        if (!best || shape < best_shape) {
            best = route.get();
            best_params = std::move(params);
            best_shape = std::move(shape);
        }
    }
    raw_params = std::move(best_params);
    return best;
}

HttpResponse Router::Dispatch(const HttpRequest &req) const {
    std::vector<std::string_view> raw_params;
    const Route *route = Match(req.path, raw_params);
    PathParams params;
    auto call = [&](const HttpHandler &handler) -> HttpResponse {
        try {
            return handler(req, params);
        } catch (const std::exception &err) {
            return ExceptionResponse(err, m_opts.log);
        }
    };
    if (!route) {
        return call(m_fallback);
    }
    const HttpHandler *handler = route->Find(req.method);
    bool strip_body = false;
    if (!handler && req.method == "HEAD") {
        handler = route->Find("GET");
        strip_body = handler != nullptr;
    }
    if (!handler) {
        // MethodRouter default fallback: 405 with the Allow header
        HttpResponse resp = HttpResponse::Empty(405);
        resp.headers.emplace_back("allow", route->allow);
        return resp;
    }
    // Path extractor: percent-decode params; invalid UTF-8 is a rejection.
    // Only routes with params extract them (Path<...>).
    params.names = route->param_names;
    for (size_t i = 0; i < raw_params.size(); ++i) {
        std::string decoded = PercentDecode(raw_params[i]);
        if (!IsValidUtf8(decoded)) {
            HttpResponse resp = HttpResponse::Text(
                400, "Invalid URL: Invalid UTF-8 in `" +
                         route->param_names[i] + "`");
            if (strip_body) {
                resp.SetHeader("content-length",
                               std::to_string(resp.body.size()));
                resp.body.clear();
            }
            return resp;
        }
        params.values.push_back(std::move(decoded));
    }
    HttpResponse resp = call(*handler);
    if (strip_body) {
        // axum: set content-length before removing the body
        if (!resp.Header("content-length")) {
            resp.headers.emplace_back("content-length",
                                      std::to_string(resp.body.size()));
        }
        resp.body.clear();
    }
    return resp;
}

void Router::ApplyCors(HttpResponse &resp) const {
    // extend() overwrites allow-origin; vary is appended
    resp.SetHeader("access-control-allow-origin", "*");
    resp.headers.emplace_back("vary", std::string(CORS_VARY));
}

HttpResponse Router::Handle(const HttpRequest &req) const {
    const auto start = m_opts.observe_request ? std::chrono::steady_clock::now()
                                             : std::chrono::steady_clock::time_point{};
    const auto finish = [&](HttpResponse resp) {
        if (m_opts.observe_request) {
            try {
                m_opts.observe_request(req.path, resp.status,
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - start).count());
            } catch (...) {
                // Operator bookkeeping never changes a protocol response.
            }
        }
        return resp;
    };
    if (m_opts.enable_cors && req.method == "OPTIONS") {
        // tower-http answers every OPTIONS request as a preflight
        HttpResponse resp = HttpResponse::Empty(200);
        resp.headers.emplace_back("access-control-allow-origin", "*");
        resp.headers.emplace_back("vary", std::string(CORS_VARY));
        resp.headers.emplace_back("access-control-allow-methods", "*");
        return finish(std::move(resp));
    }
    HttpResponse resp = Dispatch(req);
    if (m_opts.enable_cors) {
        ApplyCors(resp);
    }
    return finish(std::move(resp));
}

bool Router::IsWebSocketUpgrade(const HttpRequest &req) const {
    std::vector<std::string_view> raw_params;
    const Route *route = Match(req.path, raw_params);
    if (!route || !route->is_websocket) {
        return false;
    }
    return !WebSocketRejection(req).has_value();
}

std::vector<HttpHeader>
Router::UpgradeResponseHeaders(const HttpRequest &req) const {
    const auto start = m_opts.observe_request ? std::chrono::steady_clock::now()
                                             : std::chrono::steady_clock::time_point{};
    std::vector<HttpHeader> headers;
    if (m_opts.enable_cors) {
        headers.emplace_back("access-control-allow-origin", "*");
        headers.emplace_back("vary", std::string(CORS_VARY));
    }
    if (m_opts.observe_request) {
        try {
            // The successful upgrade bypasses Handle; count it once here.
            m_opts.observe_request(req.path, 101,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - start).count());
        } catch (...) {
        }
    }
    return headers;
}

} // namespace chronik::native
