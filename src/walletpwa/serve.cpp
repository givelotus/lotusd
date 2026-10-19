// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletpwa/serve.h>

#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <system_error>

namespace walletpwa {

static int HexValue(char c) {
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

std::optional<std::string> NormalizeAssetPath(std::string_view raw) {
    raw = raw.substr(0, std::min(raw.find('?'), raw.size()));
    std::string path;
    path.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] != '%') {
            path.push_back(raw[i]);
            continue;
        }
        if (i + 2 >= raw.size()) {
            return std::nullopt;
        }
        const int hi{HexValue(raw[i + 1])};
        const int lo{HexValue(raw[i + 2])};
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        const char decoded{static_cast<char>(hi * 16 + lo)};
        // An encoded separator is never a plain file name.
        if (decoded == '/' || decoded == '\\') {
            return std::nullopt;
        }
        path.push_back(decoded);
        i += 2;
    }
    if (path.empty()) {
        return "index.html";
    }
    if (path.size() > MAX_ASSET_PATH_LENGTH || path.front() == '/' ||
        path.find('\\') != std::string::npos ||
        path.find('\0') != std::string::npos) {
        return std::nullopt;
    }
    size_t pos{0};
    while (pos <= path.size()) {
        const size_t slash{std::min(path.find('/', pos), path.size())};
        const std::string_view segment{
            std::string_view{path}.substr(pos, slash - pos)};
        // Covers "", ".", ".." and dot-files.
        if (segment.empty() || segment.front() == '.') {
            return std::nullopt;
        }
        pos = slash + 1;
    }
    return path;
}

std::optional<std::string_view> MimeType(std::string_view path) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>,
                                13>
        TYPES{{
            {".html", "text/html; charset=utf-8"},
            {".js", "text/javascript; charset=utf-8"},
            {".mjs", "text/javascript; charset=utf-8"},
            {".css", "text/css; charset=utf-8"},
            {".json", "application/json"},
            {".webmanifest", "application/manifest+json"},
            {".svg", "image/svg+xml"},
            {".png", "image/png"},
            {".ico", "image/x-icon"},
            {".woff2", "font/woff2"},
            {".wasm", "application/wasm"},
            {".wgsl", "text/plain; charset=utf-8"},
            {".txt", "text/plain; charset=utf-8"},
        }};
    const size_t slash{path.rfind('/')};
    const size_t dot{path.rfind('.')};
    if (dot == std::string_view::npos ||
        (slash != std::string_view::npos && dot < slash)) {
        return std::nullopt;
    }
    const std::string ext{ToLower(path.substr(dot))};
    for (const auto &[e, type] : TYPES) {
        if (e == ext) {
            return type;
        }
    }
    return std::nullopt;
}

static std::string_view TrimSpace(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

/** Split a comma-separated header value into trimmed, non-empty items */
static std::vector<std::string_view> SplitList(std::string_view value) {
    std::vector<std::string_view> items;
    while (true) {
        const size_t comma{value.find(',')};
        const std::string_view item{TrimSpace(value.substr(0, comma))};
        if (!item.empty()) {
            items.push_back(item);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return items;
}

/** Whether a q-value ("0", "0.0", "1", "0.5", ...) is greater than zero */
static bool PositiveQ(std::string_view q) {
    return std::any_of(q.begin(), q.end(),
                       [](char c) { return c >= '1' && c <= '9'; });
}

bool AcceptsGzip(std::string_view accept_encoding) {
    std::optional<bool> gzip;
    std::optional<bool> any;
    for (std::string_view item : SplitList(accept_encoding)) {
        const size_t semi{item.find(';')};
        const std::string coding{ToLower(TrimSpace(item.substr(0, semi)))};
        bool positive{true};
        if (semi != std::string_view::npos) {
            const std::string params{ToLower(item.substr(semi + 1))};
            const size_t q{params.find("q=")};
            if (q != std::string::npos) {
                positive = PositiveQ(
                    TrimSpace(std::string_view{params}.substr(q + 2)));
            }
        }
        if (coding == "gzip" || coding == "x-gzip") {
            gzip = positive;
        } else if (coding == "*") {
            any = positive;
        }
    }
    return gzip.value_or(any.value_or(false));
}

bool IfNoneMatchMatches(std::string_view if_none_match, std::string_view etag) {
    const auto opaque = [](std::string_view tag) {
        if (tag.substr(0, 2) == "W/") {
            tag.remove_prefix(2);
        }
        return tag;
    };
    for (std::string_view item : SplitList(if_none_match)) {
        if (item == "*" || opaque(item) == opaque(etag)) {
            return true;
        }
    }
    return false;
}

const HeaderList &SecurityHeaders() {
    static const HeaderList HEADERS{
        {"Content-Security-Policy",
         "default-src 'none'; script-src 'self'; style-src 'self'; "
         "img-src 'self' data: blob:; connect-src 'self'; "
         "manifest-src 'self'; worker-src 'self'; font-src 'self'; "
         "media-src 'self'; form-action 'none'; frame-ancestors 'none'; "
         "base-uri 'none'"},
        {"X-Content-Type-Options", "nosniff"},
        {"Referrer-Policy", "no-referrer"},
        {"X-Frame-Options", "DENY"},
        {"Cross-Origin-Opener-Policy", "same-origin"},
        {"Cross-Origin-Resource-Policy", "same-origin"},
        {"Permissions-Policy",
         "camera=(self), microphone=(), geolocation=(), usb=(), hid=()"},
    };
    return HEADERS;
}

static AssetReply NotFound() {
    AssetReply reply;
    reply.status = 404;
    reply.headers = SecurityHeaders();
    reply.headers.emplace_back("Content-Type", "text/plain; charset=utf-8");
    reply.headers.emplace_back("Cache-Control", "no-store");
    reply.body = "Not found\n";
    return reply;
}

AssetReply ServeAsset(std::span<const EmbeddedAsset> assets,
                      std::string_view raw,
                      const std::optional<std::string> &accept_encoding,
                      const std::optional<std::string> &if_none_match) {
    const auto path{NormalizeAssetPath(raw)};
    if (!path || !MimeType(*path)) {
        return NotFound();
    }
    const auto it{
        std::lower_bound(assets.begin(), assets.end(), *path,
                         [](const EmbeddedAsset &a, const std::string &p) {
                             return a.path < p;
                         })};
    if (it == assets.end() || it->path != *path) {
        return NotFound();
    }
    const bool gzip{!it->body_gzip.empty() && accept_encoding &&
                    AcceptsGzip(*accept_encoding)};
    std::string etag{it->etag};
    if (gzip) {
        // Each representation has its own tag: "<hash>" and "<hash>-gz".
        etag.insert(etag.size() - 1, "-gz");
    }

    AssetReply reply;
    reply.headers = SecurityHeaders();
    reply.headers.emplace_back("Content-Type", std::string{it->content_type});
    reply.headers.emplace_back("ETag", etag);
    reply.headers.emplace_back("Cache-Control", "no-cache");
    reply.headers.emplace_back("Vary", "Accept-Encoding");
    if (if_none_match && IfNoneMatchMatches(*if_none_match, etag)) {
        reply.status = 304;
        return reply;
    }
    reply.status = 200;
    if (gzip) {
        reply.headers.emplace_back("Content-Encoding", "gzip");
        reply.body = std::string{it->body_gzip};
    } else {
        reply.body = std::string{it->body};
    }
    return reply;
}

AssetReply ServeFromDirectory(const fs::path &dir, std::string_view raw) {
    const auto path{NormalizeAssetPath(raw)};
    if (!path) {
        return NotFound();
    }
    const auto type{MimeType(*path)};
    if (!type) {
        return NotFound();
    }
    std::error_code ec;
    std::filesystem::path root{std::filesystem::weakly_canonical(dir, ec)};
    if (ec) {
        return NotFound();
    }
    if (root.has_parent_path() && root.filename().empty()) {
        // "dir/" iterates as "dir", "": drop the empty last element.
        root = root.parent_path();
    }
    const std::filesystem::path file{
        std::filesystem::weakly_canonical(root / fs::u8path(*path), ec)};
    if (ec) {
        return NotFound();
    }
    // The resolved file (symlinks followed) must stay inside the directory.
    const auto [root_end, file_it] =
        std::mismatch(root.begin(), root.end(), file.begin(), file.end());
    if (root_end != root.end() || file_it == file.end()) {
        return NotFound();
    }
    const auto status{std::filesystem::status(file, ec)};
    if (ec || !std::filesystem::is_regular_file(status)) {
        return NotFound();
    }
    const auto size{std::filesystem::file_size(file, ec)};
    if (ec || size > MAX_DIR_FILE_SIZE) {
        return NotFound();
    }
    std::ifstream in{file, std::ios::binary};
    if (!in) {
        return NotFound();
    }
    AssetReply reply;
    reply.body.assign(std::istreambuf_iterator<char>{in},
                      std::istreambuf_iterator<char>{});
    if (in.bad() || reply.body.size() > MAX_DIR_FILE_SIZE) {
        return NotFound();
    }
    reply.status = 200;
    reply.headers = SecurityHeaders();
    reply.headers.emplace_back("Content-Type", std::string{*type});
    reply.headers.emplace_back("Cache-Control", "no-store");
    return reply;
}

AssetReply NoBundleReply() {
    AssetReply reply;
    reply.status = 404;
    reply.headers = SecurityHeaders();
    reply.headers.emplace_back("Content-Type", "text/html; charset=utf-8");
    reply.headers.emplace_back("Cache-Control", "no-store");
    reply.body =
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Wallet UI not available</title></head><body>"
        "<p>This node was built without the wallet UI. Restart with "
        "-walletpwadir=&lt;dir&gt; or use a release build.</p>"
        "</body></html>\n";
    return reply;
}

} // namespace walletpwa
