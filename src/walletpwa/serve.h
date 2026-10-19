// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETPWA_SERVE_H
#define BITCOIN_WALLETPWA_SERVE_H

#include <walletpwa/assets.h>

#include <util/fs.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/** Serving the wallet PWA's files under /wallet/ (pure functions). */
namespace walletpwa {

using HeaderList = std::vector<std::pair<std::string, std::string>>;

/** A reply to GET /wallet/<path>, before it is written to the request */
struct AssetReply {
    int status{404};
    HeaderList headers;
    std::string body;
};

//! Largest file served from -walletpwadir
static constexpr uint64_t MAX_DIR_FILE_SIZE{16 * 1024 * 1024};
//! Longest accepted asset path, after decoding
static constexpr size_t MAX_ASSET_PATH_LENGTH{256};

/**
 * Turn the URI part after "/wallet/" into a relative file path: strip the
 * query, percent-decode once, and reject empty, "." and ".." segments,
 * segments starting with ".", backslashes, NUL, a leading "/" and paths over
 * MAX_ASSET_PATH_LENGTH. An empty path is "index.html".
 */
std::optional<std::string> NormalizeAssetPath(std::string_view raw);

/** Content-Type for a path by its extension, or nullopt (not served). */
std::optional<std::string_view> MimeType(std::string_view path);

/** Whether an Accept-Encoding value accepts gzip (with q > 0) */
bool AcceptsGzip(std::string_view accept_encoding);

/** Whether an If-None-Match value matches an ETag (weak comparison) */
bool IfNoneMatchMatches(std::string_view if_none_match, std::string_view etag);

/** Headers sent on every /wallet/ response (CSP and friends) */
const HeaderList &SecurityHeaders();

/**
 * Serve from the embedded bundle.
 * @param raw  the URI after "/wallet/"
 */
AssetReply ServeAsset(std::span<const EmbeddedAsset> assets,
                      std::string_view raw,
                      const std::optional<std::string> &accept_encoding,
                      const std::optional<std::string> &if_none_match);

/** Serve from a development directory, read on every request. */
AssetReply ServeFromDirectory(const fs::path &dir, std::string_view raw);

/** The 404 page when there is neither a bundle nor -walletpwadir */
AssetReply NoBundleReply();

} // namespace walletpwa

#endif // BITCOIN_WALLETPWA_SERVE_H
