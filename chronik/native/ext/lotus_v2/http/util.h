// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_UTIL_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_UTIL_H

#include <chronik/native/http.h>

#include <ext/lotus_v2/http/json.h>
#include <ext/lotus_v2/http/v2_http.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

/** Helpers shared by the /v2 and explorer routes. */
namespace chronik::native::lotus_v2::http::detail {

/** hex::encode (lowercase). */
std::string Hex(const uint8_t *data, size_t len);
template <typename C> std::string Hex(const C &c) {
    return Hex(reinterpret_cast<const uint8_t *>(c.data()), c.size());
}

/** hex digit value accepting both cases (hex crate), or -1. */
int HexDigit(char c);
/** Whether every byte is a lowercase hex digit. */
bool IsLowerHex(std::string_view s);
/** hex::decode (both cases); nullopt on odd length or a bad digit. */
std::optional<Bytes> HexDecode(std::string_view s);

/** Rust u64::to_string()-canonical decimal (`s.parse::<u64>()` and back). */
std::optional<uint64_t> CanonicalU64(std::string_view s);

/** A JSON HTTP response with the given extra headers. */
HttpResponse JsonResponse(int status, std::string body,
                          bool no_store = false);

/** The state's observation (None without a node anchor). */
inline std::optional<AuthoritativeState> Observe(const V2HttpState &s) {
    if (!s.node_anchor) {
        return std::nullopt;
    }
    return s.node_anchor();
}

} // namespace chronik::native::lotus_v2::http::detail

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_UTIL_H
