// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CODEC_HEX_H
#define CHRONIK_NATIVE_CODEC_HEX_H

#include <chronik/native/types.h>

#include <optional>
#include <string>
#include <string_view>

namespace chronik::native {

/** Lowercase hex, like Rust's hex::encode. */
std::string HexEncode(ByteView bytes);
/** Hex of the bytes in reverse order (display order of a Hash32). */
std::string HexEncodeRev(ByteView bytes);
/** Accepts upper and lower case; nullopt on odd length or bad digit. */
std::optional<Bytes> HexDecode(std::string_view hex);

inline std::string HexEncode(const Hash32 &h) {
    return HexEncode(ByteView(h.b.data(), h.b.size()));
}
/** Display (big-endian) hex of a hash, e.g. a txid as shown by the node. */
inline std::string HashToHex(const Hash32 &h) {
    return HexEncodeRev(ByteView(h.b.data(), h.b.size()));
}

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CODEC_HEX_H
