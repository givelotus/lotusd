// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http parse.rs (hex/LOKAD ID parts) plus axum's typed Path
// rejections and Rust Debug formatting used in wire-visible messages.

#include <chronik/native/error.h>
#include <chronik/native/http.h>

#include <cstdio>
#include <limits>

namespace chronik::native {

namespace {

/** Decode one UTF-8 code point (input assumed valid UTF-8). */
uint32_t NextCodePoint(std::string_view s, size_t &i) {
    const auto b = static_cast<uint8_t>(s[i]);
    auto cont = [&](size_t k) {
        return i + k < s.size() ? uint32_t(uint8_t(s[i + k]) & 0x3F) : 0u;
    };
    if (b < 0x80) {
        i += 1;
        return b;
    }
    if (b < 0xE0) {
        uint32_t cp = (uint32_t(b & 0x1F) << 6) | cont(1);
        i += 2;
        return cp;
    }
    if (b < 0xF0) {
        uint32_t cp = (uint32_t(b & 0x0F) << 12) | (cont(1) << 6) | cont(2);
        i += 3;
        return cp;
    }
    uint32_t cp = (uint32_t(b & 0x07) << 18) | (cont(1) << 12) |
                  (cont(2) << 6) | cont(3);
    i += 4;
    return cp;
}

void AppendUtf8(std::string &out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(char(cp));
    } else if (cp < 0x800) {
        out.push_back(char(0xC0 | (cp >> 6)));
        out.push_back(char(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(char(0xE0 | (cp >> 12)));
        out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(char(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(char(0xF0 | (cp >> 18)));
        out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(char(0x80 | (cp & 0x3F)));
    }
}

/**
 * Approximation of Rust's `char::is_printable` for the code points that
 * plausibly occur in request parameters: controls, soft hyphen, zero-width
 * and bidi format characters, private use and specials are not printable.
 */
bool IsPrintable(uint32_t cp) {
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0xA0) || cp == 0xAD) {
        return false;
    }
    if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) ||
        (cp >= 0x2060 && cp <= 0x206F) || cp == 0xFEFF ||
        (cp >= 0xE000 && cp <= 0xF8FF) || (cp >= 0xFFF0 && cp <= 0xFFFC) ||
        cp == 0xFFFE || cp == 0xFFFF || cp >= 0xF0000) {
        return false;
    }
    return true;
}

void AppendEscaped(std::string &out, uint32_t cp, bool in_str) {
    switch (cp) {
        case '\t':
            out += "\\t";
            return;
        case '\r':
            out += "\\r";
            return;
        case '\n':
            out += "\\n";
            return;
        case '\\':
            out += "\\\\";
            return;
        case 0:
            out += "\\0";
            return;
        case '"':
            out += in_str ? "\\\"" : "\"";
            return;
        case '\'':
            out += in_str ? "'" : "\\'";
            return;
        default:
            break;
    }
    if (!IsPrintable(cp)) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "\\u{%x}", cp);
        out += buf;
        return;
    }
    AppendUtf8(out, cp);
}

/** Rust `{:?}` of a char */
std::string RustDebugChar(uint32_t cp) {
    std::string out = "'";
    AppendEscaped(out, cp, false);
    out += "'";
    return out;
}

/** Rust `str::parse::<i64>` restricted to [min, max]. */
std::optional<int64_t> ParseRustInt(std::string_view s, int64_t min,
                                    int64_t max) {
    if (s.empty()) {
        return std::nullopt;
    }
    bool neg = false;
    size_t i = 0;
    if (s[0] == '+' || s[0] == '-') {
        neg = s[0] == '-';
        i = 1;
        if (s.size() == 1) {
            return std::nullopt;
        }
    }
    if (neg && min >= 0) {
        // unsigned types reject a '-' sign
        return std::nullopt;
    }
    __int128 value = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return std::nullopt;
        }
        value = value * 10 + (s[i] - '0');
        if (value > (__int128(1) << 64)) {
            return std::nullopt;
        }
    }
    if (neg) {
        value = -value;
    }
    if (value < min || value > max) {
        return std::nullopt;
    }
    return int64_t(value);
}

} // namespace

std::string RustDebugStr(std::string_view s) {
    std::string out = "\"";
    size_t i = 0;
    while (i < s.size()) {
        AppendEscaped(out, NextCodePoint(s, i), true);
    }
    out += "\"";
    return out;
}

std::optional<std::string> HexDecodeError(std::string_view payload) {
    if (payload.size() % 2 != 0) {
        return "Odd number of digits";
    }
    for (size_t i = 0; i < payload.size(); ++i) {
        const char c = payload[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) {
            // hex 0.4: `c as char` of the byte, so each byte is a Latin-1
            // char; formatted with {:?}
            return "Invalid character " +
                   RustDebugChar(static_cast<uint8_t>(c)) + " at position " +
                   std::to_string(i);
        }
    }
    return std::nullopt;
}

Bytes ParseHex(std::string_view payload) {
    if (auto err = HexDecodeError(payload)) {
        throw ChronikError("400: Invalid hex: " + *err);
    }
    Bytes out(payload.size() / 2);
    auto val = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') {
            return uint8_t(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return uint8_t(c - 'a' + 10);
        }
        return uint8_t(c - 'A' + 10);
    };
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = uint8_t(val(payload[2 * i]) << 4 | val(payload[2 * i + 1]));
    }
    return out;
}

std::array<uint8_t, 4> ParseLokadId(ByteView lokad_id) {
    if (lokad_id.size() != 4) {
        throw ChronikError(
            "400: Invalid LOKAD ID length: expected 4 but got " +
            std::to_string(lokad_id.size()));
    }
    return {lokad_id[0], lokad_id[1], lokad_id[2], lokad_id[3]};
}

std::array<uint8_t, 4> ParseLokadIdHex(std::string_view lokad_id_hex) {
    const Bytes bytes = ParseHex(lokad_id_hex);
    return ParseLokadId(bytes);
}

int32_t PathI32(const PathParams &params, size_t index) {
    const std::string &value = params[index];
    auto parsed =
        ParseRustInt(value, std::numeric_limits<int32_t>::min(),
                     std::numeric_limits<int32_t>::max());
    if (!parsed) {
        throw HttpRejection(400, "Invalid URL: Cannot parse value at index " +
                                     std::to_string(index) + " with value `" +
                                     RustDebugStr(value) + "` to a `i32`");
    }
    return int32_t(*parsed);
}

uint32_t PathU32(const PathParams &params, size_t index) {
    const std::string &value = params[index];
    auto parsed = ParseRustInt(value, 0, std::numeric_limits<uint32_t>::max());
    if (!parsed) {
        throw HttpRejection(400, "Invalid URL: Cannot parse value at index " +
                                     std::to_string(index) + " with value `" +
                                     RustDebugStr(value) + "` to a `u32`");
    }
    return uint32_t(*parsed);
}

int32_t PathSingleI32(const PathParams &params) {
    const std::string &value = params[0];
    auto parsed =
        ParseRustInt(value, std::numeric_limits<int32_t>::min(),
                     std::numeric_limits<int32_t>::max());
    if (!parsed) {
        throw HttpRejection(400, "Invalid URL: Cannot parse `" +
                                     RustDebugStr(value) + "` to a `i32`");
    }
    return int32_t(*parsed);
}

} // namespace chronik::native
