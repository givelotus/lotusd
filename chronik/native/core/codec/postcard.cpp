// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/codec/hex.h>
#include <chronik/native/codec/postcard.h>

namespace chronik::native::postcard {

void Writer::Varint(uint64_t v) {
    while (v >= 0x80) {
        m_out.push_back(uint8_t(v) | 0x80);
        v >>= 7;
    }
    m_out.push_back(uint8_t(v));
}

void Writer::U128(unsigned __int128 v) {
    while (v >= 0x80) {
        m_out.push_back(uint8_t(v) | 0x80);
        v >>= 7;
    }
    m_out.push_back(uint8_t(v));
}

uint8_t Reader::U8() {
    if (m_pos >= m_data.size()) {
        throw Error(std::string(kUnexpectedEnd));
    }
    return m_data[m_pos++];
}

bool Reader::Bool() {
    const uint8_t b = U8();
    if (b > 1) {
        throw Error(std::string(kBadBool));
    }
    return b == 1;
}

bool Reader::OptionTag() {
    const uint8_t b = U8();
    if (b > 1) {
        throw Error(std::string(kBadOption));
    }
    return b == 1;
}

uint64_t Reader::Varint(size_t max_bytes, uint8_t max_last) {
    uint64_t out = 0;
    for (size_t i = 0; i < max_bytes; ++i) {
        const uint8_t val = U8();
        out |= uint64_t(val & 0x7f) << (7 * i);
        if ((val & 0x80) == 0) {
            if (i == max_bytes - 1 && val > max_last) {
                throw Error(std::string(kBadVarint));
            }
            return out;
        }
    }
    throw Error(std::string(kBadVarint));
}

unsigned __int128 Reader::U128() {
    unsigned __int128 out = 0;
    constexpr size_t max_bytes = 19;
    for (size_t i = 0; i < max_bytes; ++i) {
        const uint8_t val = U8();
        out |= (unsigned __int128)(val & 0x7f) << (7 * i);
        if ((val & 0x80) == 0) {
            if (i == max_bytes - 1 && val > 0x03) {
                throw Error(std::string(kBadVarint));
            }
            return out;
        }
    }
    throw Error(std::string(kBadVarint));
}

ByteView Reader::Raw(size_t n) {
    if (m_data.size() - m_pos < n) {
        throw Error(std::string(kUnexpectedEnd));
    }
    const ByteView v = m_data.subspan(m_pos, n);
    m_pos += n;
    return v;
}

Bytes Reader::ByteVec() {
    const uint64_t len = Usize();
    if (len > m_data.size() - m_pos) {
        throw Error(std::string(kUnexpectedEnd));
    }
    const ByteView v = Raw(size_t(len));
    return Bytes(v.begin(), v.end());
}

static bool IsValidUtf8(ByteView v) {
    size_t i = 0;
    while (i < v.size()) {
        const uint8_t c = v[i];
        size_t n;
        uint32_t cp;
        if (c < 0x80) {
            ++i;
            continue;
        } else if ((c & 0xe0) == 0xc0) {
            n = 1;
            cp = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
            n = 2;
            cp = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            n = 3;
            cp = c & 0x07;
        } else {
            return false;
        }
        if (i + n >= v.size()) {
            return false;
        }
        for (size_t k = 1; k <= n; ++k) {
            if ((v[i + k] & 0xc0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (v[i + k] & 0x3f);
        }
        // Reject overlong encodings, surrogates and out-of-range code points.
        if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) ||
            (n == 3 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

std::string Reader::Str() {
    const uint64_t len = Usize();
    if (len > m_data.size() - m_pos) {
        throw Error(std::string(kUnexpectedEnd));
    }
    const ByteView v = Raw(size_t(len));
    if (!IsValidUtf8(v)) {
        throw Error(std::string(kBadUtf8));
    }
    return std::string(v.begin(), v.end());
}

void ThrowDeserializeError(std::string_view type_name, std::string_view error,
                           ByteView bytes) {
    throw ChronikError("Inconsistent DB: Cannot deserialize byte sequence as " +
                       std::string(type_name) + ": " + std::string(error) +
                       ". Byte sequence: " + HexEncode(bytes));
}

void ThrowDeserializeLeftover(std::string_view type_name, ByteView processed,
                              ByteView leftover) {
    throw ChronikError("Inconsistent DB: Deserializing as " +
                       std::string(type_name) + " has leftover data: " +
                       HexEncode(processed) + "[" + HexEncode(leftover) + "]");
}

} // namespace chronik::native::postcard
