// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/codec/script_compress.h>

namespace chronik::native {

namespace {
constexpr uint8_t OP_DUP = 0x76;
constexpr uint8_t OP_HASH160 = 0xa9;
constexpr uint8_t OP_EQUAL = 0x87;
constexpr uint8_t OP_EQUALVERIFY = 0x88;
constexpr uint8_t OP_CHECKSIG = 0xac;
} // namespace

void WriteCoreVarInt(Bytes &out, uint64_t n) {
    uint8_t tmp[10];
    size_t len = 0;
    while (true) {
        tmp[len] = uint8_t(n & 0x7f) | (len != 0 ? 0x80 : 0x00);
        if (n <= 0x7f) {
            break;
        }
        n = (n >> 7) - 1;
        len++;
    }
    while (true) {
        out.push_back(tmp[len]);
        if (len == 0) {
            break;
        }
        len--;
    }
}

bool ReadCoreVarInt(ByteView in, size_t &pos, uint64_t &n) {
    n = 0;
    while (true) {
        if (pos >= in.size()) {
            return false;
        }
        const uint8_t ch = in[pos++];
        if (n > (UINT64_MAX >> 7)) {
            return false;
        }
        n = (n << 7) | (ch & 0x7f);
        if (ch & 0x80) {
            if (n == UINT64_MAX) {
                return false;
            }
            n++;
        } else {
            return true;
        }
    }
}

Bytes CompressScript(ByteView s) {
    Bytes out;
    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if (s.size() == 25 && s[0] == OP_DUP && s[1] == OP_HASH160 &&
        s[2] == 20 && s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG) {
        out.reserve(21);
        out.push_back(0x00);
        out.insert(out.end(), s.begin() + 3, s.begin() + 23);
        return out;
    }
    // P2SH: OP_HASH160 <20> OP_EQUAL
    if (s.size() == 23 && s[0] == OP_HASH160 && s[1] == 20 &&
        s[22] == OP_EQUAL) {
        out.reserve(21);
        out.push_back(0x01);
        out.insert(out.end(), s.begin() + 2, s.begin() + 22);
        return out;
    }
    // P2PK compressed: <33> pubkey OP_CHECKSIG
    if (s.size() == 35 && s[0] == 33 && s[34] == OP_CHECKSIG &&
        (s[1] == 0x02 || s[1] == 0x03)) {
        return Bytes(s.begin() + 1, s.begin() + 34);
    }
    // P2PK uncompressed: <65> 04 x y OP_CHECKSIG
    if (s.size() == 67 && s[0] == 65 && s[66] == OP_CHECKSIG &&
        s[1] == 0x04) {
        out.reserve(33);
        out.push_back(uint8_t((s[65] & 0x01) | 0x04));
        out.insert(out.end(), s.begin() + 2, s.begin() + 34);
        return out;
    }
    out.reserve(s.size() + 3);
    WriteCoreVarInt(out, uint64_t(s.size()) + kCompressNumSpecialScripts);
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

std::optional<Bytes> DecompressScript(ByteView c,
                                      const DecompressPubKeyFn &decompress) {
    size_t pos = 0;
    uint64_t n;
    if (!ReadCoreVarInt(c, pos, n)) {
        return std::nullopt;
    }
    const ByteView rest = c.subspan(pos);
    Bytes out;
    switch (n) {
        case 0x00:
            if (rest.size() != 20) {
                return std::nullopt;
            }
            out = {OP_DUP, OP_HASH160, 20};
            out.insert(out.end(), rest.begin(), rest.end());
            out.push_back(OP_EQUALVERIFY);
            out.push_back(OP_CHECKSIG);
            return out;
        case 0x01:
            if (rest.size() != 20) {
                return std::nullopt;
            }
            out = {OP_HASH160, 20};
            out.insert(out.end(), rest.begin(), rest.end());
            out.push_back(OP_EQUAL);
            return out;
        case 0x02:
        case 0x03:
            if (rest.size() != 32) {
                return std::nullopt;
            }
            out = {33, uint8_t(n)};
            out.insert(out.end(), rest.begin(), rest.end());
            out.push_back(OP_CHECKSIG);
            return out;
        case 0x04:
        case 0x05: {
            if (rest.size() != 32 || !decompress) {
                return std::nullopt;
            }
            // Compressed pubkey form: 02/03 || x
            const auto pk = decompress(c);
            if (!pk || pk->size() != 65) {
                return std::nullopt;
            }
            out = {65};
            out.insert(out.end(), pk->begin(), pk->end());
            out.push_back(OP_CHECKSIG);
            return out;
        }
        default:
            if (rest.size() != n - kCompressNumSpecialScripts) {
                return std::nullopt;
            }
            return Bytes(rest.begin(), rest.end());
    }
}

} // namespace chronik::native
