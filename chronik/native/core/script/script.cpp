// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/script/script.h>

#include <cstring>

namespace chronik::native::script {

std::string HexEncode(ByteView data) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string s;
    s.reserve(data.size() * 2);
    for (uint8_t b : data) {
        s.push_back(HEX[b >> 4]);
        s.push_back(HEX[b & 0xf]);
    }
    return s;
}

namespace {

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

/** Decode one UTF-8 code point; returns false on invalid encoding. */
bool DecodeUtf8(std::string_view s, size_t &pos, uint32_t &cp) {
    const auto c0 = uint8_t(s[pos]);
    size_t len;
    if (c0 < 0x80) {
        cp = c0;
        len = 1;
    } else if ((c0 & 0xe0) == 0xc0) {
        cp = c0 & 0x1f;
        len = 2;
    } else if ((c0 & 0xf0) == 0xe0) {
        cp = c0 & 0x0f;
        len = 3;
    } else if ((c0 & 0xf8) == 0xf0) {
        cp = c0 & 0x07;
        len = 4;
    } else {
        return false;
    }
    if (pos + len > s.size()) {
        return false;
    }
    for (size_t i = 1; i < len; ++i) {
        const auto c = uint8_t(s[pos + i]);
        if ((c & 0xc0) != 0x80) {
            return false;
        }
        cp = (cp << 6) | (c & 0x3f);
    }
    // Reject overlong encodings, surrogates and out of range values
    static constexpr uint32_t MIN[] = {0, 0, 0x80, 0x800, 0x10000};
    if (cp < MIN[len] || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
        return false;
    }
    pos += len;
    return true;
}

bool IsValidUtf8(std::string_view s) {
    size_t pos = 0;
    uint32_t cp;
    while (pos < s.size()) {
        if (!DecodeUtf8(s, pos, cp)) {
            return false;
        }
    }
    return true;
}

/**
 * Approximation of Rust's regex class
 * [\w\s\p{Punctuation}\p{Symbol}\p{Emoji}] used to decide whether a pushop is
 * displayed as text. Exact for ASCII; for non-ASCII it accepts every code
 * point except C1 controls and format characters other than joiners.
 */
bool IsTextCodePoint(uint32_t cp) {
    if (cp < 0x80) {
        if (cp == ' ' || (cp >= 0x09 && cp <= 0x0d)) {
            return true;
        }
        return cp > 0x20 && cp < 0x7f;
    }
    if (cp < 0xa0) {
        // C1 controls; U+0085 (NEL) is whitespace
        return cp == 0x85;
    }
    if (cp == 0xad) {
        return false;
    }
    if ((cp >= 0x200b && cp <= 0x200f && cp != 0x200c && cp != 0x200d) ||
        (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064) ||
        cp == 0xfeff) {
        return false;
    }
    if ((cp >= 0xe000 && cp <= 0xf8ff) || cp >= 0xf0000) {
        // Private use
        return false;
    }
    return true;
}

bool LooksLikeText(std::string_view text) {
    if (text.empty()) {
        return false;
    }
    size_t pos = 0;
    uint32_t cp;
    while (pos < text.size()) {
        if (!DecodeUtf8(text, pos, cp) || !IsTextCodePoint(cp)) {
            return false;
        }
    }
    return true;
}

Result<Bytes, DataError> ReadBytes(ByteView &data, size_t num_bytes) {
    if (data.size() < num_bytes) {
        return Err(DataError::InvalidLength(num_bytes, data.size()));
    }
    Bytes out(data.begin(), data.begin() + num_bytes);
    data = data.subspan(num_bytes);
    return out;
}

} // namespace

std::string DataError::ToString() const {
    switch (kind) {
        case Kind::InvalidLength:
            return "Invalid length, expected " + std::to_string(expected) +
                   " bytes but got " + std::to_string(actual) + " bytes";
        case Kind::InvalidLengthMulti:
            return "Invalid length, expected one of " +
                   DebugSizes(expected_multi) + " but got " +
                   std::to_string(actual) + " bytes";
        case Kind::InvalidHex:
            return "Invalid hex: " + hex_error;
    }
    return {};
}

Result<Bytes, DataError> HexDecode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return Err(DataError::InvalidHex("Odd number of digits"));
    }
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        for (size_t j = i; j < i + 2; ++j) {
            if (HexVal(hex[j]) < 0) {
                // hex::FromHexError::InvalidHexCharacter, with Rust's char
                // Debug quoting
                std::string c;
                size_t pos = j;
                uint32_t cp;
                if (DecodeUtf8(hex, pos, cp)) {
                    c = std::string(hex.substr(j, pos - j));
                } else {
                    c = "\\u{fffd}";
                }
                if (c == "'" || c == "\\") {
                    c = "\\" + c;
                }
                return Err(DataError::InvalidHex("Invalid character '" + c +
                                                 "' at position " +
                                                 std::to_string(j)));
            }
        }
        out.push_back(uint8_t(HexVal(hex[i]) << 4 | HexVal(hex[i + 1])));
    }
    return out;
}

std::string DebugSizes(const std::vector<size_t> &sizes) {
    std::string s = "[";
    for (size_t i = 0; i < sizes.size(); ++i) {
        if (i > 0) {
            s += ", ";
        }
        s += std::to_string(sizes[i]);
    }
    return s + "]";
}

std::string DebugBytes(ByteView bytes) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string s = "b\"";
    for (uint8_t b : bytes) {
        if (b == '\n') {
            s += "\\n";
        } else if (b == '\r') {
            s += "\\r";
        } else if (b == '\t') {
            s += "\\t";
        } else if (b == '\\' || b == '"') {
            s += '\\';
            s += char(b);
        } else if (b == 0) {
            s += "\\0";
        } else if (b >= 0x20 && b < 0x7f) {
            s += char(b);
        } else {
            s += "\\x";
            s += HEX[b >> 4];
            s += HEX[b & 0xf];
        }
    }
    return s + "\"";
}

Result<Op, DataError> ReadOp(ByteView &data) {
    if (data.empty()) {
        return Err(DataError::InvalidLength(1, 0));
    }
    const uint8_t opcode_num = data[0];
    data = data.subspan(1);
    const Opcode opcode{opcode_num};
    size_t size;
    if (opcode_num >= 0x01 && opcode_num <= 0x4b) {
        size = opcode_num;
    } else if (opcode == OP_PUSHDATA1) {
        if (data.size() < 1) {
            return Err(DataError::InvalidLength(1, data.size()));
        }
        size = data[0];
        data = data.subspan(1);
    } else if (opcode == OP_PUSHDATA2) {
        if (data.size() < 2) {
            return Err(DataError::InvalidLength(2, data.size()));
        }
        size = size_t(data[0]) | size_t(data[1]) << 8;
        data = data.subspan(2);
    } else if (opcode == OP_PUSHDATA4) {
        if (data.size() < 4) {
            return Err(DataError::InvalidLength(4, data.size()));
        }
        size = size_t(data[0]) | size_t(data[1]) << 8 |
               size_t(data[2]) << 16 | size_t(data[3]) << 24;
        data = data.subspan(4);
    } else {
        return Op::Code(opcode);
    }
    auto bytes = ReadBytes(data, size);
    if (!bytes) {
        return Err(bytes.error());
    }
    return Op::Push(opcode, std::move(bytes.value()));
}

std::optional<Result<Op, DataError>> ScriptOpIter::Next() {
    if (remaining_.empty()) {
        return std::nullopt;
    }
    auto op = ReadOp(remaining_);
    if (!op) {
        remaining_ = {};
    }
    return op;
}

std::string Op::ToString() const {
    if (!is_push) {
        return opcode.ToString();
    }
    if (data.empty()) {
        return "\"\"";
    }
    std::string_view text(reinterpret_cast<const char *>(data.data()),
                          data.size());
    if (IsValidUtf8(text)) {
        std::string_view trimmed = text;
        while (!trimmed.empty() && trimmed.back() == '\0') {
            trimmed.remove_suffix(1);
        }
        if (LooksLikeText(trimmed)) {
            std::string out = "\"";
            for (char c : text) {
                if (c == '\0') {
                    out += "\\0";
                } else {
                    out += c;
                }
            }
            return out + "\"";
        }
    }
    return "0x" + HexEncode(data);
}

Script Script::P2pkh(const ShaRmd160 &hash) {
    ScriptMut script;
    script.PutOpcodes({OP_DUP, OP_HASH160});
    const uint8_t size = SHA_RMD160_SIZE;
    script.PutBytecode(ByteView(&size, 1));
    script.PutBytecode(hash);
    script.PutOpcodes({OP_EQUALVERIFY, OP_CHECKSIG});
    return script.Freeze();
}

Script Script::P2sh(const ShaRmd160 &hash) {
    ScriptMut script;
    script.PutOpcodes({OP_HASH160});
    const uint8_t size = SHA_RMD160_SIZE;
    script.PutBytecode(ByteView(&size, 1));
    script.PutBytecode(hash);
    script.PutOpcodes({OP_EQUAL});
    return script.Freeze();
}

Script Script::P2pk(ByteView pubkey) {
    ScriptMut script;
    const uint8_t size = PUBKEY_SIZE;
    script.PutBytecode(ByteView(&size, 1));
    script.PutBytecode(pubkey);
    script.PutOpcodes({OP_CHECKSIG});
    return script.Freeze();
}

Script Script::P2pkUncompressed(ByteView pubkey) {
    ScriptMut script;
    const uint8_t size = UNCOMPRESSED_PUBKEY_SIZE;
    script.PutBytecode(ByteView(&size, 1));
    script.PutBytecode(pubkey);
    script.PutOpcodes({OP_CHECKSIG});
    return script.Freeze();
}

bool Script::IsOpReturn() const {
    return !bytecode_.empty() && bytecode_[0] == OP_RETURN.n;
}

ScriptVariant Script::Variant() const {
    const Bytes &b = bytecode_;
    const size_t n = b.size();
    if (n == 25 && b[0] == OP_DUP.n && b[1] == OP_HASH160.n && b[2] == 20 &&
        b[23] == OP_EQUALVERIFY.n && b[24] == OP_CHECKSIG.n) {
        return ScriptVariant{ScriptType::P2PKH, Bytes(b.begin() + 3,
                                                      b.begin() + 23)};
    }
    if (n == 23 && b[0] == OP_HASH160.n && b[1] == 20 &&
        b[22] == OP_EQUAL.n) {
        return ScriptVariant{ScriptType::P2SH,
                             Bytes(b.begin() + 2, b.begin() + 22)};
    }
    if (n == 35 && b[0] == PUBKEY_SIZE && b[34] == OP_CHECKSIG.n &&
        (b[1] == 0x02 || b[1] == 0x03)) {
        return ScriptVariant{ScriptType::P2PK,
                             Bytes(b.begin() + 1, b.begin() + 34)};
    }
    if (n == 67 && b[0] == UNCOMPRESSED_PUBKEY_SIZE &&
        b[66] == OP_CHECKSIG.n && b[1] == 0x04) {
        return ScriptVariant{ScriptType::P2PK,
                             Bytes(b.begin() + 1, b.begin() + 66)};
    }
    return ScriptVariant{ScriptType::Other, b};
}

std::string Script::ToString() const {
    std::string asm_str;
    auto iter = IterOps();
    while (auto op = iter.Next()) {
        if (op->ok()) {
            asm_str += op->value().ToString();
        } else {
            asm_str += "[corrupt PUSHDATA] ";
            break;
        }
        asm_str += ' ';
    }
    if (!asm_str.empty()) {
        asm_str.pop_back();
    }
    return asm_str;
}

void ScriptMut::PutOpcodes(std::initializer_list<Opcode> opcodes) {
    for (Opcode opcode : opcodes) {
        bytes_.push_back(opcode.n);
    }
}

void ScriptMut::PutBytecode(ByteView bytes) {
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
}

void ScriptMut::PutPushdata(ByteView pushdata) {
    const size_t len = pushdata.size();
    if (len == 0) {
        PutOpcodes({OP_0});
    } else if (len <= 0x4b) {
        bytes_.push_back(uint8_t(len));
    } else if (len <= 0xff) {
        PutOpcodes({OP_PUSHDATA1});
        bytes_.push_back(uint8_t(len));
    } else if (len <= 0xffff) {
        PutOpcodes({OP_PUSHDATA2});
        bytes_.push_back(uint8_t(len));
        bytes_.push_back(uint8_t(len >> 8));
    } else {
        PutOpcodes({OP_PUSHDATA4});
        for (int i = 0; i < 4; ++i) {
            bytes_.push_back(uint8_t(len >> (8 * i)));
        }
    }
    PutBytecode(pushdata);
}

void ScriptMut::PutSlpPushdata(ByteView pushdata) {
    if (pushdata.empty()) {
        bytes_.push_back(OP_PUSHDATA1.n);
        bytes_.push_back(0);
    } else {
        PutPushdata(pushdata);
    }
}

Result<ScriptType, std::string> ParseScriptType(std::string_view s) {
    if (s == "p2pkh") {
        return ScriptType::P2PKH;
    }
    if (s == "p2sh") {
        return ScriptType::P2SH;
    }
    if (s == "p2pk") {
        return ScriptType::P2PK;
    }
    if (s == "other") {
        return ScriptType::Other;
    }
    return Err("Unknown script type: " + std::string(s));
}

Result<ScriptVariant, DataError>
ScriptVariant::FromTypeAndPayload(ScriptType type, ByteView payload) {
    switch (type) {
        case ScriptType::P2PKH:
        case ScriptType::P2SH:
            if (payload.size() != SHA_RMD160_SIZE) {
                return Err(DataError::InvalidLength(SHA_RMD160_SIZE,
                                                    payload.size()));
            }
            break;
        case ScriptType::P2PK:
            if (payload.size() != PUBKEY_SIZE &&
                payload.size() != UNCOMPRESSED_PUBKEY_SIZE) {
                return Err(DataError::InvalidLengthMulti(
                    {PUBKEY_SIZE, UNCOMPRESSED_PUBKEY_SIZE}, payload.size()));
            }
            break;
        case ScriptType::Other:
            break;
    }
    return ScriptVariant{type, Bytes(payload.begin(), payload.end())};
}

Script ScriptVariant::ToScript() const {
    switch (type) {
        case ScriptType::P2PKH: {
            ShaRmd160 hash{};
            std::memcpy(hash.data(), payload.data(), hash.size());
            return Script::P2pkh(hash);
        }
        case ScriptType::P2SH: {
            ShaRmd160 hash{};
            std::memcpy(hash.data(), payload.data(), hash.size());
            return Script::P2sh(hash);
        }
        case ScriptType::P2PK:
            if (payload.size() == PUBKEY_SIZE) {
                return Script::P2pk(payload);
            }
            return Script::P2pkUncompressed(payload);
        case ScriptType::Other:
            return Script(payload);
    }
    return {};
}

std::string ScriptVariant::ToString() const {
    switch (type) {
        case ScriptType::P2PKH:
            return "p2pkh(" + HexEncode(payload) + ")";
        case ScriptType::P2SH:
            return "p2sh(" + HexEncode(payload) + ")";
        case ScriptType::P2PK:
            return "p2pk(" + HexEncode(payload) + ")";
        case ScriptType::Other:
            return "other(" + HexEncode(payload) + ")";
    }
    return {};
}

namespace {

size_t CompactSizeLen(uint64_t size) {
    if (size <= 0xfc) {
        return 1;
    }
    if (size <= 0xffff) {
        return 3;
    }
    if (size <= 0xffffffff) {
        return 5;
    }
    return 9;
}

Result<uint64_t, DataError> ReadLe(ByteView &data, size_t n) {
    if (data.size() < n) {
        return Err(DataError::InvalidLength(n, data.size()));
    }
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        value |= uint64_t(data[i]) << (8 * i);
    }
    data = data.subspan(n);
    return value;
}

} // namespace

Bytes Script::Ser() const {
    Bytes out;
    out.reserve(SerLen());
    const uint64_t size = bytecode_.size();
    size_t width = 0;
    if (size <= 0xfc) {
        out.push_back(uint8_t(size));
    } else if (size <= 0xffff) {
        out.push_back(0xfd);
        width = 2;
    } else if (size <= 0xffffffff) {
        out.push_back(0xfe);
        width = 4;
    } else {
        out.push_back(0xff);
        width = 8;
    }
    for (size_t i = 0; i < width; ++i) {
        out.push_back(uint8_t(size >> (8 * i)));
    }
    out.insert(out.end(), bytecode_.begin(), bytecode_.end());
    return out;
}

size_t Script::SerLen() const {
    return CompactSizeLen(bytecode_.size()) + bytecode_.size();
}

Result<Script, DataError> Script::Deser(ByteView &data) {
    auto first = ReadLe(data, 1);
    if (!first) {
        return Err(first.error());
    }
    uint64_t size = first.value();
    if (size >= 0xfd) {
        auto rest = ReadLe(data, size == 0xfd ? 2 : size == 0xfe ? 4 : 8);
        if (!rest) {
            return Err(rest.error());
        }
        size = rest.value();
    }
    if (data.size() < size) {
        return Err(DataError::InvalidLength(size, data.size()));
    }
    Script script(data.first(size));
    data = data.subspan(size);
    return script;
}

} // namespace chronik::native::script
