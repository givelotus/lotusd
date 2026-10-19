// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/http/json.h>

#include <algorithm>

namespace chronik::native::lotus_v2::http {

// ---- Json ----

Json Json::U(uint64_t v) {
    Json j;
    j.m_kind = Kind::UInt;
    j.m_uint = v;
    return j;
}

Json Json::Array(std::vector<Json> items) {
    Json j;
    j.m_kind = Kind::Arr;
    j.m_items = std::move(items);
    return j;
}

Json Json::Object(std::initializer_list<std::pair<std::string, Json>> m) {
    Json j;
    j.m_kind = Kind::Obj;
    for (const auto &[k, v] : m) {
        j.Set(k, v);
    }
    return j;
}

void Json::Set(std::string key, Json value) {
    m_kind = Kind::Obj;
    for (auto &[k, v] : m_members) {
        if (k == key) {
            v = std::move(value);
            return;
        }
    }
    m_members.emplace_back(std::move(key), std::move(value));
}

void Json::Extend(const Json &other) {
    for (const auto &[k, v] : other.m_members) {
        Set(k, v);
    }
}

void Json::Push(Json value) {
    m_kind = Kind::Arr;
    m_items.push_back(std::move(value));
}

std::string Json::Dump() const {
    std::string out;
    Write(out);
    return out;
}

void Json::Write(std::string &out) const {
    switch (m_kind) {
        case Kind::Null:
            out += "null";
            return;
        case Kind::Bool:
            out += m_bool ? "true" : "false";
            return;
        case Kind::UInt:
            out += std::to_string(m_uint);
            return;
        case Kind::Str:
            WriteJsonString(m_str, out);
            return;
        case Kind::Arr: {
            out += '[';
            for (size_t i = 0; i < m_items.size(); ++i) {
                if (i) {
                    out += ',';
                }
                m_items[i].Write(out);
            }
            out += ']';
            return;
        }
        case Kind::Obj: {
            // serde_json::Map is a BTreeMap: keys in byte order.
            std::vector<const std::pair<std::string, Json> *> sorted;
            sorted.reserve(m_members.size());
            for (const auto &m : m_members) {
                sorted.push_back(&m);
            }
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto *a, const auto *b) {
                          return a->first < b->first;
                      });
            out += '{';
            for (size_t i = 0; i < sorted.size(); ++i) {
                if (i) {
                    out += ',';
                }
                WriteJsonString(sorted[i]->first, out);
                out += ':';
                sorted[i]->second.Write(out);
            }
            out += '}';
            return;
        }
    }
}

void WriteJsonString(std::string_view s, std::string &out) {
    static constexpr char kHex[] = "0123456789abcdef";
    out += '"';
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        switch (u) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (u < 0x20) {
                    out += "\\u00";
                    out += kHex[u >> 4];
                    out += kHex[u & 0xf];
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

// ---- parser ----

namespace {

constexpr int kMaxDepth = 128;

/** Rust str::from_utf8 validity. */
bool ValidUtf8(std::string_view s) {
    size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            ++i;
            continue;
        }
        size_t n;
        uint32_t cp;
        if (c >= 0xc2 && c <= 0xdf) {
            n = 1;
            cp = c & 0x1f;
        } else if (c >= 0xe0 && c <= 0xef) {
            n = 2;
            cp = c & 0x0f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            n = 3;
            cp = c & 0x07;
        } else {
            return false;
        }
        if (i + n >= s.size()) {
            return false;
        }
        for (size_t k = 1; k <= n; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xc0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (cc & 0x3f);
        }
        if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) ||
            cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

void AppendUtf8(uint32_t cp, std::string &out) {
    if (cp < 0x80) {
        out += char(cp);
    } else if (cp < 0x800) {
        out += char(0xc0 | (cp >> 6));
        out += char(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        out += char(0xe0 | (cp >> 12));
        out += char(0x80 | ((cp >> 6) & 0x3f));
        out += char(0x80 | (cp & 0x3f));
    } else {
        out += char(0xf0 | (cp >> 18));
        out += char(0x80 | ((cp >> 12) & 0x3f));
        out += char(0x80 | ((cp >> 6) & 0x3f));
        out += char(0x80 | (cp & 0x3f));
    }
}

class Parser {
public:
    explicit Parser(ByteView b) : m_b(b) {}

    std::optional<JsonNode> Document() {
        JsonNode node;
        SkipWs();
        if (!Value(node, 0)) {
            return std::nullopt;
        }
        SkipWs();
        if (m_pos != m_b.size()) {
            return std::nullopt;
        }
        return node;
    }

private:
    bool AtEnd() const { return m_pos >= m_b.size(); }
    uint8_t Peek() const { return m_b[m_pos]; }

    void SkipWs() {
        while (!AtEnd() && (Peek() == ' ' || Peek() == '\n' ||
                            Peek() == '\t' || Peek() == '\r')) {
            ++m_pos;
        }
    }

    bool Literal(std::string_view lit) {
        if (m_b.size() - m_pos < lit.size()) {
            return false;
        }
        for (size_t i = 0; i < lit.size(); ++i) {
            if (m_b[m_pos + i] != uint8_t(lit[i])) {
                return false;
            }
        }
        m_pos += lit.size();
        return true;
    }

    bool Value(JsonNode &node, int depth) {
        if (AtEnd()) {
            return false;
        }
        switch (Peek()) {
            case 'n':
                node.kind = JsonNode::Kind::Null;
                return Literal("null");
            case 't':
                node.kind = JsonNode::Kind::Bool;
                node.b = true;
                return Literal("true");
            case 'f':
                node.kind = JsonNode::Kind::Bool;
                node.b = false;
                return Literal("false");
            case '"':
                node.kind = JsonNode::Kind::Str;
                return String(node.s);
            case '[':
                return ArrayValue(node, depth + 1);
            case '{':
                return ObjectValue(node, depth + 1);
            default:
                return Number(node);
        }
    }

    bool Number(JsonNode &node) {
        node.kind = JsonNode::Kind::Num;
        bool negative = false;
        if (!AtEnd() && Peek() == '-') {
            negative = true;
            ++m_pos;
        }
        if (AtEnd() || Peek() < '0' || Peek() > '9') {
            return false;
        }
        bool overflow = false;
        uint64_t v = 0;
        if (Peek() == '0') {
            ++m_pos;
        } else {
            while (!AtEnd() && Peek() >= '0' && Peek() <= '9') {
                const uint64_t d = Peek() - '0';
                if (v > (UINT64_MAX - d) / 10) {
                    overflow = true;
                }
                v = v * 10 + d;
                ++m_pos;
            }
        }
        bool integer = true;
        if (!AtEnd() && Peek() == '.') {
            integer = false;
            ++m_pos;
            if (AtEnd() || Peek() < '0' || Peek() > '9') {
                return false;
            }
            while (!AtEnd() && Peek() >= '0' && Peek() <= '9') {
                ++m_pos;
            }
        }
        if (!AtEnd() && (Peek() == 'e' || Peek() == 'E')) {
            integer = false;
            ++m_pos;
            if (!AtEnd() && (Peek() == '+' || Peek() == '-')) {
                ++m_pos;
            }
            if (AtEnd() || Peek() < '0' || Peek() > '9') {
                return false;
            }
            while (!AtEnd() && Peek() >= '0' && Peek() <= '9') {
                ++m_pos;
            }
        }
        if (integer && !negative && !overflow) {
            node.u = v;
        }
        return true;
    }

    bool Hex4(uint32_t &out) {
        if (m_b.size() - m_pos < 4) {
            return false;
        }
        out = 0;
        for (int i = 0; i < 4; ++i) {
            const uint8_t c = m_b[m_pos++];
            uint32_t d;
            if (c >= '0' && c <= '9') {
                d = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                d = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                d = c - 'A' + 10;
            } else {
                return false;
            }
            out = (out << 4) | d;
        }
        return true;
    }

    bool String(std::string &out) {
        ++m_pos; // opening quote
        std::string raw;
        while (true) {
            if (AtEnd()) {
                return false;
            }
            const uint8_t c = m_b[m_pos++];
            if (c == '"') {
                break;
            }
            if (c < 0x20) {
                return false;
            }
            if (c != '\\') {
                raw += char(c);
                continue;
            }
            if (AtEnd()) {
                return false;
            }
            const uint8_t e = m_b[m_pos++];
            switch (e) {
                case '"':
                    raw += '"';
                    break;
                case '\\':
                    raw += '\\';
                    break;
                case '/':
                    raw += '/';
                    break;
                case 'b':
                    raw += '\b';
                    break;
                case 'f':
                    raw += '\f';
                    break;
                case 'n':
                    raw += '\n';
                    break;
                case 'r':
                    raw += '\r';
                    break;
                case 't':
                    raw += '\t';
                    break;
                case 'u': {
                    uint32_t cp;
                    if (!Hex4(cp)) {
                        return false;
                    }
                    if (cp >= 0xdc00 && cp <= 0xdfff) {
                        return false;
                    }
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (!Literal("\\u")) {
                            return false;
                        }
                        uint32_t low;
                        if (!Hex4(low) || low < 0xdc00 || low > 0xdfff) {
                            return false;
                        }
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    }
                    AppendUtf8(cp, raw);
                    break;
                }
                default:
                    return false;
            }
        }
        if (!ValidUtf8(raw)) {
            return false;
        }
        out += raw;
        return true;
    }

    bool ArrayValue(JsonNode &node, int depth) {
        if (depth >= kMaxDepth) {
            return false;
        }
        node.kind = JsonNode::Kind::Arr;
        ++m_pos;
        SkipWs();
        if (!AtEnd() && Peek() == ']') {
            ++m_pos;
            return true;
        }
        while (true) {
            JsonNode item;
            SkipWs();
            if (!Value(item, depth)) {
                return false;
            }
            node.arr.push_back(std::move(item));
            SkipWs();
            if (AtEnd()) {
                return false;
            }
            if (Peek() == ',') {
                ++m_pos;
                continue;
            }
            if (Peek() == ']') {
                ++m_pos;
                return true;
            }
            return false;
        }
    }

    bool ObjectValue(JsonNode &node, int depth) {
        if (depth >= kMaxDepth) {
            return false;
        }
        node.kind = JsonNode::Kind::Obj;
        ++m_pos;
        SkipWs();
        if (!AtEnd() && Peek() == '}') {
            ++m_pos;
            return true;
        }
        while (true) {
            SkipWs();
            if (AtEnd() || Peek() != '"') {
                return false;
            }
            std::string key;
            if (!String(key)) {
                return false;
            }
            SkipWs();
            if (AtEnd() || Peek() != ':') {
                return false;
            }
            ++m_pos;
            SkipWs();
            JsonNode value;
            if (!Value(value, depth)) {
                return false;
            }
            node.obj.emplace_back(std::move(key), std::move(value));
            SkipWs();
            if (AtEnd()) {
                return false;
            }
            if (Peek() == ',') {
                ++m_pos;
                continue;
            }
            if (Peek() == '}') {
                ++m_pos;
                return true;
            }
            return false;
        }
    }

    ByteView m_b;
    size_t m_pos = 0;
};

} // namespace

std::optional<JsonNode> ParseJson(ByteView bytes) {
    return Parser(bytes).Document();
}

bool DecodeStruct(const JsonNode &node, const std::vector<JsonField> &fields) {
    if (node.kind == JsonNode::Kind::Obj) {
        std::vector<bool> seen(fields.size(), false);
        for (const auto &[key, value] : node.obj) {
            size_t i = 0;
            while (i < fields.size() && fields[i].name != key) {
                ++i;
            }
            if (i == fields.size() || seen[i]) {
                // deny_unknown_fields / duplicate field
                return false;
            }
            seen[i] = true;
            if (!fields[i].set(&value)) {
                return false;
            }
        }
        for (size_t i = 0; i < fields.size(); ++i) {
            if (seen[i]) {
                continue;
            }
            if (!fields[i].serde_default && !fields[i].option) {
                return false; // missing field
            }
            if (!fields[i].set(nullptr)) {
                return false;
            }
        }
        return true;
    }
    if (node.kind == JsonNode::Kind::Arr) {
        if (node.arr.size() > fields.size()) {
            return false;
        }
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i < node.arr.size()) {
                if (!fields[i].set(&node.arr[i])) {
                    return false;
                }
            } else if (!fields[i].serde_default || !fields[i].set(nullptr)) {
                return false; // invalid length
            }
        }
        return true;
    }
    return false;
}

bool DecodeString(const JsonNode *node, std::string &out) {
    if (!node || node->kind != JsonNode::Kind::Str) {
        return false;
    }
    out = node->s;
    return true;
}

bool DecodeBool(const JsonNode *node, bool &out) {
    if (!node) {
        out = false;
        return true;
    }
    if (node->kind != JsonNode::Kind::Bool) {
        return false;
    }
    out = node->b;
    return true;
}

bool DecodeUnsigned(const JsonNode *node, uint64_t max, uint64_t &out) {
    if (!node || node->kind != JsonNode::Kind::Num || !node->u ||
        *node->u > max) {
        return false;
    }
    out = *node->u;
    return true;
}

bool DecodeStrings(const JsonNode *node, std::vector<std::string> &out) {
    out.clear();
    if (!node) {
        return true; // #[serde(default)]
    }
    if (node->kind != JsonNode::Kind::Arr) {
        return false;
    }
    for (const JsonNode &item : node->arr) {
        std::string s;
        if (!DecodeString(&item, s)) {
            return false;
        }
        out.push_back(std::move(s));
    }
    return true;
}

bool DecodeOptString(const JsonNode *node, std::optional<std::string> &out) {
    out.reset();
    if (!node || node->kind == JsonNode::Kind::Null) {
        return true;
    }
    std::string s;
    if (!DecodeString(node, s)) {
        return false;
    }
    out = std::move(s);
    return true;
}

bool DecodeOptBool(const JsonNode *node, std::optional<bool> &out) {
    out.reset();
    if (!node || node->kind == JsonNode::Kind::Null) {
        return true;
    }
    if (node->kind != JsonNode::Kind::Bool) {
        return false;
    }
    out = node->b;
    return true;
}

} // namespace chronik::native::lotus_v2::http
