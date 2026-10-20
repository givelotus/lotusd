// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging/event.h>

#include <tinyformat.h>

#include <cassert>
#include <charconv>
#include <cstring>

namespace BCLog {

namespace {
    template <typename T> T Load(std::span<const std::byte> data) {
        T v{};
        assert(data.size() >= sizeof(T));
        std::memcpy(&v, data.data(), sizeof(T));
        return v;
    }

    template <typename T> void AppendNumber(std::string &out, T v) {
        char buf[32];
        const auto res{std::to_chars(buf, buf + sizeof(buf), v)};
        out.append(buf, res.ptr);
    }

    struct StaticStr {
        const char *str;
        uint64_t len;
    };

    constexpr size_t Align8(size_t n) {
        return (n + 7) & ~size_t{7};
    }
} // namespace

int64_t FieldView::I64() const {
    return Load<int64_t>(data);
}
uint64_t FieldView::U64() const {
    return Load<uint64_t>(data);
}
double FieldView::F64() const {
    return Load<double>(data);
}
bool FieldView::Bool() const {
    return Load<uint8_t>(data) != 0;
}
int64_t FieldView::DurationNs() const {
    return Load<int64_t>(data);
}

bool FieldView::IsNumber() const {
    return kind == FieldKind::I64 || kind == FieldKind::U64 ||
           kind == FieldKind::F64 || kind == FieldKind::DURATION_NS;
}

void FieldView::AppendText(std::string &out) const {
    switch (kind) {
        case FieldKind::I64:
            AppendNumber(out, I64());
            return;
        case FieldKind::U64:
            AppendNumber(out, U64());
            return;
        case FieldKind::F64:
            AppendNumber(out, F64());
            return;
        case FieldKind::BOOL:
            out += Bool() ? "true" : "false";
            return;
        case FieldKind::STR:
            out.append(reinterpret_cast<const char *>(data.data()),
                       data.size());
            return;
        case FieldKind::STATIC_STR: {
            const auto s{Load<StaticStr>(data)};
            out.append(s.str, s.len);
            return;
        }
        case FieldKind::HASH: {
            // As uint256::GetHex: most significant byte first
            static constexpr char HEX[]{"0123456789abcdef"};
            for (size_t i = data.size(); i-- > 0;) {
                const uint8_t b{uint8_t(data[i])};
                out += HEX[b >> 4];
                out += HEX[b & 0xf];
            }
            return;
        }
        case FieldKind::DURATION_NS: {
            // Generic unit: microseconds
            const int64_t ns{DurationNs()};
            if (ns % 1000 == 0) {
                AppendNumber(out, ns / 1000);
            } else {
                AppendNumber(out, double(ns) / 1000);
            }
            return;
        }
        case FieldKind::CUSTOM: {
            const auto fn{Load<PackedRenderFn>(data)};
            fn(data.subspan(sizeof(fn)), out);
            return;
        }
        case FieldKind::REF: {
            const auto &obj{
                *reinterpret_cast<const std::shared_ptr<const void> *>(
                    data.data())};
            const auto fn{Load<RefRenderFn>(
                data.subspan(sizeof(std::shared_ptr<const void>)))};
            fn(obj.get(), out);
            return;
        }
    }
}

FieldView FieldList::Iterator::operator*() const {
    FieldHeader h;
    std::memcpy(&h, m_pos, sizeof(h));
    return FieldView{h.id, h.kind, h.truncated,
                     std::span<const std::byte>{m_pos + sizeof(h), h.size}};
}

FieldList::Iterator &FieldList::Iterator::operator++() {
    FieldHeader h;
    std::memcpy(&h, m_pos, sizeof(h));
    m_pos += Align8(sizeof(h) + h.size);
    --m_left;
    return *this;
}

void ReleaseFields(FieldList fields) {
    for (const FieldView f : fields) {
        if (f.kind == FieldKind::REF) {
            auto *obj{const_cast<std::shared_ptr<const void> *>(
                reinterpret_cast<const std::shared_ptr<const void> *>(
                    f.data.data()))};
            std::destroy_at(obj);
        }
    }
}

void AppendQuotedText(std::string &out, std::string_view text) {
    bool quote{text.empty()};
    for (const char c : text) {
        const uint8_t u{uint8_t(c)};
        if (u <= ' ' || c == '"' || c == '=' || c == '\\' || u == 0x7f) {
            quote = true;
            break;
        }
    }
    if (!quote) {
        out += text;
        return;
    }
    out += '"';
    for (const char c : text) {
        const uint8_t u{uint8_t(c)};
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
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
                if (u < 0x20 || u == 0x7f) {
                    static constexpr char HEX[]{"0123456789abcdef"};
                    const char esc[6]{'\\', 'u',         '0',
                                      '0',  HEX[u >> 4], HEX[u & 0xf]};
                    out.append(esc, sizeof(esc));
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

namespace {
    // Explicit, bounded formatting runs on the consumer, with the same
    // backend and integral values as the original printf call.
    bool AppendFormattedField(std::string &out, const FieldView &field,
                              std::string_view format) {
        if (format.empty()) {
            field.AppendText(out);
            return true;
        }
        // Match fs::quoted(string): double quotes with '&' escaping quotes
        // and ampersands. Only the human message is quoted; the copied string
        // remains raw for structured encoders. Never guess this from a path.
        if (format == "fsq") {
            std::string_view value;
            if (field.kind == FieldKind::STR) {
                value = {reinterpret_cast<const char *>(field.data.data()),
                         field.data.size()};
            } else if (field.kind == FieldKind::STATIC_STR) {
                const auto str{Load<StaticStr>(field.data)};
                value = {str.str, str.len};
            } else {
                return false;
            }
            out += '"';
            for (const char character : value) {
                if (character == '"' || character == '&') out += '&';
                out += character;
            }
            out += '"';
            return true;
        }
        // Decimal padding is bounded to a 64-bit integer's maximum width.
        // Preserve the numeric field, including all UINT64_MAX bits. A signed
        // negative value with %u needs its original source width to reproduce
        // its cast, which the normalized field does not retain: reject it.
        if ((format.back() == 'd' || format.back() == 'u') &&
            (field.kind == FieldKind::I64 || field.kind == FieldKind::U64)) {
            const bool unsigned_format{format.back() == 'u'};
            if (unsigned_format && field.kind == FieldKind::I64 &&
                field.I64() < 0)
                return false;
            format.remove_suffix(1);
            if (format.empty()) {
                field.AppendText(out);
                return true;
            }
            const bool zero_pad{format.front() == '0'};
            if (zero_pad) format.remove_prefix(1);
            if (format.empty() || format.front() == '0') return false;
            int width{0};
            const auto [end, error]{std::from_chars(
                format.data(), format.data() + format.size(), width)};
            if (error != std::errc{} || end != format.data() + format.size() ||
                width < 1 || width > 20)
                return false;
            if (field.kind == FieldKind::U64) {
                out += strprintf(zero_pad ? "%0*u" : "%*u", width, field.U64());
            } else if (unsigned_format) {
                out += strprintf(zero_pad ? "%0*u" : "%*u", width,
                                 uint64_t(field.I64()));
            } else {
                out += strprintf(zero_pad ? "%0*d" : "%*d", width, field.I64());
            }
            return true;
        }
        // Bounded zero-padded hexadecimal preserves diagnostic bit patterns
        // without turning the structured integer into a string. Signed values
        // must be nonnegative; callers cast a signed bitfield to its wire type.
        if (format.back() == 'x' &&
            (field.kind == FieldKind::I64 || field.kind == FieldKind::U64)) {
            if (field.kind == FieldKind::I64 && field.I64() < 0) return false;
            format.remove_suffix(1);
            int width{0};
            if (!format.empty()) {
                if (format.front() != '0' || format.size() < 2) return false;
                format.remove_prefix(1);
                const auto [end, error]{std::from_chars(
                    format.data(), format.data() + format.size(), width)};
                if (error != std::errc{} || end != format.data() + format.size() ||
                    width < 1 || width > 16) return false;
            }
            const uint64_t value{field.kind == FieldKind::U64
                                     ? field.U64() : uint64_t(field.I64())};
            out += strprintf("%0*x", width, value);
            return true;
        }
        if ((field.kind != FieldKind::F64 && field.kind != FieldKind::I64 &&
             field.kind != FieldKind::U64) ||
            (format.back() != 'f' && format.back() != 'g'))
            return false;
        const char kind{format.back()};
        format.remove_suffix(1);
        int precision{6};
        if (!format.empty()) {
            if (format.front() != '.' || format.size() < 2) return false;
            format.remove_prefix(1);
            const auto [end, error]{std::from_chars(
                format.data(), format.data() + format.size(), precision)};
            if (error != std::errc{} || end != format.data() + format.size() ||
                precision < 0 || precision > 18) return false;
        }
        // tinyformat streams integral operands as integers even with %f/%g;
        // precision does not invent a fractional part or round a large value.
        if (field.kind == FieldKind::I64 || field.kind == FieldKind::U64) {
            field.AppendText(out);
        } else {
            out += kind == 'f' ? strprintf("%.*f", precision, field.F64())
                               : strprintf("%.*g", precision, field.F64());
        }
        return true;
    }
} // namespace

void AppendEventMessage(std::string &out, const LogEventSite &site,
                        FieldList fields, uint64_t *used) {
    if (used) {
        *used = 0;
    }
    if (!site.message) {
        out += site.event;
        return;
    }
    const std::string_view tmpl{site.message};
    size_t pos{0};
    while (pos < tmpl.size()) {
        const size_t open{tmpl.find('{', pos)};
        if (open == std::string_view::npos) {
            break;
        }
        const size_t close{tmpl.find('}', open)};
        if (close == std::string_view::npos) {
            break;
        }
        out.append(tmpl.substr(pos, open - pos));
        const std::string_view placeholder{tmpl.substr(open + 1, close - open - 1)};
        const size_t colon{placeholder.find(':')};
        const std::string_view name{placeholder.substr(0, colon)};
        const std::string_view format{colon == std::string_view::npos
                                          ? std::string_view{}
                                          : placeholder.substr(colon + 1)};
        bool found{false};
        size_t i{0};
        for (const FieldView f : fields) {
            if (f.Info().name == name && AppendFormattedField(out, f, format)) {
                if (used && i < 64) {
                    *used |= uint64_t{1} << i;
                }
                found = true;
                break;
            }
            ++i;
        }
        if (!found) {
            // A field the call site did not give: keep the placeholder
            out.append(tmpl.substr(open, close - open + 1));
        }
        pos = close + 1;
    }
    out.append(tmpl.substr(pos));
}

} // namespace BCLog
