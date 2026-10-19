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
    // Only explicit, bounded float precision is supported; formatting runs here
    // on the consumer, with the same backend as the original printf call.
    bool AppendFormattedField(std::string &out, const FieldView &field,
                              std::string_view format) {
        if (format.empty()) {
            field.AppendText(out);
            return true;
        }
        if (field.kind != FieldKind::F64 ||
            (format.back() != 'f' && format.back() != 'g')) return false;
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
        out += kind == 'f' ? strprintf("%.*f", precision, field.F64())
                           : strprintf("%.*g", precision, field.F64());
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
