// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// HttpRequest/HttpResponse helpers and the port of chronik-http error.rs.

#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/proto.h>

#include <google/protobuf/message_lite.h>

#include <cctype>

namespace chronik::native {

namespace {

bool IEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

const std::string *FindHeader(const std::vector<HttpHeader> &headers,
                              std::string_view name) {
    for (const auto &[key, value] : headers) {
        if (IEquals(key, name)) {
            return &value;
        }
    }
    return nullptr;
}

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

/** Append `cp` as UTF-8. */
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
 * Rust String::from_utf8_lossy: invalid sequences become U+FFFD, with the
 * "maximal subpart" rule (each invalid sequence prefix is one replacement).
 */
std::string Utf8Lossy(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    const auto *s = reinterpret_cast<const uint8_t *>(in.data());
    size_t i = 0, n = in.size();
    while (i < n) {
        uint8_t b = s[i];
        if (b < 0x80) {
            out.push_back(char(b));
            ++i;
            continue;
        }
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (b >= 0xC2 && b <= 0xDF) {
            need = 1;
        } else if (b >= 0xE0 && b <= 0xEF) {
            need = 2;
            if (b == 0xE0) {
                lo = 0xA0;
            } else if (b == 0xED) {
                hi = 0x9F;
            }
        } else if (b >= 0xF0 && b <= 0xF4) {
            need = 3;
            if (b == 0xF0) {
                lo = 0x90;
            } else if (b == 0xF4) {
                hi = 0x8F;
            }
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
            continue;
        }
        size_t j = 1;
        bool ok = true;
        for (; j <= need; ++j) {
            if (i + j >= n) {
                ok = false;
                break;
            }
            uint8_t c = s[i + j];
            uint8_t l = j == 1 ? lo : 0x80, h = j == 1 ? hi : 0xBF;
            if (c < l || c > h) {
                ok = false;
                break;
            }
        }
        if (ok) {
            out.append(in.substr(i, need + 1));
            i += need + 1;
        } else {
            out += "\xEF\xBF\xBD";
            i += j;
        }
    }
    return out;
}

/** form_urlencoded byte decoding: '+' -> ' ', %XX -> byte. */
std::string FormDecode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '+') {
            out.push_back(' ');
        } else if (c == '%' && i + 2 < in.size() &&
                   HexVal(in[i + 1]) >= 0 && HexVal(in[i + 2]) >= 0) {
            out.push_back(char(HexVal(in[i + 1]) * 16 + HexVal(in[i + 2])));
            i += 2;
        } else {
            out.push_back(c);
        }
    }
    return Utf8Lossy(out);
}

} // namespace

const std::string *HttpRequest::Header(std::string_view name) const {
    return FindHeader(headers, name);
}

std::string HttpRequest::Target() const {
    if (!has_query) {
        return path;
    }
    return path + "?" + query_string;
}

std::map<std::string, std::string> HttpRequest::QueryParams() const {
    std::map<std::string, std::string> params;
    std::string_view qs = query_string;
    while (!qs.empty()) {
        size_t amp = qs.find('&');
        std::string_view pair = qs.substr(0, amp);
        qs = amp == std::string_view::npos ? std::string_view{}
                                           : qs.substr(amp + 1);
        if (pair.empty()) {
            continue;
        }
        size_t eq = pair.find('=');
        std::string key = FormDecode(pair.substr(0, eq));
        std::string value = eq == std::string_view::npos
                                ? std::string{}
                                : FormDecode(pair.substr(eq + 1));
        params[std::move(key)] = std::move(value);
    }
    return params;
}

const std::string *HttpResponse::Header(std::string_view name) const {
    return FindHeader(headers, name);
}

void HttpResponse::SetHeader(std::string name, std::string value) {
    for (auto &[key, val] : headers) {
        if (IEquals(key, name)) {
            val = std::move(value);
            return;
        }
    }
    headers.emplace_back(std::move(name), std::move(value));
}

std::string HttpResponse::ContentType() const {
    const std::string *ct = Header("content-type");
    return ct ? *ct : std::string{};
}

HttpResponse HttpResponse::Protobuf(const google::protobuf::MessageLite &msg,
                                    int status) {
    HttpResponse resp;
    resp.status = status;
    std::string out;
    msg.SerializeToString(&out);
    resp.body.assign(out.begin(), out.end());
    resp.headers.emplace_back("content-type",
                              std::string(CONTENT_TYPE_PROTOBUF));
    return resp;
}

HttpResponse HttpResponse::Text(int status, std::string_view text) {
    HttpResponse resp;
    resp.status = status;
    resp.body.assign(text.begin(), text.end());
    resp.headers.emplace_back("content-type", std::string(CONTENT_TYPE_TEXT));
    return resp;
}

HttpResponse HttpResponse::Empty(int status) {
    HttpResponse resp;
    resp.status = status;
    return resp;
}

StatusError ReportStatusError(std::string_view error_msg,
                              const HttpLogFn &log) {
    const std::string msg(error_msg);
    const std::optional<int> status = ParseErrorStatus(msg);
    if (!status) {
        if (log) {
            log(msg + "\n", true);
            log("Chronik HTTP server got an unknown error: " + msg + "\n",
                false);
        }
        return {500, "Unknown error, contact admins"};
    }
    if (*status >= 500 && *status <= 599) {
        if (log) {
            log(msg + "\n", true);
            log("Chronik HTTP server got an internal server error: " + msg +
                    "\n",
                false);
        }
    }
    return {*status, msg};
}

HttpResponse ErrorResponse(std::string_view error_msg, const HttpLogFn &log) {
    StatusError err = ReportStatusError(error_msg, log);
    proto::Error proto;
    proto.set_msg(err.msg);
    return HttpResponse::Protobuf(proto, err.status);
}

HttpResponse ExceptionResponse(const std::exception &err,
                               const HttpLogFn &log) {
    if (const auto *rejection = dynamic_cast<const HttpRejection *>(&err)) {
        return HttpResponse::Text(rejection->Status(), rejection->Body());
    }
    return ErrorResponse(err.what(), log);
}

} // namespace chronik::native
