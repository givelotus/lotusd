// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging/encoder.h>

#include <logging.h>
#include <util/string.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cmath>

using util::RemovePrefixView;
using namespace std::chrono_literals;

/**
 * Name of a category for the JSON format, without copying it.
 * Uncategorized messages (NONE, or the ALL mask) are "none".
 */
std::string_view BCLog::LogCategoryName(LogFlags category) {
    if (category == NONE || category == ALL) {
        return "none";
    }
    return LogCategoryText(category);
}

std::string_view BCLog::SourceFileName(const std::source_location &loc) {
    return RemovePrefixView(loc.file_name(), "./");
}

std::string_view BCLog::LogLevelName(Level level) {
    switch (level) {
        case Level::Trace:
            return "trace";
        case Level::Debug:
            return "debug";
        case Level::Info:
            return "info";
        case Level::Warning:
            return "warning";
        case Level::Error:
            return "error";
    }
    assert(false);
}

unsigned BCLog::LogPriority(Level level) {
    switch (level) {
        case Level::Trace:
        case Level::Debug:
            return 7;
        case Level::Info:
            return 6;
        case Level::Warning:
            return 4;
        case Level::Error:
            return 3;
    }
    assert(false);
}

namespace BCLog {
namespace {
    //! Characters needing no JSON escaping: printable ASCII but '"', '\\', DEL.
    constexpr std::array<bool, 256> JSON_PLAIN{[] {
        std::array<bool, 256> plain{};
        for (int c = 0x20; c < 0x7f; ++c) {
            plain[c] = c != '"' && c != '\\';
        }
        return plain;
    }()};

    /**
     * Length of the valid UTF-8 sequence starting at s[0] (a byte >= 0x80), or
     * 0 if it is not one (overlong, surrogate, beyond U+10FFFF or truncated).
     */
    size_t Utf8SequenceLength(std::string_view s) {
        const auto b{[&](size_t i) { return uint8_t(s[i]); }};
        const uint8_t c{b(0)};
        size_t len;
        uint8_t lo{0x80}, hi{0xbf};
        if (c >= 0xc2 && c <= 0xdf) {
            len = 2;
        } else if (c >= 0xe0 && c <= 0xef) {
            len = 3;
            if (c == 0xe0) {
                lo = 0xa0;
            } else if (c == 0xed) {
                hi = 0x9f;
            }
        } else if (c >= 0xf0 && c <= 0xf4) {
            len = 4;
            if (c == 0xf0) {
                lo = 0x90;
            } else if (c == 0xf4) {
                hi = 0x8f;
            }
        } else {
            return 0;
        }
        if (s.size() < len || b(1) < lo || b(1) > hi) {
            return 0;
        }
        for (size_t i = 2; i < len; ++i) {
            if (b(i) < 0x80 || b(i) > 0xbf) {
                return 0;
            }
        }
        return len;
    }

} // namespace
} // namespace BCLog

void BCLog::AppendDigits(std::string &out, uint32_t value, int width) {
    char buf[10];
    for (int i = width - 1; i >= 0; --i) {
        buf[i] = char('0' + value % 10);
        value /= 10;
    }
    out.append(buf, width);
}

void BCLog::AppendRfc3339(std::string &out, SystemClock::time_point tp,
                          bool with_micros) {
    const auto secs{std::chrono::floor<std::chrono::seconds>(tp)};
    const auto days{std::chrono::floor<std::chrono::days>(secs)};
    const std::chrono::year_month_day ymd{days};
    const std::chrono::hh_mm_ss hms{secs - days};
    AppendDigits(out, uint32_t(std::clamp(int{ymd.year()}, 0, 9999)), 4);
    out += '-';
    AppendDigits(out, unsigned{ymd.month()}, 2);
    out += '-';
    AppendDigits(out, unsigned{ymd.day()}, 2);
    out += 'T';
    AppendDigits(out, uint32_t(hms.hours().count()), 2);
    out += ':';
    AppendDigits(out, uint32_t(hms.minutes().count()), 2);
    out += ':';
    AppendDigits(out, uint32_t(hms.seconds().count()), 2);
    if (with_micros) {
        out += '.';
        AppendDigits(
            out,
            uint32_t(
                std::chrono::duration_cast<std::chrono::microseconds>(tp - secs)
                    .count()),
            6);
    }
    out += 'Z';
}

void BCLog::AppendJsonEscaped(std::string &out, std::string_view str) {
    static constexpr char HEX[]{"0123456789abcdef"};
    size_t i{0};
    while (i < str.size()) {
        // Copy runs of plain characters at once.
        size_t run{i};
        while (run < str.size() && JSON_PLAIN[uint8_t(str[run])]) {
            ++run;
        }
        out.append(str.data() + i, run - i);
        i = run;
        if (i == str.size()) {
            break;
        }
        const uint8_t c{uint8_t(str[i])};
        if (c >= 0x80) {
            const size_t len{Utf8SequenceLength(str.substr(i))};
            if (len) {
                out.append(str.data() + i, len);
                i += len;
            } else {
                // U+FFFD REPLACEMENT CHARACTER for each invalid byte
                out.append("\xef\xbf\xbd");
                ++i;
            }
            continue;
        }
        switch (c) {
            case '"':
                out.append("\\\"");
                break;
            case '\\':
                out.append("\\\\");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            case '\t':
                out.append("\\t");
                break;
            default: {
                const char esc[6]{'\\', 'u',         '0',
                                  '0',  HEX[c >> 4], HEX[c & 0xf]};
                out.append(esc, sizeof(esc));
            }
        }
        ++i;
    }
}

std::string_view BCLog::BareFunctionName(std::string_view signature) {
    // "void CConnman::DumpAddresses(int) const" -> "CConnman::DumpAddresses"
    const size_t close{signature.rfind(')')};
    if (close == std::string_view::npos) {
        return signature;
    }
    // The parameter list's '(' (skipping nested parentheses)
    int depth{0};
    size_t open{close};
    while (true) {
        const char c{signature[open]};
        depth += c == ')' ? 1 : c == '(' ? -1 : 0;
        if (depth == 0 || open == 0) {
            break;
        }
        --open;
    }
    // The name ends there; it starts after the last space outside brackets
    // (before it: the return type).
    size_t start{open};
    depth = 0;
    while (start > 0) {
        const char c{signature[start - 1]};
        if (c == ')' || c == '>') {
            ++depth;
        } else if (c == '(' || c == '<') {
            --depth;
        } else if (c == ' ' && depth == 0) {
            break;
        }
        --start;
    }
    return signature.substr(start, open - start);
}

/** Append GetLogPrefix(category, level) to out, without allocating */
void BCLog::AppendLogPrefix(std::string &out, LogFlags category, Level level,
                            bool always_print_category_level) {
    if (category == LogFlags::NONE) {
        category = LogFlags::ALL;
    }
    const bool has_category{always_print_category_level ||
                            category != LogFlags::ALL};
    // If there is no category, Info is implied
    if (!has_category && level == Level::Info) {
        return;
    }
    out += '[';
    if (has_category) {
        out += LogCategoryText(category);
    }
    if (always_print_category_level || !has_category || level != Level::Debug) {
        // If there is a category, Debug is implied, so don't add the level
        if (has_category) {
            out += ':';
        }
        out += LogLevelName(level);
    }
    out += "] ";
}

namespace BCLog {

namespace {
    //! Scratch space of the logger thread (encoders run there only)
    thread_local std::string t_scratch;

    /** A structured event's message and the text of the fields it lacks */
    std::string_view EventText(const LogLine &line, bool with_fields) {
        std::string &text{t_scratch};
        text.clear();
        uint64_t used{0};
        AppendEventMessage(text, *line.event, line.fields, &used);
        if (with_fields) {
            size_t i{0};
            std::string value;
            for (const FieldView f : line.fields) {
                if (i >= 64 || !(used >> i & 1)) {
                    text += ' ';
                    text += f.Info().name;
                    text += '=';
                    value.clear();
                    f.AppendText(value);
                    AppendQuotedText(text, value);
                }
                ++i;
            }
            if (line.fields_truncated) {
                text += " [fields truncated]";
            }
        }
        text += '\n';
        return text;
    }

    /** Append a field's value as a JSON value of its type */
    void AppendJsonValue(std::string &out, const FieldView &f) {
        switch (f.kind) {
            case FieldKind::I64:
            case FieldKind::U64:
            case FieldKind::DURATION_NS:
                f.AppendText(out);
                return;
            case FieldKind::F64:
                // JSON has no NaN or infinity literals; retain the key as null.
                if (std::isfinite(f.F64())) {
                    f.AppendText(out);
                } else {
                    out += "null";
                }
                return;
            case FieldKind::BOOL:
                out += f.Bool() ? "true" : "false";
                return;
            default: {
                std::string text;
                f.AppendText(text);
                out += '"';
                AppendJsonEscaped(out, text);
                out += '"';
            }
        }
    }
} // namespace

void TextEncoder::Encode(const LogLine &line, const LogOptions &opts,
                         std::string &out) const {
    const std::string_view msg{
        line.event ? EventText(line, /*with_fields=*/true) : line.message};
    out.clear();
    const auto priority{[&] {
        out += '<';
        out += char('0' + LogPriority(line.level));
        out += '>';
    }};
    if (opts.text_priority) priority();
    if (line.ratelimited) {
        // To avoid confusion caused by dropped log messages when debugging
        // an issue, lines are prefixed with "[*]" when there are any
        // suppressed source locations.
        out += "[*] ";
    }
    if (opts.timestamps) {
        AppendRfc3339(out, line.time, opts.time_micros);
        if (line.mocktime > 0s) {
            out += " (mocktime: ";
            AppendRfc3339(out, SystemClock::time_point{line.mocktime},
                          /*with_micros=*/false);
            out += ')';
        }
        out += ' ';
    }
    if (opts.threadnames) {
        out += '[';
        out += line.thread.empty() ? "unknown" : line.thread;
        out += "] ";
    }
    if (opts.sourcelocations) {
        out += '[';
        out += SourceFileName(line.loc);
        out += ':';
        char num[16];
        const auto res{std::to_chars(num, num + sizeof(num), line.loc.line())};
        out.append(num, res.ptr);
        out += "] [";
        out += line.loc.function_name();
        out += "] ";
    }
    AppendLogPrefix(out, line.category, line.level,
                    opts.always_print_category_level);
    // Escape control characters except newline ('\n') in C syntax, as
    // LogEscapeMessage does; copy runs of other characters at once.
    size_t run{0};
    for (size_t i = 0; i < msg.size(); ++i) {
        const uint8_t ch{uint8_t(msg[i])};
        if (opts.text_priority && ch == '\n' && i + 1 < msg.size()) {
            out.append(msg.data() + run, i + 1 - run);
            priority();
            run = i + 1;
            continue;
        }
        if ((ch >= 32 || ch == '\n') && ch != '\x7f') {
            continue;
        }
        out.append(msg.data() + run, i - run);
        static constexpr char HEX[]{"0123456789abcdef"};
        const char esc[4]{'\\', 'x', HEX[ch >> 4], HEX[ch & 0xf]};
        out.append(esc, sizeof(esc));
        run = i + 1;
    }
    out.append(msg.data() + run, msg.size() - run);
}

namespace {
    enum class JsonSchema { GENERIC, GCP, ECS };

    void EncodeJson(const LogLine &line, const LogOptions &opts,
                    std::string &out, JsonSchema schema) {
        std::string_view msg{line.event ? EventText(line, /*with_fields=*/false)
                                        : line.message};
        const bool ecs{schema == JsonSchema::ECS};
        out.clear();
        out += '{';
        // ECS requires an event timestamp, even when text timestamps are off.
        if (opts.timestamps || ecs) {
            out += ecs ? "\"@timestamp\":\"" : "\"time\":\"";
            AppendRfc3339(out, line.time, /*with_micros=*/true);
            out += "\",";
        }
        out += schema == JsonSchema::GCP ? "\"severity\":\""
               : ecs                     ? "\"log.level\":\""
                                         : "\"level\":\"";
        if (schema == JsonSchema::GCP) {
            switch (line.level) {
                case Level::Trace:
                case Level::Debug:
                    out += "DEBUG";
                    break;
                case Level::Info:
                    out += "INFO";
                    break;
                case Level::Warning:
                    out += "WARNING";
                    break;
                case Level::Error:
                    out += "ERROR";
                    break;
            }
        } else {
            out += LogLevelName(line.level);
        }
        out += ecs ? "\",\"log.logger\":\"" : "\",\"category\":\"";
        out += LogCategoryName(line.category);
        out += ecs ? "\",\"process.thread.name\":\"" : "\",\"thread\":\"";
        AppendJsonEscaped(out, line.thread.empty() ? "unknown" : line.thread);
        out += "\",\"message\":\"";
        if (!msg.empty() && msg.back() == '\n') {
            msg.remove_suffix(1);
        }
        AppendJsonEscaped(out, msg);
        out += '"';
        if (ecs) out += ",\"ecs.version\":\"8.11.0\"";
        if (line.event) {
            out += ecs ? ",\"event.action\":\"" : ",\"event\":\"";
            AppendJsonEscaped(out, line.event->event);
            out += '"';
            for (const FieldView f : line.fields) {
                out += ",\"";
                if (ecs && !f.Info().ecs.empty()) {
                    out += f.Info().ecs;
                } else {
                    if (ecs) out += "lotus.";
                    out += f.Info().name;
                }
                out += "\":";
                if (ecs && f.kind == FieldKind::DURATION_NS) {
                    // ECS event.duration is an integer number of nanoseconds.
                    char number[32];
                    const auto result{std::to_chars(
                        number, number + sizeof(number), f.DurationNs())};
                    out.append(number, result.ptr);
                } else {
                    AppendJsonValue(out, f);
                }
            }
            if (line.fields_truncated) {
                out += ecs ? ",\"lotus.fields_truncated\":true"
                           : ",\"fields_truncated\":true";
            }
        }
        if (line.mocktime > 0s) {
            out += ecs ? ",\"lotus.mocktime\":\"" : ",\"mocktime\":\"";
            AppendRfc3339(out, SystemClock::time_point{line.mocktime},
                          /*with_micros=*/false);
            out += '"';
        }
        if (line.continued) {
            out += ecs ? ",\"lotus.continued\":true" : ",\"continued\":true";
        }
        if (line.ratelimited) {
            out +=
                ecs ? ",\"lotus.ratelimited\":true" : ",\"ratelimited\":true";
        }
        if (opts.sourcelocations && ecs) {
            out += ",\"log.origin.file.name\":\"";
            AppendJsonEscaped(out, SourceFileName(line.loc));
            out += "\",\"log.origin.file.line\":";
            char number[16];
            const auto result{std::to_chars(number, number + sizeof(number),
                                            line.loc.line())};
            out.append(number, result.ptr);
            out += ",\"log.origin.function\":\"";
            AppendJsonEscaped(out, BareFunctionName(line.loc.function_name()));
            out += '"';
        } else if (opts.sourcelocations) {
            out +=
                schema == JsonSchema::GCP
                    ? ",\"logging.googleapis.com/sourceLocation\":{\"file\":\""
                    : ",\"source\":{\"file\":\"";
            AppendJsonEscaped(out, SourceFileName(line.loc));
            out += "\",\"line\":";
            char num[16];
            const auto res{
                std::to_chars(num, num + sizeof(num), line.loc.line())};
            // LogEntrySourceLocation.line is an int64 JSON string in the GCP
            // API.
            if (schema == JsonSchema::GCP) out += '"';
            out.append(num, res.ptr);
            if (schema == JsonSchema::GCP) out += '"';
            out += ",\"function\":\"";
            AppendJsonEscaped(out, BareFunctionName(line.loc.function_name()));
            out += "\"}";
        }
        out += "}\n";
    }

} // namespace

void JsonEncoder::Encode(const LogLine &line, const LogOptions &opts,
                         std::string &out) const {
    EncodeJson(line, opts, out, JsonSchema::GENERIC);
}

void JsonGcpEncoder::Encode(const LogLine &line, const LogOptions &opts,
                            std::string &out) const {
    EncodeJson(line, opts, out, JsonSchema::GCP);
}

void JsonEcsEncoder::Encode(const LogLine &line, const LogOptions &opts,
                            std::string &out) const {
    EncodeJson(line, opts, out, JsonSchema::ECS);
}

void LogfmtEncoder::Encode(const LogLine &line, const LogOptions &opts,
                           std::string &out) const {
    std::string_view message{line.event ? EventText(line, false)
                                        : line.message};
    if (!message.empty() && message.back() == '\n') message.remove_suffix(1);
    out.clear();
    auto field = [&](std::string_view key, std::string_view value) {
        if (!out.empty()) out += ' ';
        out += key;
        out += "=\"";
        AppendJsonEscaped(out, value);
        out += '"';
    };
    if (opts.timestamps) {
        std::string time;
        AppendRfc3339(time, line.time, true);
        field("time", time);
    }
    field("level", LogLevelName(line.level));
    field("category", LogCategoryName(line.category));
    field("thread", line.thread.empty() ? "unknown" : line.thread);
    field("message", message);
    if (line.mocktime > 0s) {
        std::string mocktime;
        AppendRfc3339(mocktime, SystemClock::time_point{line.mocktime}, false);
        field("mocktime", mocktime);
    }
    if (line.event) {
        field("event", line.event->event);
        for (const FieldView f : line.fields) {
            std::string value;
            f.AppendText(value);
            if (f.kind == FieldKind::I64 || f.kind == FieldKind::U64 ||
                f.kind == FieldKind::F64 || f.kind == FieldKind::DURATION_NS ||
                f.kind == FieldKind::BOOL) {
                out += ' ';
                out += f.Info().name;
                out += '=';
                out += value;
            } else {
                field(f.Info().name, value);
            }
        }
        if (line.fields_truncated) out += " fields_truncated=true";
    }
    if (opts.sourcelocations) {
        field("source_file", SourceFileName(line.loc));
        out += " source_line=" + std::to_string(line.loc.line());
        field("source_function", BareFunctionName(line.loc.function_name()));
    }
    if (line.continued) out += " continued=true";
    if (line.ratelimited) out += " ratelimited=true";
    out += '\n';
}

void JournaldEncoder::Encode(const LogLine &line, const LogOptions &opts,
                             std::string &out) const {
    auto message{line.event ? EventText(line, false) : line.message};
    if (!message.empty() && message.back() == '\n') message.remove_suffix(1);
    out.clear();
    const auto field{[&](std::string_view key, std::string_view value) {
        out += key;
        if (value.find('\n') == std::string_view::npos &&
            value.find('\0') == std::string_view::npos) {
            out += '=';
        } else {
            out += '\n';
            const uint64_t size{value.size()};
            for (unsigned i = 0; i < 8; ++i)
                out += char(size >> (i * 8));
        }
        out += value;
        out += '\n';
    }};
    field("PRIORITY", std::to_string(LogPriority(line.level)));
    field("MESSAGE", message);
    field("LOTUS_CATEGORY", LogCategoryName(line.category));
    field("LOTUS_LEVEL", LogLevelName(line.level));
    field("LOTUS_THREAD", line.thread.empty() ? "unknown" : line.thread);
    if (opts.timestamps) {
        std::string time;
        AppendRfc3339(time, line.time, true);
        field("LOTUS_TIME", time);
    }
    if (opts.sourcelocations) {
        field("CODE_FILE", SourceFileName(line.loc));
        field("CODE_LINE", std::to_string(line.loc.line()));
        field("CODE_FUNC", BareFunctionName(line.loc.function_name()));
    }
    if (line.mocktime > 0s)
        field("LOTUS_MOCKTIME", std::to_string(line.mocktime.count()));
    if (line.event) {
        field("LOTUS_EVENT", line.event->event);
        for (const FieldView f : line.fields) {
            std::string key{"LOTUS_"}, value;
            for (char c : f.Info().name)
                key += c >= 'a' && c <= 'z' ? char(c - 'a' + 'A') : c;
            f.AppendText(value);
            field(key, value);
        }
    }
    if (line.continued) field("LOTUS_CONTINUED", "1");
    if (line.ratelimited) field("LOTUS_RATELIMITED", "1");
    if (line.fields_truncated) field("LOTUS_FIELDS_TRUNCATED", "1");
}

void SyslogEncoder::Encode(const LogLine &line, const LogOptions &opts,
                           std::string &out) const {
    // RFC 5424: PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG.
    // Facility 3 is daemon. Do not invent host/process identity or an SD-ID.
    out = "<" + std::to_string(3 * 8 + LogPriority(line.level)) + ">1 ";
    if (opts.timestamps)
        AppendRfc3339(out, line.time, true);
    else
        out += '-';
    out += " - - - - - ";
    // MSG-UTF8 requires BOM. JsonEncoder ensures valid UTF-8, even for
    // malformed original bytes, and escapes embedded newlines into one physical
    // record.
    out += "\xef\xbb\xbf";
    thread_local std::string body;
    JsonEncoder{}.Encode(line, opts, body);
    out += body;
}

std::unique_ptr<LogEncoder> MakeLogEncoder(LogFormat format) {
    switch (format) {
        case LogFormat::SYSLOG:
            return std::make_unique<SyslogEncoder>();
        case LogFormat::JOURNALD:
            return std::make_unique<JournaldEncoder>();
        case LogFormat::TEXT:
            return std::make_unique<TextEncoder>();
        case LogFormat::JSON_ECS:
            return std::make_unique<JsonEcsEncoder>();
        case LogFormat::JSON_GCP:
            return std::make_unique<JsonGcpEncoder>();
        case LogFormat::LOGFMT:
            return std::make_unique<LogfmtEncoder>();
        case LogFormat::JSON:
            return std::make_unique<JsonEncoder>();
    }
    assert(false);
}

} // namespace BCLog
