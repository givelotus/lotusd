// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <memusage.h>
#include <util/fs.h>

#include <util/string.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <map>
#include <optional>
#include <unordered_map>

using util::Join;
using util::RemovePrefixView;

bool fLogIPs = DEFAULT_LOGIPS;
const char *const DEFAULT_DEBUGLOGFILE = "debug.log";
constexpr auto MAX_USER_SETABLE_SEVERITY_LEVEL{BCLog::Level::Info};
//! Largest JSON line buffer kept for reuse between log lines
static constexpr size_t MAX_RETAINED_LINE_BUFFER{64 * 1024};

BCLog::Logger &LogInstance() {
    /**
     * NOTE: the logger instance is leaked on exit. This is ugly, but will be
     * cleaned up by the OS/libc. Defining a logger as a global object doesn't
     * work since the order of destruction of static/global objects is
     * undefined. Consider if the logger gets destroyed, and then some later
     * destructor calls LogPrintf, maybe indirectly, and you get a core dump at
     * shutdown trying to access the logger. When the shutdown sequence is fully
     * audited and tested, explicit destruction of these objects can be
     * implemented by changing this from a raw pointer to a std::unique_ptr.
     * Since the ~Logger() destructor is never called, the Logger class and all
     * its subclasses must have implicitly-defined destructors.
     *
     * This method of initialization was originally introduced in
     * ee3374234c60aba2cc4c5cd5cac1c0aefc2d817c.
     */
    static BCLog::Logger *g_logger{new BCLog::Logger()};
    return *g_logger;
}

namespace BCLog {
std::string LogEscapeMessage(std::string_view str);
} // namespace BCLog

static int FileWriteStr(std::string_view str, FILE *fp) {
    return fwrite(str.data(), 1, str.size(), fp);
}

bool BCLog::Logger::StartLogging() {
    StdLockGuard scoped_lock(m_cs);

    assert(m_buffering);
    assert(m_fileout == nullptr);

    if (m_print_to_file) {
        assert(!m_file_path.empty());
        m_fileout = fsbridge::fopen(m_file_path, "a");
        if (!m_fileout) {
            return false;
        }

        // Unbuffered.
        setbuf(m_fileout, nullptr);

        // Add newlines to the logfile to distinguish this execution from the
        // last one.
        FileWriteStr("\n\n\n\n\n", m_fileout);
    }

    // Dump buffered messages from before we opened the log.
    m_buffering = false;
    if (m_buffer_lines_discarded > 0) {
        LogPrintStr_(
            strprintf(
                "Early logging buffer overflowed, %d log lines discarded.\n",
                m_buffer_lines_discarded),
            std::source_location::current(), BCLog::ALL, Level::Info,
            /*should_ratelimit=*/false);
    }
    while (!m_msgs_before_open.empty()) {
        const auto &buflog = m_msgs_before_open.front();
        std::string s;
        if (m_log_format == LogFormat::JSON) {
            s.swap(m_line_buf);
            FormatJsonLine(s, buflog.str, buflog.category, buflog.level,
                           buflog.source_loc, buflog.threadname, buflog.now,
                           buflog.mocktime, /*continued=*/false,
                           /*ratelimited=*/false);
        } else {
            s = LogEscapeMessage(buflog.str);
            FormatLogStrInPlace(s, buflog.category, buflog.level,
                                buflog.source_loc, buflog.threadname,
                                buflog.now, buflog.mocktime);
        }
        m_msgs_before_open.pop_front();

        if (m_print_to_file) {
            FileWriteStr(s, m_fileout);
        }
        if (m_print_to_console) {
            fwrite(s.data(), 1, s.size(), stdout);
        }
        for (const auto &cb : m_print_callbacks) {
            cb(s);
        }
        if (m_log_format == LogFormat::JSON) {
            m_line_buf.swap(s);
        }
    }
    m_cur_buffer_memusage = 0;
    if (m_print_to_console) {
        fflush(stdout);
    }

    return true;
}

void BCLog::Logger::DisconnectTestLogger() {
    StdLockGuard scoped_lock(m_cs);
    m_buffering = true;
    if (m_fileout != nullptr) {
        fclose(m_fileout);
    }
    m_fileout = nullptr;
    m_print_callbacks.clear();
    m_max_buffer_memusage = DEFAULT_MAX_LOG_BUFFER;
    m_cur_buffer_memusage = 0;
    m_buffer_lines_discarded = 0;
    m_msgs_before_open.clear();
}

void BCLog::Logger::DisableLogging() {
    {
        StdLockGuard scoped_lock(m_cs);
        assert(m_buffering);
        assert(m_print_callbacks.empty());
    }
    m_print_to_file = false;
    m_print_to_console = false;
    StartLogging();
}

static const std::map<std::string, BCLog::LogFlags, std::less<>>
    LOG_CATEGORIES_BY_STR{
        {"0", BCLog::NONE},
        {"", BCLog::NONE},
        {"net", BCLog::NET},
        {"tor", BCLog::TOR},
        {"mempool", BCLog::MEMPOOL},
        {"http", BCLog::HTTP},
        {"bench", BCLog::BENCH},
        {"zmq", BCLog::ZMQ},
        {"walletdb", BCLog::WALLETDB},
        {"rpc", BCLog::RPC},
        {"estimatefee", BCLog::ESTIMATEFEE},
        {"addrman", BCLog::ADDRMAN},
        {"selectcoins", BCLog::SELECTCOINS},
        {"reindex", BCLog::REINDEX},
        {"cmpctblock", BCLog::CMPCTBLOCK},
        {"rand", BCLog::RAND},
        {"prune", BCLog::PRUNE},
        {"proxy", BCLog::PROXY},
        {"mempoolrej", BCLog::MEMPOOLREJ},
        {"libevent", BCLog::LIBEVENT},
        {"coindb", BCLog::COINDB},
        {"qt", BCLog::QT},
        {"leveldb", BCLog::LEVELDB},
        {"validation", BCLog::VALIDATION},
        {"avalanche", BCLog::AVALANCHE},
        {"i2p", BCLog::I2P},
        {"chronik", BCLog::CHRONIK},
#ifdef DEBUG_LOCKCONTENTION
        {"lock", BCLog::LOCK},
#endif
        {"blockstorage", BCLog::BLOCKSTORE},
        {"netdebug", BCLog::NETDEBUG},
        {"txpackages", BCLog::TXPACKAGES},
        {"1", BCLog::ALL},
        {"all", BCLog::ALL},
    };

static const std::unordered_map<BCLog::LogFlags, std::string>
    LOG_CATEGORIES_BY_FLAG{
        // Swap keys and values from LOG_CATEGORIES_BY_STR.
        [](const auto &in) {
            std::unordered_map<BCLog::LogFlags, std::string> out;
            for (const auto &[k, v] : in) {
                switch (v) {
                    case BCLog::NONE:
                        out.emplace(BCLog::NONE, "");
                        break;
                    case BCLog::ALL:
                        out.emplace(BCLog::ALL, "all");
                        break;
                    default:
                        out.emplace(v, k);
                }
            }
            return out;
        }(LOG_CATEGORIES_BY_STR)};

bool GetLogCategory(BCLog::LogFlags &flag, std::string_view str) {
    if (str.empty()) {
        flag = BCLog::ALL;
        return true;
    }
    auto it = LOG_CATEGORIES_BY_STR.find(str);
    if (it != LOG_CATEGORIES_BY_STR.end()) {
        flag = it->second;
        return true;
    }
    return false;
}

std::string BCLog::Logger::LogLevelToStr(BCLog::Level level) {
    switch (level) {
        case BCLog::Level::Trace:
            return "trace";
        case BCLog::Level::Debug:
            return "debug";
        case BCLog::Level::Info:
            return "info";
        case BCLog::Level::Warning:
            return "warning";
        case BCLog::Level::Error:
            return "error";
    }
    assert(false);
}

/**
 * Name of a category for the JSON format, without copying it.
 * Uncategorized messages (NONE, or the ALL mask) are "none".
 */
static std::string_view LogCategoryName(BCLog::LogFlags category) {
    if (category == BCLog::NONE || category == BCLog::ALL) {
        return "none";
    }
    auto it = LOG_CATEGORIES_BY_FLAG.find(category);
    return it == LOG_CATEGORIES_BY_FLAG.end() ? std::string_view{"unknown"}
                                              : std::string_view{it->second};
}

/** The "file" field of a JSON record (the source file of the log call) */
static std::string_view JsonSourceFile(const std::source_location &loc) {
    return RemovePrefixView(loc.file_name(), "./");
}

static std::string_view LogLevelName(BCLog::Level level) {
    switch (level) {
        case BCLog::Level::Trace:
            return "trace";
        case BCLog::Level::Debug:
            return "debug";
        case BCLog::Level::Info:
            return "info";
        case BCLog::Level::Warning:
            return "warning";
        case BCLog::Level::Error:
            return "error";
    }
    assert(false);
}

std::string LogCategoryToStr(BCLog::LogFlags category) {
    auto it = LOG_CATEGORIES_BY_FLAG.find(category);
    assert(it != LOG_CATEGORIES_BY_FLAG.end());
    return it->second;
}

static std::optional<BCLog::Level> GetLogLevel(std::string_view level_str) {
    if (level_str == "trace") {
        return BCLog::Level::Trace;
    } else if (level_str == "debug") {
        return BCLog::Level::Debug;
    } else if (level_str == "info") {
        return BCLog::Level::Info;
    } else if (level_str == "warning") {
        return BCLog::Level::Warning;
    } else if (level_str == "error") {
        return BCLog::Level::Error;
    } else {
        return std::nullopt;
    }
}

std::vector<LogCategory> BCLog::Logger::LogCategoriesList() const {
    std::vector<LogCategory> ret;
    for (const auto &[category, flag] : LOG_CATEGORIES_BY_STR) {
        if (flag != BCLog::NONE && flag != BCLog::ALL) {
            ret.push_back(LogCategory{.category = category,
                                      .active = WillLogCategory(flag)});
        }
    }
    return ret;
}

BCLog::Logger::~Logger() {
    if (m_fileout) {
        fclose(m_fileout);
    }
}

/** Log severity levels that can be selected by the user. */
static constexpr std::array<BCLog::Level, 3> LogLevelsList() {
    return {{BCLog::Level::Info, BCLog::Level::Debug, BCLog::Level::Trace}};
}

std::string BCLog::Logger::LogLevelsString() const {
    const auto &levels = LogLevelsList();
    return Join(std::vector<BCLog::Level>{levels.begin(), levels.end()}, ", ",
                [](BCLog::Level level) { return LogLevelToStr(level); });
}

std::string
BCLog::Logger::LogTimestampStr(SystemClock::time_point now,
                               std::chrono::seconds mocktime) const {
    std::string strStamped;

    if (!m_log_timestamps) {
        return strStamped;
    }

    const auto now_seconds{
        std::chrono::time_point_cast<std::chrono::seconds>(now)};
    strStamped = FormatISO8601DateTime(
        TicksSinceEpoch<std::chrono::seconds>(now_seconds));
    if (m_log_time_micros && !strStamped.empty()) {
        strStamped.pop_back();
        strStamped += strprintf(
            ".%06dZ", Ticks<std::chrono::microseconds>(now - now_seconds));
    }
    if (mocktime > 0s) {
        strStamped +=
            " (mocktime: " + FormatISO8601DateTime(count_seconds(mocktime)) +
            ")";
    }
    strStamped += ' ';

    return strStamped;
}

namespace BCLog {
/** Belts and suspenders: make sure outgoing log messages don't contain
 * potentially suspicious characters, such as terminal control codes.
 *
 * This escapes control characters except newline ('\n') in C syntax.
 * It escapes instead of removes them to still allow for troubleshooting
 * issues where they accidentally end up in strings.
 */
std::string LogEscapeMessage(std::string_view str) {
    std::string ret;
    for (char ch_in : str) {
        uint8_t ch = (uint8_t)ch_in;
        if ((ch >= 32 || ch == '\n') && ch != '\x7f') {
            ret += ch_in;
        } else {
            ret += strprintf("\\x%02x", ch);
        }
    }
    return ret;
}
} // namespace BCLog

std::optional<BCLog::LogFormat> BCLog::ParseLogFormat(std::string_view str) {
    if (str == "text") {
        return LogFormat::TEXT;
    }
    if (str == "json") {
        return LogFormat::JSON;
    }
    return std::nullopt;
}

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

void AppendDigits(std::string &out, uint32_t value, int width) {
    char buf[10];
    for (int i = width - 1; i >= 0; --i) {
        buf[i] = char('0' + value % 10);
        value /= 10;
    }
    out.append(buf, width);
}

/** RFC 3339 UTC time, e.g. 2026-10-19T12:34:56.123456Z */
void AppendRfc3339(std::string &out, SystemClock::time_point tp,
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
} // namespace

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

void BCLog::Logger::FormatJsonLine(std::string &out, std::string_view msg,
                                   LogFlags category, Level level,
                                   const std::source_location &source_loc,
                                   std::string_view threadname,
                                   SystemClock::time_point now,
                                   std::chrono::seconds mocktime,
                                   bool continued, bool ratelimited) const {
    out.clear();
    out += '{';
    if (m_log_timestamps) {
        out += "\"ts\":\"";
        AppendRfc3339(out, now, /*with_micros=*/true);
        out += "\",";
    }
    if (mocktime > 0s) {
        out += "\"mocktime\":\"";
        AppendRfc3339(out, SystemClock::time_point{mocktime},
                      /*with_micros=*/false);
        out += "\",";
    }
    out += "\"level\":\"";
    out += LogLevelName(level);
    out += "\",\"category\":\"";
    out += LogCategoryName(category);
    out += "\",\"thread\":\"";
    AppendJsonEscaped(out, threadname.empty() ? "unknown" : threadname);
    out += "\",\"file\":\"";
    AppendJsonEscaped(out, JsonSourceFile(source_loc));
    out += "\",\"line\":";
    char num[16];
    const auto res{std::to_chars(num, num + sizeof(num), source_loc.line())};
    out.append(num, res.ptr);
    if (m_log_sourcelocations) {
        out += ",\"func\":\"";
        AppendJsonEscaped(out, source_loc.function_name());
        out += '"';
    }
    if (continued) {
        out += ",\"continued\":true";
    }
    if (ratelimited) {
        out += ",\"ratelimited\":true";
    }
    out += ",\"msg\":\"";
    if (!msg.empty() && msg.back() == '\n') {
        msg.remove_suffix(1);
    }
    AppendJsonEscaped(out, msg);
    out += "\"}\n";
}

std::string BCLog::Logger::GetLogPrefix(BCLog::LogFlags category,
                                        BCLog::Level level) const {
    if (category == LogFlags::NONE) {
        category = LogFlags::ALL;
    }

    const bool has_category{m_always_print_category_level ||
                            category != LogFlags::ALL};

    // If there is no category, Info is implied
    if (!has_category && level == Level::Info) {
        return {};
    }

    std::string s{"["};
    if (has_category) {
        s += LogCategoryToStr(category);
    }

    if (m_always_print_category_level || !has_category ||
        level != Level::Debug) {
        // If there is a category, Debug is implied, so don't add the level

        // Only add separator if we have a category
        if (has_category) {
            s += ":";
        }
        s += Logger::LogLevelToStr(level);
    }

    s += "] ";
    return s;
}

static size_t MemUsage(const BCLog::Logger::BufferedLog &buflog) {
    // TODO: use memusage::DynamicUsage for string after PR #31164
    return buflog.str.size() + buflog.threadname.size() +
           memusage::MallocUsage(
               sizeof(memusage::list_node<BCLog::Logger::BufferedLog>));
}

BCLog::LogRateLimiter::LogRateLimiter(uint64_t max_bytes,
                                      std::chrono::seconds reset_window)
    : m_max_bytes{max_bytes}, m_reset_window{reset_window} {}

std::shared_ptr<BCLog::LogRateLimiter>
BCLog::LogRateLimiter::Create(SchedulerFunction &&scheduler_func,
                              uint64_t max_bytes,
                              std::chrono::seconds reset_window) {
    auto limiter{std::shared_ptr<LogRateLimiter>(
        new LogRateLimiter(max_bytes, reset_window))};
    std::weak_ptr<LogRateLimiter> weak_limiter{limiter};
    auto reset = [weak_limiter] {
        if (auto shared_limiter{weak_limiter.lock()}) {
            shared_limiter->Reset();
        }
        return true;
    };
    scheduler_func(reset, limiter->m_reset_window);
    return limiter;
}

BCLog::LogRateLimiter::Status
BCLog::LogRateLimiter::Consume(const std::source_location &source_loc,
                               std::string_view str) {
    StdLockGuard scoped_lock(m_mutex);
    auto &stats{
        m_source_locations.try_emplace(source_loc, m_max_bytes).first->second};
    Status status{stats.m_dropped_bytes > 0 ? Status::STILL_SUPPRESSED
                                            : Status::UNSUPPRESSED};

    if (!stats.Consume(str.size()) && status == Status::UNSUPPRESSED) {
        status = Status::NEWLY_SUPPRESSED;
        m_suppression_active = true;
    }

    return status;
}

void BCLog::Logger::FormatLogStrInPlace(
    std::string &str, BCLog::LogFlags category, BCLog::Level level,
    const std::source_location &source_loc, std::string_view threadname,
    SystemClock::time_point now, std::chrono::seconds mocktime) const {
    str.insert(0, GetLogPrefix(category, level));

    if (m_log_sourcelocations) {
        str.insert(0, strprintf("[%s:%d] [%s] ",
                                RemovePrefixView(source_loc.file_name(), "./"),
                                source_loc.line(), source_loc.function_name()));
    }

    if (m_log_threadnames) {
        str.insert(0, strprintf("[%s] ",
                                (threadname.empty() ? "unknown" : threadname)));
    }

    str.insert(0, LogTimestampStr(now, mocktime));
}

void BCLog::Logger::LogPrintStr(std::string_view str,
                                std::source_location &&source_loc,
                                BCLog::LogFlags category, BCLog::Level level,
                                bool should_ratelimit) {
    StdLockGuard scoped_lock(m_cs);
    return LogPrintStr_(str, std::move(source_loc), category, level,
                        should_ratelimit);
}

void BCLog::Logger::LogPrintStr_(std::string_view str,
                                 std::source_location &&source_loc,
                                 BCLog::LogFlags category, BCLog::Level level,
                                 bool should_ratelimit) {
    const bool starts_new_line = m_started_new_line;
    m_started_new_line = !str.empty() && str[str.size() - 1] == '\n';

    if (m_buffering) {
        // Messages are kept raw and escaped for the selected format when the
        // buffer is flushed.
        if (!starts_new_line) {
            if (!m_msgs_before_open.empty()) {
                m_msgs_before_open.back().str += str;
                m_cur_buffer_memusage += str.size();
                return;
            }
        }

        {
            BufferedLog buf{
                .now = SystemClock::now(),
                .mocktime = GetMockTime(),
                // unlikely edge case; add a marker that something was trimmed
                .str = starts_new_line ? std::string{str}
                                       : "[...] " + std::string{str},
                .threadname = util::ThreadGetInternalName(),
                .source_loc = std::move(source_loc),
                .category = category,
                .level = level,
            };
            m_cur_buffer_memusage += MemUsage(buf);
            m_msgs_before_open.push_back(std::move(buf));
        }

        while (m_cur_buffer_memusage > m_max_buffer_memusage) {
            if (m_msgs_before_open.empty()) {
                m_cur_buffer_memusage = 0;
                break;
            }
            m_cur_buffer_memusage -= MemUsage(m_msgs_before_open.front());
            m_msgs_before_open.pop_front();
            ++m_buffer_lines_discarded;
        }

        return;
    }

    const bool json{m_log_format == LogFormat::JSON};
    const SystemClock::time_point now{SystemClock::now()};
    const std::chrono::seconds mocktime{GetMockTime()};
    const std::string &threadname{util::ThreadGetInternalName()};
    // The line written. In JSON mode it takes over the reusable buffer
    // (a nested call below, for the rate limiting notice, then finds it
    // empty and uses its own).
    std::string str_prefixed;
    bool json_ratelimited{false};
    const auto format_json{[&] {
        FormatJsonLine(str_prefixed, str, category, level, source_loc,
                       threadname, now, mocktime, !starts_new_line,
                       json_ratelimited);
    }};
    if (json) {
        str_prefixed.swap(m_line_buf);
        json_ratelimited = m_limiter && m_limiter->SuppressionsActive();
        format_json();
    } else {
        str_prefixed = LogEscapeMessage(str);
        FormatLogStrInPlace(str_prefixed, category, level, source_loc,
                            threadname, now, mocktime);
    }
    bool ratelimit{false};
    if (should_ratelimit && m_limiter) {
        // The quota counts the message (as passed to the logger, before
        // any prefix or JSON wrapping), so that a limit means the same in
        // both formats.
        auto status{m_limiter->Consume(source_loc, str)};
        if (status == LogRateLimiter::Status::NEWLY_SUPPRESSED) {
            // with should_ratelimit=false, this cannot lead to infinit
            // recursion
            // NOLINTNEXTLINE(misc-no-recursion)
            LogPrintStr_(
                strprintf(
                    "Excessive logging detected from %s:%d (%s): >%d bytes "
                    "logged during "
                    "the last time window of %is. Suppressing logging to disk "
                    "from this "
                    "source location until time window resets. Console logging "
                    "unaffected. Last log entry.\n",
                    source_loc.file_name(), source_loc.line(),
                    source_loc.function_name(), m_limiter->m_max_bytes,
                    Ticks<std::chrono::seconds>(m_limiter->m_reset_window)),
                std::source_location::current(), LogFlags::ALL, Level::Warning,
                /*should_ratelimit=*/false);
        } else if (status == LogRateLimiter::Status::STILL_SUPPRESSED) {
            ratelimit = true;
        }
    }

    // To avoid confusion caused by dropped log messages when debugging an
    // issue, we prefix log lines with "[*]" when there are any suppressed
    // source locations.
    if (m_limiter && m_limiter->SuppressionsActive()) {
        if (!json) {
            str_prefixed.insert(0, "[*] ");
        } else if (!json_ratelimited) {
            // Suppression started with this very line: rare, format again.
            json_ratelimited = true;
            format_json();
        }
    }

    if (m_print_to_console) {
        // Print to console.
        fwrite(str_prefixed.data(), 1, str_prefixed.size(), stdout);
        fflush(stdout);
    }
    for (const auto &cb : m_print_callbacks) {
        cb(str_prefixed);
    }
    if (m_print_to_file && !ratelimit) {
        assert(m_fileout != nullptr);

        // Reopen the log file, if requested.
        if (m_reopen_file) {
            m_reopen_file = false;
            FILE *new_fileout = fsbridge::fopen(m_file_path, "a");
            if (new_fileout) {
                // unbuffered, like the file opened by StartLogging
                setbuf(new_fileout, nullptr);
                fclose(m_fileout);
                m_fileout = new_fileout;
            }
        }
        FileWriteStr(str_prefixed, m_fileout);
    }

    // Give the buffer back for the next line, unless an unusually long
    // message made it large: that memory is not kept around.
    if (json && str_prefixed.capacity() <= MAX_RETAINED_LINE_BUFFER &&
        str_prefixed.capacity() >= m_line_buf.capacity()) {
        m_line_buf.swap(str_prefixed);
    }
}

void BCLog::Logger::ShrinkDebugFile() {
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;

    assert(!m_file_path.empty());

    // Scroll debug.log if it's getting too big.
    FILE *file = fsbridge::fopen(m_file_path, "r");

    // Special files (e.g. device nodes) may not have a size.
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (const fs::filesystem_error &) {
    }

    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes.
    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10)) {
        // Restart the file with some of the end.
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        if (fseek(file, -((long)vch.size()), SEEK_END)) {
            LogPrintf("Failed to shrink debug log file: fseek(...) failed\n");
            fclose(file);
            return;
        }
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fsbridge::fopen(m_file_path, "w");
        if (file) {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    } else if (file != nullptr) {
        fclose(file);
    }
}

void BCLog::Logger::EnableCategory(LogFlags category) {
    m_categories |= category;
}

bool BCLog::Logger::EnableCategory(std::string_view str) {
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) {
        return false;
    }
    EnableCategory(flag);
    return true;
}

void BCLog::Logger::DisableCategory(LogFlags category) {
    m_categories &= ~category;
}

bool BCLog::Logger::DisableCategory(std::string_view str) {
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) {
        return false;
    }
    DisableCategory(flag);
    return true;
}

bool BCLog::Logger::WillLogCategory(LogFlags category) const {
    // ALL is not meant to be used as a logging category, but only as a mask
    // representing all categories.
    if (category == BCLog::NONE || category == BCLog::ALL) {
        LogPrintf("Error trying to log using a category mask instead of an "
                  "explicit category.\n");
        return true;
    }

    return (m_categories.load(std::memory_order_relaxed) & category) != 0;
}

bool BCLog::Logger::WillLogCategoryLevel(BCLog::LogFlags category,
                                         BCLog::Level level) const {
    // Log messages at Info, Warning and Error level unconditionally, so that
    // important troubleshooting information doesn't get lost.
    if (level >= BCLog::Level::Info) {
        return true;
    }

    if (!WillLogCategory(category)) {
        return false;
    }

    StdLockGuard scoped_lock(m_cs);
    const auto it{m_category_log_levels.find(category)};
    return level >=
           (it == m_category_log_levels.end() ? LogLevel() : it->second);
}

bool BCLog::Logger::DefaultShrinkDebugFile() const {
    return m_categories != BCLog::NONE;
}

void BCLog::LogRateLimiter::Reset() {
    decltype(m_source_locations) source_locations;
    {
        StdLockGuard scoped_lock(m_mutex);
        source_locations.swap(m_source_locations);
        m_suppression_active = false;
    }
    for (const auto &[source_loc, stats] : source_locations) {
        if (stats.m_dropped_bytes == 0) {
            continue;
        }
        LogPrintLevel_(LogFlags::ALL, Level::Warning,
                       /*should_ratelimit=*/false,
                       "Restarting logging from %s:%d (%s): %d bytes were "
                       "dropped during the last %ss.\n",
                       source_loc.file_name(), source_loc.line(),
                       source_loc.function_name(), stats.m_dropped_bytes,
                       Ticks<std::chrono::seconds>(m_reset_window));
    }
}

bool BCLog::LogRateLimiter::Stats::Consume(uint64_t bytes) {
    if (bytes > m_available_bytes) {
        m_dropped_bytes += bytes;
        m_available_bytes = 0;
        return false;
    }

    m_available_bytes -= bytes;
    return true;
}

bool BCLog::Logger::SetLogLevel(std::string_view level_str) {
    const auto level = GetLogLevel(level_str);
    if (!level.has_value() || level.value() > MAX_USER_SETABLE_SEVERITY_LEVEL) {
        return false;
    }
    m_log_level = level.value();
    return true;
}

bool BCLog::Logger::SetCategoryLogLevel(std::string_view category_str,
                                        std::string_view level_str) {
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, category_str)) {
        return false;
    }

    const auto level = GetLogLevel(level_str);
    if (!level.has_value() || level.value() > MAX_USER_SETABLE_SEVERITY_LEVEL) {
        return false;
    }

    StdLockGuard scoped_lock(m_cs);
    m_category_log_levels[flag] = level.value();
    return true;
}
