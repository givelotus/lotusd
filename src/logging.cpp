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
#include <bit>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <unordered_map>
#ifndef WIN32
#include <unistd.h>
#endif

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

namespace {
//! Logger uid source (distinguishes loggers in the threads' ring caches)
std::atomic<uint64_t> g_next_logger_uid{1};

/** The calling thread's ring, per logger it has logged to */
struct ThreadLogRing {
    uint64_t logger_uid{0};
    std::shared_ptr<BCLog::LogRing> ring;
    ~ThreadLogRing() {
        if (ring) {
            ring->m_orphaned.store(true, std::memory_order_release);
        }
    }
};
thread_local ThreadLogRing t_log_ring;
//! Set while this thread renders and writes records (the consumer). A
//! thread logging from there must not wait for a ring to drain.
thread_local bool t_in_consumer{false};

//! Size of the log file's stdio buffer; flushed after each pass
constexpr size_t LOG_FILE_BUFFER{64 * 1024};

FILE *OpenLogFile(const fs::path &path) {
    FILE *file{fsbridge::fopen(path, "a")};
    if (file) {
        // Fully buffered: the logger thread flushes after each pass, every
        // few milliseconds, instead of one write per line.
        setvbuf(file, nullptr, _IOFBF, LOG_FILE_BUFFER);
    }
    return file;
}
} // namespace

BCLog::Logger::Logger()
    : m_uid{g_next_logger_uid.fetch_add(1, std::memory_order_relaxed)} {
    for (auto &level : m_category_levels) {
        level.store(-1, std::memory_order_relaxed);
    }
}

bool BCLog::Logger::StartLogging() {
    {
        StdLockGuard consumer_lock(m_consumer_mutex);
        StdLockGuard scoped_lock(m_cs);

        assert(m_buffering);
        assert(m_fileout == nullptr);

        if (m_print_to_file) {
            assert(!m_file_path.empty());
            m_fileout = OpenLogFile(m_file_path);
            if (!m_fileout) {
                return false;
            }

            // Add newlines to the logfile to distinguish this execution from
            // the last one.
            FileWriteStr("\n\n\n\n\n", m_fileout);
        }

        // Dump buffered messages from before we opened the log.
        if (m_buffer_lines_discarded > 0) {
            BufferLog(strprintf("Early logging buffer overflowed, %d log lines "
                                "discarded.\n",
                                m_buffer_lines_discarded),
                      std::source_location::current(), BCLog::ALL, Level::Info);
        }
        while (!m_msgs_before_open.empty()) {
            const auto &buflog = m_msgs_before_open.front();
            if (m_log_format == LogFormat::JSON) {
                FormatJsonLine(m_line_buf, buflog.str, buflog.category,
                               buflog.level, buflog.source_loc,
                               buflog.threadname, buflog.now, buflog.mocktime,
                               /*continued=*/false, /*ratelimited=*/false);
            } else {
                FormatTextLine(m_line_buf, buflog.str, buflog.category,
                               buflog.level, buflog.source_loc,
                               buflog.threadname, buflog.now, buflog.mocktime,
                               /*ratelimited=*/false);
            }
            WriteLine(m_line_buf, /*to_file=*/true);
            m_msgs_before_open.pop_front();
        }
        m_cur_buffer_memusage = 0;
        if (m_fileout) {
            fflush(m_fileout);
        }
        if (m_print_to_console) {
            fflush(stdout);
        }
        // From now on, lines go through the threads' rings.
        m_buffering = false;
    }
    StartThread();

    // Lines still queued at exit are written then (the logger is never
    // destroyed, see LogInstance).
    static std::once_flag flush_at_exit;
    std::call_once(flush_at_exit,
                   [] { std::atexit([] { LogInstance().StopThread(); }); });
    return true;
}

void BCLog::Logger::DisconnectTestLogger() {
    StopThread();
    StdLockGuard consumer_lock(m_consumer_mutex);
    StdLockGuard scoped_lock(m_cs);
    m_buffering = true;
    if (m_fileout != nullptr) {
        fclose(m_fileout);
    }
    m_fileout = nullptr;
    m_print_callbacks.clear();
    m_has_callbacks = false;
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

void BCLog::Logger::StartThread() {
    {
        std::lock_guard<std::mutex> lock(m_wake_mutex);
        m_stop = false;
    }
    m_thread_running = true;
    m_thread = std::thread{[this] {
        util::ThreadRename("logger");
        ThreadMain();
    }};
}

#ifndef WIN32
int BCLog::Logger::ForkProcess() {
    // The caller quiesces application producers. Join before fork so neither
    // process inherits a dead thread handle, held consumer locks, pending
    // error acknowledgement or buffered stdio belonging to the other process.
    const bool restart{m_thread_running.load()};
    StopThread();
    const int pid{fork()};
    const int fork_errno{errno};
    if (restart) StartThread();
    errno = fork_errno;
    return pid;
}
#endif

void BCLog::Logger::StopThread() {
    if (!m_thread.joinable()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_wake_mutex);
        m_stop = true;
    }
    m_wake_cv.notify_all();
    m_thread.join();
    m_thread_running = false;
}

void BCLog::Logger::ThreadMain() NO_THREAD_SAFETY_ANALYSIS {
    while (true) {
        bool busy{false};
        if (!m_paused_for_testing) {
            StdLockGuard consumer_lock(m_consumer_mutex);
            // A test can pause while this pass is waiting for the lock.
            if (!m_paused_for_testing) {
                busy = DrainLocked();
            }
        }
        std::unique_lock<std::mutex> lock(m_wake_mutex);
        if (m_stop) {
            break;
        }
        m_wake_cv.wait_for(
            lock, busy ? FLUSH_INTERVAL : IDLE_FLUSH_INTERVAL,
            [this]() NO_THREAD_SAFETY_ANALYSIS { return m_wake || m_stop; });
        m_wake = false;
        m_wake_requested = false;
    }
    StdLockGuard consumer_lock(m_consumer_mutex);
    DrainLocked();
}

void BCLog::Logger::Flush() {
    if (m_buffering || t_in_consumer) {
        return;
    }
    StdLockGuard consumer_lock(m_consumer_mutex);
    DrainLocked();
}

std::shared_ptr<BCLog::LogRing> BCLog::Logger::ClaimRing() {
    std::shared_ptr<LogRing> ring;
    {
        StdLockGuard lock(m_rings_mutex);
        if (!m_free_rings.empty()) {
            ring = std::move(m_free_rings.back());
            m_free_rings.pop_back();
        }
    }
    if (!ring) {
        ring = std::make_shared<LogRing>();
    }
    StdLockGuard lock(m_rings_mutex);
    m_rings.push_back(ring);
    return ring;
}

BCLog::LogRing *BCLog::Logger::ThreadRing() noexcept {
    if (t_log_ring.logger_uid != m_uid) {
        try {
            auto ring{ClaimRing()};
            if (t_log_ring.ring) {
                // The thread logged to another logger (tests): release it.
                t_log_ring.ring->m_orphaned.store(true,
                                                  std::memory_order_release);
            }
            t_log_ring.ring = std::move(ring);
            t_log_ring.logger_uid = m_uid;
        } catch (const std::bad_alloc &) {
            return nullptr;
        }
    }
    return t_log_ring.ring.get();
}

void BCLog::Logger::PrepareThisThread() noexcept {
    ThreadRing();
}

uint64_t BCLog::Logger::DroppedLines() const {
    StdLockGuard lock(m_rings_mutex);
    uint64_t dropped{m_dropped_retired};
    for (const auto &ring : m_rings) {
        dropped += ring->Dropped();
    }
    return dropped;
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
    StopThread();
    StdLockGuard consumer_lock(m_consumer_mutex);
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

/** Append GetLogPrefix(category, level) to out, without allocating */
void BCLog::Logger::AppendLogPrefix(std::string &out, LogFlags category,
                                    Level level) const {
    if (category == LogFlags::NONE) {
        category = LogFlags::ALL;
    }
    const bool has_category{m_always_print_category_level ||
                            category != LogFlags::ALL};
    // If there is no category, Info is implied
    if (!has_category && level == Level::Info) {
        return;
    }
    out += '[';
    if (has_category) {
        const auto it{LOG_CATEGORIES_BY_FLAG.find(category)};
        if (it != LOG_CATEGORIES_BY_FLAG.end()) {
            out += it->second;
        }
    }
    if (m_always_print_category_level || !has_category ||
        level != Level::Debug) {
        // If there is a category, Debug is implied, so don't add the level
        if (has_category) {
            out += ':';
        }
        out += LogLevelName(level);
    }
    out += "] ";
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

//! Source of rate limiting windows (epochs), unique across limiters. Sites
//! start at epoch 0, which no window uses.
static std::atomic<uint64_t> g_next_ratelimit_epoch{1};

BCLog::LogRateLimiter::LogRateLimiter(uint64_t max_bytes,
                                      std::chrono::seconds reset_window)
    : m_epoch{g_next_ratelimit_epoch.fetch_add(1)},
      m_max_bytes{std::min(max_bytes, LogSiteLimit::AVAILABLE_MASK)},
      m_reset_window{reset_window} {}

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

BCLog::LogRateLimiter::Status BCLog::LogRateLimiter::Consume(
    LogSiteLimit &site, const std::source_location &loc, uint64_t bytes) {
    constexpr auto relaxed{std::memory_order_relaxed};
    using S = LogSiteLimit;
    const uint64_t epoch{m_epoch.load(std::memory_order_acquire)};
    uint64_t state{site.state.load(relaxed)};
    while (true) {
        // A site not used yet in this window (or by this limiter) starts
        // with the full quota.
        const bool fresh{state >> S::EPOCH_SHIFT != epoch};
        if (!fresh && (state & S::SUPPRESSED)) {
            site.dropped.fetch_add(bytes, relaxed);
            return Status::STILL_SUPPRESSED;
        }
        const uint64_t available{fresh ? m_max_bytes
                                       : state & S::AVAILABLE_MASK};
        const bool fits{bytes <= available};
        const uint64_t next{(epoch << S::EPOCH_SHIFT) |
                            (fits ? available - bytes : S::SUPPRESSED)};
        if (!site.state.compare_exchange_weak(state, next, relaxed)) {
            continue;
        }
        if (fresh) {
            // Drops counted in an earlier window were reported already.
            site.dropped.store(0, relaxed);
        }
        if (fits) {
            return Status::UNSUPPRESSED;
        }
        break;
    }
    // This call suppressed the site for the rest of the window.
    site.dropped.fetch_add(bytes, relaxed);
    if (site.listed_epoch.exchange(epoch, relaxed) != epoch) {
        site.loc = loc;
        LogSiteLimit *head{m_suppressed.load(relaxed)};
        do {
            site.next = head;
        } while (!m_suppressed.compare_exchange_weak(
            head, &site, std::memory_order_release, relaxed));
    }
    m_suppression_active = true;
    return Status::NEWLY_SUPPRESSED;
}

void BCLog::Logger::FormatTextLine(std::string &out, std::string_view msg,
                                   LogFlags category, Level level,
                                   const std::source_location &source_loc,
                                   std::string_view threadname,
                                   SystemClock::time_point now,
                                   std::chrono::seconds mocktime,
                                   bool ratelimited) const {
    out.clear();
    if (ratelimited) {
        // To avoid confusion caused by dropped log messages when debugging
        // an issue, lines are prefixed with "[*]" when there are any
        // suppressed source locations.
        out += "[*] ";
    }
    if (m_log_timestamps) {
        AppendRfc3339(out, now, m_log_time_micros);
        if (mocktime > 0s) {
            out += " (mocktime: ";
            AppendRfc3339(out, SystemClock::time_point{mocktime},
                          /*with_micros=*/false);
            out += ')';
        }
        out += ' ';
    }
    if (m_log_threadnames) {
        out += '[';
        out += threadname.empty() ? "unknown" : threadname;
        out += "] ";
    }
    if (m_log_sourcelocations) {
        out += '[';
        out += JsonSourceFile(source_loc);
        out += ':';
        char num[16];
        const auto res{
            std::to_chars(num, num + sizeof(num), source_loc.line())};
        out.append(num, res.ptr);
        out += "] [";
        out += source_loc.function_name();
        out += "] ";
    }
    AppendLogPrefix(out, category, level);
    // Escape control characters except newline ('\n') in C syntax, as
    // LogEscapeMessage does; copy runs of other characters at once.
    size_t run{0};
    for (size_t i = 0; i < msg.size(); ++i) {
        const uint8_t ch{uint8_t(msg[i])};
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

void BCLog::Logger::BufferLog(std::string_view str,
                              std::source_location &&source_loc,
                              LogFlags category, Level level) {
    // Lines of one thread without trailing newline are merged.
    static thread_local bool buffered_open_line{false};
    const bool continues{buffered_open_line};
    buffered_open_line = !str.empty() && str.back() != '\n';
    if (continues && !m_msgs_before_open.empty()) {
        m_msgs_before_open.back().str += str;
        m_cur_buffer_memusage += str.size();
        return;
    }
    {
        BufferedLog buf{
            .now = SystemClock::now(),
            .mocktime = GetMockTime(),
            // unlikely edge case; add a marker that something was trimmed
            .str = continues ? "[...] " + std::string{str} : std::string{str},
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
}

void BCLog::Logger::LogPrintStr(std::string_view str,
                                std::source_location &&source_loc,
                                BCLog::LogFlags category, BCLog::Level level,
                                LogSiteLimit *site) {
    Enqueue(str, nullptr, std::move(source_loc), category, level, site);
}

void BCLog::Logger::LogPrintMovedStr(std::string &&str,
                                     std::source_location &&source_loc,
                                     BCLog::LogFlags category,
                                     BCLog::Level level, LogSiteLimit *site) {
    Enqueue(str, &str, std::move(source_loc), category, level, site);
}

BCLog::LogRecord *BCLog::Logger::ClaimSlow(LogRing &ring) {
    // Ordinary severe backpressure leaves rendering on the consumer. The
    // paused/stopped fallback below is for explicit test/shutdown operation.
    while (!t_in_consumer && m_thread_running && !m_paused_for_testing) {
        if (LogRecord * rec{ring.Claim()}) return rec;
        m_wake = true;
        m_wake_cv.notify_one();
        std::this_thread::sleep_for(std::chrono::microseconds{50});
    }

    // Warnings and errors are never dropped: wait for the logger thread
    // (or write the queue ourselves) until a slot is free. Only a thread
    // writing records itself (logging from a print callback) cannot wait.
    while (!t_in_consumer) {
        if (m_consumer_mutex.try_lock()) {
            DrainLocked();
            m_consumer_mutex.unlock();
        } else {
            m_wake = true;
            m_wake_cv.notify_one();
            std::this_thread::sleep_for(std::chrono::microseconds{100});
        }
        if (LogRecord * rec{ring.Claim()}) {
            return rec;
        }
    }
    return nullptr;
}

void BCLog::Logger::FlushOnConsumer() {
    if (t_in_consumer) return;
    if (!m_thread_running || m_paused_for_testing) {
        Flush();
        return;
    }
    const uint64_t requested{
        m_flush_requested.fetch_add(1, std::memory_order_acq_rel) + 1};
    while (m_flush_completed.load(std::memory_order_acquire) < requested) {
        if (!m_thread_running || m_paused_for_testing) {
            Flush();
            return;
        }
        m_wake = true;
        m_wake_cv.notify_one();
        std::this_thread::sleep_for(std::chrono::microseconds{50});
    }
}

void BCLog::Logger::WriteEmergency(LogRecord &rec) NO_THREAD_SAFETY_ANALYSIS {
    // A print callback already holds the consumer and callback locks. It
    // cannot drain its own full ring or call itself again. Keep the outer
    // callback's string object intact while using a separate render buffer.
    assert(t_in_consumer);
    std::string saved;
    saved.swap(m_line_buf);
    const bool previous{m_writing_emergency};
    m_writing_emergency = true;
    WriteRecord(rec);
    // Callback-only loggers still need a visible severe record when callbacks
    // cannot safely recurse. Auxiliary sinks may receive a duplicate here.
    if (!m_print_to_console && (!m_print_to_file || !m_fileout)) {
        fwrite(m_line_buf.data(), 1, m_line_buf.size(), stderr);
        fflush(stderr);
    }
    m_writing_emergency = previous;
    m_line_buf.swap(saved);
    // An error may be followed immediately by abort inside the callback.
    if (m_fileout) fflush(m_fileout);
    if (m_print_to_console) fflush(stdout);
}

void BCLog::Logger::Enqueue(std::string_view str, std::string *owned,
                            std::source_location &&source_loc,
                            LogFlags category, Level level,
                            LogSiteLimit *site) {
    if (m_buffering.load(std::memory_order_acquire)) {
        StdLockGuard scoped_lock(m_cs);
        // (StartLogging may have finished meanwhile.)
        if (m_buffering) {
            BufferLog(str, std::move(source_loc), category, level);
            return;
        }
    }

    bool no_file{false};
    LogRateLimiter *limiter{m_limiter_ptr.load(std::memory_order_acquire)};
    if (site) {
        if (limiter) {
            switch (limiter->Consume(*site, source_loc, str.size())) {
                case LogRateLimiter::Status::UNSUPPRESSED:
                    break;
                case LogRateLimiter::Status::NEWLY_SUPPRESSED:
                    // Rare: formatting the notice here is fine. Without a
                    // site it is not rate limited (no recursion).
                    LogPrintStr(
                        strprintf(
                            "Excessive logging detected from %s:%d (%s): >%d "
                            "bytes logged during the last time window of "
                            "%is. Suppressing logging to disk from this source "
                            "location until time window resets. Console "
                            "logging unaffected. Last log entry.\n",
                            source_loc.file_name(), source_loc.line(),
                            source_loc.function_name(), limiter->m_max_bytes,
                            Ticks<std::chrono::seconds>(
                                limiter->m_reset_window)),
                        std::source_location::current(), LogFlags::ALL,
                        Level::Warning, /*site=*/nullptr);
                    break;
                case LogRateLimiter::Status::STILL_SUPPRESSED:
                    no_file = true;
                    if (!m_print_to_console && !m_has_callbacks) {
                        return;
                    }
                    break;
            }
        }
    }

    LogRing *ring{ThreadRing()};
    if (!ring) {
        return;
    }
    LogRecord *rec{ring->Claim()};
    if (!rec) {
        if (level < Level::Warning) {
            // Never block for debug and info: drop and count (reported by
            // the logger thread once it catches up).
            ring->CountDrop();
            return;
        }
        rec = t_in_consumer ? &ring->m_emergency : ClaimSlow(*ring);
        if (!rec) {
            ring->CountDrop();
            return;
        }
    }

    const auto now{SystemClock::now()};
    rec->time_us = TicksSinceEpoch<std::chrono::microseconds>(now);
    rec->mocktime_s = count_seconds(GetMockTime());
    rec->loc = source_loc;
    rec->event = nullptr;
    rec->category = category;
    rec->level = level;
    rec->flags =
        (ring->m_open_line ? LogRecord::CONTINUED : 0) |
        (no_file ? LogRecord::NO_FILE : 0) |
        (limiter && limiter->SuppressionsActive() ? LogRecord::SUPPRESSIONS
                                                  : 0);
    rec->num_fields = 0;
    ring->m_open_line = !str.empty() && str.back() != '\n';
    const std::string &thread{util::ThreadGetInternalName()};
    const size_t thread_len{std::min(thread.size(), sizeof(rec->thread) - 1)};
    std::memcpy(rec->thread, thread.data(), thread_len);
    rec->thread[thread_len] = '\0';
    if (str.size() <= sizeof(rec->payload)) {
        std::memcpy(rec->payload, str.data(), str.size());
        rec->size = uint16_t(str.size());
    } else {
        // Spill path for long messages: one heap string, the message itself
        // when the caller hands it over. Most messages fit in the slot.
        std::string *spill{owned ? new std::string(std::move(*owned))
                                 : new std::string(str)};
        std::memcpy(rec->payload, &spill, sizeof(spill));
        rec->size = sizeof(spill);
        rec->flags |= LogRecord::SPILLED;
    }
    if (rec == &ring->m_emergency) {
        WriteEmergency(*rec);
        return;
    }
    if (ring->Commit() && !m_wake_requested.load(std::memory_order_relaxed) &&
        !m_wake_requested.exchange(true)) {
        // The ring reached its wake threshold: wake the logger now rather than
        // at its next tick (one notification per wake-up, rare).
        m_wake = true;
        m_wake_cv.notify_one();
    }

    if (level >= Level::Error) {
        // Errors often precede abort. Wait for a consumer pass that starts
        // after this publication and completes its stdio flush.
        FlushOnConsumer();
    }
}

void BCLog::Logger::ReopenIfRequested() {
    if (m_reopen_file && m_fileout) {
        m_reopen_file = false;
        if (FILE * new_fileout{OpenLogFile(m_file_path)}) {
            fclose(m_fileout);
            m_fileout = new_fileout;
        }
    }
}

void BCLog::Logger::WriteLine(const std::string &line, bool to_file) {
    if (m_print_to_console) {
        fwrite(line.data(), 1, line.size(), stdout);
    }
    if (!m_writing_emergency) {
        for (const auto &cb : m_print_callbacks)
            cb(line);
    }
    if (m_print_to_file && to_file && m_fileout) {
        FileWriteStr(line, m_fileout);
    }
}

void BCLog::Logger::WriteRecord(LogRecord &rec) {
    const bool ratelimited{(rec.flags & LogRecord::SUPPRESSIONS) != 0};
    std::string *spill{nullptr};
    std::string_view msg;
    if (rec.flags & LogRecord::SPILLED) {
        std::memcpy(&spill, rec.payload, sizeof(spill));
        msg = *spill;
    } else {
        msg = std::string_view{reinterpret_cast<const char *>(rec.payload),
                               rec.size};
    }
    const SystemClock::time_point now{std::chrono::microseconds{rec.time_us}};
    const std::chrono::seconds mocktime{rec.mocktime_s};
    if (m_log_format == LogFormat::JSON) {
        FormatJsonLine(m_line_buf, msg, rec.category, rec.level, rec.loc,
                       rec.thread, now, mocktime,
                       rec.flags & LogRecord::CONTINUED, ratelimited);
    } else {
        FormatTextLine(m_line_buf, msg, rec.category, rec.level, rec.loc,
                       rec.thread, now, mocktime, ratelimited);
    }
    delete spill;
    WriteLine(m_line_buf, !(rec.flags & LogRecord::NO_FILE));
}

bool BCLog::Logger::DrainLocked() {
    const uint64_t flush_requested{
        m_flush_requested.load(std::memory_order_acquire)};
    t_in_consumer = true;
    ReopenIfRequested();
    {
        StdLockGuard lock(m_rings_mutex);
        m_drain_rings.clear();
        for (const auto &ring : m_rings) {
            m_drain_rings.push_back(ring.get());
        }
    }
    StdLockGuard scoped_lock(m_cs);
    bool wrote{false};
    // Write the records available now, oldest first across threads (each
    // thread's records stay in order).
    std::array<size_t, 256> pending_small;
    std::vector<size_t> pending_large;
    const bool small{m_drain_rings.size() <= pending_small.size()};
    if (!small) {
        pending_large.resize(m_drain_rings.size());
    }
    size_t *pending{small ? pending_small.data() : pending_large.data()};
    for (size_t i = 0; i < m_drain_rings.size(); ++i) {
        pending[i] = m_drain_rings[i]->Available();
    }
    while (true) {
        size_t best{m_drain_rings.size()};
        int64_t best_time{0};
        for (size_t i = 0; i < m_drain_rings.size(); ++i) {
            if (pending[i] == 0) {
                continue;
            }
            const int64_t t{m_drain_rings[i]->Front().time_us};
            if (best == m_drain_rings.size() || t < best_time) {
                best = i;
                best_time = t;
            }
        }
        if (best == m_drain_rings.size()) {
            break;
        }
        LogRing &ring{*m_drain_rings[best]};
        WriteRecord(ring.Front());
        ring.Pop();
        --pending[best];
        wrote = true;
    }

    // Report lines dropped because a ring was full, once caught up.
    {
        uint64_t dropped;
        {
            StdLockGuard lock(m_rings_mutex);
            dropped = m_dropped_retired;
            for (const auto &ring : m_rings) {
                dropped += ring->Dropped();
            }
            // Reuse the rings of exited threads once drained.
            for (auto it = m_rings.begin(); it != m_rings.end();) {
                if ((*it)->m_orphaned.load(std::memory_order_acquire) &&
                    (*it)->Available() == 0) {
                    m_dropped_retired += (*it)->Recycle();
                    m_free_rings.push_back(std::move(*it));
                    it = m_rings.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (dropped > m_dropped_reported) {
            const auto now{SystemClock::now()};
            const std::string msg{strprintf(
                "Logging could not keep up: %d debug/info log lines were "
                "dropped (%d in total).\n",
                dropped - m_dropped_reported, dropped)};
            if (m_log_format == LogFormat::JSON) {
                FormatJsonLine(m_line_buf, msg, LogFlags::ALL, Level::Warning,
                               std::source_location::current(), "logger", now,
                               GetMockTime(), false, false);
            } else {
                FormatTextLine(m_line_buf, msg, LogFlags::ALL, Level::Warning,
                               std::source_location::current(), "logger", now,
                               GetMockTime(), false);
            }
            WriteLine(m_line_buf, /*to_file=*/true);
            m_dropped_reported = dropped;
            wrote = true;
        }
    }
    if (m_line_buf.capacity() > MAX_RETAINED_LINE_BUFFER) {
        // An unusually long line: do not keep its memory.
        std::string{}.swap(m_line_buf);
    }
    if (wrote) {
        if (m_fileout) {
            fflush(m_fileout);
        }
        if (m_print_to_console) {
            fflush(stdout);
        }
    }
    m_flush_completed.store(flush_requested, std::memory_order_release);
    t_in_consumer = false;
    return wrote;
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

    const int8_t category_level{
        std::has_single_bit(uint32_t(category))
            ? m_category_levels[std::countr_zero(uint32_t(category))].load(
                  std::memory_order_relaxed)
            : int8_t{-1}};
    return level >= (category_level < 0 ? LogLevel() : Level(category_level));
}

std::unordered_map<BCLog::LogFlags, BCLog::Level>
BCLog::Logger::CategoryLevels() const {
    std::unordered_map<LogFlags, Level> levels;
    for (int bit = 0; bit < 32; ++bit) {
        const int8_t level{m_category_levels[bit].load()};
        if (level >= 0) {
            levels.emplace(LogFlags(uint32_t{1} << bit), Level(level));
        }
    }
    return levels;
}

void BCLog::Logger::SetCategoryLogLevel(
    const std::unordered_map<LogFlags, Level> &levels) {
    for (auto &level : m_category_levels) {
        level.store(-1);
    }
    for (const auto &[flag, level] : levels) {
        if (std::has_single_bit(uint32_t(flag))) {
            m_category_levels[std::countr_zero(uint32_t(flag))].store(
                int8_t(level));
        }
    }
}

bool BCLog::Logger::DefaultShrinkDebugFile() const {
    return m_categories != BCLog::NONE;
}

void BCLog::LogRateLimiter::Reset() {
    // Take the suppressed sites, then start a new window. A site suppressed
    // in between is noticed in the next window (one notice late).
    LogSiteLimit *site{
        m_suppressed.exchange(nullptr, std::memory_order_acquire)};
    struct Dropped {
        std::source_location loc;
        uint64_t bytes;
    };
    std::vector<Dropped> dropped;
    for (; site; site = site->next) {
        dropped.push_back({site->loc, site->dropped.load()});
    }
    m_suppression_active = false;
    m_epoch.store(g_next_ratelimit_epoch.fetch_add(1),
                  std::memory_order_release);
    for (const auto &[loc, bytes] : dropped) {
        if (bytes == 0) {
            continue;
        }
        LogPrintLevel_(LogFlags::ALL, Level::Warning,
                       /*should_ratelimit=*/false,
                       "Restarting logging from %s:%d (%s): %d bytes were "
                       "dropped during the last %ss.\n",
                       loc.file_name(), loc.line(), loc.function_name(), bytes,
                       Ticks<std::chrono::seconds>(m_reset_window));
    }
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

    if (std::has_single_bit(uint32_t(flag))) {
        m_category_levels[std::countr_zero(uint32_t(flag))].store(
            int8_t(level.value()));
    }
    return true;
}
