// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include <logging/encoder.h>
#include <logging/journal.h>
#include <span.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/time.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
static const bool DEFAULT_LOGTHREADNAMES = false;
static const bool DEFAULT_LOGSOURCELOCATIONS = false;
static constexpr bool DEFAULT_LOGLEVELALWAYS = false;
static constexpr const char *DEFAULT_LOGFORMAT = "text";

extern bool fLogIPs;
extern const char *const DEFAULT_DEBUGLOGFILE;

struct LogCategory {
    std::string category;
    bool active;
};

namespace BCLog {

enum LogFlags : uint32_t {
    NONE = 0,
    NET = (1 << 0),
    TOR = (1 << 1),
    MEMPOOL = (1 << 2),
    HTTP = (1 << 3),
    BENCH = (1 << 4),
    ZMQ = (1 << 5),
    WALLETDB = (1 << 6),
    RPC = (1 << 7),
    ESTIMATEFEE = (1 << 8),
    ADDRMAN = (1 << 9),
    SELECTCOINS = (1 << 10),
    REINDEX = (1 << 11),
    CMPCTBLOCK = (1 << 12),
    RAND = (1 << 13),
    PRUNE = (1 << 14),
    PROXY = (1 << 15),
    MEMPOOLREJ = (1 << 16),
    LIBEVENT = (1 << 17),
    COINDB = (1 << 18),
    QT = (1 << 19),
    LEVELDB = (1 << 20),
    VALIDATION = (1 << 21),
    AVALANCHE = (1 << 22),
    I2P = (1 << 23),
    CHRONIK = (1 << 24),
#ifdef DEBUG_LOCKCONTENTION
    LOCK = (1 << 25),
#endif
    BLOCKSTORE = (1 << 26),
    NETDEBUG = (1 << 27),
    TXPACKAGES = (1 << 28),
    ALL = ~uint32_t(0),
};

enum class Level {
    // High-volume or detailed logging for development/debugging
    Trace = 0,
    // Reasonably noisy logging, but still usable in production
    Debug,
    // Default
    Info,
    Warning,
    Error,
};
constexpr auto DEFAULT_LOG_LEVEL{Level::Debug};
// buffer up to 1MB of log data prior to StartLogging
constexpr size_t DEFAULT_MAX_LOG_BUFFER{1'000'000};
// maximum number of bytes per source location that can be logged within the
// RATELIMIT_WINDOW
constexpr uint64_t RATELIMIT_MAX_BYTES{1024 * 1024};
// time window after which log ratelimit stats are reset
constexpr auto RATELIMIT_WINDOW{1h};
constexpr bool DEFAULT_LOGRATELIMIT{true};

//! How each log line is written (-logformat)
enum class LogFormat {
    //! Human-readable text, with optional prefixes (the historical format)
    TEXT,
    //! One JSON object per line, for log shippers (see FormatJsonLine)
    JSON,
    LOGFMT,
    JSON_GCP,
    JSON_ECS,
    JOURNALD,
};

/** Parse a supported -logformat value */
std::optional<LogFormat> ParseLogFormat(std::string_view str);
/** Formats available on this platform (help and validation). */
const char *SupportedLogFormats();

/**
 * Append str to out as the contents of a JSON string (without the quotes).
 * Quotes, backslashes and control characters (and DEL) are escaped; valid
 * UTF-8 is copied as is; each byte that is not part of a valid UTF-8
 * sequence becomes U+FFFD, so the output is always valid JSON and the same
 * input always gives the same output. Never allocates if out has capacity.
 */
void AppendJsonEscaped(std::string &out, std::string_view str);

/**
 * The bare name of a function from its signature (as in
 * std::source_location::function_name()): "void CConnman::Stop(int) const"
 * gives "CConnman::Stop". Structured formats name functions this way.
 */
std::string_view BareFunctionName(std::string_view signature);

class LogRateLimiter;

/**
 * Rate limiting state of one log call site. Every log macro expansion owns
 * one (a function-local static, constant-initialized), so checking the
 * quota is a few relaxed atomic operations on that site's own state: no
 * lock and no lookup by source location.
 */
struct LogSiteLimit {
    /**
     * Window, suppression and remaining quota, packed in one word so that
     * they change together: epoch (bits 25..63), suppressed (bit 24) and
     * bytes still allowed in that window (bits 0..23).
     */
    std::atomic<uint64_t> state{0};
    //! Bytes of messages suppressed in the window the site is suppressed in
    std::atomic<uint64_t> dropped{0};
    //! Epoch in which this site was put on its limiter's suppressed list
    std::atomic<uint64_t> listed_epoch{0};
    //! Next suppressed site (list owned by the limiter)
    LogSiteLimit *next{nullptr};
    //! Where the site is, for the suppression notices
    std::source_location loc;

    static constexpr int AVAILABLE_BITS{24};
    static constexpr uint64_t AVAILABLE_MASK{(uint64_t{1} << AVAILABLE_BITS) -
                                             1};
    static constexpr uint64_t SUPPRESSED{uint64_t{1} << AVAILABLE_BITS};
    static constexpr int EPOCH_SHIFT{AVAILABLE_BITS + 1};
    //! Bytes still allowed (for tests)
    uint64_t Available() const { return state.load() & AVAILABLE_MASK; }
};

//! Fixed window rate limiter for logging.
class LogRateLimiter {
private:
    //! Current window. Unique across limiters, so that sites last used by
    //! another limiter start afresh.
    std::atomic<uint64_t> m_epoch;
    //! Sites suppressed in the current window (lock-free stack)
    std::atomic<LogSiteLimit *> m_suppressed{nullptr};
    //! Whether any log locations are suppressed.
    std::atomic<bool> m_suppression_active{false};
    LogRateLimiter(uint64_t max_bytes, std::chrono::seconds reset_window);

public:
    using SchedulerFunction =
        std::function<void(std::function<bool()>, std::chrono::milliseconds)>;
    /**
     * @param scheduler_func    Callable object used to schedule resetting the
     *                          window. The first parameter is the function to
     *                          be executed, and the second is the reset_window
     *                          interval.
     * @param max_bytes         Maximum number of bytes that can be logged for
     *                          each source location.
     * @param reset_window      Time window after which the stats are reset.
     */
    static std::shared_ptr<LogRateLimiter>
    Create(SchedulerFunction &&scheduler_func, uint64_t max_bytes,
           std::chrono::seconds reset_window);
    //! Maximum number of bytes logged per location per window (at most
    //! LogSiteLimit::AVAILABLE_MASK, 16 MiB).
    const uint64_t m_max_bytes;
    //! Interval after which the window is reset.
    const std::chrono::seconds m_reset_window;
    //! Suppression status of a source log location.
    enum class Status {
        // string fits within the limit
        UNSUPPRESSED,
        // suppression has started since this string
        NEWLY_SUPPRESSED,
        // suppression is still ongoing
        STILL_SUPPRESSED,
    };
    /**
     * Consume `bytes` (the message's length, without log prefixes or JSON
     * wrapping) of `site`'s quota and return its status. Lock-free.
     */
    [[nodiscard]] Status Consume(LogSiteLimit &site,
                                 const std::source_location &loc,
                                 uint64_t bytes);
    //! Starts a new window: logs a notice for each site whose messages were
    //! dropped, and lifts all suppressions. Called periodically by the
    //! scheduler.
    void Reset();
    //! Returns true if any log locations are currently being suppressed.
    bool SuppressionsActive() const { return m_suppression_active; }
};

//! Size of one log record (see LogRecord)
inline constexpr size_t LOG_RECORD_SIZE{512};

/**
 * One log line on its way from the logging thread to the logger thread: a
 * fixed-size slot of a per-thread ring. The producer copies what it knows
 * (time, thread, source location, level, category) and the message into
 * it; rendering (text or JSON), rate limit notices and I/O happen on the
 * logger thread.
 */
struct LogRecord {
    enum Flags : uint8_t {
        //! Continues the thread's previous record, which had no newline
        CONTINUED = 1,
        //! The payload is a pointer to a heap std::string (long message)
        SPILLED = 2,
        //! Rate limited: console and callbacks only, not the log file
        NO_FILE = 4,
        //! Some call site was suppressed when this was logged (the "[*]"
        //! marker)
        SUPPRESSIONS = 8,
        //! This record's call site has just been suppressed: write the
        //! notice first
        SUPPRESSION_NOTICE = 16,
        //! Some fields did not fit
        FIELDS_TRUNCATED = 32,
    };
    //! Producer's time (SystemClock), microseconds since the epoch
    int64_t time_us;
    //! Mock time in seconds, 0 if none
    int64_t mocktime_s;
    std::source_location loc;
    //! Structured event descriptor; nullptr for plain messages
    const void *event;
    LogFlags category;
    Level level;
    uint8_t flags;
    uint8_t num_fields;
    uint8_t reserved;
    //! Bytes used in payload
    uint16_t size;
    //! Producer's thread name, NUL terminated (truncated)
    char thread[18];
    //! Message bytes (or a std::string* if SPILLED), or encoded fields
    alignas(8) std::byte payload[LOG_RECORD_SIZE - 64];
};
static_assert(sizeof(LogRecord) == LOG_RECORD_SIZE);
static_assert(std::is_trivially_destructible_v<LogRecord>);
static_assert(offsetof(LogRecord, payload) == 64);

/**
 * Single-producer single-consumer ring of log records, owned by one thread.
 * Claim/Commit never block, lock, allocate or make a system call.
 */
class LogRing {
    friend class Logger;
    // Reserved for severe reentrant writes; never part of the SPSC queue.
    LogRecord m_emergency;

public:
    static constexpr size_t CAPACITY{131072};
    static constexpr size_t WAKE_THRESHOLD{512};
    static_assert(WAKE_THRESHOLD <= CAPACITY);
    static_assert((CAPACITY & (CAPACITY - 1)) == 0);

    //! User-provided, so unused slot bytes are not initialized: their pages
    //! are only touched when used.
    LogRing() {}

    /** Producer: a free slot, or nullptr if the ring is full */
    LogRecord *Claim() noexcept {
        const uint64_t head{m_head.load(std::memory_order_relaxed)};
        if (head - m_cached_tail >= CAPACITY) {
            m_cached_tail = m_tail.load(std::memory_order_acquire);
            if (head - m_cached_tail >= CAPACITY) {
                return nullptr;
            }
        }
        // Begin the record lifetime only when used: default-constructing all
        // source_location members at ring allocation would touch every page.
        void *slot{m_slots.data() + (head & (CAPACITY - 1)) * LOG_RECORD_SIZE};
        return ::new (slot) LogRecord;
    }
    /**
     * Producer: publish the slot returned by Claim. Returns true while the
     * ring has reached the wake threshold (independent of burst capacity).
     */
    bool Commit() noexcept {
        const uint64_t head{m_head.load(std::memory_order_relaxed) + 1};
        m_head.store(head, std::memory_order_release);
        if (head - m_cached_tail < WAKE_THRESHOLD) {
            return false;
        }
        // Possibly: look at the consumer's progress (only while backed up).
        m_cached_tail = m_tail.load(std::memory_order_acquire);
        return head - m_cached_tail >= WAKE_THRESHOLD;
    }
    /** Producer: count a line dropped because the ring was full */
    void CountDrop() noexcept {
        m_dropped.store(m_dropped.load(std::memory_order_relaxed) + 1,
                        std::memory_order_relaxed);
    }

    /** Consumer: number of records ready */
    size_t Available() const noexcept {
        return size_t(m_head.load(std::memory_order_acquire) -
                      m_tail.load(std::memory_order_relaxed));
    }
    /** Consumer: the oldest record (Available() > 0) */
    LogRecord &Front() noexcept {
        const auto offset{
            (m_tail.load(std::memory_order_relaxed) & (CAPACITY - 1)) *
            LOG_RECORD_SIZE};
        return *std::launder(
            reinterpret_cast<LogRecord *>(m_slots.data() + offset));
    }
    /** Consumer: release the oldest record */
    void Pop() noexcept {
        m_tail.store(m_tail.load(std::memory_order_relaxed) + 1,
                     std::memory_order_release);
    }
    uint64_t Dropped() const noexcept {
        return m_dropped.load(std::memory_order_relaxed);
    }
    /**
     * Consumer, once the owning thread has exited and the ring is drained:
     * make it ready for another thread. Returns the drops it had counted.
     */
    uint64_t Recycle() noexcept {
        m_orphaned.store(false, std::memory_order_relaxed);
        m_open_line = false;
        return m_dropped.exchange(0, std::memory_order_relaxed);
    }

    //! Set when the owning thread exits; the consumer then reuses the ring
    //! for another thread once it has drained it.
    std::atomic<bool> m_orphaned{false};
    //! The owning thread's last record had no trailing newline
    bool m_open_line{false};

private:
    // Producer-owned
    alignas(64) std::atomic<uint64_t> m_head{0};
    uint64_t m_cached_tail{0};
    std::atomic<uint64_t> m_dropped{0};
    // Consumer-owned
    alignas(64) std::atomic<uint64_t> m_tail{0};
    alignas(64) std::array<std::byte, CAPACITY * LOG_RECORD_SIZE> m_slots;
};

/**
 * The logger. Producers (any thread logging) put records into their own
 * LogRing; a dedicated thread ("logger") renders them and writes them,
 * flushing the file every few milliseconds. See doc/logging.md.
 */
class Logger {
    friend struct LoggerTestAccess;

public:
    /** A record on the heap; releases what its fields hold */
    struct RecordDeleter {
        void operator()(LogRecord *rec) const;
    };
    using OwnedRecord = std::unique_ptr<LogRecord, RecordDeleter>;

    struct BufferedLog {
        SystemClock::time_point now;
        std::chrono::seconds mocktime;
        std::string str, threadname;
        std::source_location source_loc;
        LogFlags category;
        Level level;
        //! A structured event logged before StartLogging
        OwnedRecord record;
    };

    //! How often the logger thread writes queued lines while busy
    static constexpr std::chrono::milliseconds FLUSH_INTERVAL{2};
    //! ... and when its last pass found nothing to write (a thread whose
    //! ring fills up, or an error, wakes it earlier)
    static constexpr std::chrono::milliseconds IDLE_FLUSH_INTERVAL{20};

private:
    // Can not use Mutex from sync.h because in debug mode it would cause a
    // deadlock when a potential deadlock was detected
    mutable StdMutex m_cs;

    std::list<BufferedLog> m_msgs_before_open GUARDED_BY(m_cs);
    //! Buffer messages before logging can be started.
    std::atomic<bool> m_buffering{true};
    size_t m_max_buffer_memusage GUARDED_BY(m_cs){DEFAULT_MAX_LOG_BUFFER};
    size_t m_cur_buffer_memusage GUARDED_BY(m_cs){0};
    size_t m_buffer_lines_discarded GUARDED_BY(m_cs){0};

    //! Manages the rate limiting of each log location.
    std::shared_ptr<LogRateLimiter> m_limiter GUARDED_BY(m_cs);
    //! m_limiter, read by producers without the lock. Limiters that were
    //! replaced are kept alive (m_old_limiters) since a producer may still
    //! use one.
    std::atomic<LogRateLimiter *> m_limiter_ptr{nullptr};
    std::vector<std::shared_ptr<LogRateLimiter>>
        m_old_limiters GUARDED_BY(m_cs);

    //! Per-category minimum level (index: bit of the category), or -1 to
    //! use m_log_level.
    std::array<std::atomic<int8_t>, 32> m_category_levels{};

    //! If there is no category-specific log level, all logs with a severity
    //! level lower than `m_log_level` will be ignored.
    std::atomic<Level> m_log_level{DEFAULT_LOG_LEVEL};

    /**
     * Log categories bitfield.
     */
    std::atomic<uint32_t> m_categories{0};

    /** Slots that connect to the print signal */
    std::list<std::function<void(const std::string &)>>
        m_print_callbacks GUARDED_BY(m_cs){};
    std::atomic<bool> m_has_callbacks{false};

    // --- Consumer side (the logger thread, or a thread calling Flush) ---
    StdMutex m_consumer_mutex;
    FILE *m_fileout GUARDED_BY(m_consumer_mutex) = nullptr;
    //! Line being rendered; reused, so rendering does not allocate once it
    //! has grown to the longest line.
    std::string m_line_buf GUARDED_BY(m_consumer_mutex);
    //! Rings drained in the current pass (reused)
    std::vector<LogRing *> m_drain_rings GUARDED_BY(m_consumer_mutex);
    //! Dropped lines already reported
    uint64_t m_dropped_reported GUARDED_BY(m_consumer_mutex){0};
    //! Renders lines in m_log_format (recreated if that changes)
    std::unique_ptr<LogEncoder> m_encoder GUARDED_BY(m_consumer_mutex);
    std::optional<LogFormat> m_encoder_format GUARDED_BY(m_consumer_mutex);

    /** Encode a line into m_line_buf in the current format */
    void Encode(const LogLine &line) EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex);
    /** Write a line to every sink (encoding it in each one's format) */
    void WriteLogLine(const LogLine &line, bool to_file)
        EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex, m_cs);
    //! The secondary JSON log file (-debuglogjsonfile)
    FILE *m_json_fileout GUARDED_BY(m_consumer_mutex) = nullptr;
    JsonEncoder m_json_encoder;
    JournalSink m_journal GUARDED_BY(m_consumer_mutex);
    std::string m_startup_error GUARDED_BY(m_consumer_mutex);
    std::atomic<uint64_t> m_journal_failures{0};
    std::string m_json_buf GUARDED_BY(m_consumer_mutex);

    friend class EventBuilder;
    /** Claim a record for an event (or leave the builder inert) */
    void BeginEvent(EventBuilder &builder) noexcept
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
    /** Publish an event's record */
    void EndEvent(EventBuilder &builder) noexcept
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
    /** The "Excessive logging" notice for a call site */
    std::string SuppressionNotice(const std::source_location &loc) const
        EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    //! Rings of threads (in use or orphaned), and rings ready for reuse
    mutable StdMutex m_rings_mutex;
    std::vector<std::shared_ptr<LogRing>> m_rings GUARDED_BY(m_rings_mutex);
    std::vector<std::shared_ptr<LogRing>>
        m_free_rings GUARDED_BY(m_rings_mutex);
    //! Drops counted by rings since reused
    uint64_t m_dropped_retired GUARDED_BY(m_rings_mutex){0};
    //! Distinguishes loggers in the threads' ring caches
    const uint64_t m_uid;

    std::thread m_thread;
    StdMutex m_wake_mutex;
    std::condition_variable m_wake_cv;
    std::atomic<bool> m_wake{false};
    bool m_stop GUARDED_BY(m_wake_mutex){false};
    std::atomic<bool> m_thread_running{false};
    //! A wake-up of the logger thread is pending (rings filling up)
    std::atomic<bool> m_wake_requested{false};
    //! Errors request a pass that starts after publication; the consumer
    //! acknowledges it only after all captured sinks have been flushed.
    std::atomic<uint64_t> m_flush_requested{0};
    std::atomic<uint64_t> m_flush_completed{0};
    //! Tests: the logger thread stops writing (Flush and full rings still
    //! do)
    std::atomic<bool> m_paused_for_testing{false};


    /** Keep a message logged before StartLogging (with m_cs held) */
    void BufferLog(std::string_view str, std::source_location &&source_loc,
                   LogFlags category, Level level)
        EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    /** The calling thread's ring (claimed once per thread) */
    LogRing *ThreadRing() noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);
    std::shared_ptr<LogRing> ClaimRing()
        EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);
    /** A slot when the ring is full, for warnings and errors: waits */
    LogRecord *ClaimSlow(LogRing &ring)
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
    /** Error path: wait for the consumer to flush, without rendering here. */
    void FlushOnConsumer()
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
    /** Consumer reentrancy only: write severe overflow without callbacks. */
    void WriteEmergency(LogRecord &rec);
    bool m_writing_emergency GUARDED_BY(m_consumer_mutex){false};
    /** Queue a plain message (owned: moved into the record if too long) */
    void Enqueue(std::string_view str, std::string *owned,
                 std::source_location &&source_loc, LogFlags category,
                 Level level, LogSiteLimit *site)
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);

    /** Render and write every queued record (consumer); false if none */
    bool DrainLocked()
        EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex, !m_cs, !m_rings_mutex);
    /** Render one record into m_line_buf and write it */
    void WriteRecord(LogRecord &rec)
        EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex, m_cs);
    /** Write a rendered line to the outputs */
    void WriteLine(const std::string &line, bool to_file)
        EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex, m_cs);
    void ReopenIfRequested() EXCLUSIVE_LOCKS_REQUIRED(m_consumer_mutex);
    void ThreadMain() EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs,
                                               !m_rings_mutex, !m_wake_mutex);
    void StartThread() EXCLUSIVE_LOCKS_REQUIRED(!m_wake_mutex);
    void StopThread() EXCLUSIVE_LOCKS_REQUIRED(!m_wake_mutex, !m_consumer_mutex,
                                               !m_cs, !m_rings_mutex);

public:
    Logger();

    bool m_print_to_console = false;
    bool m_print_to_file = false;

    bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    bool m_log_threadnames = DEFAULT_LOGTHREADNAMES;
    bool m_log_sourcelocations = DEFAULT_LOGSOURCELOCATIONS;
    bool m_always_print_category_level = DEFAULT_LOGLEVELALWAYS;
    LogFormat m_log_format = LogFormat::TEXT;

    fs::path m_file_path;
    //! Also write generic JSON lines here, if set (-debuglogjsonfile)
    fs::path m_json_file_path;
    std::atomic<bool> m_reopen_file{false};

    std::string GetLogPrefix(LogFlags category, Level level) const;

    ~Logger();

    /**
     * Send a string to the log output. With a site, unconditional logging
     * is rate limited by that call site's quota (see LogSiteLimit).
     */
    void LogPrintStr(std::string_view str, std::source_location &&source_loc,
                     BCLog::LogFlags category, BCLog::Level level,
                     LogSiteLimit *site)
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
    /** As LogPrintStr, taking the message (moved, not copied, if long) */
    void LogPrintMovedStr(std::string &&str, std::source_location &&source_loc,
                          BCLog::LogFlags category, BCLog::Level level,
                          LogSiteLimit *site)
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);

    /** Returns whether logs will be written to any output (lock-free) */
    bool Enabled() const {
        return m_buffering.load(std::memory_order_relaxed) ||
               m_print_to_console || m_print_to_file ||
               !m_json_file_path.empty() ||
               m_log_format == LogFormat::JOURNALD ||
               m_has_callbacks.load(std::memory_order_relaxed);
    }

    /**
     * Write every line queued so far, on the calling thread, and flush the
     * outputs. For shutdown, fatal errors and tests. Does nothing before
     * StartLogging (lines are kept in memory until then).
     */
    void Flush()
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex);

    /**
     * Give the calling thread its ring now (called at thread start by
     * util::ThreadRename), so that logging never allocates later on.
     */
    void PrepareThisThread() noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);

#ifndef WIN32
    /**
     * Fork with the logger consumer stopped, joined and drained; restart it
     * independently in parent and child (also in the parent on fork failure).
     * Call only with application logging producers/configuration quiescent,
     * no live event builder, and child-compatible sinks/callbacks. This does
     * not make arbitrary concurrent application forks safe.
     */
    int ForkProcess()
        EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex, !m_cs, !m_rings_mutex,
                                 !m_wake_mutex);
#endif

    /** Tests: stop (or resume) the logger thread's periodic writes */
    void PauseForTesting(bool paused) { m_paused_for_testing = paused; }

    /** Lines dropped because their thread's ring was full (ever) */
    uint64_t DroppedLines() const EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);

    /** Connect a slot to the print signal and return the connection */
    std::list<std::function<void(const std::string &)>>::iterator
    PushBackCallback(std::function<void(const std::string &)> fun)
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs) {
        StdLockGuard scoped_lock(m_cs);
        m_print_callbacks.push_back(std::move(fun));
        m_has_callbacks = true;
        return --m_print_callbacks.end();
    }

    /** Delete a connection */
    void DeleteCallback(
        std::list<std::function<void(const std::string &)>>::iterator it)
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs) {
        StdLockGuard scoped_lock(m_cs);
        m_print_callbacks.erase(it);
        m_has_callbacks = !m_print_callbacks.empty();
    }

    /** Start logging (and flush all buffered messages) */
    bool StartLogging()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs, !m_consumer_mutex, !m_wake_mutex);
    /** Error from the most recent StartLogging attempt. */
    std::string StartupError() EXCLUSIVE_LOCKS_REQUIRED(!m_consumer_mutex) {
        StdLockGuard lock(m_consumer_mutex);
        return m_startup_error;
    }
    /** Journal send failures; these records are explicitly sent to stderr. */
    uint64_t JournalFailures() const { return m_journal_failures.load(); }
    /** Only for testing */
    void DisconnectTestLogger()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs, !m_consumer_mutex, !m_rings_mutex,
                                 !m_wake_mutex);

    /**
     * This offers a slight speedup and slightly smaller memory usage compared
     * to leaving the logging system in its default state.
     * Mostly intended for libbitcoin-kernel apps that don't want any logging.
     * Should be used instead of StartLogging().
     */
    void DisableLogging()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs, !m_consumer_mutex, !m_wake_mutex);

    void SetRateLimiting(std::shared_ptr<LogRateLimiter> limiter)
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs) {
        StdLockGuard scoped_lock(m_cs);
        if (m_limiter) {
            m_old_limiters.push_back(m_limiter);
        }
        m_limiter = std::move(limiter);
        m_limiter_ptr.store(m_limiter.get(), std::memory_order_release);
    }

    void ShrinkDebugFile();

    std::unordered_map<LogFlags, Level> CategoryLevels() const;
    void SetCategoryLogLevel(const std::unordered_map<LogFlags, Level> &levels);
    bool SetCategoryLogLevel(std::string_view category_str,
                             std::string_view level_str);

    Level LogLevel() const { return m_log_level.load(); }
    void SetLogLevel(Level level) { m_log_level = level; }
    bool SetLogLevel(std::string_view level);

    uint32_t GetCategoryMask() const { return m_categories.load(); }

    void EnableCategory(LogFlags category);
    bool EnableCategory(std::string_view str);
    void DisableCategory(LogFlags category);
    bool DisableCategory(std::string_view str);

    /** Return true if log accepts specified category */
    bool WillLogCategory(LogFlags category) const;
    /**
     * Whether a message of this category and level is logged: lock-free. A
     * disabled debug category costs one relaxed load.
     */
    bool WillLogCategoryLevel(LogFlags category, Level level) const;

    /** Returns a vector of the log categories in alphabetical order. */
    std::vector<LogCategory> LogCategoriesList() const;
    /** Returns a string with the log categories in alphabetical order. */
    std::string LogCategoriesString() const {
        return util::Join(LogCategoriesList(), ", ",
                          [&](const LogCategory &i) { return i.category; });
    };

    //! Returns a string with all user-selectable log levels.
    std::string LogLevelsString() const;

    //! Returns the string representation of a log level.
    static std::string LogLevelToStr(BCLog::Level level);

    /** Default for whether ShrinkDebugFile should be run */
    bool DefaultShrinkDebugFile() const;
};

} // namespace BCLog

BCLog::Logger &LogInstance();

/** Return true if log accepts specified category, at the specified level. */
static inline bool LogAcceptCategory(BCLog::LogFlags category,
                                     BCLog::Level level) {
    return LogInstance().WillLogCategoryLevel(category, level);
}

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags &flag, std::string_view str);

// Be conservative when using LogPrintf/error or other things which
// unconditionally log to debug.log! It should not be the case that an inbound
// peer can fill up a user's disk with debug.log entries.
template <typename... Args>
static inline void LogPrintf_(std::source_location &&source_loc,
                              BCLog::LogSiteLimit *site, BCLog::LogFlags flag,
                              BCLog::Level level, bool should_ratelimit,
                              const char *fmt, const Args &...args) {
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (tinyformat::format_error &fmterr) {
            /**
             * Original format string will have newline so don't add one here
             */
            log_msg = "Error \"" + std::string(fmterr.what()) +
                      "\" while formatting log message: " + fmt;
        }
        LogInstance().LogPrintMovedStr(std::move(log_msg),
                                       std::move(source_loc), flag, level,
                                       should_ratelimit ? site : nullptr);
    }
}

/**
 * The rate limiting state of the call site this is expanded at: a lambda's
 * function-local static, unique to each macro expansion.
 */
#define LOG_SITE_LIMIT_                                                        \
    ([]() -> BCLog::LogSiteLimit & {                                           \
        static constinit BCLog::LogSiteLimit site_limit;                       \
        return site_limit;                                                     \
    }())

#define LogPrintLevel_(category, level, should_ratelimit, ...)                 \
    LogPrintf_(std::source_location::current(), &LOG_SITE_LIMIT_, category,    \
               level, should_ratelimit, __VA_ARGS__)

// Log unconditionally. Uses basic rate limiting to mitigate disk filling
// attacks.
#define LogInfo(...)                                                           \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Info,                   \
                   /*should_ratelimit=*/true, __VA_ARGS__)
#define LogWarning(...)                                                        \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Warning,                \
                   /*should_ratelimit=*/true, __VA_ARGS__)
#define LogError(...)                                                          \
    LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Error,                  \
                   /*should_ratelimit=*/true, __VA_ARGS__)

// Deprecated unconditional logging.
#define LogPrintf(...) LogInfo(__VA_ARGS__)

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.

// Log by prefixing the output with the passed category name and severity level.
// This can either log conditionally if the category is allowed or
// unconditionally if level >= BCLog::Level::Info is passed. If this function
// logs unconditionally, logging to disk is rate-limited. This is important so
// that callers don't need to worry about accidentally introducing a disk-fill
// vulnerability if level >= Info is used. Additionally, users specifying -debug
// are assumed to be developers or power users who are aware that -debug may
// cause excessive disk usage due to logging.
#define LogPrintLevel(category, level, ...)                                    \
    do {                                                                       \
        if (LogAcceptCategory((category), (level))) {                          \
            bool rate_limit{level >= BCLog::Level::Info};                      \
            LogPrintLevel_(category, level, rate_limit, __VA_ARGS__);          \
        }                                                                      \
    } while (0)

// Log conditionally, prefixing the output with the passed category name.
#define LogDebug(category, ...)                                                \
    LogPrintLevel(category, BCLog::Level::Debug, __VA_ARGS__)
#define LogTrace(category, ...)                                                \
    LogPrintLevel(category, BCLog::Level::Trace, __VA_ARGS__)

/**
 * These are aliases used to explicitly state that the message should not end
 * with a newline character. It allows for detecting the missing newlines that
 * could make the logs hard to read.
 */
#define LogPrintfToBeContinued LogPrintf
#define LogPrintToBeContinued LogDebug
#define LogPrintLevelToBeContinued LogPrintLevel

// Structured events (LogEvent etc.)
#include <logging/event.h> // IWYU pragma: export

#endif // BITCOIN_LOGGING_H
