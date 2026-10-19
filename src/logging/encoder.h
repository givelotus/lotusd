// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_ENCODER_H
#define BITCOIN_LOGGING_ENCODER_H

#include <logging/event.h>
#include <util/time.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <source_location>
#include <string>
#include <string_view>

namespace BCLog {

enum LogFlags : uint32_t;
enum class Level;
enum class LogFormat;

/** Logger options that shape lines (snapshot taken by the logger thread) */
struct LogOptions {
    bool timestamps{true};
    bool time_micros{false};
    bool threadnames{false};
    bool sourcelocations{false};
    bool always_print_category_level{false};
};

/** One log line, as an encoder sees it (views valid during Encode) */
struct LogLine {
    //! Producer's time
    SystemClock::time_point time;
    //! Mock time (0 if none)
    std::chrono::seconds mocktime{0};
    Level level;
    LogFlags category;
    std::string_view thread;
    std::source_location loc;
    //! The message, possibly ending with its newline
    std::string_view message;
    //! Continues the thread's previous line, which had no newline
    bool continued{false};
    //! Some call site was rate limited when this was logged
    bool ratelimited{false};
    //! A structured event (then message is empty), or nullptr
    const LogEventSite *event{nullptr};
    //! The event's fields
    FieldList fields;
    //! Some fields did not fit in the record and were left out
    bool fields_truncated{false};
};

/**
 * Renders log lines in one format. Encoders run on the logger thread only,
 * never on the thread that logged, and write into a reused buffer.
 */
class LogEncoder {
public:
    virtual ~LogEncoder() = default;
    /** Replace out's contents with the encoded line, newline included */
    virtual void Encode(const LogLine &line, const LogOptions &opts,
                        std::string &out) const = 0;
};

/** The historical human-readable format (-logformat=text) */
class TextEncoder final : public LogEncoder {
public:
    void Encode(const LogLine &line, const LogOptions &opts,
                std::string &out) const override;
};

/** Generic JSON lines (-logformat=json); see Logger::FormatJsonLine */
class JsonEncoder final : public LogEncoder {
public:
    void Encode(const LogLine &line, const LogOptions &opts,
                std::string &out) const override;
};

std::unique_ptr<LogEncoder> MakeLogEncoder(LogFormat format);

// Building blocks shared by encoders
/** "trace", "debug", "info", "warning" or "error" */
std::string_view LogLevelName(Level level);
/** A category's name; "none" for uncategorized lines (NONE or ALL) */
std::string_view LogCategoryName(LogFlags category);
/** A category's name as in -debug (ALL is "all") */
std::string_view LogCategoryText(LogFlags category);
/** The source file of a log call, relative to the source tree */
std::string_view SourceFileName(const std::source_location &loc);
/** Append value as exactly width decimal digits */
void AppendDigits(std::string &out, uint32_t value, int width);
/** RFC 3339 UTC time, e.g. 2026-10-19T12:34:56.123456Z */
void AppendRfc3339(std::string &out, SystemClock::time_point tp,
                   bool with_micros);
/** Append the text format's "[category:level] " prefix (may be empty) */
void AppendLogPrefix(std::string &out, LogFlags category, Level level,
                     bool always_print_category_level);

} // namespace BCLog

#endif // BITCOIN_LOGGING_ENCODER_H
