// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_EVENT_H
#define BITCOIN_LOGGING_EVENT_H

#include <logging/fields.h>
#include <uint256.h>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

/**
 * Structured log events: an event name and typed fields instead of a
 * preformatted string.
 *
 *     LogEvent(BCLog::NET, "peer_connected",
 *              "New outbound peer connected: peer={peer_id}")
 *         .Field(LogField::PeerId, id)
 *         .Field(LogField::Addr, addr)
 *         .Field(LogField::Transport, LogStatic("wss"));
 *
 * When the category/level is disabled, nothing after the check is
 * evaluated (the builder and its arguments are in the else branch of an
 * if). When enabled, the builder claims a slot in the calling thread's log
 * ring and each Field() appends the field's id and its value in binary;
 * the slot is published when the statement ends. No string is built, no
 * lock is taken and nothing is allocated: rendering (text, JSON, ...)
 * happens on the logger thread.
 *
 * Values are copied into the slot, except string literals passed as
 * LogStatic (a pointer) and shared immutable objects passed by shared_ptr
 * (the record keeps a reference, released by the logger thread after
 * rendering). Strings longer than the slot's remaining space are truncated
 * and marked. Large blobs cannot be logged: log a hash or a size.
 */

namespace BCLog {

enum LogFlags : uint32_t;
enum class Level;
struct LogRecord;
class LogRing;
struct LogSiteLimit;

/** The static description of one structured log call site */
struct LogEventSite {
    //! Event name, snake_case
    const char *event;
    //! Human message template with {field_name} placeholders, or nullptr
    const char *message;
    LogFlags category;
    Level level;
};

namespace detail {
    consteval const char *EventMessage() {
        return nullptr;
    }
    consteval const char *EventMessage(const char *message) {
        return message;
    }
} // namespace detail

/**
 * A string that lives forever (a string literal), stored as a pointer.
 * The constructor only accepts constant expressions, so a local buffer
 * does not compile here: pass it as a std::string_view to have it copied.
 */
struct LogStatic {
    const char *str;
    size_t len;
    template <size_t N>
    consteval LogStatic(const char (&s)[N]) : str{s}, len{N - 1} {}
};

/** How a field's value is stored in a record */
enum class FieldKind : uint8_t {
    I64,
    U64,
    F64,
    BOOL,
    //! Copied bytes
    STR,
    //! Pointer and length of a LogStatic
    STATIC_STR,
    //! 32 bytes, as in uint256
    HASH,
    //! int64 nanoseconds
    DURATION_NS,
    //! Bytes packed by LogValue<T>, rendered by its function
    CUSTOM,
    //! A shared_ptr<const T> kept in the record, rendered by its function
    REF,
};

/** Header of one field in a record's payload; the value follows */
struct FieldHeader {
    FieldId id;
    FieldKind kind;
    //! The value was cut to fit
    bool truncated;
    //! Bytes of value that follow (the next header is 8-byte aligned)
    uint16_t size;
    uint16_t reserved;
};
static_assert(sizeof(FieldHeader) == 8);

//! Renders a CUSTOM value (packed bytes) as text
using PackedRenderFn = void (*)(std::span<const std::byte> packed,
                                std::string &out);
//! Renders a REF value (the referenced object) as text
using RefRenderFn = void (*)(const void *object, std::string &out);

/** One field of a record, as encoders see it */
struct FieldView {
    FieldId id;
    FieldKind kind;
    bool truncated;
    std::span<const std::byte> data;

    const FieldInfo &Info() const { return GetFieldInfo(id); }
    int64_t I64() const;
    uint64_t U64() const;
    double F64() const;
    bool Bool() const;
    int64_t DurationNs() const;
    /** Append the value as text: numbers in decimal, hashes in hex, ... */
    void AppendText(std::string &out) const;
    /** Whether the value is a number (I64, U64, F64, DURATION_NS) */
    bool IsNumber() const;
};

/** The fields of a record's payload */
class FieldList {
public:
    FieldList() = default;
    FieldList(std::span<const std::byte> payload, uint8_t count)
        : m_payload{payload}, m_count{count} {}
    uint8_t size() const { return m_count; }
    bool empty() const { return m_count == 0; }

    class Iterator {
    public:
        Iterator(const std::byte *pos, uint8_t left)
            : m_pos{pos}, m_left{left} {}
        FieldView operator*() const;
        Iterator &operator++();
        bool operator!=(const Iterator &other) const {
            return m_left != other.m_left;
        }

    private:
        const std::byte *m_pos;
        uint8_t m_left;
    };
    Iterator begin() const { return {m_payload.data(), m_count}; }
    Iterator end() const { return {nullptr, 0}; }

private:
    std::span<const std::byte> m_payload;
    uint8_t m_count{0};
};

/**
 * Logging of a type other than numbers, strings, hashes and durations:
 * specialize with
 *   static constexpr size_t MAX_SIZE;  // bytes packed at most
 *   static size_t Pack(const T &value, std::span<std::byte> out);
 *   static void Render(std::span<const std::byte> packed, std::string &out);
 * Pack copies what Render needs (no pointers to the caller's memory).
 * A variable-size type may also provide Size(value), at most MAX_SIZE.
 * Only that many bytes are reserved, so short values of a potentially long
 * type still fit; a value that does not fit is explicitly marked truncated.
 */
template <typename T> struct LogValue;

/**
 * Logging of an immutable shared object by reference: specialize with
 *   static void Render(const T &object, std::string &out);
 * and pass a std::shared_ptr<const T>. The record holds one reference
 * until the logger thread has rendered it (the object is then released,
 * possibly destroyed, on the logger thread).
 */
template <typename T> struct LogRef;

/** Builds one structured log record; see the file comment */
class EventBuilder {
public:
    EventBuilder(
        const LogEventSite &site, LogSiteLimit *limit,
        std::source_location loc = std::source_location::current()) noexcept;
    ~EventBuilder();
    EventBuilder(const EventBuilder &) = delete;
    EventBuilder &operator=(const EventBuilder &) = delete;

    // Integers
    template <std::integral V>
        requires(!std::same_as<V, bool>)
    EventBuilder &Field(FieldKey<FieldType::INT> key, V value) {
        const int64_t v{int64_t(value)};
        return Put(key.id, FieldKind::I64, &v, sizeof(v));
    }
    template <std::integral V>
        requires(!std::same_as<V, bool>)
    EventBuilder &Field(FieldKey<FieldType::UINT> key, V value) {
        const uint64_t v{uint64_t(value)};
        return Put(key.id, FieldKind::U64, &v, sizeof(v));
    }
    template <typename V>
        requires std::is_arithmetic_v<V>
    EventBuilder &Field(FieldKey<FieldType::FLOAT> key, V value) {
        const double v{double(value)};
        return Put(key.id, FieldKind::F64, &v, sizeof(v));
    }
    template <std::same_as<bool> V>
    EventBuilder &Field(FieldKey<FieldType::BOOL> key, V value) {
        const uint8_t v{value};
        return Put(key.id, FieldKind::BOOL, &v, sizeof(v));
    }
    // Hashes (uint256, BlockHash, TxId, ...)
    EventBuilder &Field(FieldKey<FieldType::HASH> key, const uint256 &hash) {
        return Put(key.id, FieldKind::HASH, hash.data(), uint256::size());
    }
    // Durations
    template <typename Rep, typename Period>
    EventBuilder &Field(FieldKey<FieldType::DURATION> key,
                        std::chrono::duration<Rep, Period> d) {
        const int64_t ns{
            std::chrono::duration_cast<std::chrono::nanoseconds>(d).count()};
        return Put(key.id, FieldKind::DURATION_NS, &ns, sizeof(ns));
    }
    // Strings: literals by pointer, anything else copied
    EventBuilder &Field(FieldKey<FieldType::STRING> key, LogStatic s) {
        struct {
            const char *str;
            uint64_t len;
        } v{s.str, s.len};
        return Put(key.id, FieldKind::STATIC_STR, &v, sizeof(v));
    }
    EventBuilder &Field(FieldKey<FieldType::STRING> key, std::string_view s) {
        return Put(key.id, FieldKind::STR, s.data(), s.size(),
                   /*truncate=*/true);
    }
    EventBuilder &Field(FieldKey<FieldType::STRING> key, const std::string &s) {
        return Field(key, std::string_view{s});
    }
    EventBuilder &Field(FieldKey<FieldType::STRING> key, const char *s) {
        return Field(key, std::string_view{s});
    }
    // Other types, packed by their LogValue
    template <typename T>
        requires requires { LogValue<T>::MAX_SIZE; }
    EventBuilder &Field(FieldKey<FieldType::STRING> key, const T &value) {
        const size_t capacity{[&] {
            if constexpr (requires { LogValue<T>::Size(value); }) {
                return size_t{LogValue<T>::Size(value)};
            } else {
                return size_t{LogValue<T>::MAX_SIZE};
            }
        }()};
        std::byte *out{Reserve(key.id, FieldKind::CUSTOM,
                               sizeof(PackedRenderFn) + capacity)};
        if (out) {
            const PackedRenderFn fn{&LogValue<T>::Render};
            std::memcpy(out, &fn, sizeof(fn));
            const size_t size{LogValue<T>::Pack(
                value, std::span<std::byte>{out + sizeof(fn), capacity})};
            Finish(sizeof(fn) + size);
        }
        return *this;
    }
    // Shared immutable objects, by reference
    template <typename T>
        requires requires(const T &o, std::string &s) {
            LogRef<T>::Render(o, s);
        }
    EventBuilder &Field(FieldKey<FieldType::STRING> key,
                        const std::shared_ptr<const T> &object) {
        if (!object) {
            return Field(key, LogStatic("null"));
        }
        return PutRef(key.id, std::shared_ptr<const void>{object},
                      [](const void *o, std::string &out) {
                          LogRef<T>::Render(*static_cast<const T *>(o), out);
                      });
    }
    // Blobs are not logged: log their hash or size instead
    EventBuilder &Field(FieldKey<FieldType::STRING>,
                        std::span<const uint8_t>) = delete;
    EventBuilder &Field(FieldKey<FieldType::STRING>,
                        const std::vector<uint8_t> &) = delete;

    /** Whether this builder records anything (category/level on, room) */
    bool Active() const { return m_rec != nullptr; }

private:
    friend class Logger;
    const LogEventSite &m_site;
    LogSiteLimit *const m_limit;
    //! Captured at the caller, outside the descriptor's constexpr lambda.
    const std::source_location m_source_loc;
    //! The slot being filled (in the thread's ring, or m_buffered)
    LogRecord *m_rec{nullptr};
    LogRing *m_ring{nullptr};
    //! Rare reentrant severe overflow (already on the consuming thread).
    bool m_emergency{false};
    //! Before logging starts: a heap record kept until StartLogging
    std::unique_ptr<LogRecord> m_buffered;
    //! Payload bytes used
    size_t m_used{0};
    FieldHeader *m_pending{nullptr};

    EventBuilder &Put(FieldId id, FieldKind kind, const void *data, size_t size,
                      bool truncate = false) noexcept;
    EventBuilder &PutRef(FieldId id, std::shared_ptr<const void> object,
                         RefRenderFn render) noexcept;
    /** Space for a field of up to max_size bytes, or nullptr */
    std::byte *Reserve(FieldId id, FieldKind kind, size_t max_size) noexcept;
    void Finish(size_t size) noexcept;
};

/**
 * Release what a record's fields hold (REF references). The logger calls
 * this after rendering; records are never copied.
 */
void ReleaseFields(FieldList fields);

/** Append text, quoted and escaped as in logfmt if it needs quoting */
void AppendQuotedText(std::string &out, std::string_view text);

/**
 * The event's human message: its template with {field} placeholders
 * replaced by the fields' text values (or the event name if it has none).
 * FLOAT fields also accept :f/:g or :.Nf/:.Ng (precision 0..18), formatted
 * only on the consumer. Nonnegative INT/UINT fields accept :x or :0Nx
 * (width 1..16). Copied/static STRING fields accept :fsq for fs::quoted's
 * double-quote and ampersand escaping in the human message. Their structured
 * value remains the original unquoted string. Numeric fields retain raw values.
 * Bit i of *used is set if the template used field i.
 */
void AppendEventMessage(std::string &out, const LogEventSite &site,
                        FieldList fields, uint64_t *used = nullptr);

} // namespace BCLog

/**
 * The site description of the call site this is expanded at, a constant
 * (category, level, event name and message template).
 */
#define LOG_EVENT_SITE_(category, level, event, ...)                           \
    ([]() -> const BCLog::LogEventSite & {                                     \
        static constexpr BCLog::LogEventSite site{                             \
            event, BCLog::detail::EventMessage(__VA_ARGS__), category, level}; \
        return site;                                                           \
    }())

#define LOG_EVENT_(category, level, event, ...)                                \
    if (!LogAcceptCategory((category), (level))) {                             \
    } else                                                                     \
        BCLog::EventBuilder {                                                  \
            LOG_EVENT_SITE_(category, level,                                   \
                            event __VA_OPT__(, ) __VA_ARGS__),                 \
                (level) >= BCLog::Level::Info ? &LOG_SITE_LIMIT_ : nullptr     \
        }

/**
 * Structured events. Use as a statement, chaining .Field(...) calls:
 *   LogEvent(category, "event_name"[, "message template"]).Field(...)...;
 * LogEvent logs at debug level when the category is enabled (as LogDebug);
 * LogInfoEvent, LogWarningEvent and LogErrorEvent log unconditionally (with
 * per call site rate limiting), in a category or none.
 */
#define LogEvent(category, event, ...)                                         \
    LOG_EVENT_(category, BCLog::Level::Debug, event __VA_OPT__(, ) __VA_ARGS__)
#define LogTraceEvent(category, event, ...)                                    \
    LOG_EVENT_(category, BCLog::Level::Trace, event __VA_OPT__(, ) __VA_ARGS__)
#define LogInfoEvent(category, event, ...)                                     \
    LOG_EVENT_(category, BCLog::Level::Info, event __VA_OPT__(, ) __VA_ARGS__)
/** Explicit bypass for progress events which already logged without a limiter.
 * Ring-full/drop behavior is unchanged; this bypasses only the per-site limiter.
 */
#define LogInfoEventNoRateLimit(category, event, ...)                          \
    if (!LogAcceptCategory((category), BCLog::Level::Info)) {                  \
    } else                                                                   \
        BCLog::EventBuilder {                                                \
            LOG_EVENT_SITE_(category, BCLog::Level::Info,                     \
                            event __VA_OPT__(, ) __VA_ARGS__), nullptr       \
        }
#define LogWarningEvent(category, event, ...)                                  \
    LOG_EVENT_(category, BCLog::Level::Warning,                                \
               event __VA_OPT__(, ) __VA_ARGS__)
#define LogErrorEvent(category, event, ...)                                    \
    LOG_EVENT_(category, BCLog::Level::Error, event __VA_OPT__(, ) __VA_ARGS__)

#endif // BITCOIN_LOGGING_EVENT_H
