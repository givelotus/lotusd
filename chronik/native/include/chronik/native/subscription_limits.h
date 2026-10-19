// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SUBSCRIPTION_LIMITS_H
#define CHRONIK_NATIVE_SUBSCRIPTION_LIMITS_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

/** Port of chronik-http subscription_limits.rs: global and per-client caps. */
namespace chronik::native {

/** Default global subscription limit across all clients (-chronikmaxsubs) */
constexpr size_t MAX_SUBS = 10'000'000;
/** Default per-IP / per-client subscription limit (-chronikmaxsubsperip) */
constexpr size_t MAX_SUBS_PER_IP = 75'000;

/** Key used to attribute a subscription to a client. */
struct SubscriptionClientKey {
    enum class Kind : uint8_t { Ip, Connection };
    Kind kind = Kind::Ip;
    /** Real client IP address (Kind::Ip) */
    std::string ip;
    /** Opaque connection identity (Kind::Connection) */
    uint64_t connection = 0;

    static SubscriptionClientKey Ip(std::string ip) {
        return {Kind::Ip, std::move(ip), 0};
    }
    static SubscriptionClientKey Connection(uint64_t id) {
        return {Kind::Connection, {}, id};
    }
    bool operator==(const SubscriptionClientKey &) const = default;
};

struct SubscriptionClientKeyHasher {
    size_t operator()(const SubscriptionClientKey &k) const {
        return std::hash<std::string>{}(k.ip) ^
               (std::hash<uint64_t>{}(k.connection) << 1) ^ size_t(k.kind);
    }
};

/** Errors when accepting a new subscription. */
struct SubscriptionLimitError {
    enum class Kind : uint8_t { Global, PerClient };
    Kind kind;
    size_t limit;
    /** "Global subscription limit of N exceeded" /
     *  "Subscription limit of N exceeded for this client" */
    std::string Message() const;
    bool operator==(const SubscriptionLimitError &) const = default;
};

class SubscriptionLimiter;

/** RAII guard that releases one reserved subscription slot on destruction. */
class SubscriptionGuard {
public:
    SubscriptionGuard(std::shared_ptr<SubscriptionLimiter> limiter,
                      SubscriptionClientKey key);
    SubscriptionGuard(SubscriptionGuard &&other) noexcept;
    SubscriptionGuard &operator=(SubscriptionGuard &&other) noexcept;
    SubscriptionGuard(const SubscriptionGuard &) = delete;
    SubscriptionGuard &operator=(const SubscriptionGuard &) = delete;
    ~SubscriptionGuard();

private:
    void Release();
    std::shared_ptr<SubscriptionLimiter> m_limiter;
    SubscriptionClientKey m_key;
};

struct SubscriptionAcquire {
    std::optional<SubscriptionGuard> guard;
    std::optional<SubscriptionLimitError> error;
    explicit operator bool() const { return guard.has_value(); }
};

/** Tracks active subscriptions against global and per-client caps. */
class SubscriptionLimiter
    : public std::enable_shared_from_this<SubscriptionLimiter> {
public:
    static std::shared_ptr<SubscriptionLimiter>
    Create(size_t max_subs = MAX_SUBS, size_t max_subs_per_ip = MAX_SUBS_PER_IP,
           std::function<void(int32_t)> observe_delta = {});

    /** Try to reserve one subscription slot for `key`. */
    SubscriptionAcquire TryAcquire(const SubscriptionClientKey &key);

    size_t Total() const { return m_total.load(std::memory_order_relaxed); }
    size_t ClientCount(const SubscriptionClientKey &key) const;
    bool HasClient(const SubscriptionClientKey &key) const;
    size_t MaxSubs() const { return m_max_subs; }
    size_t MaxSubsPerIp() const { return m_max_subs_per_ip; }

private:
    friend class SubscriptionGuard;
    SubscriptionLimiter(size_t max_subs, size_t max_subs_per_ip,
                        std::function<void(int32_t)> observe_delta)
        : m_observe_delta(std::move(observe_delta)), m_max_subs(max_subs),
          m_max_subs_per_ip(max_subs_per_ip) {}
    /** Immutable host callback, atomic/non-blocking/noexcept; invoked under
     * the existing limiter mutex, never allowed to acquire host/indexer locks. */
    const std::function<void(int32_t)> m_observe_delta;
    void Release(const SubscriptionClientKey &key);

    size_t m_max_subs;
    size_t m_max_subs_per_ip;
    std::atomic<size_t> m_total{0};
    mutable std::mutex m_mutex;
    std::unordered_map<SubscriptionClientKey, size_t,
                       SubscriptionClientKeyHasher>
        m_per_client;
};

/** ws.rs ChronikWsError::SubscriptionLimit: "503: <limit error>" */
std::string WsSubscriptionLimitErrorMessage(const SubscriptionLimitError &err);
/** ws.rs ChronikWsError::ScriptTooLarge */
std::string WsScriptTooLargeMessage(size_t size, size_t max);
/** ws.rs ChronikWsError::PluginGroupTooLarge */
std::string WsPluginGroupTooLargeMessage(size_t size, size_t max);

/** ws.rs MAX_SCRIPT_SIZE (consensus) and MAX_WS_MESSAGE_SIZE */
constexpr size_t MAX_SCRIPT_SIZE = 10'000;
constexpr size_t MAX_WS_MESSAGE_SIZE = 2 * MAX_SCRIPT_SIZE;
/** Default -chroniksubsmaxscriptsize */
constexpr size_t DEFAULT_SUBSCRIPTION_MAX_SCRIPT_SIZE = 201;

} // namespace chronik::native

#endif // CHRONIK_NATIVE_SUBSCRIPTION_LIMITS_H
