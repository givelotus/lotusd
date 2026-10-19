// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/subscription_limits.h>

namespace chronik::native {

std::string SubscriptionLimitError::Message() const {
    switch (kind) {
        case Kind::Global:
            return "Global subscription limit of " + std::to_string(limit) +
                   " exceeded";
        case Kind::PerClient:
            return "Subscription limit of " + std::to_string(limit) +
                   " exceeded for this client";
    }
    return {};
}

SubscriptionGuard::SubscriptionGuard(
    std::shared_ptr<SubscriptionLimiter> limiter, SubscriptionClientKey key)
    : m_limiter(std::move(limiter)), m_key(std::move(key)) {}

SubscriptionGuard::SubscriptionGuard(SubscriptionGuard &&other) noexcept
    : m_limiter(std::move(other.m_limiter)), m_key(std::move(other.m_key)) {
    other.m_limiter.reset();
}

SubscriptionGuard &
SubscriptionGuard::operator=(SubscriptionGuard &&other) noexcept {
    if (this != &other) {
        Release();
        m_limiter = std::move(other.m_limiter);
        m_key = std::move(other.m_key);
        other.m_limiter.reset();
    }
    return *this;
}

SubscriptionGuard::~SubscriptionGuard() {
    Release();
}

void SubscriptionGuard::Release() {
    if (m_limiter) {
        m_limiter->Release(m_key);
        m_limiter.reset();
    }
}

std::shared_ptr<SubscriptionLimiter>
SubscriptionLimiter::Create(size_t max_subs, size_t max_subs_per_ip,
                            std::function<void(int32_t)> observe_delta) {
    return std::shared_ptr<SubscriptionLimiter>(
        new SubscriptionLimiter(max_subs, max_subs_per_ip, std::move(observe_delta)));
}

SubscriptionAcquire
SubscriptionLimiter::TryAcquire(const SubscriptionClientKey &key) {
    std::lock_guard lock(m_mutex);
    auto it = m_per_client.find(key);
    const size_t client_count = it == m_per_client.end() ? 0 : it->second;
    if (client_count >= m_max_subs_per_ip) {
        return {std::nullopt, SubscriptionLimitError{
                                  SubscriptionLimitError::Kind::PerClient,
                                  m_max_subs_per_ip}};
    }
    // Check-and-increment total under the same lock as per-client so the two
    // counters stay consistent under concurrency.
    if (m_total.load(std::memory_order_relaxed) >= m_max_subs) {
        return {std::nullopt,
                SubscriptionLimitError{SubscriptionLimitError::Kind::Global,
                                       m_max_subs}};
    }
    m_per_client[key] = client_count + 1;
    m_total.fetch_add(1, std::memory_order_relaxed);
    if (m_observe_delta) { try { m_observe_delta(1); } catch (...) {} }
    SubscriptionAcquire result;
    result.guard.emplace(shared_from_this(), key);
    return result;
}

void SubscriptionLimiter::Release(const SubscriptionClientKey &key) {
    std::lock_guard lock(m_mutex);
    auto it = m_per_client.find(key);
    if (it != m_per_client.end()) {
        if (it->second > 0) {
            --it->second;
        }
        if (it->second == 0) {
            m_per_client.erase(it);
        }
    }
    m_total.fetch_sub(1, std::memory_order_relaxed);
    if (m_observe_delta) { try { m_observe_delta(-1); } catch (...) {} }
}

size_t SubscriptionLimiter::ClientCount(const SubscriptionClientKey &key) const {
    std::lock_guard lock(m_mutex);
    auto it = m_per_client.find(key);
    return it == m_per_client.end() ? 0 : it->second;
}

bool SubscriptionLimiter::HasClient(const SubscriptionClientKey &key) const {
    std::lock_guard lock(m_mutex);
    return m_per_client.count(key) > 0;
}

std::string WsSubscriptionLimitErrorMessage(const SubscriptionLimitError &err) {
    return "503: " + err.Message();
}

std::string WsScriptTooLargeMessage(size_t size, size_t max) {
    return "400: Script subscription of " + std::to_string(size) +
           " bytes exceeds the maximum of " + std::to_string(max) + " bytes";
}

std::string WsPluginGroupTooLargeMessage(size_t size, size_t max) {
    return "400: Plugin group of " + std::to_string(size) +
           " bytes exceeds the maximum of " + std::to_string(max) + " bytes";
}

} // namespace chronik::native
