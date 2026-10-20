// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_ADMISSION_H
#define BITCOIN_NET_QUIC_QUIC_ADMISSION_H

#include <netaddress.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <list>
#include <map>

/** Address validation is standard QUIC Retry, not rendezvous or discovery. */
enum class QuicRetryMode { OFF, AUTO, ALWAYS };

/** Engine-thread-only admission state. IPv4 uses /32, IPv6 uses /64.
 * Closing connections retain their slot until their state is collected, so
 * repeated close/reopen cannot evade the memory bound. Rate buckets survive
 * connection closure for the ten-second token-less Initial window. */
class QuicAdmission {
public:
    using Clock = std::chrono::steady_clock;
    enum class Decision { ACCEPT, RETRY, PER_IP, HANDSHAKING, TABLE_FULL };
    static constexpr size_t MAX_BUCKETS{4096};

    QuicAdmission(size_t max_per_ip = 16, size_t max_handshaking = 256,
                  size_t capacity = MAX_BUCKETS)
        : m_max_per_ip{max_per_ip}, m_max_handshaking{max_handshaking},
          m_capacity{capacity} {}
    QuicAdmission(const QuicAdmission &) = delete;
    QuicAdmission &operator=(const QuicAdmission &) = delete;

    Decision Inspect(const CNetAddr &addr, bool validated, QuicRetryMode retry,
                     Clock::time_point now = Clock::now()) {
        if (m_handshaking >= m_max_handshaking) return Decision::HANDSHAKING;
        const auto key{Key(addr)};
        auto it{m_buckets.find(key)};
        if (it == m_buckets.end()) {
            if (m_buckets.size() == m_capacity) {
                // Never evict an active count. A validated source may replace
                // an inactive recent rate bucket; an unvalidated one cannot
                // erase a recent source's rate history by cycling addresses.
                auto victim{m_lru.end()};
                for (auto p{m_lru.end()}; p != m_lru.begin();) {
                    --p;
                    const auto &bucket{m_buckets.at(*p)};
                    if (bucket.active == 0 &&
                        (validated ||
                         now - bucket.window >= std::chrono::seconds{10})) {
                        victim = p;
                        break;
                    }
                }
                if (victim == m_lru.end()) {
                    return !validated && retry != QuicRetryMode::OFF
                               ? Decision::RETRY
                               : Decision::TABLE_FULL;
                }
                m_buckets.erase(*victim);
                m_lru.erase(victim);
            }
            if (m_capacity == 0) return Decision::TABLE_FULL;
            m_lru.push_front(key);
            it = m_buckets.emplace(key, Bucket{0, 0, now, m_lru.begin()}).first;
        }
        auto &bucket{it->second};
        m_lru.splice(m_lru.begin(), m_lru, bucket.lru);
        if (bucket.active >= m_max_per_ip) return Decision::PER_IP;
        if (now - bucket.window >= std::chrono::seconds{10}) {
            bucket.window = now;
            bucket.tokenless = 0;
        }
        if (!validated) {
            // Saturate at the threshold: packets cannot overflow the counter.
            bucket.tokenless = std::min<uint32_t>(9, bucket.tokenless + 1);
            if (retry == QuicRetryMode::ALWAYS ||
                (retry == QuicRetryMode::AUTO &&
                 (m_handshaking > 64 || bucket.tokenless > 8))) {
                return Decision::RETRY;
            }
        }
        return Decision::ACCEPT;
    }

    void Started(const CNetAddr &addr) {
        ++m_buckets.at(Key(addr)).active;
        ++m_active;
        ++m_handshaking;
    }
    void HandshakeDone() {
        assert(m_handshaking > 0);
        --m_handshaking;
    }
    void Closed(const CNetAddr &addr, bool handshake_done) {
        auto &bucket{m_buckets.at(Key(addr))};
        assert(bucket.active > 0);
        --bucket.active;
        assert(m_active > 0);
        --m_active;
        if (!handshake_done) HandshakeDone();
    }
    size_t Handshaking() const { return m_handshaking; }
    size_t Active() const { return m_active; }
    size_t Buckets() const { return m_buckets.size(); }

private:
    using AddressKey = std::array<uint8_t, 17>;
    static AddressKey Key(const CNetAddr &addr) {
        AddressKey key{};
        if (addr.IsIPv4()) {
            key[0] = 4;
            const auto ip{addr.GetLinkedIPv4()};
            for (unsigned i{0}; i < 4; ++i)
                key[i + 1] = uint8_t(ip >> (24 - 8 * i));
        } else {
            key[0] = 6;
            const auto bytes{addr.GetAddrBytes()};
            std::copy_n(bytes.begin(), std::min<size_t>(8, bytes.size()),
                        key.begin() + 1);
        }
        return key;
    }
    struct Bucket {
        size_t active;
        uint32_t tokenless;
        Clock::time_point window;
        std::list<AddressKey>::iterator lru;
    };
    const size_t m_max_per_ip;
    const size_t m_max_handshaking;
    const size_t m_capacity;
    size_t m_handshaking{0};
    size_t m_active{0};
    std::list<AddressKey> m_lru;
    std::map<AddressKey, Bucket> m_buckets;
};

#endif // BITCOIN_NET_QUIC_QUIC_ADMISSION_H
