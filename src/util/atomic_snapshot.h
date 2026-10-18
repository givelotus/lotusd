// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_ATOMIC_SNAPSHOT_H
#define BITCOIN_UTIL_ATOMIC_SNAPSHOT_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <utility>

namespace util {
template <typename Tuple> class AtomicSnapshot;

/** Coherent fixed-size scalar publication without a reader mutex, allocation,
 * shared_ptr reference count or memory reclamation. Every payload field is
 * atomic: unlike a seqlock over ordinary memory, retries cannot hide a C++ data
 * race. Sequential consistency makes the generation/payload ordering explicit.
 * Writers serialize only the bounded stores; readers retry a concurrent write.
 * This is not a wait-free API. Native atomic availability depends on Fields.
 */
template <typename... Fields>
class AtomicSnapshot<std::tuple<Fields...>> {
    std::tuple<std::atomic<Fields>...> m_fields{};
    std::atomic<uint64_t> m_generation{0};
    std::atomic_flag m_writer = ATOMIC_FLAG_INIT;

    template <std::size_t... I>
    auto Read(std::index_sequence<I...>) const noexcept {
        return std::tuple<Fields...>{std::get<I>(m_fields).load()...};
    }
    template <std::size_t... I>
    void Write(const std::tuple<Fields...> &values,
               std::index_sequence<I...>) noexcept {
        (std::get<I>(m_fields).store(std::get<I>(values)), ...);
    }
public:
    static constexpr bool IS_ALWAYS_LOCK_FREE =
        std::atomic<uint64_t>::is_always_lock_free &&
        (std::atomic<Fields>::is_always_lock_free && ...);

    auto Load() const noexcept {
        for (;;) {
            const auto before = m_generation.load();
            if (before & 1) continue;
            auto values = Read(std::index_sequence_for<Fields...>{});
            if (m_generation.load() == before) return values;
        }
    }
    void Store(const std::tuple<Fields...> &values) noexcept {
        while (m_writer.test_and_set(std::memory_order_acquire)) {}
        const auto before = m_generation.load();
        m_generation.store(before + 1);
        Write(values, std::index_sequence_for<Fields...>{});
        m_generation.store(before + 2);
        m_writer.clear(std::memory_order_release);
    }
};
} // namespace util
#endif // BITCOIN_UTIL_ATOMIC_SNAPSHOT_H
