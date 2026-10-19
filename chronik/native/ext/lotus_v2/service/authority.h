// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_AUTHORITY_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_AUTHORITY_H

#include <ext/lotus_v2/db/model.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>

/**
 * Native chain authority published to V2 readers (port of the Authority in
 * chronik-lib/src/v2_server.rs; the HTTP listener is not part of it).
 *
 * Independent counters: the observation sequence fences every busy or
 * publication boundary (odd while a writer is mid-update); the generation
 * versions durable observations and explorer continuations. A complete idle
 * suspend/resume keeps the generation only with an exact native context
 * stamp. Neither counter wraps, and terminal failure stays unknown. Writers
 * throw ChronikError on exhaustion; observe() never blocks.
 */
namespace chronik::native::lotus_v2 {

/** chronik_http::v2::AuthoritativeState */
struct AuthoritativeState {
    uint64_t observation = 0;
    uint64_t generation = 0;
    std::optional<Anchor> anchor;
    bool operator==(const AuthoritativeState &) const = default;
};

class Authority {
public:
    /** Durable invalidation (nullopt) or generic publication; always a new
     * generation. Generic publication cannot certify an unchanged stamp. */
    uint64_t Publish(const std::optional<Anchor> &anchor);
    /** Hide authority while native work runs; keeps the generation. */
    uint64_t Suspend();
    /** Publish a reconciled stamp; an unchanged stamp keeps the generation. */
    uint64_t PublishContext(const Anchor &anchor, uint64_t context_generation,
                            uint64_t chain_revision);
    /** One coherent stamped state, without taking any lock. */
    AuthoritativeState Observe() const;

    /** Test hooks (Rust tests poke the atomics directly). */
    void TestSetSequence(uint64_t v) { m_sequence.store(v); }
    void TestSetGeneration(uint64_t v) { m_generation.store(v); }
    std::unique_lock<std::mutex> TestLockWriter() {
        return std::unique_lock<std::mutex>(m_writer);
    }

private:
    struct NativeContext {
        Anchor anchor;
        uint64_t context_generation = 0;
        uint64_t chain_revision = 0;
        bool operator==(const NativeContext &) const = default;
    };
    enum class UpdateKind { Suspend, Invalidate, Publish, Context };

    uint64_t Update(UpdateKind kind, const Anchor &anchor,
                    const NativeContext &context);
    void Terminal();

    std::mutex m_writer;
    std::optional<NativeContext> m_context; // guarded by m_writer
    std::atomic<uint64_t> m_sequence{0};
    std::atomic<uint64_t> m_generation{0};
    std::atomic<uint64_t> m_height{0};
    std::array<std::atomic<uint64_t>, 4> m_words{};
    std::atomic<uint64_t> m_known{0};
};

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_AUTHORITY_H
