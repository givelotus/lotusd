// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/service/authority.h>

namespace chronik::native::lotus_v2 {

void Authority::Terminal() {
    m_known.store(0);
    m_generation.store(UINT64_MAX);
    m_sequence.store(UINT64_MAX);
}

uint64_t Authority::Update(UpdateKind kind, const Anchor &anchor,
                           const NativeContext &context) {
    std::lock_guard<std::mutex> lock(m_writer);
    const uint64_t previous = m_sequence.load();
    if (previous > UINT64_MAX - 2 || previous + 2 == UINT64_MAX) {
        Terminal();
        throw ChronikError("authority observation exhausted");
    }
    const uint64_t next = previous + 2;
    uint64_t generation = m_generation.load();
    bool known = false;
    bool advance = false;
    switch (kind) {
        case UpdateKind::Suspend:
            break;
        case UpdateKind::Invalidate:
            advance = true;
            break;
        case UpdateKind::Publish:
            known = true;
            advance = true;
            break;
        case UpdateKind::Context:
            known = true;
            advance = m_context != context;
            break;
    }
    if (advance) {
        if (generation >= UINT64_MAX - 1) {
            Terminal();
            throw ChronikError("authority generation exhausted");
        }
        ++generation;
    }
    m_sequence.store(previous + 1);
    if (kind == UpdateKind::Context) {
        m_context = context;
    } else if (kind == UpdateKind::Publish) {
        m_context.reset();
    }
    m_known.store(known ? 1 : 0);
    if (known) {
        m_height.store(anchor.height);
        for (size_t w = 0; w < 4; ++w) {
            uint64_t word = 0;
            for (size_t i = 0; i < 8; ++i) {
                word |= uint64_t(anchor.block_id[w * 8 + i]) << (8 * i);
            }
            m_words[w].store(word);
        }
    }
    m_generation.store(generation);
    m_sequence.store(next);
    return generation;
}

uint64_t Authority::Publish(const std::optional<Anchor> &anchor) {
    return anchor ? Update(UpdateKind::Publish, *anchor, {})
                  : Update(UpdateKind::Invalidate, {}, {});
}

uint64_t Authority::Suspend() { return Update(UpdateKind::Suspend, {}, {}); }

uint64_t Authority::PublishContext(const Anchor &anchor,
                                   uint64_t context_generation,
                                   uint64_t chain_revision) {
    return Update(UpdateKind::Context, anchor,
                  NativeContext{anchor, context_generation, chain_revision});
}

AuthoritativeState Authority::Observe() const {
    const uint64_t first = m_sequence.load();
    if (first % 2 != 0) {
        return {first, m_generation.load(), std::nullopt};
    }
    const uint64_t generation = m_generation.load();
    const bool known = m_known.load() != 0;
    const uint64_t height = m_height.load();
    Anchor anchor;
    for (size_t w = 0; w < 4; ++w) {
        const uint64_t word = m_words[w].load();
        for (size_t i = 0; i < 8; ++i) {
            anchor.block_id[w * 8 + i] = uint8_t(word >> (8 * i));
        }
    }
    anchor.height = height;
    const uint64_t last = m_sequence.load();
    AuthoritativeState state{last, generation, std::nullopt};
    if (first == last && known) {
        state.anchor = anchor;
    }
    return state;
}

} // namespace chronik::native::lotus_v2
