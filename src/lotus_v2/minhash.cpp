// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "minhash.h"

#include <crypto/siphash.h>

#include <algorithm>
#include <cmath>

namespace lotus::v2::minhash {

uint64_t Value(const Hash &tx_id, const Hash &tx_hash) noexcept {
    return CSipHasher(KEY0, KEY1)
        .Write(Span<const uint8_t>{tx_id.data(), tx_id.size()})
        .Write(Span<const uint8_t>{tx_hash.data(), tx_hash.size()})
        .Finalize();
}

std::vector<uint64_t> Reference(std::vector<uint64_t> all) {
    std::sort(all.begin(), all.end());
    if (all.size() > K) all.resize(K);
    return all;
}

double EstimateJaccard(std::span<const uint64_t> a, std::span<const uint64_t> b) {
    if (a.empty() && b.empty()) return 1.0;
    if (a.empty() || b.empty()) return 0.0;
    // Merge the two ascending sketches; the K smallest union values are the
    // union sketch. A value counts as shared when both sketches contain it.
    size_t i{0}, j{0}, taken{0}, shared{0};
    while (taken < K && (i < a.size() || j < b.size())) {
        if (j == b.size() || (i < a.size() && a[i] < b[j])) {
            ++i;
        } else if (i == a.size() || b[j] < a[i]) {
            ++j;
        } else {
            ++shared;
            ++i;
            ++j;
        }
        ++taken;
    }
    return taken ? double(shared) / double(taken) : 1.0;
}

double EstimateOnlyInB(double jaccard, uint64_t size_a, uint64_t size_b) {
    // |A n B| = J (|A| + |B|) / (1 + J).
    const double inter = jaccard * (double(size_a) + double(size_b)) / (1.0 + jaccard);
    return std::max(0.0, double(size_b) - inter);
}

void Maintainer::Insert(uint64_t value) {
    if (m_capped && value > m_threshold) return;
    m_buffer.insert(std::upper_bound(m_buffer.begin(), m_buffer.end(), value), value);
    if (m_buffer.size() > CANDIDATES) Shrink();
}

void Maintainer::Shrink() {
    // Drop every copy of the maximum so that "all members <= threshold" holds
    // exactly. Refuse when that would leave fewer than K (pathological ties).
    const uint64_t top = m_buffer.back();
    const auto first_top = std::lower_bound(m_buffer.begin(), m_buffer.end(), top);
    if (size_t(first_top - m_buffer.begin()) < K) return;
    m_buffer.erase(first_top, m_buffer.end());
    m_threshold = m_buffer.back();
    m_capped = true;
}

void Maintainer::Erase(uint64_t value) {
    if (m_capped && value > m_threshold) return;
    const auto it = std::lower_bound(m_buffer.begin(), m_buffer.end(), value);
    if (it == m_buffer.end() || *it != value) {
        // Caller contract violation (erasing a non-member); recover exactly.
        m_needs_rebuild = true;
        return;
    }
    m_buffer.erase(it);
    if (m_capped && m_buffer.size() < K) m_needs_rebuild = true;
}

void Maintainer::Clear() {
    m_buffer.clear();
    m_threshold = 0;
    m_capped = false;
    m_needs_rebuild = false;
}

void Maintainer::Rebuild(std::vector<uint64_t> all) {
    m_needs_rebuild = false;
    if (all.size() <= CANDIDATES) {
        std::sort(all.begin(), all.end());
        m_buffer = std::move(all);
        m_capped = false;
        m_threshold = 0;
        return;
    }
    std::nth_element(all.begin(), all.begin() + (CANDIDATES - 1), all.end());
    m_threshold = all[CANDIDATES - 1];
    const auto end = std::partition(all.begin(), all.end(),
                                    [t = m_threshold](uint64_t v) { return v <= t; });
    all.erase(end, all.end());
    std::sort(all.begin(), all.end());
    m_buffer = std::move(all);
    m_buffer.shrink_to_fit();
    m_capped = true;
}

std::vector<uint64_t> Maintainer::Export() const {
    const size_t n = std::min(K, m_buffer.size());
    return {m_buffer.begin(), m_buffer.begin() + n};
}

} // namespace lotus::v2::minhash
