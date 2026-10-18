// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef LOTUS_V2_BATCH_RANDOMIZERS_H
#define LOTUS_V2_BATCH_RANDOMIZERS_H

#include <crypto/hmac_sha256.h>
#include <random.h>
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace lotus::v2 {
// Obtain fresh unpredictable entropy after the batch is fixed, then expand
// coefficients with keyed HMAC-SHA256. Neither clocks, addresses nor counters
// supply entropy. The secp batch API fixes the first coefficient to one.
inline std::vector<unsigned char> GenerateBatchRandomizers(
    size_t count, std::string_view domain) {
    std::array<uint8_t, 32> seed{};
    GetStrongRandBytes(seed);
    std::vector<unsigned char> weights(32 * count, 0);
    for (size_t i = 1; i < count; ++i) {
        std::array<uint8_t, 8> index{};
        for (size_t j = 0; j < index.size(); ++j) {
            index[j] = uint64_t(i) >> (8 * j);
        }
        CHMAC_SHA256(seed.data(), seed.size())
            .Write(reinterpret_cast<const uint8_t *>(domain.data()), domain.size())
            .Write(index.data(), index.size())
            .Finalize(weights.data() + 32 * i);
    }
    return weights;
}
} // namespace lotus::v2
#endif
