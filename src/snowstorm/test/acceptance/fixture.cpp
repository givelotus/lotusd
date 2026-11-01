// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#define BOOST_TEST_MODULE SnowstormAcceptance
#include <boost/test/included/unit_test.hpp>
#include "fixture.h"
#include <stdexcept>

namespace snowstorm_test {
Rng::Rng(std::uint64_t seed) : engine_(seed) {}
std::uint64_t Rng::next() { return engine_(); }
std::uint64_t Rng::nonzero() {
    auto value = next();
    while (value == 0) value = next();
    return value;
}
std::uint64_t Rng::bounded(std::uint64_t exclusive) {
    if (exclusive == 0) throw std::invalid_argument("empty random domain");
    return std::uniform_int_distribution<std::uint64_t>(0, exclusive - 1)(engine_);
}
snowstorm::Cell to_core(const snowstorm_oracle::Cell &cell) {
    return {cell.count, cell.s1, cell.s3, cell.s5};
}
snowstorm_oracle::Cell to_oracle(const snowstorm::Cell &cell) {
    return {cell.count, cell.s1, cell.s3, cell.s5};
}
void require_cell_equal(const snowstorm::Cell &actual,
                        const snowstorm_oracle::Cell &expected) {
    BOOST_REQUIRE_EQUAL(actual.count, expected.count);
    BOOST_REQUIRE_EQUAL(actual.s1, expected.s1);
    BOOST_REQUIRE_EQUAL(actual.s3, expected.s3);
    BOOST_REQUIRE_EQUAL(actual.s5, expected.s5);
}
namespace {
bool contains(const void *context, snowstorm::ShortId id) noexcept {
    return static_cast<const IdSet *>(context)->contains(id);
}
}
snowstorm::ReferenceView reference(const IdSet &ids) {
    return {&ids, contains};
}
std::vector<snowstorm_oracle::SignedItem> to_oracle(
    const snowstorm::DecodeResult &decoded) {
    std::vector<snowstorm_oracle::SignedItem> items;
    for (std::size_t i = 0; i < decoded.size; ++i) {
        items.push_back({decoded.items[i].item,
                        static_cast<int>(decoded.items[i].sign)});
    }
    return items;
}
SyntheticBody::SyntheticBody(snowstorm::TxId txid, snowstorm::TxHash hash,
                             snowstorm::ShortId cached_id)
    : txid_(txid), hash_(hash), cached_id_(cached_id) {}
snowstorm::TxId SyntheticBody::txid() const noexcept { return txid_; }
snowstorm::TxHash SyntheticBody::tx_hash() const noexcept { return hash_; }
snowstorm::ShortId SyntheticBody::short_id() const noexcept { return cached_id_; }
snowstorm::TxHash make_hash(std::uint64_t seed) {
    Rng rng(seed);
    snowstorm::TxHash result{};
    for (std::size_t word = 0; word < 4; ++word) {
        const auto value = rng.next();
        for (std::size_t byte = 0; byte < 8; ++byte) {
            result[8 * word + byte] = static_cast<std::uint8_t>(value >> (8 * byte));
        }
    }
    return result;
}
snowstorm::TxHandle make_body(std::uint64_t seed,
                              snowstorm::ShortId cached_id) {
    return std::make_shared<SyntheticBody>(make_hash(seed ^ 0xa60cdb3a521ae491ULL),
                                           make_hash(seed), cached_id);
}
std::vector<std::uint64_t> sorted_ids(const IdSet &ids) {
    return {ids.begin(), ids.end()};
}
} // namespace snowstorm_test

namespace snowstorm_test {
std::array<snowstorm::TxHandle, 2> collision_bodies() {
    const snowstorm::TxHash a{0xa9, 0xd6, 0xe4, 0x25, 0xdf, 0x72, 0xfd, 0xca};
    const snowstorm::TxHash b{0x11, 0x57, 0x00, 0xdb, 0xc1, 0xc8, 0x97, 0xc7};
    return {std::make_shared<SyntheticBody>(make_hash(1001), a, collision_id),
            std::make_shared<SyntheticBody>(make_hash(1002), b, collision_id)};
}
} // namespace snowstorm_test
