#include "header.h"
#include "tagged_hash.h"

#include <algorithm>
#include <array>

namespace lotus::v2 {
namespace {

template <size_t N> void PutLE(std::array<uint8_t, N> &out, size_t pos,
                              uint64_t value, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) {
        out[pos + i] = static_cast<uint8_t>(value >> (8 * i));
    }
}

uint64_t ReadLE(const uint8_t *data, size_t bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; ++i) {
        value |= uint64_t{data[i]} << (8 * i);
    }
    return value;
}

uint32_t EncodeTarget(const Hash &target) {
    int top = 31;
    while (top >= 0 && target[top] == 0) {
        --top;
    }
    if (top < 0) return 0;
    uint32_t exponent = static_cast<uint32_t>(top + 1);
    uint32_t mantissa = 0;
    if (exponent <= 3) {
        for (int i = top; i >= 0; --i) mantissa = (mantissa << 8) | target[i];
        mantissa <<= 8 * (3 - exponent);
    } else {
        mantissa = (uint32_t{target[top]} << 16) |
                   (uint32_t{target[top - 1]} << 8) | target[top - 2];
    }
    if (mantissa & 0x00800000U) {
        mantissa >>= 8;
        ++exponent;
    }
    return (exponent << 24) | mantissa;
}

} // namespace

bool SerializeHeader(const Header &h, std::array<uint8_t, HEADER_SIZE> &out) {
    if (h.time > MAX_TIME) return false;
    std::copy(h.prev_id.begin(), h.prev_id.end(), out.begin());
    PutLE(out, 32, h.bits, 4);
    PutLE(out, 36, h.time, 6);
    PutLE(out, 42, h.nonce, 8);
    PutLE(out, 50, h.version, 4);
    PutLE(out, 54, h.size, 8);
    PutLE(out, 62, h.height, 8);
    std::copy(h.tx_root.begin(), h.tx_root.end(), out.begin() + 70);
    std::copy(h.state_root.begin(), h.state_root.end(), out.begin() + 102);
    return true;
}

bool ParseHeader(const uint8_t *data, size_t size, Header &out) {
    if (data == nullptr || size != HEADER_SIZE) return false;
    Header parsed;
    std::copy_n(data, 32, parsed.prev_id.begin());
    parsed.bits = static_cast<uint32_t>(ReadLE(data + 32, 4));
    parsed.time = ReadLE(data + 36, 6);
    parsed.nonce = ReadLE(data + 42, 8);
    parsed.version = static_cast<uint32_t>(ReadLE(data + 50, 4));
    parsed.size = ReadLE(data + 54, 8);
    parsed.height = ReadLE(data + 62, 8);
    std::copy_n(data + 70, 32, parsed.tx_root.begin());
    std::copy_n(data + 102, 32, parsed.state_root.begin());
    out = parsed;
    return true;
}

Hash BodyHash(const ChainId &chain_id, const Header &header) {
    std::array<uint8_t, 116> body{};
    std::copy(chain_id.begin(), chain_id.end(), body.begin());
    PutLE(body, 32, header.version, 4);
    PutLE(body, 36, header.size, 8);
    PutLE(body, 44, header.height, 8);
    std::copy(header.tx_root.begin(), header.tx_root.end(), body.begin() + 52);
    std::copy(header.state_root.begin(), header.state_root.end(), body.begin() + 84);
    return TaggedHash(HashDomain::HeaderBody, body);
}

bool WorkHash(const ChainId &chain_id, const Header &header, Hash &out) {
    if (header.time > MAX_TIME) return false;
    std::array<uint8_t, 50> work{};
    PutLE(work, 0, header.bits, 4);
    PutLE(work, 4, header.time, 6);
    PutLE(work, 10, header.nonce, 8);
    const Hash body_hash = BodyHash(chain_id, header);
    std::copy(body_hash.begin(), body_hash.end(), work.begin() + 18);
    out = TaggedHash(HashDomain::HeaderWork, work);
    return true;
}

bool BlockId(const ChainId &chain_id, const Header &header, Hash &out) {
    if (header.time > MAX_TIME) return false;
    std::array<uint8_t, 64> input{};
    std::copy(header.prev_id.begin(), header.prev_id.end(), input.begin());
    Hash work_hash;
    WorkHash(chain_id, header, work_hash);
    std::copy(work_hash.begin(), work_hash.end(), input.begin() + 32);
    out = TaggedHash(HashDomain::BlockId, input);
    return true;
}

bool MeetsTarget(const Hash &block_id, const Hash &target) {
    for (int i = 31; i >= 0; --i) {
        if (block_id[i] < target[i]) return true;
        if (block_id[i] > target[i]) return false;
    }
    return true;
}

bool DecodeTarget(uint32_t bits, const Hash &pow_limit, Hash &target) {
    const uint32_t exponent = bits >> 24;
    const uint32_t mantissa = bits & 0x007fffffU;
    if ((bits & 0x00800000U) || mantissa == 0) return false;
    Hash decoded{};
    for (unsigned i = 0; i < 3; ++i) {
        const int position = static_cast<int>(exponent) - 3 + static_cast<int>(i);
        const uint8_t byte = static_cast<uint8_t>(mantissa >> (8 * i));
        if (position >= 32 && byte != 0) return false;
        if (position >= 0 && position < 32) decoded[position] = byte;
    }
    if (std::all_of(decoded.begin(), decoded.end(), [](uint8_t b) { return b == 0; })) return false;
    if (EncodeTarget(decoded) != bits || !MeetsTarget(decoded, pow_limit)) return false;
    target = decoded;
    return true;
}

} // namespace lotus::v2
