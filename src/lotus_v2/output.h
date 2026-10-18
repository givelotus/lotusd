// Candidate Lotus V2 output wire codec. No transaction validation is implied.
#ifndef LOTUS_V2_OUTPUT_H
#define LOTUS_V2_OUTPUT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace lotus::v2 {

using Hash32 = std::array<uint8_t, 32>;

// P01 hard bounds. Any stricter deployment profile must be checked by its
// caller.
constexpr size_t MAX_OUTPUT_BRANCHES = 16;
constexpr size_t MAX_OUTPUT_PATHS = 16;
constexpr size_t MAX_OUTPUT_BYTES = 812;

struct Output {
    uint8_t flags = 0;
    uint64_t value = 0;
    Hash32 token_id{};
    std::vector<Hash32> branches;
    std::vector<std::vector<uint8_t>> paths;
    // State transfer only; EncodeOutput rejects this legacy representation.
    std::optional<std::vector<uint8_t>> legacy_script;

    bool HasToken() const { return (flags & 1) != 0; }
    bool IsBurn() const { return (flags & 2) != 0; }
    bool operator==(const Output &) const = default;
};

// Decode consumes exactly one output frame; any trailing byte is invalid.
// On failure, result is unchanged and error gives a stable category string.
bool DecodeOutput(const std::vector<uint8_t> &frame, Output &result,
                  std::string &error);
bool EncodeOutput(const Output &output, std::vector<uint8_t> &result,
                  std::string &error);
bool ComputeOutputSerializedSize(const Output &output, size_t &size,
                                 std::string &error);

} // namespace lotus::v2

#endif
