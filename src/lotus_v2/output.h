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
// 812 bytes for the largest stateless output plus a 32-byte state root.
constexpr size_t MAX_OUTPUT_BYTES = 844;

constexpr uint8_t OUTPUT_FLAG_HAS_TOKEN = 0x01;
constexpr uint8_t OUTPUT_FLAG_IS_BURN = 0x02;
constexpr uint8_t OUTPUT_FLAG_HAS_STATE = 0x04;

struct Output {
    uint8_t flags = 0;
    uint64_t value = 0;
    Hash32 token_id{};
    // Present on the wire iff HAS_STATE; must then be nonzero. A burn output
    // cannot carry state.
    Hash32 state_root{};
    std::vector<Hash32> branches;
    std::vector<std::vector<uint8_t>> paths;
    // A legacy coin (created by a version 1 or 2 transaction): its legacy
    // scriptPubKey. Such an Output is a spent coin or a state coin, never a
    // V2 transaction output; EncodeOutput rejects it, EncodeCoinOutput
    // gives its coin wire.
    std::optional<std::vector<uint8_t>> legacy_script;

    bool HasToken() const { return (flags & 1) != 0; }
    bool IsBurn() const { return (flags & 2) != 0; }
    bool HasState() const { return (flags & 4) != 0; }
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

// Largest legacy coin script (the legacy MAX_SCRIPT_SIZE).
constexpr size_t MAX_LEGACY_COIN_SCRIPT_BYTES = 10000;

// The wire of a coin, the spent output an input commits to (coins root, own
// input hash, coin introspection, state records): EncodeOutput for a V2
// coin; for a legacy coin
//   LegacyCoinWire = 0x80 || value:u64le || CompactSize(|script|) || script.
// 0x80 is not a valid V2 output flags byte, so the two cannot collide.
bool EncodeCoinOutput(const Output &coin, std::vector<uint8_t> &result,
                      std::string &error);
bool ComputeCoinOutputSerializedSize(const Output &coin, size_t &size,
                                     std::string &error);
// The inverse of EncodeCoinOutput: a frame starting with 0x80 is a
// LegacyCoinWire (canonical CompactSize, no trailing byte), any other frame
// an output (DecodeOutput). DecodeCoinOutput(EncodeCoinOutput(c)) == c.
bool DecodeCoinOutput(const std::vector<uint8_t> &frame, Output &result,
                      std::string &error);
// Largest coin wire: a LegacyCoinWire of the largest legacy script.
constexpr size_t MAX_COIN_OUTPUT_BYTES = 1 + 8 + 3 + MAX_LEGACY_COIN_SCRIPT_BYTES;

} // namespace lotus::v2

#endif
