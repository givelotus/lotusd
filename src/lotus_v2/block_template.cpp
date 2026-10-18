#include "block_template.h"

#include <array>
#include <limits>

namespace lotus::v2 {
namespace {

Hash TargetCeiling() {
    Hash ceiling{};
    ceiling.fill(0xff);
    return ceiling;
}

} // namespace

std::optional<Header> BuildChildHeader(const Header &parent, const ChainId &chain_id,
                                       const Hash &tx_root, const Hash &state_root,
                                       uint64_t time, uint64_t size, uint32_t bits) {
    if (time > MAX_TIME) return std::nullopt;
    if (parent.height == std::numeric_limits<uint64_t>::max()) return std::nullopt;
    Hash target;
    if (!DecodeTarget(bits, TargetCeiling(), target)) return std::nullopt;
    Hash prev_id;
    if (!BlockId(chain_id, parent, prev_id)) return std::nullopt;

    Header child;
    child.prev_id = prev_id;
    child.bits = bits;
    child.time = time;
    child.nonce = 0;
    child.version = parent.version;
    child.size = size;
    child.height = parent.height + 1;
    child.tx_root = tx_root;
    child.state_root = state_root;

    std::array<uint8_t, HEADER_SIZE> bytes{};
    if (!SerializeHeader(child, bytes) || bytes.size() != HEADER_SIZE) return std::nullopt;
    return child;
}

bool SearchNonce(Header &header, const ChainId &chain_id, const Hash &target,
                 uint64_t start_nonce, uint64_t max_attempts) {
    if (max_attempts > MAX_NONCE_ATTEMPTS) return false;

    for (uint64_t attempt = 0; attempt < max_attempts; ++attempt) {
        if (attempt > std::numeric_limits<uint64_t>::max() - start_nonce) return false;
        Header candidate = header;
        candidate.nonce = start_nonce + attempt;
        Hash block_id{};
        if (!BlockId(chain_id, candidate, block_id)) return false;
        if (MeetsTarget(block_id, target)) {
            header = candidate;
            return true;
        }
    }
    return false;
}

} // namespace lotus::v2
