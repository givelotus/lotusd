#include "tagged_hash.h"

#include "vendor/blake3/blake3.h"

#include <cstdlib>
#include <cstring>

namespace lotus::v2 {
namespace {
constexpr std::string_view TagView(HashDomain domain) noexcept {
    switch (domain) {
    case HashDomain::HeaderBody: return "Lotus/v2/header/body";
    case HashDomain::HeaderWork: return "Lotus/v2/header/work";
    case HashDomain::BlockId: return "Lotus/v2/blockid";
    case HashDomain::Branch: return "Lotus/v2/branch";
    case HashDomain::InputCore: return "Lotus/v2/inputcore";
    case HashDomain::InputFull: return "Lotus/v2/inputfull";
    case HashDomain::OwnInput: return "Lotus/v2/owninput";
    case HashDomain::Sighash: return "Lotus/v2/sighash";
    case HashDomain::Output: return "Lotus/v2/output";
    case HashDomain::CoinEntry: return "Lotus/v2/coinentry";
    case HashDomain::MerkleIndex: return "Lotus/v2/merkleidx";
    case HashDomain::TxId: return "Lotus/v2/txid";
    case HashDomain::TxHash: return "Lotus/v2/txhash";
    case HashDomain::TxRoot: return "Lotus/v2/txroot";
    case HashDomain::OutpointKey: return "Lotus/v2/outpointkey";
    case HashDomain::Utxo: return "Lotus/v2/utxo";
    case HashDomain::PreconsensusBatch: return "lotus.v2.preconsensus.batch";
    case HashDomain::State: return "Lotus/v2/state";
    case HashDomain::ContractState: return "Lotus/v2/contractstate";
    case HashDomain::SimPlaceholder: return "Lotus/v2/sim/placeholder";
    case HashDomain::VmProfile: return "Lotus/v2/vmprofile";
    case HashDomain::TxIdFallback: return "Lotus/v2/txid/nonstructural";
    }
    std::abort();
}
} // namespace

Hash TaggedHash(HashDomain domain, std::span<const uint8_t> payload) {
    const std::string_view tag = TagView(domain);
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (payload.size() <= 960) {
        uint8_t combined[1024];
        std::memcpy(combined, tag.data(), tag.size());
        combined[tag.size()] = 0;
        if (!payload.empty()) {
            std::memcpy(combined + tag.size() + 1, payload.data(), payload.size());
        }
        blake3_hasher_update(&hasher, combined, tag.size() + 1 + payload.size());
    } else {
        blake3_hasher_update(&hasher, tag.data(), tag.size());
        constexpr uint8_t separator = 0;
        blake3_hasher_update(&hasher, &separator, 1);
        blake3_hasher_update(&hasher, payload.data(), payload.size());
    }
    Hash result;
    blake3_hasher_finalize(&hasher, result.data(), result.size());
    return result;
}

Hash ContractStateHash(std::span<const std::vector<uint8_t>> items) {
    const std::string_view tag = TagView(HashDomain::ContractState);
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, tag.data(), tag.size());
    constexpr uint8_t separator = 0;
    blake3_hasher_update(&hasher, &separator, 1);
    auto compact = [&](uint64_t value) {
        uint8_t buffer[9];
        size_t size = 0;
        if (value < 253) {
            buffer[size++] = uint8_t(value);
        } else {
            const size_t width = value <= 0xffff ? 2 : value <= 0xffffffff ? 4 : 8;
            buffer[size++] = width == 2 ? 253 : width == 4 ? 254 : 255;
            for (size_t i = 0; i < width; ++i)
                buffer[size++] = uint8_t(value >> (8 * i));
        }
        blake3_hasher_update(&hasher, buffer, size);
    };
    compact(items.size());
    for (const auto &item : items) {
        compact(item.size());
        if (!item.empty()) blake3_hasher_update(&hasher, item.data(), item.size());
    }
    Hash result;
    blake3_hasher_finalize(&hasher, result.data(), result.size());
    return result;
}

} // namespace lotus::v2
