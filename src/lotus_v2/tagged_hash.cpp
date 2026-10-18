#include "tagged_hash.h"

#include <crypto/sha256.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <string_view>

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
    }
    std::abort();
}

constexpr size_t kNumDomains = static_cast<size_t>(HashDomain::PreconsensusBatch) + 1;

CSHA256 MakeTagMidstate(HashDomain domain) {
    const std::string_view tag = TagView(domain);
    uint8_t tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(reinterpret_cast<const uint8_t *>(tag.data()), tag.size())
        .Finalize(tag_hash);
    CSHA256 hasher;
    hasher.Write(tag_hash, CSHA256::OUTPUT_SIZE);
    hasher.Write(tag_hash, CSHA256::OUTPUT_SIZE);
    return hasher;
}

const std::array<CSHA256, kNumDomains> &GetTagMidstates() {
    static const std::array<CSHA256, kNumDomains> kMidstates = []() {
        std::array<CSHA256, kNumDomains> arr{};
        for (size_t i = 0; i < kNumDomains; ++i) {
            arr[i] = MakeTagMidstate(static_cast<HashDomain>(i));
        }
        return arr;
    }();
    return kMidstates;
}
} // namespace

Hash TaggedHash(HashDomain domain, std::span<const uint8_t> payload) {
    const size_t idx = static_cast<size_t>(domain);
    if (idx >= kNumDomains) {
        std::abort();
    }
    CSHA256 hasher = GetTagMidstates()[idx];
    if (!payload.empty()) {
        hasher.Write(payload.data(), payload.size());
    }
    Hash result;
    hasher.Finalize(result.data());
    return result;
}

} // namespace lotus::v2
