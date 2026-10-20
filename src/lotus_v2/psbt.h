// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef LOTUS_V2_PSBT_H
#define LOTUS_V2_PSBT_H

#include "psbt_map.h"
#include "signing.h"
#include "sparse_state.h"

#include <compare>
#include <map>
#include <optional>
#include <span>

namespace lotus::v2 {

constexpr uint32_t NATIVE_PSBT_VERSION = 0x4c560001;
constexpr size_t MAX_NATIVE_PSBT_BYTES = 16777216;
constexpr size_t MAX_NATIVE_PSBT_KEY_BYTES = 1024;
constexpr size_t MAX_NATIVE_PSBT_VALUE_BYTES = 8388608;
constexpr size_t MAX_NATIVE_PSBT_MAP_ENTRIES = 4096;

using PsbtBytes = psbt_detail::Bytes;
using PsbtMap = psbt_detail::Map;
using PsbtArguments = std::vector<PsbtBytes>;

struct PsbtSlot {
    uint16_t witness{};
    uint16_t argument{};
    auto operator<=>(const PsbtSlot &) const = default;
};

struct PsbtSignRequest {
    uint8_t scheme{};
    uint8_t mode{};
    PsbtBytes public_key;
};

struct NativePsbtInput {
    std::optional<Coin> coin;
    std::optional<CoinProof> proof;
    std::map<uint16_t, PsbtArguments> arguments;
    std::map<PsbtSlot, PsbtSignRequest> requests;
    std::map<PsbtSlot, PsbtBytes> signatures;
    std::map<uint16_t, PsbtArguments> final_arguments;
};

struct NativePsbtData {
    ChainId chain_id{};
    Transaction tx_template;
    std::optional<Hash> utxo_root;
    std::vector<NativePsbtInput> inputs;
};

// Maps remain lossless, including opaque proprietary fields. Every operation
// validates them anew; callers cannot bypass schema checks through mutation.
struct NativePsbt {
    PsbtMap global;
    std::vector<PsbtMap> inputs;
    std::vector<PsbtMap> outputs;

    bool Inspect(NativePsbtData &result, std::string &error) const;
    bool Serialize(PsbtBytes &result, std::string &error) const;
    bool Merge(const NativePsbt &other, std::string &error);
};

bool DecodeNativePsbt(std::span<const uint8_t> wire, NativePsbt &result,
                      std::string &error);
bool CreateNativePsbt(const Transaction &tx_template, const ChainId &chain_id,
                      NativePsbt &result, std::string &error);

// Keys/arguments use only the exact profile registry. These helpers do not
// claim that supplied coins, roots, origins or policies are authenticated.
PsbtBytes NativePsbtKey(uint64_t subtype,
                        std::span<const uint8_t> keydata = {});
PsbtBytes EncodePsbtArguments(const PsbtArguments &arguments);
PsbtBytes EncodePsbtWitness(uint16_t witness);
PsbtBytes EncodePsbtSlot(PsbtSlot slot);

} // namespace lotus::v2
#endif
