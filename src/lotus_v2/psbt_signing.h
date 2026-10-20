// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef LOTUS_V2_PSBT_SIGNING_H
#define LOTUS_V2_PSBT_SIGNING_H

#include "ordinary_validation.h"
#include "psbt.h"

#include <functional>

namespace lotus::v2 {

// All context here is provisioned independently of the transported document.
// A proof root is an authenticated snapshot, not a claim of future
// availability.
struct NativePsbtContext {
    ChainId chain_id{};
    OrdinaryCandidateProfile profile{};
    CoinLookup lookup;
    std::optional<Hash> trusted_utxo_root;
    bool allow_partial_modes = false;
};

struct NativePsbtReview {
    VmAssetTotalsMap assets;
    __uint128_t native_fee{};
    uint64_t signed_wire_bytes{};
};

// The provider must only return keys whose use the wallet policy authorizes.
// The signer verifies key ownership and supported program placement itself.
using NativePsbtKeyLookup =
    std::function<bool(std::span<const uint8_t>, std::array<uint8_t, 32> &)>;

bool UpdateNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                      std::string &error);
bool ReviewNativePsbt(const NativePsbt &psbt, const NativePsbtContext &context,
                      NativePsbtReview &review, std::string &error);
bool SignNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                    const NativePsbtKeyLookup &keys,
                    const std::array<uint8_t, 32> &aux_randomness,
                    size_t &signed_slots, std::string &error);
bool FinalizeNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                        Transaction &extracted, std::string &error);

} // namespace lotus::v2
#endif
