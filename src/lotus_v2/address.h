// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LOTUS_V2_ADDRESS_H
#define LOTUS_V2_ADDRESS_H

#include "output.h"

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace lotus::v2 {

// Lotus V2 addresses ("xpi1..."), specified in doc/standards/xpiaddr.md.
// A version 0 address carries one 32-byte branch root; its output is
// flags=0, branches=[root], paths=[[0]].

enum class AddressNetwork { MAINNET, TESTNET, REGTEST };

std::string_view AddressPrefix(AddressNetwork network);

// Always lowercase.
std::string EncodeAddress(AddressNetwork network, const Hash32 &root);

// Type 1 commits BLAKE3(x-only secp256k1 public key). It is a native
// BIP340 spending template, not a legacy P2PKH script or address alias.
std::string EncodeKeyHashAddress(AddressNetwork network, const Hash32 &key_hash);
Hash32 NativeKeyHash(std::span<const uint8_t, 32> xonly_key);
std::vector<uint8_t> KeyHashProgram(const Hash32 &key_hash);
Hash32 KeyHashRoot(const Hash32 &key_hash);

struct DecodedAddress {
    AddressNetwork network;
    // For type 0 this is the root; for type 1 this is the key hash.
    Hash32 root;
    uint8_t type = 0;

    Hash32 BranchRoot() const;
};

// Accepts all-lowercase or all-uppercase input, nothing else (callers strip
// whitespace and URI framing). Never corrects errors. On failure returns
// nullopt and sets error to one of: "mixed case", "unknown prefix",
// "bad length", "bad character", "bad checksum", "unknown version",
// "nonzero padding".
std::optional<DecodedAddress> DecodeAddress(std::string_view address,
                                            std::string &error);

} // namespace lotus::v2

#endif // LOTUS_V2_ADDRESS_H
