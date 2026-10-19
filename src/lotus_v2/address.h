// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LOTUS_V2_ADDRESS_H
#define LOTUS_V2_ADDRESS_H

#include "output.h"

#include <optional>
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

struct DecodedAddress {
    AddressNetwork network;
    Hash32 root;
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
