// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_XADDR_H
#define BITCOIN_XADDR_H

#include <string>
#include <vector>

namespace XAddress {

const std::string TOKEN_NAME = "lotus";

enum NetworkType : uint8_t {
    MAINNET = '_',
    TESTNET = 'T',
    REGTEST = 'R',
};

enum AddressType : uint8_t {
    SCRIPT_PUB_KEY = 0,
};

class Content {
public:
    std::string token;
    NetworkType network;
    AddressType type;
    std::vector<uint8_t> payload;

    Content() = default;

    Content(std::string _token, NetworkType _network, AddressType _type,
            std::vector<uint8_t> _payload)
        : token(_token), network(_network), type(_type), payload(_payload) {}
};

/**
 * Encode an XAddress string.
 */
std::string Encode(const Content &addressContent);
/**
 * Decode an XAddress string. Returns false on failure, and parsedOutput is not
 * modified.
 */
bool Decode(const std::string &address, Content &parsedOutput);
} // namespace XAddress

#endif // BITCOIN_XADDR_H
