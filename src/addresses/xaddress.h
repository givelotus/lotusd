// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_XADDR_H
#define BITCOIN_XADDR_H

#include <chainparams.h>
#include <script/standard.h>

#include <string>
#include <vector>

namespace XAddress {

const std::string TOKEN_NAME = "lotus";

enum NetworkType : uint8_t {
    MAINNET = '_',
    TESTNET = 'T',
    REGTEST = 'R',
    UNKNOWN = 'U'
};

enum AddressType : uint8_t {
    SCRIPT_PUB_KEY = 0,
};

enum DecodeError : uint8_t {
    DECODE_OK = 0,
    NO_NETWORK_POSITION = 1,
    BASE58_DECODE_FAILED = 2,
    UNDERSIZED_PAYLOAD = 3,
    INTEGRITY_CHECK_FAILED = 4,
};

class Content {
public:
    std::string m_token;
    NetworkType m_network;
    AddressType m_type;
    std::vector<uint8_t> m_payload;

    Content() = default;

    Content(std::string token, NetworkType network, AddressType type,
            std::vector<uint8_t> payload)
        : m_token(token), m_network(network), m_type(type), m_payload(payload) {
    }
};

/**
 * Encode an XAddress string.
 */
std::string Encode(const Content &addressContent);
/**
 * Decode an XAddress string. Returns false on failure, and parsedOutput is not
 * modified.
 */
DecodeError Decode(const std::string &address, Content &parsedOutput);
/**
 * Parse an XAddress string into a CTxDestination. Returns false on failure.
 */
bool Parse(const CChainParams &params, const std::string &address,
           CTxDestination &retDestination);
} // namespace XAddress

#endif // BITCOIN_XADDR_H
