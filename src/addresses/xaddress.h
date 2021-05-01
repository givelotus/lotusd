// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_XADDR_H
#define BITCOIN_XADDR_H

#include <boost/utility/string_ref.hpp>
#include <string>
#include <vector>

namespace XAddress {

class Content {
public:
    std::string token;
    uint8_t network;
    std::vector<uint8_t> payload;

    Content() = default;

    Content(std::string _token, uint8_t _network, std::vector<uint8_t> _payload)
        : token(_token), network(_network), payload(_payload) {}
};

/**
 * Encode an XAddress string.
 */
std::string Encode(const std::string &token, const uint8_t network,
                   const std::vector<uint8_t> &payload);
/**
 * Decode an XAddress string. Returns false on failure, and parsedOutput is not
 * modified.
 */
bool Decode(boost::string_ref address, Content &parsedOutput);
} // namespace XAddress

#endif // BITCOIN_XADDR_H
