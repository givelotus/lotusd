// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <base58.h>
#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>

#include <boost/utility/string_ref.hpp>
#include <string>

namespace XAddress {
/**
 * Create a checksum.
 */
std::string CreateCheck(const boost::string_ref addressWithoutCheck) {
    uint256 hash = Hash(addressWithoutCheck);
    std::vector<uint8_t> vch(hash.begin(), hash.begin() + 4);
    std::string unpaddedCheck = EncodeBase58(vch);
    const size_t padding = 6 - unpaddedCheck.length();
    return std::string(padding, '1').append(unpaddedCheck);
}

/**
 * Encode a XAddress string.
 */
std::string Encode(const std::string &token, const uint8_t network,
                   const std::vector<uint8_t> &payload) {
    const std::string encodedPayload = EncodeBase58(payload);
    std::string address;
    address.append(token);
    address.append(1, network);
    address.append(encodedPayload);
    address.append(CreateCheck(address));
    return address;
}

/**
 * Check integrity of an XAddress
 */
bool IntegrityCheck(const boost::string_ref address) {
    if (address.length() < 6) {
        return false;
    }
    std::vector<uint8_t> decodedCheck;
    const std::string encodedCheck(address.substr(address.length() - 6, 6));
    if (!DecodeBase58(encodedCheck, decodedCheck, 6)) {
        return false;
    }
    if (decodedCheck.size() < 4) {
        return false;
    }
    const uint256 check = Hash(address.substr(0, address.length() - 6));
    // decodedCheck potentially has excess padding due to the way
    // base58 decode processes padding and bytes.
    if (memcmp(&check, &decodedCheck[decodedCheck.size() - 4], 4)) {
        return false;
    }
    return true;
}

/**
 * Decode a XAddress string.
 */
bool Decode(const boost::string_ref address, Content &parsedOutput) {
    if (!IntegrityCheck(address)) {
        return false;
    }
    const boost::string_ref addressWithoutCheck =
        address.substr(0, address.length() - 6);
    const auto networkPosition =
        std::find_if(addressWithoutCheck.begin(), addressWithoutCheck.end(),
                     [](const char c) -> bool {
                         return std::isupper(c) || std::isdigit(c) || c == '_';
                     });
    if (networkPosition == addressWithoutCheck.end()) {
        return false;
    }
    const boost::string_ref token = addressWithoutCheck.substr(
        0, std::distance(addressWithoutCheck.begin(), networkPosition));
    const uint8_t networkByte = uint8_t(*networkPosition);
    // Need to be able to get a c_str() from this, so we must do a copy.
    const std::string encodedPayload(networkPosition + 1,
                                     addressWithoutCheck.end());
    // vch length cannot be greater than encodedPayload
    std::vector<uint8_t> vch;
    if (!DecodeBase58(encodedPayload, vch, encodedPayload.length())) {
        return false;
    }
    parsedOutput =
        Content(std::string(token.begin(), token.end()), networkByte, vch);
    return true;
}

} // namespace XAddress
