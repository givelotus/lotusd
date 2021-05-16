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

#include <string>

namespace XAddress {
/**
 * Create SHA256 Hash of the address contents for integrity checks.
 */
uint256 HashAddressContents(const Content &addressContent) {
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << addressContent.m_token;
    hasher << uint8_t(addressContent.m_network);
    hasher << uint8_t(addressContent.m_type);
    hasher << addressContent.m_payload;
    return hasher.GetSHA256();
}

/**
 * Encode a XAddress string.
 */
std::string Encode(const Content &addressContent) {
    std::vector<uint8_t> preencodedBuffer;
    uint256 check = HashAddressContents(addressContent);
    preencodedBuffer.reserve(addressContent.m_payload.size() + 5);
    preencodedBuffer.push_back(addressContent.m_type);
    preencodedBuffer.insert(preencodedBuffer.end(),
                            addressContent.m_payload.begin(),
                            addressContent.m_payload.end());
    preencodedBuffer.insert(preencodedBuffer.end(), check.begin(),
                            check.begin() + 4);
    std::string address;
    address.append(addressContent.m_token);
    address.append(1, addressContent.m_network);
    address.append(EncodeBase58(preencodedBuffer));
    return address;
}

/**
 * Decode a XAddress string.
 */
DecodeError Decode(const std::string &address, Content &parsedOutput) {
    const auto networkPosition =
        std::find_if(address.begin(), address.end(), [](const char c) -> bool {
            return std::isupper(c) || std::isdigit(c) || c == '_';
        });
    if (networkPosition == address.end()) {
        return NO_NETWORK_POSITION;
    }
    const std::string token =
        address.substr(0, std::distance(address.begin(), networkPosition));
    const NetworkType networkByte = NetworkType(*networkPosition);

    // Need to be able to get a c_str() from this, so we must do a copy.
    const std::string encodedPayload(networkPosition + 1, address.end());
    // vch length cannot be greater than encodedPayload
    std::vector<uint8_t> vch;
    if (!DecodeBase58(encodedPayload, vch, encodedPayload.length())) {
        return BASE58_DECODE_FAILED;
    }
    // Undersized payload. Can't include type byte and checksum
    if (vch.size() < 5) {
        return UNDERSIZED_PAYLOAD;
    }
    const AddressType addressByte = AddressType(vch[0]);
    parsedOutput = Content(token, networkByte, addressByte,
                           std::vector(vch.begin() + 1, vch.end() - 4));
    const uint256 check = HashAddressContents(parsedOutput);
    if (memcmp(&check, &vch[vch.size() - 4], 4)) {
        return INTEGRITY_CHECK_FAILED;
    }
    return DECODE_OK;
}

} // namespace XAddress
