// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <base58.h>
#include <chainparams.h>
#include <hash.h>
#include <script/script.h>
#include <script/standard.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>

#include <assert.h>
#include <string>

namespace XAddress {
/**
 * Create SHA256 Hash of the address contents for integrity checks.
 */
uint256 HashAddressContents(const Content &addressContent) {
    CSHA256 hasher;
    uint256 out;
    const char *prefix = addressContent.m_token.c_str();
    const auto payloadSpan = MakeSpan(addressContent.m_payload);
    hasher.Write((uint8_t *)prefix, strlen(prefix));
    hasher.Write((uint8_t *)&addressContent.m_network, 1);
    hasher.Write((uint8_t *)&addressContent.m_type, 1);
    hasher.Write(payloadSpan.begin(), payloadSpan.end() - payloadSpan.begin());
    hasher.Finalize(out.begin());
    return out;
}

/**
 * Create SHA256 Hash of the address contents for integrity checks. This
 * is a legacy function that will be deprecated. It is only for validating
 * check bytes generated incorrectly in versions of lotusd 1.0.1 and prior.
 */
static uint256 LegacyHashAddressContents(const Content &addressContent) {
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
    if (!memcmp(&check, &vch[vch.size() - 4], 4)) {
        return DECODE_OK;
    }
    const uint256 legacyCheck = LegacyHashAddressContents(parsedOutput);
    if (!memcmp(&legacyCheck, &vch[vch.size() - 4], 4)) {
        return DECODE_OK;
    }
    return INTEGRITY_CHECK_FAILED;
}

static NetworkType GetAddressNetworkByte(const CChainParams &p) {
    if (p.NetworkIDString() == CBaseChainParams::MAIN) {
        return MAINNET;
    }
    if (p.NetworkIDString() == CBaseChainParams::TESTNET) {
        return TESTNET;
    }
    if (p.NetworkIDString() == CBaseChainParams::REGTEST) {
        return REGTEST;
    }
    assert(false || "Unknown network for XAddress");
    return UNKNOWN;
}

bool Parse(const CChainParams &params, const std::string &address,
           CTxDestination &retDestination) {
    Content content;
    if (Decode(address, content) != DECODE_OK) {
        return false;
    }
    if (GetAddressNetworkByte(params) != content.m_network) {
        return false;
    }
    if (TOKEN_NAME != content.m_token) {
        return false;
    }
    if (SCRIPT_PUB_KEY != content.m_type) {
        return false;
    }
    CScript scriptPubKey(content.m_payload.begin(), content.m_payload.end());
    return ExtractDestination(scriptPubKey, retDestination);
}

class Encoder : public boost::static_visitor<std::string> {
public:
    explicit Encoder(const CChainParams &p) : params(p) {}

    std::string operator()(const PKHash &id) const {
        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << id
                                         << OP_EQUALVERIFY << OP_CHECKSIG;
        return Encode(Content(TOKEN_NAME, GetAddressNetworkByte(params),
                              SCRIPT_PUB_KEY, ToByteVector(scriptPubKey)));
    }

    std::string operator()(const ScriptHash &id) const {
        CScript scriptPubKey = CScript() << OP_HASH160 << id << OP_EQUAL;
        return Encode(Content(TOKEN_NAME, GetAddressNetworkByte(params),
                              SCRIPT_PUB_KEY, ToByteVector(scriptPubKey)));
    }

    std::string operator()(const CNoDestination &) const { return ""; }

private:
    const CChainParams &params;
};

std::string EncodeDestination(const CChainParams &params,
                              const CTxDestination &dst) {
    return boost::apply_visitor(Encoder(params), dst);
}

} // namespace XAddress
