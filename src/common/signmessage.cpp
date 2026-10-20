// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <chainparams.h>
#include <common/signmessage.h>
#include <util/chaintype.h>

#include <hash.h>            // For HashWriter
#include <key.h>             // For CKey
#include <key_io.h>          // For DecodeDestination()
#include <pubkey.h>          // For CPubKey
#include <script/standard.h> // For CTxDestination, IsValidDestination(), PKHash
#include <serialize.h>       // For SER_GETHASH
#include <util/strencodings.h> // For DecodeBase64()

#include <string>
#include <vector>

/**
 * Text used to signify that a signed message follows and to prevent
 * inadvertently signing a transaction.
 */
const std::string MESSAGE_MAGIC = "eCash Signed Message:\n";

MessageVerificationResult MessageVerify(const CChainParams &params,
                                        const std::string &address,
                                        const std::string &signature,
                                        const std::string &message) {
    CTxDestination destination = DecodeDestination(address, params);
    if (!IsValidDestination(destination)) {
        return MessageVerificationResult::ERR_INVALID_ADDRESS;
    }

    if (std::get_if<PKHash>(&destination) == nullptr) {
        return MessageVerificationResult::ERR_ADDRESS_NO_KEY;
    }

    auto signature_bytes = DecodeBase64(signature);
    if (!signature_bytes) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(MessageHash(message), *signature_bytes)) {
        return MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED;
    }

    if (!(CTxDestination(PKHash(pubkey)) == destination)) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }

    return MessageVerificationResult::OK;
}

bool MessageSign(const CKey &privkey, const std::string &message,
                 std::string &signature) {
    std::vector<uint8_t> signature_bytes;

    if (!privkey.SignCompact(MessageHash(message), signature_bytes)) {
        return false;
    }

    signature = EncodeBase64(signature_bytes);

    return true;
}

uint256 MessageHash(const std::string &message) {
    HashWriter hasher{};
    hasher << MESSAGE_MAGIC << message;

    return hasher.GetHash();
}

lotus::v2::AddressNetwork LotusAddressNetwork(const CChainParams &params) {
    switch (params.GetChainType()) {
        case ChainType::MAIN:
            return lotus::v2::AddressNetwork::MAINNET;
        case ChainType::REGTEST:
            return lotus::v2::AddressNetwork::REGTEST;
        default:
            return lotus::v2::AddressNetwork::TESTNET;
    }
}

std::optional<lotus::v2::Hash32> LotusMessageKeyHash(const CPubKey &pubkey) {
    if (!pubkey.IsFullyValid()) return std::nullopt;
    // Both SEC forms put the x coordinate at bytes 1..32. Ignoring parity is
    // intentional: d and n-d have the same BIP340 key and spending authority.
    return lotus::v2::NativeKeyHash(
        std::span<const uint8_t, 32>(pubkey.begin() + 1, 32));
}

uint256 LotusMessageHash(const CChainParams &params,
                         const std::string &message) {
    HashWriter hasher{};
    hasher << std::string("Lotus Signed Message:\n") << uint8_t{1};
    hasher << params.V2ChainId();
    hasher << message;
    return hasher.GetHash();
}

bool LotusMessageSign(const CChainParams &params, const CKey &key,
                      const std::string &message, std::string &signature) {
    if (!key.IsValid()) return false;
    std::vector<uint8_t> bytes;
    if (!key.SignCompact(LotusMessageHash(params, message), bytes))
        return false;
    signature = EncodeBase64(bytes);
    return true;
}

MessageVerificationResult LotusMessageVerify(const CChainParams &params,
                                             const std::string &address,
                                             const std::string &signature,
                                             const std::string &message) {
    std::string error;
    const auto native = lotus::v2::DecodeAddress(address, error);
    CTxDestination legacy;
    if (native) {
        if (native->network != LotusAddressNetwork(params))
            return MessageVerificationResult::ERR_INVALID_ADDRESS;
        if (native->type != 1)
            return MessageVerificationResult::ERR_ADDRESS_NO_KEY;
    } else {
        legacy = DecodeDestination(address, params);
        if (!IsValidDestination(legacy))
            return MessageVerificationResult::ERR_INVALID_ADDRESS;
        if (!std::get_if<PKHash>(&legacy))
            return MessageVerificationResult::ERR_ADDRESS_NO_KEY;
    }
    const auto bytes = DecodeBase64(signature);
    if (!bytes || EncodeBase64(*bytes) != signature)
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    // Canonical compact ECDSA only: 65 bytes, compressed header, low S.
    static constexpr std::array<uint8_t, 32> HALF_ORDER{
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
        0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};
    if (bytes->size() != 65 || (*bytes)[0] < (native ? 31 : 27) ||
        (*bytes)[0] > 34 ||
        std::lexicographical_compare(HALF_ORDER.begin(), HALF_ORDER.end(),
                                     bytes->begin() + 33, bytes->end()))
        return MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED;
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(LotusMessageHash(params, message), *bytes))
        return MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED;
    if (native) {
        const auto hash = LotusMessageKeyHash(pubkey);
        if (!hash || *hash != native->root)
            return MessageVerificationResult::ERR_NOT_SIGNED;
    } else if (CTxDestination(PKHash(pubkey)) != legacy) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }
    return MessageVerificationResult::OK;
}

std::string SigningResultString(const SigningResult res) {
    switch (res) {
        case SigningResult::OK:
            return "No error";
        case SigningResult::PRIVATE_KEY_NOT_AVAILABLE:
            return "Private key not available";
        case SigningResult::SIGNING_FAILED:
            return "Sign failed";
            // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}
