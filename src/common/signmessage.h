// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SIGNMESSAGE_H
#define BITCOIN_COMMON_SIGNMESSAGE_H

#include <lotus_v2/address.h>
#include <uint256.h>

#include <string>

class CChainParams;
class CKey;
class CPubKey;

extern const std::string MESSAGE_MAGIC;

/**
 * The result of a signed message verification.
 * Message verification takes as an input:
 * - address (with whose private key the message is supposed to have been
 * signed)
 * - signature
 * - message
 */
enum class MessageVerificationResult {
    //! The provided address is invalid.
    ERR_INVALID_ADDRESS,

    //! The provided address is valid but does not refer to a public key.
    ERR_ADDRESS_NO_KEY,

    //! The provided signature couldn't be parsed (maybe invalid base64).
    ERR_MALFORMED_SIGNATURE,

    //! A public key could not be recovered from the provided signature and
    //! message.
    ERR_PUBKEY_NOT_RECOVERED,

    //! The message was not signed with the private key of the provided address.
    ERR_NOT_SIGNED,

    //! The message verification was successful.
    OK
};

enum class SigningResult {
    OK, //!< No error
    PRIVATE_KEY_NOT_AVAILABLE,
    SIGNING_FAILED,
};

/**
 * Verify a signed message.
 * @param[in] params Chain params to be used to interpret the address.
 * @param[in] address Signer's bitcoin address, it must refer to a public key.
 * @param[in] signature The signature in base64 format.
 * @param[in] message The message that was signed.
 * @return result code
 */
MessageVerificationResult MessageVerify(const CChainParams &params,
                                        const std::string &address,
                                        const std::string &signature,
                                        const std::string &message);

/**
 * Sign a message.
 * @param[in] privkey Private key to sign with.
 * @param[in] message The message to sign.
 * @param[out] signature Signature, base64 encoded, only set if true is
 * returned.
 * @return true if signing was successful.
 */
bool MessageSign(const CKey &privkey, const std::string &message,
                 std::string &signature);

/**
 * Hashes a message for signing and verification in a manner that prevents
 * inadvertently signing a transaction.
 */
uint256 MessageHash(const std::string &message);

// Lotus V2 application signatures. Transaction signatures remain BIP340.
// These deliberately do not replace the eCash compatibility primitives above.
uint256 LotusMessageHash(const CChainParams &params,
                         const std::string &message);
bool LotusMessageSign(const CChainParams &params, const CKey &key,
                      const std::string &message, std::string &signature);
MessageVerificationResult LotusMessageVerify(const CChainParams &params,
                                             const std::string &address,
                                             const std::string &signature,
                                             const std::string &message);
lotus::v2::AddressNetwork LotusAddressNetwork(const CChainParams &params);
// Empty for an invalid key; hashes the 32-byte x coordinate, never SEC bytes.
std::optional<lotus::v2::Hash32> LotusMessageKeyHash(const CPubKey &pubkey);

std::string SigningResultString(const SigningResult res);

#endif // BITCOIN_COMMON_SIGNMESSAGE_H
