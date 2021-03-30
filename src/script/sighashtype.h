// Copyright (c) 2017-2018 Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGHASHTYPE_H
#define BITCOIN_SCRIPT_SIGHASHTYPE_H

#include <serialize.h>

#include <cstdint>
#include <stdexcept>

/** Signature hash types/flags */
enum {
    // Sign all outputs
    SIGHASH_ALL = 1,
    // Sign no outputs
    SIGHASH_NONE = 2,
    // Sign the output at the same index as the signed input
    SIGHASH_SINGLE = 3,
    // Use the BIP143 sighash algorithm
    SIGHASH_FORKID = 0x40,
    // Use the BIP341 sighash algorithm
    SIGHASH_BIP341 = 0x60,
    // Sign only this input, other inputs can be added or removed
    SIGHASH_ANYONECANPAY = 0x80,

    // Bits which specify which sighash algorithm to use
    SIGHASH_TYPE_MASK = 0x60,
};

/**
 * Base signature hash types
 * Base sig hash types not defined in this enum may be used, but they will be
 * represented as UNSUPPORTED.  See transaction
 * c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73 for an
 * example where an unsupported base sig hash of 0 was used.
 */
enum class BaseSigHashType : uint8_t {
    UNSUPPORTED = 0,
    ALL = SIGHASH_ALL,
    NONE = SIGHASH_NONE,
    SINGLE = SIGHASH_SINGLE
};

/** Signature hash type wrapper class */
class SigHashType {
private:
    uint32_t sigHash;

public:
    explicit SigHashType() : sigHash(SIGHASH_ALL) {}

    explicit SigHashType(uint32_t sigHashIn) : sigHash(sigHashIn) {}

    SigHashType withBaseType(BaseSigHashType baseSigHashType) const {
        return SigHashType((sigHash & ~0x1f) | uint32_t(baseSigHashType));
    }

    SigHashType withForkValue(uint32_t forkId) const {
        return SigHashType((forkId << 8) | (sigHash & 0xff));
    }

    SigHashType withForkId(bool forkId = true) const {
        return SigHashType((sigHash & ~SIGHASH_TYPE_MASK) |
                           (forkId ? SIGHASH_FORKID : 0));
    }

    SigHashType withBIP341(bool bip341 = true) const {
        return SigHashType((sigHash & ~SIGHASH_TYPE_MASK) |
                           (bip341 ? SIGHASH_BIP341 : 0));
    }

    SigHashType withAnyoneCanPay(bool anyoneCanPay = true) const {
        return SigHashType((sigHash & ~SIGHASH_ANYONECANPAY) |
                           (anyoneCanPay ? SIGHASH_ANYONECANPAY : 0));
    }

    BaseSigHashType getBaseType() const {
        return BaseSigHashType(sigHash & 0x1f);
    }

    uint32_t getForkValue() const { return sigHash >> 8; }

    bool isDefined() const {
        auto baseType =
            BaseSigHashType(sigHash & ~(SIGHASH_FORKID | SIGHASH_ANYONECANPAY));
        return baseType >= BaseSigHashType::ALL &&
               baseType <= BaseSigHashType::SINGLE;
    }

    bool hasForkId() const {
        return (sigHash & SIGHASH_TYPE_MASK) == SIGHASH_FORKID;
    }

    bool hasBIP341() const {
        return (sigHash & SIGHASH_TYPE_MASK) == SIGHASH_BIP341;
    }

    bool isLegacy() const { return !(sigHash & SIGHASH_TYPE_MASK); }

    bool hasAnyoneCanPay() const {
        return (sigHash & SIGHASH_ANYONECANPAY) != 0;
    }

    uint32_t getRawSigHashType() const { return sigHash; }

    template <typename Stream> void Serialize(Stream &s) const {
        ::Serialize(s, getRawSigHashType());
    }

    template <typename Stream> void Unserialize(Stream &s) {
        ::Unserialize(s, sigHash);
    }

    /**
     * Handy operators.
     */
    friend constexpr bool operator==(const SigHashType &a,
                                     const SigHashType &b) {
        return a.sigHash == b.sigHash;
    }

    friend constexpr bool operator!=(const SigHashType &a,
                                     const SigHashType &b) {
        return !(a == b);
    }
};

#endif // BITCOIN_SCRIPT_SIGHASHTYPE_H
