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
    //! Sign all outputs
    SIGHASH_ALL = 1,
    //! Sign no outputs
    SIGHASH_NONE = 2,
    //! Sign the output at the same index as the signed input
    SIGHASH_SINGLE = 3,
    //! Sign only this input, other inputs can be added or removed
    SIGHASH_ANYONECANPAY = 0x80,

    //! Use the original legacy Bitcoin sighash algorim
    SIGHASH_LEGACY = 0x00,
    //! Invalid reserved sighash algorithm
    SIGHASH_RESERVED = 0x20,
    //! Use the BIP143 sighash algorithm
    SIGHASH_FORKID = 0x40,
    //! Use the Lotus sighash algorithm
    SIGHASH_LOTUS = 0x60,

    //! Bits which specify which sighash algorithm to use
    SIGHASH_ALGORITHM_MASK = 0x60,
    //! Bits which currently are not used and must be 0
    SIGHASH_UNUSED_MASK = 0x1c,
    //! Bits encoding the output type (ALL, NONE, SINGLE) as well as unused bits
    SIGHASH_BASE_TYPE_MASK = 0x1f,
};

/**
 * The Lotus chain's fork id, committed to every signature while replay
 * protection is active.
 *
 * This is a chain identity, not an epoch marker: a signature made for this
 * value is invalid on any chain using a different fork id, and a signature
 * made for another chain is invalid here. It occupies the 24-bit fork-value
 * field of SigHashType, so it must fit in 24 bits and must not be zero.
 *
 * Do not change this value without a coordinated hard fork.
 */
static constexpr uint32_t CHAIN_FORK_ID = 0x4c4f54; // "LOT"
static_assert(CHAIN_FORK_ID != 0, "CHAIN_FORK_ID must be non-zero");
static_assert(CHAIN_FORK_ID <= 0xffffff,
              "CHAIN_FORK_ID must fit in the 24-bit fork-value field");

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
        return SigHashType((sigHash & ~SIGHASH_BASE_TYPE_MASK) |
                           uint32_t(baseSigHashType));
    }

    SigHashType withForkValue(uint32_t forkId) const {
        return SigHashType((forkId << 8) | (sigHash & 0xff));
    }

    SigHashType withForkId() const {
        return SigHashType((sigHash & ~SIGHASH_ALGORITHM_MASK) |
                           SIGHASH_FORKID);
    }

    SigHashType withLotus() const {
        return SigHashType((sigHash & ~SIGHASH_ALGORITHM_MASK) |
                           SIGHASH_LOTUS);
    }

    SigHashType withAlgorithm(uint32_t algorithm) const {
        return SigHashType((sigHash & ~SIGHASH_ALGORITHM_MASK) | algorithm);
    }

    SigHashType withAnyoneCanPay(bool anyoneCanPay = true) const {
        return SigHashType((sigHash & ~SIGHASH_ANYONECANPAY) |
                           (anyoneCanPay ? SIGHASH_ANYONECANPAY : 0));
    }

    BaseSigHashType getBaseType() const {
        return BaseSigHashType(sigHash & SIGHASH_BASE_TYPE_MASK);
    }

    uint32_t getForkValue() const { return sigHash >> 8; }

    uint32_t getUnusedBits() const { return sigHash & SIGHASH_UNUSED_MASK; }

    bool isDefined() const {
        BaseSigHashType baseType = getBaseType();
        switch (baseType) {
            case BaseSigHashType::ALL:
            case BaseSigHashType::NONE:
            case BaseSigHashType::SINGLE:
                break;
            default:
                return false;
        }
        switch (sigHash & SIGHASH_ALGORITHM_MASK) {
            case SIGHASH_LEGACY:
            case SIGHASH_FORKID:
            case SIGHASH_LOTUS:
                break;
            default:
                return false;
        }
        return true;
    }

    bool isLegacy() const {
        return (sigHash & SIGHASH_ALGORITHM_MASK) == SIGHASH_LEGACY;
    }

    bool isReserved() const {
        return (sigHash & SIGHASH_ALGORITHM_MASK) == SIGHASH_RESERVED;
    }

    bool hasForkId() const {
        return (sigHash & SIGHASH_ALGORITHM_MASK) == SIGHASH_FORKID;
    }

    bool hasLotus() const {
        return (sigHash & SIGHASH_ALGORITHM_MASK) == SIGHASH_LOTUS;
    }

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
