// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sighashtype.h>

#include <streams.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(sighashtype_tests, BasicTestingSetup)

static void CheckSigHashType(SigHashType t, BaseSigHashType baseType,
                             bool isDefined, uint32_t forkValue, bool hasForkId,
                             bool hasBIP341, bool hasAnyoneCanPay) {
    BOOST_CHECK(t.getBaseType() == baseType);
    BOOST_CHECK_EQUAL(t.isDefined(), isDefined);
    BOOST_CHECK_EQUAL(t.getForkValue(), forkValue);
    BOOST_CHECK_EQUAL(t.hasForkId(), hasForkId);
    BOOST_CHECK_EQUAL(t.hasBIP341(), hasBIP341);
    BOOST_CHECK_EQUAL(t.hasAnyoneCanPay(), hasAnyoneCanPay);
}

BOOST_AUTO_TEST_CASE(sighash_construction_test) {
    // Check default values.
    CheckSigHashType(SigHashType(), BaseSigHashType::ALL, true, 0, false, false,
                     false);

    // Check all possible permutations.
    std::set<BaseSigHashType> baseTypes{
        BaseSigHashType::UNSUPPORTED, BaseSigHashType::ALL,
        BaseSigHashType::NONE, BaseSigHashType::SINGLE};
    std::set<uint32_t> forkValues{0, 1, 0x123456, 0xfedcba, 0xffffff};
    std::set<uint32_t> algorithmFlagValues{0, SIGHASH_FORKID, SIGHASH_BIP341};
    std::set<bool> anyoneCanPayFlagValues{false, true};

    for (BaseSigHashType baseType : baseTypes) {
        for (uint32_t forkValue : forkValues) {
            for (uint32_t algorithmFlags : algorithmFlagValues) {
                for (bool hasAnyoneCanPay : anyoneCanPayFlagValues) {
                    SigHashType t = SigHashType()
                                        .withBaseType(baseType)
                                        .withForkValue(forkValue)
                                        .withAnyoneCanPay(hasAnyoneCanPay);
                    bool hasForkId = algorithmFlags == SIGHASH_FORKID;
                    bool hasBIP341 = algorithmFlags == SIGHASH_BIP341;
                    if (hasForkId) {
                        t = t.withForkId();
                    } else if (hasBIP341) {
                        t = t.withBIP341();
                    }

                    bool isDefined = baseType != BaseSigHashType::UNSUPPORTED;
                    CheckSigHashType(t, baseType, isDefined, forkValue,
                                     hasForkId, hasBIP341, hasAnyoneCanPay);

                    // Also check all possible alterations.
                    CheckSigHashType(t.withForkId(hasForkId), baseType,
                                     isDefined, forkValue, hasForkId, false,
                                     hasAnyoneCanPay);
                    CheckSigHashType(t.withForkId(!hasForkId), baseType,
                                     isDefined, forkValue, !hasForkId, false,
                                     hasAnyoneCanPay);
                    CheckSigHashType(t.withAnyoneCanPay(hasAnyoneCanPay),
                                     baseType, isDefined, forkValue, hasForkId,
                                     hasBIP341, hasAnyoneCanPay);
                    CheckSigHashType(t.withAnyoneCanPay(!hasAnyoneCanPay),
                                     baseType, isDefined, forkValue, hasForkId,
                                     hasBIP341, !hasAnyoneCanPay);

                    for (BaseSigHashType newBaseType : baseTypes) {
                        bool isNewDefined =
                            newBaseType != BaseSigHashType::UNSUPPORTED;
                        CheckSigHashType(t.withBaseType(newBaseType),
                                         newBaseType, isNewDefined, forkValue,
                                         hasForkId, hasBIP341, hasAnyoneCanPay);
                    }

                    for (uint32_t newForkValue : forkValues) {
                        CheckSigHashType(t.withForkValue(newForkValue),
                                         baseType, isDefined, newForkValue,
                                         hasForkId, hasBIP341, hasAnyoneCanPay);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sighash_serialization_test) {
    std::set<uint32_t> forkValues{0, 1, 0xab1fe9, 0xc81eea, 0xffffff};

    // Test all possible sig hash values embedded in signatures.
    for (uint32_t sigHashType = 0x00; sigHashType <= 0xff; sigHashType++) {
        for (uint32_t forkValue : forkValues) {
            uint32_t rawType = sigHashType | (forkValue << 8);

            uint32_t baseType = rawType & 0x1f;
            bool hasForkId = (rawType & SIGHASH_TYPE_MASK) == SIGHASH_FORKID;
            bool hasBIP341 = (rawType & SIGHASH_TYPE_MASK) == SIGHASH_BIP341;
            bool hasAnyoneCanPay = (rawType & SIGHASH_ANYONECANPAY) != 0;

            uint32_t noflag =
                sigHashType & ~(SIGHASH_TYPE_MASK | SIGHASH_ANYONECANPAY);
            bool isDefined = (noflag != 0) && (noflag <= SIGHASH_SINGLE);
            if ((sigHashType & 0x20) && !(sigHashType & SIGHASH_FORKID)) {
                // BIP341 without FORKID is invalid
                isDefined = false;
            }

            const SigHashType tbase(rawType);

            // Check deserialization.
            CheckSigHashType(tbase, BaseSigHashType(baseType), isDefined,
                             forkValue, hasForkId, hasBIP341, hasAnyoneCanPay);

            // Check raw value.
            BOOST_CHECK_EQUAL(tbase.getRawSigHashType(), rawType);

            // Check serialization/deserialization.
            uint32_t unserializedOutput;
            (CDataStream(SER_DISK, 0) << tbase) >> unserializedOutput;
            BOOST_CHECK_EQUAL(unserializedOutput, rawType);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
