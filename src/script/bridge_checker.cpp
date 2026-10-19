// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bridge_checker.h>

#include <lotus_v2/lock.h>
#include <lotus_v2/signing.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>

#include <cstring>

std::optional<uint8_t> LegacyBridgeSigningMode(uint8_t hashtype) {
    switch (hashtype) {
        case 0x41:
            return 0;
        case 0xC1:
            return 1;
        case 0xC3:
            return 2;
        default:
            return std::nullopt;
    }
}

bool LegacyBridgeSignatureChecker::VerifySignature(
    const std::vector<uint8_t> &vchSig, const CPubKey &vchPubKey,
    const uint256 &sighash) const {
    return m_verifier.VerifySignature(vchSig, vchPubKey, sighash);
}

bool LegacyBridgeSignatureChecker::CheckSig(
    const std::vector<uint8_t> &vchSigIn, const std::vector<uint8_t> &vchPubKey,
    const CScript &scriptCode, uint32_t flags) const {
    const CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid() || vchSigIn.empty()) {
        return false;
    }
    const std::optional<uint8_t> mode = LegacyBridgeSigningMode(vchSigIn.back());
    if (!mode || (*mode == 2 && m_in >= m_tx.vout.size())) {
        return false;
    }
    lotus::v2::Hash message;
    std::string error;
    if (!lotus::v2::SigningMessage(m_signing, m_in, 0, *mode, std::nullopt,
                                   message, error)) {
        return false;
    }
    uint256 sighash;
    std::memcpy(sighash.begin(), message.data(), 32);
    const std::vector<uint8_t> sig(vchSigIn.begin(), vchSigIn.end() - 1);
    return VerifySignature(sig, pubkey, sighash);
}

bool LegacyBridgeSignatureChecker::CheckLockTime(
    const CScriptNum &nLockTime) const {
    // The V2 lock: value lock >> 8, kind byte 2 for a time, else a height.
    const uint64_t lock_value = m_tx.nV2Lock >> 8;
    const bool lock_is_time = (m_tx.nV2Lock & 0xff) == 2;
    if ((nLockTime < LOCKTIME_THRESHOLD) == lock_is_time) {
        return false;
    }
    if (nLockTime < 0 || uint64_t(nLockTime.getint()) > lock_value) {
        return false;
    }
    // As in a legacy spend, a final input sequence disables the lock.
    return m_tx.vin[m_in].nSequence != CTxIn::SEQUENCE_FINAL;
}

bool LegacyBridgeSignatureChecker::CheckSequence(
    const CScriptNum &nSequence) const {
    const int64_t txToSequence = int64_t(m_tx.vin[m_in].nSequence);
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
        return false;
    }
    const uint32_t nLockTimeMask =
        CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;
    if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) {
        return false;
    }
    return !(nSequenceMasked > txToSequenceMasked);
}

namespace {
void PushMinimal(CScript &script, const std::vector<uint8_t> &data) {
    if (data.empty()) {
        script << OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        script << CScript::EncodeOP_N(data[0]);
    } else if (data.size() == 1 && data[0] == 0x81) {
        script << OP_1NEGATE;
    } else {
        script << data;
    }
}
} // namespace

CScript LegacyBridgeScriptSig(const std::vector<std::vector<uint8_t>> &args,
                              const std::vector<uint8_t> &redeem_script) {
    CScript script_sig;
    for (const auto &arg : args) {
        PushMinimal(script_sig, arg);
    }
    PushMinimal(script_sig, redeem_script);
    return script_sig;
}
