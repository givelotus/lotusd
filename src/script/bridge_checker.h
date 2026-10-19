// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_BRIDGE_CHECKER_H
#define BITCOIN_SCRIPT_BRIDGE_CHECKER_H

#include <script/interpreter.h>

#include <cstdint>
#include <optional>

class CTransaction;

namespace lotus::v2 {
class PreparedSigningContext;
} // namespace lotus::v2

/**
 * The V2 signing mode a legacy hashtype selects in a legacy bridge spend:
 * ALL|FORKID (0x41) mode 0, ALL|FORKID|ANYONECANPAY (0xC1) mode 1,
 * SINGLE|FORKID|ANYONECANPAY (0xC3) mode 2. No other hashtype has a mode.
 */
std::optional<uint8_t> LegacyBridgeSigningMode(uint8_t hashtype);

/**
 * The signature checker of a version 7 input spending a legacy P2SH coin
 * (the legacy bridge). The legacy interpreter runs the coin's script
 * unchanged; only the messages differ from a legacy spend:
 * - CheckSig: a legacy signature (ECDSA DER or 64-byte Schnorr, plus its
 *   hashtype byte) over the V2 signing message of invocation (input, 0) in
 *   the mode its hashtype selects. scriptCode does not change the message:
 *   the selector leaf commits to the redeem script.
 * - CheckLockTime: the legacy comparison against the transaction's V2 lock
 *   (value lock >> 8, height or time by its kind byte).
 * - CheckSequence: BIP68 on the input's sequence (a version 7 transaction
 *   always has relative locks).
 * Signatures are verified by `verifier`, the input's caching checker, so
 * they use the signature cache and the block's batch collector.
 */
class LegacyBridgeSignatureChecker : public BaseSignatureChecker {
    const CTransaction &m_tx;
    unsigned int m_in;
    const lotus::v2::PreparedSigningContext &m_signing;
    const BaseSignatureChecker &m_verifier;

public:
    LegacyBridgeSignatureChecker(
        const CTransaction &tx, unsigned int in,
        const lotus::v2::PreparedSigningContext &signing,
        const BaseSignatureChecker &verifier)
        : m_tx(tx), m_in(in), m_signing(signing), m_verifier(verifier) {}

    bool VerifySignature(const std::vector<uint8_t> &vchSig,
                         const CPubKey &vchPubKey,
                         const uint256 &sighash) const override;
    bool CheckSig(const std::vector<uint8_t> &vchSigIn,
                  const std::vector<uint8_t> &vchPubKey,
                  const CScript &scriptCode, uint32_t flags) const override;
    bool CheckLockTime(const CScriptNum &nLockTime) const override;
    bool CheckSequence(const CScriptNum &nSequence) const override;
};

/**
 * The scriptSig a legacy spend of a P2SH coin would have: the minimal push
 * of each argument (bottom of the stack first), then of the redeem script.
 */
CScript LegacyBridgeScriptSig(const std::vector<std::vector<uint8_t>> &args,
                              const std::vector<uint8_t> &redeem_script);

#endif // BITCOIN_SCRIPT_BRIDGE_CHECKER_H
