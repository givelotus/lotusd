// Copyright (c) 2018-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <blockindex.h>
#include <chain.h>
#include <coins.h>
#include <hash.h>
#include <pubkey.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <lotus_v2/deferred_checks.h>
#include <lotus_v2/lock.h>
#include <primitives/transaction.h>
#include <script/script_flags.h>
#include <util/check.h>
#include <util/moneystr.h> // For FormatMoney

#include <cstring>

static bool IsFinalTx(const CTransaction &tx, int nBlockHeight,
                      int64_t nBlockTime) {
    // A version 7 transaction carries the V2 lock, whose value is 56 bits
    // wide and whose kind byte (not a 500M threshold) says height or time;
    // its nLockTime is only a truncated display copy.
    if (tx.nVersion == 7) {
        return lotus::v2::AbsoluteLockSatisfied(
            tx.nV2Lock, uint64_t(std::max(nBlockHeight, 0)),
            uint64_t(std::max<int64_t>(nBlockTime, 0)));
    }

    if (tx.nLockTime == 0) {
        return true;
    }

    int64_t lockTime = tx.nLockTime;
    int64_t lockTimeLimit =
        (lockTime < LOCKTIME_THRESHOLD) ? nBlockHeight : nBlockTime;
    if (lockTime < lockTimeLimit) {
        return true;
    }

    for (const auto &txin : tx.vin) {
        if (txin.nSequence != CTxIn::SEQUENCE_FINAL) {
            return false;
        }
    }
    return true;
}

bool ContextualCheckTransaction(const Consensus::Params &params,
                                const CTransaction &tx,
                                TxValidationState &state, int nHeight,
                                int64_t nMedianTimePast) {
    if (!IsFinalTx(tx, nHeight, nMedianTimePast)) {
        // While this is only one transaction, we use txns in the error to
        // ensure continuity with other clients.
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-nonfinal", "non-final transaction");
    }

    // Size limit
    if (::GetSerializeSize(tx) < MIN_TX_SIZE) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-undersize");
    }

    // Restrict version to 1, 2, and V2 (7)
    if (tx.nVersion != 1 && tx.nVersion != 2 && tx.nVersion != 7) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-version");
    }

    return true;
}

bool ContextualCheckTransactionForCurrentBlock(
    const CBlockIndex &active_chain_tip, const Consensus::Params &params,
    const CTransaction &tx, TxValidationState &state) {
    AssertLockHeld(cs_main);

    // ContextualCheckTransactionForCurrentBlock() uses
    // active_chain_tip.Height()+1 to evaluate nLockTime because when
    // IsFinalTx() is called within AcceptBlock(), the height of the
    // block *being* evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // ContextualCheckTransaction() with one more than
    // active_chain_tip.Height().
    const int nBlockHeight = active_chain_tip.nHeight + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // ContextualCheckTransaction().
    // This time can also be used for consensus upgrades.
    const int64_t nMedianTimePast{active_chain_tip.GetMedianTimePast()};

    return ContextualCheckTransaction(params, tx, state, nBlockHeight,
                                      nMedianTimePast);
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx,
                                               int flags,
                                               std::vector<int> &prevHeights,
                                               const CBlockIndex &block) {
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.nVersion >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn &txin = tx.vin[txinIndex];
        if (txin.nFlags == 3) {
            prevHeights[txinIndex] = 0;
            continue;
        }

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{
                Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))
                    ->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics.
            // BIP 68 relative lock times have the semantics of calculating the
            // first block or time at which the transaction would be valid. When
            // calculating the effective block time or height for the entire
            // transaction, we switch to using the semantics of nLockTime which
            // is the last invalid block time or height. Thus we subtract 1 from
            // the calculated time or height.

            // Time-based relative lock-times are measured from the smallest
            // allowed timestamp of the block containing the txout being spent,
            // which is the median time past of the block prior.
            nMinTime = std::max(
                nMinTime,
                nCoinTime +
                    int64_t((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK)
                            << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) -
                    1);
        } else {
            nMinHeight = std::max(
                nMinHeight,
                nCoinHeight +
                    int(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex &block,
                           std::pair<int, int64_t> lockPair) {
    assert(block.pprev);
    if (lockPair.first >= block.nHeight) {
        return false;
    }
    if (lockPair.second < 0) {
        return true;
    }
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.second >= nBlockTime) {
        return false;
    }

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags,
                   std::vector<int> &prevHeights, const CBlockIndex &block) {
    return EvaluateSequenceLocks(
        block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

namespace Consensus {
static inline bool ExtractTokenIdAndValue(const CTxOut &txout, uint256 &tok_id,
                                          uint64_t &val) {
    if (!txout.vBranches.empty()) {
        if ((txout.nFlags & 0x01U) == 0) {
            return false;
        }
        tok_id = txout.tokenId;
        val = static_cast<uint64_t>(
            std::max<int64_t>(0, txout.nValue / SATOSHI));
        return true;
    }
    // A legacy output carries no token.
    return false;
}

std::array<uint8_t, 32> TokenKey(const uint256 &id) {
    std::array<uint8_t, 32> key;
    std::memcpy(key.data(), id.begin(), key.size());
    return key;
}

bool FinishTxConservation(const CTransaction &tx,
                          lotus::v2::NativeConservation &native,
                          const lotus::v2::TokenConservation &tokens,
                          const Amount &nValueIn, TxValidationState &state,
                          Amount &txfee) {
    switch (tokens.Check()) {
        case lotus::v2::ConservationFailure::None:
            break;
        case lotus::v2::ConservationFailure::MintWithoutDelta:
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-mint-without-positive-delta");
        default:
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-token-inflation");
    }

    const Amount value_out = tx.GetValueOut();
    native.AddOutput(uint64_t(value_out / SATOSHI));
    if (native.Check() != lotus::v2::ConservationFailure::None) {
        return state.Invalid(
            TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn),
                      FormatMoney(value_out)));
    }

    // Tally transaction fees
    const Amount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}

namespace {
bool IsP2PKHTemplate(const CScript &script) {
    return script.size() == 25 && script[0] == OP_DUP &&
           script[1] == OP_HASH160 && script[2] == 20 &&
           script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}
bool IsP2SHTemplate(const CScript &script) {
    return script.size() == 23 && script[0] == OP_HASH160 &&
           script[1] == 20 && script[22] == OP_EQUAL;
}
} // namespace

// The rules that depend on the kind of the spent coin.
// - A2: a legacy (version 1 or 2) transaction spends only coins created by
//   legacy transactions. A V2 coin's scriptPubKey is its V2 wire encoding,
//   which the legacy interpreter must never run as a legacy script.
// - A5-A7: a version 7 input spending a legacy coin (the legacy bridge)
//   spends a P2PKH or P2SH coin through path 0 with one witness without
//   siblings. For P2PKH the witness has no script, its arguments are [sig,
//   compressed pubkey] and the pubkey hashes to the coin's key hash. For
//   P2SH the witness script is the redeem script, which hashes to the
//   coin's script hash, and the arguments are the pushes before it. The
//   signatures and the redeem script run with the input's other scripts
//   (CScriptCheck).
static bool CheckSpentCoin(const CTransaction &tx, const CTxIn &in,
                           const Coin &coin, TxValidationState &state) {
    if (tx.nVersion != 7) {
        if (!coin.IsLegacy()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-legacy-spends-v2-coin");
        }
        return true;
    }
    if (in.nFlags != 1 || !coin.IsLegacy()) {
        return true;
    }
    const CScript &script = coin.GetTxOut().scriptPubKey;
    const bool p2sh = IsP2SHTemplate(script);
    if (!p2sh && !IsP2PKHTemplate(script)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-v2-legacy-coin-template");
    }
    if (in.nPathIndex != 0 || in.vWitnesses.size() != 1 ||
        !in.vWitnesses[0].siblings.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-v2-legacy-coin-witness");
    }
    const lotus::v2::BranchWitness &witness = in.vWitnesses[0];
    if (p2sh) {
        const uint160 script_hash = Hash160(witness.script);
        if (!std::equal(script_hash.begin(), script_hash.end(),
                        script.begin() + 2)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-v2-legacy-p2sh-hash");
        }
        return true;
    }
    if (!witness.script.empty() || witness.arguments.size() != 2 ||
        witness.arguments[1].size() != CPubKey::COMPRESSED_SIZE ||
        (witness.arguments[1][0] != 0x02 && witness.arguments[1][0] != 0x03)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-v2-legacy-coin-witness");
    }
    const uint160 key_hash = Hash160(witness.arguments[1]);
    if (!std::equal(key_hash.begin(), key_hash.end(), script.begin() + 3)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-v2-legacy-p2pkh");
    }
    return true;
}

bool CheckTxInputs(const CTransaction &tx, TxValidationState &state,
                   const CCoinsViewCache &inputs, int nSpendHeight,
                   Amount &txfee) {
    Amount nValueIn = Amount::zero();
    // Structural contributions to the conservation kinds.
    lotus::v2::NativeConservation native;
    lotus::v2::TokenConservation tokens;
    for (const auto &in : tx.vin) {
        if (in.nFlags == 3) {
            tokens.AddMint(Consensus::TokenKey(uint256(in.prevout.GetTxId())));
            continue;
        }
        const COutPoint &prevout = in.prevout;
        const Coin &coin = inputs.AccessCoin(prevout);
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS,
                                 "bad-txns-inputs-missingorspent",
                                 strprintf("%s: inputs missing/spent", __func__));
        }

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() &&
            nSpendHeight - coin.GetHeight() < COINBASE_MATURITY) {
            return state.Invalid(
                TxValidationResult::TX_PREMATURE_SPEND,
                "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d",
                          nSpendHeight - coin.GetHeight()));
        }

        // C17a: Reject spending expired UTXOs (spend height >= expiration height)
        if (nSpendHeight >= 0 &&
            coin.IsExpired(static_cast<uint64_t>(nSpendHeight))) {
            return state.Invalid(
                TxValidationResult::TX_CONSENSUS, "bad-txns-input-expired",
                strprintf("tried to spend expired coin at height %d (expired at %llu)",
                          nSpendHeight,
                          static_cast<unsigned long long>(coin.GetExpirationHeight())));
        }

        if (!CheckSpentCoin(tx, in, coin, state)) {
            return false;
        }

        const CTxOut &prev_txout = coin.GetTxOut();
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValue(prev_txout, tok_id, tok_val)) {
            if (prev_txout.nValue < Amount::zero() ||
                !tokens.AddInput(Consensus::TokenKey(tok_id), tok_val)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-inputvalues-outofrange");
            }
            continue;
        }

        // Check for negative or overflow input values
        nValueIn += prev_txout.nValue;
        if (!MoneyRange(prev_txout.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-inputvalues-outofrange");
        }
        native.AddInput(uint64_t(prev_txout.nValue / SATOSHI));
    }

    for (const auto &out : tx.vout) {
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValue(out, tok_id, tok_val)) {
            if (out.nValue < Amount::zero() ||
                !tokens.AddOutput(Consensus::TokenKey(tok_id), tok_val)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-vout-negative");
            }
        }
    }

    return FinishTxConservation(tx, native, tokens, nValueIn, state, txfee);
}

bool CheckTxInputsFromSpentCoins(const CTransaction &tx,
                                 const std::vector<Coin> &spent_coins,
                                 TxValidationState &state, int nSpendHeight,
                                 Amount &txfee) {
    assert(spent_coins.size() == tx.vin.size());

    Amount nValueIn = Amount::zero();
    // Structural contributions to the conservation kinds.
    lotus::v2::NativeConservation native;
    lotus::v2::TokenConservation tokens;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (tx.vin[i].nFlags == 3) {
            tokens.AddMint(Consensus::TokenKey(uint256(tx.vin[i].prevout.GetTxId())));
            continue;
        }
        const Coin &coin = spent_coins[i];
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS,
                                 "bad-txns-inputs-missingorspent",
                                 strprintf("%s: inputs missing/spent", __func__));
        }

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() &&
            nSpendHeight - coin.GetHeight() < COINBASE_MATURITY) {
            return state.Invalid(
                TxValidationResult::TX_PREMATURE_SPEND,
                "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d",
                          nSpendHeight - coin.GetHeight()));
        }

        // C17a: Reject spending expired UTXOs (spend height >= expiration height)
        if (nSpendHeight >= 0 &&
            coin.IsExpired(static_cast<uint64_t>(nSpendHeight))) {
            return state.Invalid(
                TxValidationResult::TX_CONSENSUS, "bad-txns-input-expired",
                strprintf("tried to spend expired coin at height %d (expired at %llu)",
                          nSpendHeight,
                          static_cast<unsigned long long>(coin.GetExpirationHeight())));
        }

        if (!CheckSpentCoin(tx, tx.vin[i], coin, state)) {
            return false;
        }

        const CTxOut &prev_txout = coin.GetTxOut();
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValue(prev_txout, tok_id, tok_val)) {
            if (prev_txout.nValue < Amount::zero() ||
                !tokens.AddInput(Consensus::TokenKey(tok_id), tok_val)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-inputvalues-outofrange");
            }
            continue;
        }

        // Check for negative or overflow input values
        nValueIn += prev_txout.nValue;
        if (!MoneyRange(prev_txout.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-inputvalues-outofrange");
        }
        native.AddInput(uint64_t(prev_txout.nValue / SATOSHI));
    }

    for (const auto &out : tx.vout) {
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValue(out, tok_id, tok_val)) {
            if (out.nValue < Amount::zero() ||
                !tokens.AddOutput(Consensus::TokenKey(tok_id), tok_val)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-vout-negative");
            }
        }
    }

    return FinishTxConservation(tx, native, tokens, nValueIn, state, txfee);
}
} // namespace Consensus
