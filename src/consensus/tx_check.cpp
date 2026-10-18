// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

#include <unordered_set>

static bool CheckTransactionCommon(const CTransaction &tx,
                                   TxValidationState &state) {
    // Basic checks that don't depend on any context
    if (tx.vin.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-vin-empty");
    }

    if (tx.vout.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-vout-empty");
    }

    // Size limit
    if (::GetSerializeSize(tx) > MAX_TX_SIZE) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    Amount nValueOut = Amount::zero();
    for (const auto &txout : tx.vout) {
        if (txout.nValue < Amount::zero()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-vout-negative");
        }
        if ((txout.nFlags & 1) != 0) {
            continue;
        }

        if (txout.nValue > MAX_MONEY) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-vout-toolarge");
        }

        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-txouttotal-toolarge");
        }
    }

    return true;
}

bool CheckCoinbase(const CTransaction &tx, TxValidationState &state) {
    if (!tx.IsCoinBase()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-missing",
                             "first tx is not coinbase");
    }

    if (!CheckTransactionCommon(tx, state)) {
        // CheckTransactionCommon fill in the state.
        return false;
    }

    if (tx.vin[0].nFlags == 2) {
        if (tx.vin[0].vCoinbaseData.size() > 8192 ||
            tx.vin[0].scriptSig.size() > 8192) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-cb-length");
        }
        return true;
    }

    if (tx.vin[0].scriptSig.size() < 2 ||
        tx.vin[0].scriptSig.size() > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }

    return true;
}

bool CheckRegularTransaction(const CTransaction &tx, TxValidationState &state) {
    if (tx.IsCoinBase()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-tx-coinbase");
    }

    if (!CheckTransactionCommon(tx, state)) {
        // CheckTransactionCommon fill in the state.
        return false;
    }

    if (tx.vin.size() <= 8) {
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const auto &txin = tx.vin[i];
            if (txin.nFlags != 3 &&
                (txin.prevout.IsNull() || txin.nFlags == 2)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-prevout-null");
            }
            const bool is_mint = (txin.nFlags == 3);
            for (size_t j = 0; j < i; ++j) {
                const bool prev_is_mint = (tx.vin[j].nFlags == 3);
                if (is_mint == prev_is_mint &&
                    txin.prevout == tx.vin[j].prevout) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                         "bad-txns-inputs-duplicate");
                }
            }
        }
        return true;
    }

    std::unordered_set<COutPoint, SaltedOutpointHasher> vInOutPoints;
    std::unordered_set<COutPoint, SaltedOutpointHasher> vMintTokens;
    for (const auto &txin : tx.vin) {
        if (txin.nFlags == 3) {
            if (!vMintTokens.insert(txin.prevout).second) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-inputs-duplicate");
            }
            continue;
        }
        if (txin.prevout.IsNull() || txin.nFlags == 2) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-prevout-null");
        }

        // Check for duplicate inputs (see CVE-2018-17144)
        // While Consensus::CheckTxInputs does check if all inputs of a tx are
        // available, and UpdateCoins marks all inputs of a tx as spent, it does
        // not check if the tx has duplicate inputs. Failure to run this check
        // will result in either a crash or an inflation bug, depending on the
        // implementation of the underlying coins database.
        if (!vInOutPoints.insert(txin.prevout).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-inputs-duplicate");
        }
    }

    return true;
}
