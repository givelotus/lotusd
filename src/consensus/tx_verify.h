// Copyright (c) 2018-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TX_VERIFY_H
#define BITCOIN_CONSENSUS_TX_VERIFY_H

#include <kernel/cs_main.h>
#include <threadsafety.h>

#include <array>
#include <cstdint>
#include <vector>

namespace lotus::v2 {
class NativeConservation;
class TokenConservation;
} // namespace lotus::v2

struct Amount;
class CBlockIndex;
class CCoinsViewCache;
class Coin;
class CTransaction;
class TxValidationState;
class uint256;

namespace Consensus {
struct Params;

/**
 * Check whether all inputs of this transaction are valid (no double spends and
 * amounts). This does not modify the UTXO set. This does not check scripts and
 * sigs.
 * @param[out] txfee Set to the transaction fee if successful.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction &tx, TxValidationState &state,
                   const CCoinsViewCache &inputs, int nSpendHeight,
                   Amount &txfee);

/**
 * Validate transaction input maturity, value ranges, and fee directly from
 * pre-spent Coins (e.g. CTxUndo::vprevout populated by SpendCoin) without
 * performing redundant CCoinsViewCache lookups.
 * Preconditions: tx.IsCoinBase() is false, spent_coins.size() == tx.vin.size(),
 * and the caller has successfully spent every non-authority input into
 * spent_coins. Native authority inputs (nFlags == 3) use positional placeholders
 * and are checked by the native authority rules instead of spending a Coin.
 * Missing coins are defensively rejected, but error precedence for combinations
 * of invalid inputs outside that precondition need not match CheckTxInputs.
 */
bool CheckTxInputsFromSpentCoins(const CTransaction &tx,
                                 const std::vector<Coin> &spent_coins,
                                 TxValidationState &state, int nSpendHeight,
                                 Amount &txfee);

//! The conservation kinds' token key for a token id or mint input txid.
std::array<uint8_t, 32> TokenKey(const uint256 &id);

/**
 * The final rules of the native and token conservation kinds
 * (lotus_v2/deferred_checks.h) over the contributions the caller collected
 * from the spent coins and outputs, with the node's reject reasons and
 * precedence: token rules, then native, then the fee range.
 * @param[in] nValueIn The native input total the caller range-checked.
 * @param[out] txfee Set to the transaction fee if successful.
 */
bool FinishTxConservation(const CTransaction &tx,
                          lotus::v2::NativeConservation &native,
                          const lotus::v2::TokenConservation &tokens,
                          const Amount &nValueIn, TxValidationState &state,
                          Amount &txfee);

} // namespace Consensus

/**
 * Context dependent validity checks for non coinbase transactions. This
 * doesn't check the validity of the transaction against the UTXO set, but
 * simply characteristic that are suceptible to change over time such as feature
 * activation/deactivation and CLTV.
 */
bool ContextualCheckTransaction(const Consensus::Params &params,
                                const CTransaction &tx,
                                TxValidationState &state, int nHeight,
                                int64_t nMedianTimePast);

/**
 * This is a variant of ContextualCheckTransaction which computes the contextual
 * check for a transaction based on the chain tip.
 */
bool ContextualCheckTransactionForCurrentBlock(
    const CBlockIndex &active_chain_tip, const Consensus::Params &params,
    const CTransaction &tx, TxValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/**
 * Calculates the block height and previous block's median time past at which
 * the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx,
                                               int flags,
                                               std::vector<int> &prevHeights,
                                               const CBlockIndex &block);

bool EvaluateSequenceLocks(const CBlockIndex &block,
                           std::pair<int, int64_t> lockPair);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included
 * in a block. Consensus critical. Takes as input a list of heights at which
 * tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags,
                   std::vector<int> &prevHeights, const CBlockIndex &block);

#endif // BITCOIN_CONSENSUS_TX_VERIFY_H
