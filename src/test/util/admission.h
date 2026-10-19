// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_ADMISSION_H
#define BITCOIN_TEST_UTIL_ADMISSION_H

#include <consensus/amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <cstdint>
#include <utility>
#include <vector>

struct TestChain100Setup;

/**
 * Helpers that build realistically signed transactions for mempool admission
 * tests and benchmarks: P2PKH spends with real ECDSA or Schnorr signatures,
 * so script verification costs what it costs on a live node.
 */
namespace admission_test {

struct SpendableOutput {
    COutPoint outpoint;
    Amount amount;
};

struct Wallet {
    CKey key;
    CScript script_pub_key;
    std::vector<SpendableOutput> outputs;
};

/** A fresh key and its P2PKH script. */
Wallet MakeWallet();

/**
 * Spend coinbase m_coinbase_txns[coinbase_index] of the setup into `count`
 * confirmed P2PKH outputs of `wallet`. A request larger than the consensus
 * output cap is split across chained transactions, each mined in its own
 * block. Recorded amounts are the amounts actually published.
 */
void FundWallet(TestChain100Setup &setup, Wallet &wallet, size_t count,
                size_t coinbase_index = 0);

/**
 * Sign every input of tx as a P2PKH spend of wallet.script_pub_key.
 * spent_amounts[i] is the value of input i; schnorr selects the signature
 * type for all inputs.
 */
void SignP2PKH(CMutableTransaction &tx, const Wallet &wallet,
               const std::vector<Amount> &spent_amounts, bool schnorr);

/**
 * Build a signed transaction spending `inputs` into `n_outputs` equal P2PKH
 * outputs back to the wallet. `salt` perturbs the fee so repeated calls over
 * the same inputs yield distinct transactions (and distinct signatures).
 */
CTransactionRef SignedSpend(const Wallet &wallet,
                            const std::vector<SpendableOutput> &inputs,
                            size_t n_outputs, bool schnorr, uint32_t salt = 0);

/** A signed child spending output `n` of `parent` (paying to the wallet). */
CTransactionRef SignedChild(const Wallet &wallet, const CTransactionRef &parent,
                            uint32_t n, bool schnorr, uint32_t salt = 0);

} // namespace admission_test

#endif // BITCOIN_TEST_UTIL_ADMISSION_H
