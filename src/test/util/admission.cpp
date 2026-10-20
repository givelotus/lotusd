// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/admission.h>

#include <script/interpreter.h>
#include <script/sighashtype.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/check.h>

namespace admission_test {

static constexpr Amount FEE_PER_INPUT = 400 * SATOSHI;
static constexpr Amount FEE_BASE = 300 * SATOSHI;

Wallet MakeWallet() {
    Wallet wallet;
    wallet.key.MakeNewKey(true);
    wallet.script_pub_key =
        GetScriptForDestination(PKHash(wallet.key.GetPubKey()));
    return wallet;
}

void SignP2PKH(CMutableTransaction &tx, const Wallet &wallet,
               const std::vector<Amount> &spent_amounts, bool schnorr) {
    Assert(spent_amounts.size() == tx.vin.size());
    const SigHashType sighash_type = SigHashType().withForkId();
    const CPubKey pub = wallet.key.GetPubKey();
    const std::vector<uint8_t> pubkey(pub.begin(), pub.end());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const uint256 hash = SignatureHash(wallet.script_pub_key, tx, i,
                                           sighash_type, spent_amounts[i]);
        std::vector<uint8_t> sig;
        if (schnorr) {
            Assert(wallet.key.SignSchnorr(hash, sig));
        } else {
            Assert(wallet.key.SignECDSA(hash, sig));
        }
        sig.push_back(uint8_t(sighash_type.getRawSigHashType()));
        tx.vin[i].scriptSig = CScript() << sig << pubkey;
    }
}

void FundWallet(TestChain100Setup &setup, Wallet &wallet, size_t count,
                size_t coinbase_index) {
    const CTransactionRef &coinbase = setup.m_coinbase_txns.at(coinbase_index);
    const CScript coinbase_spk = coinbase->vout[0].scriptPubKey;
    const Amount coinbase_value = coinbase->vout[0].nValue;
    const Amount fee = 10000 * SATOSHI + int64_t(count) * 50 * SATOSHI;
    const Amount per_output = (coinbase_value - fee) / int64_t(count);

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(coinbase->GetId(), 0));
    for (size_t i = 0; i < count; ++i) {
        tx.vout.emplace_back(per_output, wallet.script_pub_key);
    }
    // Coinbase outputs of TestChain100Setup are P2PK to coinbaseKey.
    const SigHashType sighash_type = SigHashType().withForkId();
    const uint256 hash =
        SignatureHash(coinbase_spk, tx, 0, sighash_type, coinbase_value);
    std::vector<uint8_t> sig;
    Assert(setup.coinbaseKey.SignECDSA(hash, sig));
    sig.push_back(uint8_t(sighash_type.getRawSigHashType()));
    tx.vin[0].scriptSig = CScript() << sig;

    const TxId funding_id = CTransaction(tx).GetId();
    setup.CreateAndProcessBlock({tx}, wallet.script_pub_key);
    for (uint32_t i = 0; i < count; ++i) {
        wallet.outputs.push_back({COutPoint(funding_id, i), per_output});
    }
}

CTransactionRef SignedSpend(const Wallet &wallet,
                            const std::vector<SpendableOutput> &inputs,
                            size_t n_outputs, bool schnorr, uint32_t salt) {
    Assert(!inputs.empty() && n_outputs > 0);
    CMutableTransaction tx;
    tx.nVersion = 2;
    Amount total = Amount::zero();
    std::vector<Amount> amounts;
    for (const auto &in : inputs) {
        tx.vin.emplace_back(in.outpoint);
        total += in.amount;
        amounts.push_back(in.amount);
    }
    const Amount fee = FEE_BASE + int64_t(inputs.size()) * FEE_PER_INPUT +
                       int64_t(salt) * SATOSHI;
    const Amount per_output = (total - fee) / int64_t(n_outputs);
    for (size_t i = 0; i < n_outputs; ++i) {
        tx.vout.emplace_back(per_output, wallet.script_pub_key);
    }
    SignP2PKH(tx, wallet, amounts, schnorr);
    return MakeTransactionRef(std::move(tx));
}

CTransactionRef SignedChild(const Wallet &wallet, const CTransactionRef &parent,
                            uint32_t n, bool schnorr, uint32_t salt) {
    return SignedSpend(
        wallet, {{COutPoint(parent->GetId(), n), parent->vout[n].nValue}}, 1,
        schnorr, salt);
}

} // namespace admission_test
