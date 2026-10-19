// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/admission.h>

#include <consensus/consensus.h>
#include <script/sighashtype.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>

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
    Assert(count > 0);
    const CTransactionRef &coinbase = setup.m_coinbase_txns.at(coinbase_index);
    const CScript coinbase_spk = coinbase->vout[0].scriptPubKey;
    const Amount coinbase_value = coinbase->vout[0].nValue;

    // Every version, including this legacy funding transaction, may publish at
    // most MAX_V2_TX_OUTPUTS outputs. A larger request is split across chained
    // transactions. All but the last reserve one output as P2PK change so the
    // next transaction can spend the still-immature coinbase's value. Only
    // coinbase index 0 is mature at height 100, so later coinbases are not
    // spent. Each transaction is mined in its own block: same-block spends
    // would depend on canonical transaction order.
    const size_t wallet_per_continuing = MAX_V2_TX_OUTPUTS - 1;
    Assert(wallet_per_continuing > 0);
    size_t n_txs = 1;
    if (count > MAX_V2_TX_OUTPUTS) {
        n_txs += (count - MAX_V2_TX_OUTPUTS + wallet_per_continuing - 1) /
                 wallet_per_continuing;
    }
    const Amount fee_each = 10000 * SATOSHI;
    const Amount total_fee = int64_t(n_txs) * fee_each;
    Assert(coinbase_value > total_fee);
    const Amount per_output = (coinbase_value - total_fee) / int64_t(count);
    Assert(per_output > Amount::zero());

    COutPoint spend{coinbase->GetId(), 0};
    Amount spend_value = coinbase_value;
    size_t remaining = count;
    while (remaining > 0) {
        const bool needs_change = remaining > MAX_V2_TX_OUTPUTS;
        const size_t n_wallet =
            needs_change ? wallet_per_continuing : remaining;
        Assert(n_wallet > 0);
        Assert(n_wallet + (needs_change ? 1 : 0) <= MAX_V2_TX_OUTPUTS);
        const Amount wallet_value = int64_t(n_wallet) * per_output;
        // The last transaction absorbs the division remainder as fee. Every
        // earlier transaction must still leave a positive change output.
        if (needs_change) {
            Assert(spend_value > wallet_value + fee_each);
        } else {
            Assert(spend_value >= wallet_value + fee_each);
        }
        const Amount change = needs_change ? spend_value - wallet_value - fee_each
                                           : Amount::zero();

        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.emplace_back(spend);
        for (size_t i = 0; i < n_wallet; ++i) {
            tx.vout.emplace_back(per_output, wallet.script_pub_key);
        }
        if (needs_change) {
            tx.vout.emplace_back(change, coinbase_spk);
        }
        // The spent output is P2PK to TestChain100Setup::coinbaseKey, both for
        // the original coinbase and for every change output.
        const SigHashType sighash_type = SigHashType().withForkId();
        const uint256 hash =
            SignatureHash(coinbase_spk, tx, 0, sighash_type, spend_value);
        std::vector<uint8_t> sig;
        Assert(setup.coinbaseKey.SignECDSA(hash, sig));
        sig.push_back(uint8_t(sighash_type.getRawSigHashType()));
        tx.vin[0].scriptSig = CScript() << sig;

        const TxId funding_id = CTransaction(tx).GetId();
        const CBlock block =
            setup.CreateAndProcessBlock({tx}, wallet.script_pub_key);
        Assert(WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain()
                                       .Tip()
                                       ->GetBlockHash()) == block.GetHash());
        SetMockTime(GetTime() + 1);
        for (uint32_t i = 0; i < n_wallet; ++i) {
            wallet.outputs.push_back({COutPoint(funding_id, i), per_output});
        }
        if (needs_change) {
            spend = COutPoint(funding_id, uint32_t(n_wallet));
            spend_value = change;
        }
        remaining -= n_wallet;
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
