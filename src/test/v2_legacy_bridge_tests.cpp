// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The legacy bridge: a version 7 input spends a legacy P2PKH coin with a V2
// BIP340 signature over the V2 signing message (rules A5/A6).

#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/validation.h>
#include <key.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/signing.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/v2_outputs.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <timedata.h>
#include <validation.h>

#include <test/util/mining.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {
/** V2 OP_CHECKSIG. */
constexpr uint8_t V2_OP_CHECKSIG = 0xbb;

std::array<uint8_t, 32> Secret(const CKey &key) {
    std::array<uint8_t, 32> secret{};
    std::copy(key.begin(), key.end(), secret.begin());
    return secret;
}

std::vector<uint8_t> XOnly(const CKey &key) {
    const CPubKey pub = key.GetPubKey();
    return std::vector<uint8_t>(pub.begin() + 1, pub.end());
}

lotus::v2::ResolvedCoins Resolve(const std::vector<CTxOut> &spent) {
    lotus::v2::ResolvedCoins resolved;
    for (const CTxOut &out : spent) {
        resolved.emplace_back(out.ToV2Output());
    }
    return resolved;
}

/** The V2 signing message of invocation (nIn, witness 0) in the mode. */
lotus::v2::Hash Message(const CMutableTransaction &mtx, size_t nIn,
                        const std::vector<CTxOut> &spent, uint8_t mode) {
    const lotus::v2::Transaction v2tx = CTransaction(mtx).ToV2Transaction();
    lotus::v2::Hash message{};
    std::string error;
    BOOST_REQUIRE_MESSAGE(lotus::v2::SigningMessage(
                              v2tx, lotus::v2::DefaultTxProfile,
                              GetActiveV2ChainId(), Resolve(spent), nIn, 0,
                              mode, std::nullopt, message, error),
                          error);
    return message;
}

std::vector<uint8_t> Sign(const CKey &key, const lotus::v2::Hash &message,
                          uint8_t mode) {
    std::vector<uint8_t> sig;
    std::string error;
    BOOST_REQUIRE_MESSAGE(lotus::v2::SignBip340Message(Secret(key), message,
                                                       mode, {}, sig, error),
                          error);
    return sig;
}

/** A v7 input spending prevout through the bridge, with a placeholder. */
CTxIn BridgeInput(const COutPoint &prevout, const CPubKey &pubkey) {
    CTxIn in(prevout, CScript(), CTxIn::SEQUENCE_FINAL);
    in.nFlags = 1;
    lotus::v2::BranchWitness w;
    w.arguments = {std::vector<uint8_t>(64, 0),
                   std::vector<uint8_t>(pubkey.begin(), pubkey.end())};
    in.vWitnesses = {w};
    return in;
}

/** Sign bridge input nIn of mtx with key in the mode. */
void SignBridge(CMutableTransaction &mtx, size_t nIn,
                const std::vector<CTxOut> &spent, const CKey &key,
                uint8_t mode) {
    mtx.vin[nIn].vWitnesses[0].arguments[0] =
        Sign(key, Message(mtx, nIn, spent, mode), mode);
}

struct BridgeSetup : public TestChain100Setup {
    CKey key = CKey::MakeCompressedKey();
    CKey other = CKey::MakeCompressedKey();
    size_t next_coinbase = 0;

    /** A mature legacy coin paying script, created by a legacy spend. */
    std::pair<COutPoint, CTxOut> FundLegacy(const CScript &script,
                                            Amount value = 10 * COIN) {
        const CMutableTransaction tx = CreateValidMempoolTransaction(
            m_coinbase_txns[next_coinbase++], 0, 0, coinbaseKey, script,
            value, /*submit=*/false);
        CreateAndProcessBlock({tx}, CScript() << OP_TRUE);
        const CTransaction ctx(tx);
        return {COutPoint(ctx.GetId(), 0), ctx.vout[0]};
    }

    std::pair<COutPoint, CTxOut> FundP2PKH(const CKey &k,
                                           Amount value = 10 * COIN) {
        return FundLegacy(GetScriptForDestination(PKHash(k.GetPubKey())),
                          value);
    }

    /** A v7 spend of one bridge coin to an OP_TRUE V2 output. */
    CMutableTransaction Spend(const COutPoint &prevout, const CTxOut &coin,
                              const CPubKey &pubkey) {
        CMutableTransaction mtx;
        mtx.nVersion = 7;
        mtx.vin.push_back(BridgeInput(prevout, pubkey));
        mtx.vout.push_back(OpTrueOutput(coin.nValue - 10000 * SATOSHI));
        return mtx;
    }

    std::string BlockReason(const std::vector<CMutableTransaction> &txs) {
        const CBlock block =
            CreateBlock(txs, CScript() << OP_TRUE,
                        m_node.chainman->ActiveChainstate());
        LOCK(cs_main);
        BlockValidationState state;
        const bool ok = TestBlockValidity(
            state, GetConfig().GetChainParams(),
            m_node.chainman->ActiveChainstate(), block,
            m_node.chainman->ActiveTip(), GetAdjustedTime,
            BlockValidationOptions(GetConfig()).withCheckPoW(false));
        return ok ? "valid" : state.GetRejectReason();
    }

    std::string MempoolReason(const CMutableTransaction &mtx) {
        LOCK(cs_main);
        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(
            MakeTransactionRef(mtx), /*test_accept=*/true);
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID
                   ? "valid"
                   : result.m_state.GetRejectReason();
    }
};

const std::string kScriptFailure =
    "mandatory-script-verify-flag-failed";

bool IsScriptFailure(const std::string &reason) {
    return reason.rfind("blk-bad-inputs", 0) == 0 ||
           reason.rfind(kScriptFailure, 0) == 0;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(v2_legacy_bridge_tests, BridgeSetup)

// Modes 0, 1 and 2 each spend a legacy P2PKH coin; the block connects, the
// legacy coin is spent and the new coin is a V2 coin.
BOOST_AUTO_TEST_CASE(p2pkh_bridge_valid_in_every_mode) {
    for (const uint8_t mode : {0, 1, 2}) {
        const auto [prevout, coin] = FundP2PKH(key);
        CMutableTransaction mtx = Spend(prevout, coin, key.GetPubKey());
        SignBridge(mtx, 0, {coin}, key, mode);
        BOOST_CHECK_EQUAL(mtx.vin[0].vWitnesses[0].arguments[0].size(),
                          mode ? 65U : 64U);
        BOOST_CHECK_EQUAL(BlockReason({mtx}), "valid");
        BOOST_CHECK_EQUAL(MempoolReason(mtx), "valid");

        CreateAndProcessBlock({mtx}, CScript() << OP_TRUE);
        LOCK(cs_main);
        const CCoinsViewCache &view =
            m_node.chainman->ActiveChainstate().CoinsTip();
        BOOST_CHECK(view.AccessCoin(prevout).IsSpent());
        const Coin &created =
            view.AccessCoin(COutPoint(CTransaction(mtx).GetId(), 0));
        BOOST_REQUIRE(!created.IsSpent());
        BOOST_CHECK(!created.IsLegacy());
    }
}

// The legacy coin stays spendable by a legacy transaction.
BOOST_AUTO_TEST_CASE(p2pkh_coin_still_spendable_by_legacy_tx) {
    const CScript p2pkh = GetScriptForDestination(PKHash(key.GetPubKey()));
    const auto [prevout, coin] = FundP2PKH(key);
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(prevout);
    mtx.vout.emplace_back(coin.nValue - 10000 * SATOSHI, p2pkh);
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<COutPoint, Coin> coins{{prevout, Coin(coin, 1, false)}};
    std::map<int, std::string> errors;
    BOOST_REQUIRE(SignTransaction(mtx, &keystore, coins,
                                  SigHashType().withForkId(), errors));
    BOOST_CHECK_EQUAL(BlockReason({mtx}), "valid");
}

// A pubkey that does not hash to the coin's key hash.
BOOST_AUTO_TEST_CASE(p2pkh_bridge_wrong_pubkey_hash) {
    const auto [prevout, coin] = FundP2PKH(key);
    CMutableTransaction mtx = Spend(prevout, coin, other.GetPubKey());
    SignBridge(mtx, 0, {coin}, other, 0);
    BOOST_CHECK_EQUAL(BlockReason({mtx}), "bad-txns-v2-legacy-p2pkh");
    BOOST_CHECK_EQUAL(MempoolReason(mtx), "bad-txns-v2-legacy-p2pkh");
}

// The right pubkey with a signature by another key, or over another
// message, fails the signature check.
BOOST_AUTO_TEST_CASE(p2pkh_bridge_bad_signatures) {
    const auto [prevout, coin] = FundP2PKH(key);
    const CMutableTransaction unsigned_tx =
        Spend(prevout, coin, key.GetPubKey());

    // Another key.
    CMutableTransaction mtx = unsigned_tx;
    SignBridge(mtx, 0, {coin}, other, 0);
    BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));
    BOOST_CHECK(IsScriptFailure(MempoolReason(mtx)));

    // A mode 0 signature labelled mode 1, and a mode 1 signature without
    // its mode byte.
    mtx = unsigned_tx;
    std::vector<uint8_t> sig = Sign(key, Message(mtx, 0, {coin}, 0), 0);
    sig.push_back(1);
    mtx.vin[0].vWitnesses[0].arguments[0] = sig;
    BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));
    mtx = unsigned_tx;
    sig = Sign(key, Message(mtx, 0, {coin}, 1), 1);
    sig.pop_back();
    mtx.vin[0].vWitnesses[0].arguments[0] = sig;
    BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));

    // A 65-byte signature whose mode byte is not 1 or 2.
    for (const uint8_t bad_mode : {0, 3}) {
        mtx = unsigned_tx;
        sig = Sign(key, Message(mtx, 0, {coin}, 0), 0);
        sig.push_back(bad_mode);
        mtx.vin[0].vWitnesses[0].arguments[0] = sig;
        BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));
    }

    // A signature for the same input of a different transaction.
    mtx = unsigned_tx;
    CMutableTransaction changed = unsigned_tx;
    changed.vout[0] = OpTrueOutput(coin.nValue - 20000 * SATOSHI);
    mtx.vin[0].vWitnesses[0].arguments[0] =
        Sign(key, Message(changed, 0, {coin}, 0), 0);
    BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));
}

// A5: the witness shape of a bridge input.
BOOST_AUTO_TEST_CASE(p2pkh_bridge_witness_shape) {
    const auto [prevout, coin] = FundP2PKH(key);
    const CMutableTransaction base = Spend(prevout, coin, key.GetPubKey());
    auto expect = [&](const std::function<void(CMutableTransaction &)> &edit) {
        // Signed first: the shape rule applies before any signature check.
        CMutableTransaction mtx = base;
        SignBridge(mtx, 0, {coin}, key, 0);
        edit(mtx);
        BOOST_CHECK_EQUAL(BlockReason({mtx}),
                          "bad-txns-v2-legacy-coin-witness");
    };
    expect([](CMutableTransaction &m) { m.vin[0].nPathIndex = 1; });
    expect([](CMutableTransaction &m) {
        m.vin[0].vWitnesses.push_back(m.vin[0].vWitnesses[0]);
    });
    expect([](CMutableTransaction &m) {
        m.vin[0].vWitnesses[0].script = {V2_OP_TRUE};
    });
    expect([](CMutableTransaction &m) {
        m.vin[0].vWitnesses[0].siblings.emplace_back();
    });
    expect([](CMutableTransaction &m) {
        m.vin[0].vWitnesses[0].arguments.push_back({0x01});
    });
    expect([](CMutableTransaction &m) {
        m.vin[0].vWitnesses[0].arguments.pop_back();
    });
}

// Q3: a coin paying the hash of an uncompressed key is not bridge-spendable
// (it stays spendable by a legacy transaction).
BOOST_AUTO_TEST_CASE(p2pkh_bridge_rejects_uncompressed_key) {
    CKey uncompressed;
    uncompressed.Set(key.begin(), key.end(), /*fCompressedIn=*/false);
    const auto [prevout, coin] = FundP2PKH(uncompressed);
    CMutableTransaction mtx = Spend(prevout, coin, uncompressed.GetPubKey());
    BOOST_REQUIRE_EQUAL(mtx.vin[0].vWitnesses[0].arguments[1].size(), 65U);
    SignBridge(mtx, 0, {coin}, uncompressed, 0);
    BOOST_CHECK_EQUAL(BlockReason({mtx}), "bad-txns-v2-legacy-coin-witness");
}

// A5: only P2PKH coins are bridge-spendable (P2SH comes with T1-07); other
// legacy scripts are refused.
BOOST_AUTO_TEST_CASE(bridge_rejects_non_template_coins) {
    const CPubKey pub = key.GetPubKey();
    for (const CScript &script :
         {CScript() << ToByteVector(pub) << OP_CHECKSIG,
          CScript() << OP_TRUE,
          CScript() << OP_1 << ToByteVector(pub) << OP_1 << OP_CHECKMULTISIG,
          GetScriptForDestination(PKHash(pub)) << OP_NOP}) {
        const auto [prevout, coin] = FundLegacy(script);
        CMutableTransaction mtx = Spend(prevout, coin, pub);
        SignBridge(mtx, 0, {coin}, key, 0);
        BOOST_CHECK_EQUAL(BlockReason({mtx}),
                          "bad-txns-v2-legacy-coin-template");
    }
}

// The bridge selector leaf commits to the coin script, so a signature for a
// bridge spend does not verify for a native V2 spend by the same key, and
// the reverse.
BOOST_AUTO_TEST_CASE(bridge_signature_does_not_replay_to_native_spend) {
    const auto [prevout, coin] = FundP2PKH(key);
    std::vector<uint8_t> key_leaf{0x20};
    const std::vector<uint8_t> xonly = XOnly(key);
    key_leaf.insert(key_leaf.end(), xonly.begin(), xonly.end());
    key_leaf.push_back(V2_OP_CHECKSIG);
    const CTransactionRef v2cb = MineV2Coinbase({CTxOut::FromV2Output(
        V0LeafV2Output(10 * COIN, std::span<const uint8_t>(key_leaf)))});
    const CTxOut native_coin = v2cb->vout[0];

    // One transaction spending both: the same key signs input 0 (bridge)
    // and input 1 (native). Swapping the two signatures must fail.
    CMutableTransaction mtx;
    mtx.nVersion = 7;
    mtx.vin.push_back(BridgeInput(prevout, key.GetPubKey()));
    CTxIn native(COutPoint(v2cb->GetId(), 0), CScript(),
                 CTxIn::SEQUENCE_FINAL);
    native.nFlags = 1;
    lotus::v2::BranchWitness w;
    w.script = key_leaf;
    w.arguments = {std::vector<uint8_t>(64, 0)};
    native.vWitnesses = {w};
    mtx.vin.push_back(native);
    mtx.vout.push_back(OpTrueOutput(19 * COIN));
    const std::vector<CTxOut> spent{coin, native_coin};

    const std::vector<uint8_t> bridge_sig =
        Sign(key, Message(mtx, 0, spent, 0), 0);
    const std::vector<uint8_t> native_sig =
        Sign(key, Message(mtx, 1, spent, 0), 0);
    BOOST_CHECK(Message(mtx, 0, spent, 0) != Message(mtx, 1, spent, 0));

    CMutableTransaction good = mtx;
    good.vin[0].vWitnesses[0].arguments[0] = bridge_sig;
    good.vin[1].vWitnesses[0].arguments[0] = native_sig;
    BOOST_CHECK_EQUAL(BlockReason({good}), "valid");

    CMutableTransaction swapped = mtx;
    swapped.vin[0].vWitnesses[0].arguments[0] = native_sig;
    swapped.vin[1].vWitnesses[0].arguments[0] = bridge_sig;
    BOOST_CHECK(IsScriptFailure(BlockReason({swapped})));

    // The bridge message differs from one whose selector leaf is a V2
    // branch leaf over an empty script.
    const std::vector<uint8_t> coin_script(coin.scriptPubKey.begin(),
                                           coin.scriptPubKey.end());
    BOOST_CHECK(lotus::v2::LegacyBridgeLeaf(coin_script, {}) !=
                lotus::v2::BranchLeaf({}));
}

// Several bridge inputs in one block go through the batch signature
// collector; one bad signature among them makes the block invalid.
BOOST_AUTO_TEST_CASE(bridge_signatures_batch_in_blocks) {
    std::vector<std::pair<COutPoint, CTxOut>> funded;
    for (int i = 0; i < 3; ++i) funded.push_back(FundP2PKH(key));
    CMutableTransaction mtx;
    mtx.nVersion = 7;
    std::vector<CTxOut> spent;
    for (const auto &[prevout, coin] : funded) {
        mtx.vin.push_back(BridgeInput(prevout, key.GetPubKey()));
        spent.push_back(coin);
    }
    // One output per input, so that every input may sign in mode 2.
    for (int i = 0; i < 3; ++i) mtx.vout.push_back(OpTrueOutput(9 * COIN));
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        SignBridge(mtx, i, spent, key, uint8_t(i % 3));
    }
    BOOST_CHECK_EQUAL(BlockReason({mtx}), "valid");
    for (size_t bad = 0; bad < mtx.vin.size(); ++bad) {
        CMutableTransaction broken = mtx;
        broken.vin[bad].vWitnesses[0].arguments[0][5] ^= 1;
        BOOST_CHECK(IsScriptFailure(BlockReason({broken})));
    }
}

BOOST_AUTO_TEST_SUITE_END()
