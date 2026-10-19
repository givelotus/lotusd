// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The legacy bridge: a version 7 input spends a legacy P2PKH coin with a V2
// BIP340 signature over the V2 signing message (rules A5/A6).

#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <key.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/signing.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/v2_outputs.h>
#include <script/bridge_checker.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <timedata.h>
#include <validation.h>

#include <core_io.h>
#include <test/data/v2_legacy_bridge.json.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <regex>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>

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

    /**
     * The block verdict with transaction ids masked, so that the verdicts of
     * two transactions spending the same coin compare.
     */
    std::string Verdict(const std::vector<CMutableTransaction> &txs) {
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
        if (ok) return "valid";
        return std::regex_replace(
            state.GetRejectReason() + " " + state.GetDebugMessage(),
            std::regex("[0-9a-f]{64}"), "<id>");
    }

    /** A P2SH coin paying redeem. */
    std::pair<COutPoint, CTxOut> FundP2SH(const CScript &redeem,
                                          Amount value = 10 * COIN) {
        return FundLegacy(GetScriptForDestination(ScriptHash(redeem)), value);
    }

    /** A v7 bridge spend of a P2SH coin with these arguments. */
    CMutableTransaction SpendP2SH(const COutPoint &prevout,
                                  const CTxOut &coin, const CScript &redeem,
                                  std::vector<std::vector<uint8_t>> args) {
        CMutableTransaction mtx;
        mtx.nVersion = 7;
        CTxIn in(prevout, CScript(), CTxIn::SEQUENCE_FINAL);
        in.nFlags = 1;
        lotus::v2::BranchWitness w;
        w.script.assign(redeem.begin(), redeem.end());
        w.arguments = std::move(args);
        in.vWitnesses = {w};
        mtx.vin.push_back(in);
        mtx.vout.push_back(OpTrueOutput(coin.nValue - 10000 * SATOSHI));
        return mtx;
    }

    /** The version 2 legacy spend of the same coin with the same pushes. */
    CMutableTransaction LegacyP2SH(const COutPoint &prevout,
                                   const CTxOut &coin, const CScript &redeem,
                                   const std::vector<std::vector<uint8_t>> &args) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(
            prevout,
            LegacyBridgeScriptSig(
                args, std::vector<uint8_t>(redeem.begin(), redeem.end())),
            uint32_t{CTxIn::SEQUENCE_FINAL});
        // Padded past the minimum transaction size.
        mtx.vout.emplace_back(coin.nValue - 10000 * SATOSHI,
                              CScript() << OP_RETURN
                                        << std::vector<uint8_t>(80, 0));
        return mtx;
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
           reason.rfind(kScriptFailure, 0) == 0 ||
           reason.rfind("non-mandatory-script-verify-flag", 0) == 0;
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

// A5: only P2PKH and P2SH coins are bridge-spendable; other legacy scripts
// are refused.
BOOST_AUTO_TEST_CASE(bridge_rejects_non_template_coins) {
    const CPubKey pub = key.GetPubKey();
    for (const CScript &script :
         {CScript() << ToByteVector(pub) << OP_CHECKSIG,
          CScript() << OP_TRUE,
          CScript() << OP_1 << ToByteVector(pub) << OP_1 << OP_CHECKMULTISIG,
          GetScriptForDestination(PKHash(pub)) << OP_NOP,
          GetScriptForDestination(ScriptHash(CScript() << OP_TRUE))
              << OP_NOP}) {
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

namespace {
/** A legacy signature (ECDSA or 64-byte Schnorr) over msg, plus hashtype. */
std::vector<uint8_t> LegacySig(const CKey &key, const lotus::v2::Hash &msg,
                               uint8_t hashtype, bool schnorr) {
    uint256 hash;
    std::memcpy(hash.begin(), msg.data(), 32);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(schnorr ? key.SignSchnorr(hash, sig)
                          : key.SignECDSA(hash, sig));
    sig.push_back(hashtype);
    return sig;
}

uint8_t ModeOf(uint8_t hashtype) {
    return *LegacyBridgeSigningMode(hashtype);
}
} // namespace

// 2-of-3 multisig behind P2SH, signed with ECDSA (legacy multisig, null
// dummy) and Schnorr (checkbits dummy) in each hashtype the bridge maps.
BOOST_AUTO_TEST_CASE(p2sh_bridge_multisig_valid) {
    const CKey k1 = CKey::MakeCompressedKey(), k2 = CKey::MakeCompressedKey(),
               k3 = CKey::MakeCompressedKey();
    const CScript redeem = CScript()
                           << OP_2 << ToByteVector(k1.GetPubKey())
                           << ToByteVector(k2.GetPubKey())
                           << ToByteVector(k3.GetPubKey()) << OP_3
                           << OP_CHECKMULTISIG;
    for (const bool schnorr : {false, true}) {
        for (const uint8_t hashtype : {0x41, 0xC1, 0xC3}) {
            const auto [prevout, coin] = FundP2SH(redeem);
            // Signed with placeholder arguments: the message does not
            // depend on them.
            CMutableTransaction mtx = SpendP2SH(prevout, coin, redeem, {});
            const lotus::v2::Hash msg =
                Message(mtx, 0, {coin}, ModeOf(hashtype));
            // Keys 1 and 3 sign; the Schnorr dummy is the checkbits 0b101.
            mtx.vin[0].vWitnesses[0].arguments = {
                schnorr ? std::vector<uint8_t>{0x05} : std::vector<uint8_t>{},
                LegacySig(k1, msg, hashtype, schnorr),
                LegacySig(k3, msg, hashtype, schnorr)};
            BOOST_CHECK_EQUAL(BlockReason({mtx}), "valid");
            BOOST_CHECK_EQUAL(MempoolReason(mtx), "valid");
        }
    }
}

// Hashtypes outside the three the bridge maps, a wrong key, and a legacy
// sighash signature (the message a v1/v2 spend would sign) all fail.
BOOST_AUTO_TEST_CASE(p2sh_bridge_bad_signatures) {
    const CScript redeem = CScript() << ToByteVector(key.GetPubKey())
                                     << OP_CHECKSIG;
    const auto [prevout, coin] = FundP2SH(redeem);
    const CMutableTransaction base = SpendP2SH(prevout, coin, redeem, {});
    const lotus::v2::Hash msg0 = Message(base, 0, {coin}, 0);

    for (const uint8_t hashtype : {0x01, 0x42, 0x43, 0x81, 0x40}) {
        CMutableTransaction mtx = base;
        mtx.vin[0].vWitnesses[0].arguments = {
            LegacySig(key, msg0, hashtype, false)};
        BOOST_CHECK(IsScriptFailure(BlockReason({mtx})));
    }
    CMutableTransaction good = base;
    good.vin[0].vWitnesses[0].arguments = {LegacySig(key, msg0, 0x41, false)};
    BOOST_CHECK_EQUAL(BlockReason({good}), "valid");

    CMutableTransaction wrong_key = base;
    wrong_key.vin[0].vWitnesses[0].arguments = {
        LegacySig(other, msg0, 0x41, false)};
    BOOST_CHECK(IsScriptFailure(BlockReason({wrong_key})));

    // The legacy signature hash of the same transaction and input.
    CMutableTransaction legacy_sighash = base;
    const uint256 sighash =
        SignatureHash(redeem, CTransaction(base), 0,
                      SigHashType().withForkId(), coin.nValue);
    std::vector<uint8_t> sig;
    BOOST_REQUIRE(key.SignECDSA(sighash, sig));
    sig.push_back(0x41);
    legacy_sighash.vin[0].vWitnesses[0].arguments = {sig};
    BOOST_CHECK(IsScriptFailure(BlockReason({legacy_sighash})));

    // A signature for the P2SH bridge does not verify in a mode it was not
    // made for.
    CMutableTransaction relabelled = base;
    relabelled.vin[0].vWitnesses[0].arguments = {
        LegacySig(key, msg0, 0xC1, false)};
    BOOST_CHECK(IsScriptFailure(BlockReason({relabelled})));
}

// A7: the redeem script must hash to the coin's script hash.
BOOST_AUTO_TEST_CASE(p2sh_bridge_wrong_redeem_hash) {
    const CScript redeem = CScript() << OP_TRUE;
    const auto [prevout, coin] = FundP2SH(redeem);
    const CMutableTransaction mtx =
        SpendP2SH(prevout, coin, CScript() << OP_2, {});
    BOOST_CHECK_EQUAL(BlockReason({mtx}), "bad-txns-v2-legacy-p2sh-hash");
    // Shape rules apply to P2SH as to P2PKH.
    CMutableTransaction siblings = SpendP2SH(prevout, coin, redeem, {});
    siblings.vin[0].vWitnesses[0].siblings.emplace_back();
    BOOST_CHECK_EQUAL(BlockReason({siblings}),
                      "bad-txns-v2-legacy-coin-witness");
    BOOST_CHECK_EQUAL(BlockReason({SpendP2SH(prevout, coin, redeem, {})}),
                      "valid");
}

// The same-result property (§2.4): without signatures, the v2 legacy spend
// and the v7 bridge spend of one P2SH coin, with the same pushes, give the
// same verdict, because both run the unchanged legacy interpreter under the
// same flags on the same scriptSig.
BOOST_AUTO_TEST_CASE(p2sh_bridge_same_result_as_legacy_spend) {
    const std::vector<uint8_t> preimage{1, 2, 3, 4};
    std::vector<uint8_t> image(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(image.data());
    const std::vector<uint8_t> msg{7, 7, 7};
    std::vector<uint8_t> msg_hash(32);
    CSHA256().Write(msg.data(), msg.size()).Finalize(msg_hash.data());
    std::vector<uint8_t> data_sig;
    BOOST_REQUIRE(key.SignECDSA(uint256(msg_hash), data_sig));
    std::vector<uint8_t> bad_data_sig = data_sig;
    bad_data_sig[10] ^= 1;
    const std::vector<uint8_t> pub = ToByteVector(key.GetPubKey());

    // CHECKDATASIG 11 times on a short scriptSig, above the input sigchecks
    // density (INPUT_SIGCHECKS, a standard flag: valid in a block, refused
    // by the mempool on both paths).
    CScript many_cds;
    for (int i = 0; i < 10; ++i) many_cds << OP_3DUP << OP_CHECKDATASIGVERIFY;
    many_cds << OP_CHECKDATASIG;

    struct Case {
        CScript redeem;
        std::vector<std::vector<uint8_t>> args;
        bool valid;
    };
    const std::vector<Case> cases{
        {CScript() << OP_TRUE, {}, true},
        {CScript() << OP_FALSE, {}, false},
        {CScript() << OP_RETURN, {}, false},
        {CScript() << OP_SHA256 << image << OP_EQUAL, {preimage}, true},
        {CScript() << OP_SHA256 << image << OP_EQUAL, {{9}}, false},
        // CLEANSTACK: an extra argument.
        {CScript() << OP_TRUE, {{5}}, false},
        {CScript() << OP_DROP << OP_TRUE, {{0x81}}, true},
        {CScript() << pub << OP_CHECKDATASIG, {data_sig, msg}, true},
        {CScript() << pub << OP_CHECKDATASIG, {bad_data_sig, msg}, false},
        {CScript() << OP_CHECKDATASIG, {{}, msg, pub}, false},
        {many_cds, {data_sig, msg, pub}, true},
        // A redeem script with a non-push opcode count above the limit.
        {[] {
             CScript s;
             for (int i = 0; i < MAX_OPS_PER_SCRIPT + 1; ++i) s << OP_NOP;
             return s << OP_TRUE;
         }(),
         {},
         false},
        // A 521-byte argument exceeds the legacy push limit.
        {CScript() << OP_DROP << OP_TRUE,
         {std::vector<uint8_t>(MAX_SCRIPT_ELEMENT_SIZE + 1, 1)},
         false},
    };
    for (const Case &c : cases) {
        const auto [prevout, coin] = FundP2SH(c.redeem);
        if (&c == &cases[10]) {
            BOOST_CHECK(MempoolReason(LegacyP2SH(prevout, coin, c.redeem,
                                                 c.args))
                            .find("Input SigChecks limit exceeded") !=
                        std::string::npos);
        }
        const std::string legacy =
            Verdict({LegacyP2SH(prevout, coin, c.redeem, c.args)});
        const std::string bridge =
            Verdict({SpendP2SH(prevout, coin, c.redeem, c.args)});
        BOOST_CHECK_EQUAL(legacy, bridge);
        // The mempool applies the standard flags on top, on both paths.
        BOOST_CHECK_EQUAL(
            MempoolReason(LegacyP2SH(prevout, coin, c.redeem, c.args)),
            MempoolReason(SpendP2SH(prevout, coin, c.redeem, c.args)));
        BOOST_CHECK_MESSAGE((legacy == "valid") == c.valid,
                            "case " << (&c - cases.data()) << ": " << legacy);
    }
}

// CLTV and CSV read the V2 lock and the input sequence in a bridge spend,
// with the legacy comparisons.
BOOST_AUTO_TEST_CASE(p2sh_bridge_locks) {
    const int height = WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight());
    const CScript cltv = CScript() << (height - 5) << OP_CHECKLOCKTIMEVERIFY
                                   << OP_DROP << OP_TRUE;
    const CScript csv = CScript() << 3 << OP_CHECKSEQUENCEVERIFY << OP_DROP
                                  << OP_TRUE;
    const auto [cltv_out, cltv_coin] = FundP2SH(cltv);
    const auto [csv_out, csv_coin] = FundP2SH(csv);
    mineBlocks(3);

    auto with_lock = [&](uint64_t lock, uint32_t sequence) {
        CMutableTransaction mtx = SpendP2SH(cltv_out, cltv_coin, cltv, {});
        mtx.nV2Lock = lock;
        mtx.nLockTime = uint32_t(lock >> 8);
        mtx.vin[0].nSequence = sequence;
        return mtx;
    };
    // Height lock at or above the script's height, input not final.
    BOOST_CHECK_EQUAL(BlockReason({with_lock((uint64_t(height - 5) << 8) | 1, 0)}),
                      "valid");
    BOOST_CHECK_EQUAL(BlockReason({with_lock((uint64_t(height) << 8) | 1, 0)}),
                      "valid");
    // Below the script's height; a time lock; a final sequence.
    BOOST_CHECK(IsScriptFailure(
        BlockReason({with_lock((uint64_t(height - 6) << 8) | 1, 0)})));
    BOOST_CHECK(IsScriptFailure(BlockReason({with_lock((uint64_t(1000) << 8) | 2, 0)})));
    BOOST_CHECK(IsScriptFailure(BlockReason(
        {with_lock((uint64_t(height) << 8) | 1, CTxIn::SEQUENCE_FINAL)})));

    auto with_sequence = [&](uint32_t sequence) {
        CMutableTransaction mtx = SpendP2SH(csv_out, csv_coin, csv, {});
        mtx.vin[0].nSequence = sequence;
        return mtx;
    };
    BOOST_CHECK_EQUAL(BlockReason({with_sequence(3)}), "valid");
    BOOST_CHECK(IsScriptFailure(BlockReason({with_sequence(2)})));
}

BOOST_AUTO_TEST_SUITE_END()

// Signing-message vectors shared with the Python test framework
// (test_framework/v7tx.py): each gives a version 7 transaction, its spent
// coins, an input, a mode and the V2 signing message of witness 0. Setting
// LOTUS_V2_BRIDGE_VECTORS_OUT writes the vectors built here to that path.
namespace {
struct BridgeVector {
    std::string comment;
    CMutableTransaction tx;
    std::vector<CTxOut> coins;
    size_t input;
    uint8_t mode;
};

CKey VectorKey(uint8_t n) {
    std::array<uint8_t, 32> secret{};
    secret[31] = n;
    CKey key;
    key.Set(secret.begin(), secret.end(), true);
    return key;
}

std::vector<BridgeVector> BuildBridgeVectors() {
    const CKey k1 = VectorKey(1), k2 = VectorKey(2), k3 = VectorKey(3);
    const CScript p2pkh = GetScriptForDestination(PKHash(k1.GetPubKey()));
    const CScript redeem = CScript() << OP_2 << ToByteVector(k2.GetPubKey())
                                     << ToByteVector(k3.GetPubKey()) << OP_2
                                     << OP_CHECKMULTISIG;
    const CScript p2sh = GetScriptForDestination(ScriptHash(redeem));
    const COutPoint a(TxId(uint256S("01" + std::string(62, '0'))), 0);
    const COutPoint b(TxId(uint256S("02" + std::string(62, '0'))), 3);

    std::vector<BridgeVector> vectors;

    CMutableTransaction one;
    one.nVersion = 7;
    one.vin.push_back(BridgeInput(a, k1.GetPubKey()));
    one.vout.push_back(OpTrueOutput(9 * COIN));
    for (uint8_t mode : {0, 1, 2}) {
        vectors.push_back({"P2PKH bridge, mode " + util::ToString(int(mode)), one,
                           {CTxOut(10 * COIN, p2pkh)}, 0, mode});
    }

    CMutableTransaction multisig;
    multisig.nVersion = 7;
    multisig.nV2Lock = (uint64_t{1234} << 8) | 1;
    multisig.nLockTime = 1234;
    CTxIn in(b, CScript(), 5);
    in.nFlags = 1;
    lotus::v2::BranchWitness w;
    w.script.assign(redeem.begin(), redeem.end());
    w.arguments = {{}, std::vector<uint8_t>(72, 0), std::vector<uint8_t>(72, 0)};
    in.vWitnesses = {w};
    multisig.vin.push_back(in);
    multisig.vout.push_back(OpTrueOutput(4 * COIN));
    multisig.vout.push_back(OpTrueOutput(1 * COIN));
    for (uint8_t mode : {0, 1, 2}) {
        vectors.push_back({"P2SH 2-of-2 bridge with height and relative locks, mode " +
                               util::ToString(int(mode)),
                           multisig, {CTxOut(5 * COIN, p2sh)}, 0, mode});
    }

    CMutableTransaction mixed;
    mixed.nVersion = 7;
    mixed.vin.push_back(BridgeInput(a, k1.GetPubKey()));
    CTxIn native(b, CScript(), CTxIn::SEQUENCE_FINAL);
    native.nFlags = 1;
    lotus::v2::BranchWitness op_true;
    op_true.script = {V2_OP_TRUE};
    native.vWitnesses = {op_true};
    mixed.vin.push_back(native);
    mixed.vout.push_back(OpTrueOutput(12 * COIN));
    for (uint8_t mode : {0, 1}) {
        vectors.push_back({"P2PKH bridge input beside a V2 coin, mode " +
                               util::ToString(int(mode)),
                           mixed,
                           {CTxOut(10 * COIN, p2pkh), OpTrueOutput(3 * COIN)},
                           0, mode});
    }
    vectors.push_back({"V2 input beside a P2PKH bridge input, mode 1", mixed,
                       {CTxOut(10 * COIN, p2pkh), OpTrueOutput(3 * COIN)}, 1,
                       1});
    return vectors;
}

lotus::v2::Hash VectorMessage(const CMutableTransaction &mtx,
                              const std::vector<CTxOut> &coins, size_t input,
                              uint8_t mode, const lotus::v2::ChainId &chain) {
    lotus::v2::Hash message{};
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::SigningMessage(CTransaction(mtx).ToV2Transaction(),
                                  lotus::v2::DefaultTxProfile, chain,
                                  Resolve(coins), input, 0, mode,
                                  std::nullopt, message, error),
        error);
    return message;
}

UniValue CoinJSON(const CTxOut &out) {
    UniValue coin(UniValue::VOBJ);
    coin.pushKV("value", out.nValue / SATOSHI);
    if (out.IsLegacy()) {
        coin.pushKV("script", HexStr(out.scriptPubKey));
    } else {
        std::vector<uint8_t> wire;
        std::string error;
        BOOST_REQUIRE(lotus::v2::EncodeOutput(out.ToV2Output(), wire, error));
        coin.pushKV("v2output", HexStr(wire));
    }
    return coin;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(v2_legacy_bridge_vector_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signing_message_vectors) {
    const lotus::v2::ChainId chain{};
    if (const char *out = std::getenv("LOTUS_V2_BRIDGE_VECTORS_OUT")) {
        UniValue all(UniValue::VARR);
        for (const BridgeVector &v : BuildBridgeVectors()) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("comment", v.comment);
            entry.pushKV("chain_id", HexStr(chain));
            entry.pushKV("tx", EncodeHexTx(CTransaction(v.tx)));
            UniValue coins(UniValue::VARR);
            for (const CTxOut &c : v.coins) {
                coins.push_back(CoinJSON(c));
            }
            entry.pushKV("coins", coins);
            entry.pushKV("input", uint64_t(v.input));
            entry.pushKV("mode", int(v.mode));
            entry.pushKV("message",
                         HexStr(VectorMessage(v.tx, v.coins, v.input, v.mode,
                                              chain)));
            all.push_back(entry);
        }
        std::ofstream(out) << all.write(2) << "\n";
    }

    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::v2_legacy_bridge) &&
                  vectors.isArray());
    const std::vector<BridgeVector> built = BuildBridgeVectors();
    BOOST_REQUIRE_EQUAL(vectors.size(), built.size());
    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue &v = vectors[i];
        const std::string comment = v["comment"].get_str();
        CMutableTransaction mtx;
        BOOST_REQUIRE_MESSAGE(DecodeHexTx(mtx, v["tx"].get_str()), comment);
        BOOST_CHECK_EQUAL(EncodeHexTx(CTransaction(mtx)),
                          EncodeHexTx(CTransaction(built[i].tx)));
        std::vector<CTxOut> coins;
        for (const UniValue &c : v["coins"].getValues()) {
            const Amount value = c["value"].getInt<int64_t>() * SATOSHI;
            if (c.exists("script")) {
                const std::vector<uint8_t> script = ParseHex(c["script"].get_str());
                coins.emplace_back(value, CScript(script.begin(), script.end()));
            } else {
                lotus::v2::Output out;
                std::string error;
                BOOST_REQUIRE(lotus::v2::DecodeOutput(
                    ParseHex(c["v2output"].get_str()), out, error));
                coins.push_back(CTxOut::FromV2Output(out));
                BOOST_CHECK_EQUAL(coins.back().nValue, value);
            }
        }
        const lotus::v2::Hash message =
            VectorMessage(mtx, coins, v["input"].getInt<int>(),
                          v["mode"].getInt<int>(), chain);
        BOOST_CHECK_MESSAGE(HexStr(message) == v["message"].get_str(),
                            comment);
    }
}

BOOST_AUTO_TEST_SUITE_END()
