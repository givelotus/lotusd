#include "signing.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
std::vector<uint8_t> Hex(const std::string &hex) {
    CHECK(hex.size() % 2 == 0);
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("hex");
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back((digit(hex[i]) << 4) | digit(hex[i + 1]));
    return out;
}
Hash HashHex(const std::string &hex) {
    auto bytes = Hex(hex);
    CHECK(bytes.size() == 32);
    Hash result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}
const TxProfile PROFILE{32, 32, 8, 8192, 16, 8192, 64};

void BIP340OfficialVector() {
    // bitcoin/bips bip-0340/test-vectors.csv row 0.
    std::array<uint8_t, 32> secret{};
    secret[31] = 3;
    Hash message{};
    std::array<uint8_t, 32> aux{};
    const auto pubkey =
        Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    const auto expected =
        Hex("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0");
    std::vector<uint8_t> sig;
    std::string error;
    CHECK(SignBip340Message(secret, message, 0, aux, sig, error));
    CHECK(sig == expected);
    CHECK(VerifyBip340Signature(pubkey, sig, message, false) ==
          SignatureStatus::Valid);
    message[0] = 1;
    CHECK(VerifyBip340Signature(pubkey, sig, message, false) ==
          SignatureStatus::InvalidSignature);
    message[0] = 0;
    auto bad = sig;
    bad.push_back(0);
    CHECK(VerifyBip340Signature(pubkey, bad, message, false) ==
          SignatureStatus::InvalidEncoding);
    bad.back() = 3;
    CHECK(VerifyBip340Signature(pubkey, bad, message, false) ==
          SignatureStatus::InvalidEncoding);
    bad.back() = 1;
    CHECK(VerifyBip340Signature(pubkey, bad, message, true) ==
          SignatureStatus::InvalidEncoding);
    auto invalid_key = pubkey;
    invalid_key.assign(32, 255);
    CHECK(VerifyBip340Signature(invalid_key, sig, message, false) ==
          SignatureStatus::InvalidPublicKey);
    secret.fill(0);
    CHECK(!SignBip340Message(secret, message, 0, aux, sig, error));
}

void PaymentFixture() {
    const auto wire =
        Hex("07000000000000000000000001000100"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "00000000ffffffff0100012220f9308a019258c31049344f85f89d5229b531c845"
            "836f99b08601f113bce036f9bb000140"
            "170c710899dd02f994fe139b507662b88c0701019174aafa87329af0b65a9c0b84"
            "9c421cd740417ddeb4c6f70f4c1f50609b58c00fe8e41f9955a1091d5754aa"
            "00e80300000000000001d0c0707d9e50c9c3aedc8409e2df04bb920a3d9f669e80"
            "a36d2f68ea1e3f0d2a010100");
    const auto coin_wire = Hex("00d00700000000000001d0c0707d9e50c9c3aedc8409e2d"
                               "f04bb920a3d9f669e80a36d2f68ea1e3f0d2a010100");
    Transaction tx;
    Output coin;
    std::string error;
    CHECK(DecodeTransaction(wire, PROFILE, tx, error));
    CHECK(DecodeOutput(coin_wire, coin, error));
    ResolvedCoins resolved{coin};
    ChainId chain{};
    for (size_t i = 0; i < 32; ++i)
        chain[i] = uint8_t(i);
    IdentityDigests ids;
    CHECK(ComputeIdentities(tx, PROFILE, chain, ids, error));
    CHECK(ids.txid == HashHex("6f097525dfa73f4c9eb428ed6e0e2e70efe63224479b8e0c"
                              "ede896a7e4caab2c"));
    CHECK(ids.txhash == HashHex("b27873b6da521172796f7365a8b338e694879bc712d8d2"
                                "ecabdb22d39378704d"));
    Hash coins, own;
    CHECK(ComputeCoinsRoot(tx, resolved, coins, error));
    CHECK(coins == HashHex("deeba4111737eec866fe0d3998ca43ca4ab84b97afa2cc144e8"
                           "9e60f6dd3dd21"));
    CHECK(ComputeOwnInputHash(tx, PROFILE, resolved, 0, own, error));
    CHECK(own == HashHex("e9c6f915cde3bab2ab260ddc74f007767042c4836b6c638b30d9e"
                         "7397832e5f8"));
    const std::array<std::string, 3> expected{
        "04a85123186ad1a571dc9878c2f2ae8e27329e6f409dcece4e47368428067ecd",
        "edd48a54efc1c6fb3a548525e570021b14c890bada1c0419a66cbdbd04c31c2a",
        "45d5a4af0c5a832acab582eb5b6fc5b5fadba6f0b670bd92e36256f6d5fd72e8"};
    PreparedSigningContext prepared;
    CHECK(PrepareSigningContext(tx, PROFILE, chain, resolved, prepared, error));
    CHECK(PrepareSigningContextChecked(tx, PROFILE, chain, resolved, prepared, error) ==
          SigningPreparationStatus::Ready);
    const auto saved_txid = prepared.Identities().txid;
    auto wrong_witness = tx;
    wrong_witness.inputs[0].witnesses[0].script[0] ^= 1;
    CHECK(PrepareSigningContextChecked(wrong_witness, PROFILE, chain, resolved, prepared, error) ==
          SigningPreparationStatus::InvalidWitness);
    CHECK(prepared.Identities().txid == saved_txid);
    CHECK(PrepareSigningContextChecked(tx, PROFILE, chain, {}, prepared, error) ==
          SigningPreparationStatus::OperationalError);
    auto invalid_profile = PROFILE;
    invalid_profile.max_inputs = 0;
    CHECK(PrepareSigningContextChecked(tx, invalid_profile, chain, resolved, prepared, error) ==
          SigningPreparationStatus::OperationalError);
    CHECK(prepared.Identities().txid == saved_txid);

    for (uint8_t mode = 0; mode < 3; ++mode) {
        Hash message;
        CHECK(SigningMessage(tx, PROFILE, chain, resolved, 0, 0, mode,
                             std::nullopt, message, error));
        CHECK(message == HashHex(expected[mode]));
        Hash cached_message;
        CHECK(SigningMessage(prepared, 0, 0, mode, std::nullopt,
                             cached_message, error));
        CHECK(cached_message == message);
    }
    const auto signature = tx.inputs[0].witnesses[0].arguments[0];
    const auto pubkey =
        Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    Hash message;
    CHECK(SigningMessage(tx, PROFILE, chain, resolved, 0, 0, 0, std::nullopt,
                         message, error));
    CHECK(VerifyBip340Signature(pubkey, signature, message, false) ==
          SignatureStatus::Valid);
    ChainId other_chain = chain;
    other_chain[0] ^= 1;
    Hash cross_chain_message;
    CHECK(SigningMessage(tx, PROFILE, other_chain, resolved, 0, 0, 0,
                         std::nullopt, cross_chain_message, error));
    CHECK(cross_chain_message != message);
    CHECK(VerifyBip340Signature(pubkey, signature, cross_chain_message,
                                false) == SignatureStatus::InvalidSignature);
    const auto original_id = ids.txid;
    const auto original_hash = ids.txhash;
    tx.inputs[0].witnesses[0].arguments[0] = {'x'};
    CHECK(ComputeIdentities(tx, PROFILE, chain, ids, error));
    CHECK(ids.txid == original_id && ids.txhash != original_hash);
    Hash mutated_message;
    CHECK(SigningMessage(tx, PROFILE, chain, resolved, 0, 0, 0, std::nullopt,
                         mutated_message, error));
    CHECK(mutated_message == message);
    tx.outputs.clear();
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 0, 0, 2, std::nullopt,
                          mutated_message, error));
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 0, 0, 3, std::nullopt,
                          mutated_message, error));
}

void MintMessage() {
    const auto wire =
        Hex("07000000000000000000000001000100"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "00000000ffffffff0100012220f9308a019258c31049344f85f89d5229b531c845"
            "836f99b08601f113bce036f9bb000140"
            "170c710899dd02f994fe139b507662b88c0701019174aafa87329af0b65a9c0b84"
            "9c421cd740417ddeb4c6f70f4c1f50609b58c00fe8e41f9955a1091d5754aa"
            "00e80300000000000001d0c0707d9e50c9c3aedc8409e2df04bb920a3d9f669e80"
            "a36d2f68ea1e3f0d2a010100");
    const auto coin_wire = Hex("00d00700000000000001d0c0707d9e50c9c3aedc8409e2d"
                               "f04bb920a3d9f669e80a36d2f68ea1e3f0d2a010100");
    Transaction tx;
    Output coin;
    std::string error;
    CHECK(DecodeTransaction(wire, PROFILE, tx, error));
    CHECK(DecodeOutput(coin_wire, coin, error));
    Input mint;
    mint.flags = 3;
    mint.sequence = UINT32_MAX;
    mint.prev_txid = HashHex(
        "a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605");
    mint.witnesses.push_back(BranchWitness{{0x4e}, {}, {{'x'}}});
    tx.inputs.push_back(mint);
    ResolvedCoins resolved{coin, std::nullopt};
    ChainId chain{};
    for (size_t i = 0; i < 32; ++i)
        chain[i] = uint8_t(i);
    PositiveDelta delta{};
    delta[0] = 1;
    PreparedSigningContext prepared;
    CHECK(PrepareSigningContext(tx, PROFILE, chain, resolved, prepared, error));
    Hash message;
    CHECK(SigningMessage(tx, PROFILE, chain, resolved, 1, 0, 0, delta, message,
                         error));
    CHECK(message == HashHex("e377de4d5eeef48cba47286c47dc88a1a61019c06f6f2f1e4"
                             "ea2f263d60bb587"));
    Hash cached_message;
    CHECK(SigningMessage(prepared, 1, 0, 0, delta, cached_message, error));
    CHECK(cached_message == message);
    CHECK(!SigningMessage(prepared, 1, 0, 1, delta, cached_message, error));
    CHECK(!SigningMessage(prepared, 1, 0, 0, std::nullopt, cached_message,
                          error));
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 1, 0, 1, delta, message,
                          error));
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 1, 0, 2, delta, message,
                          error));
    delta[0] = 0;
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 1, 0, 0, delta, message,
                          error));
    delta[0] = 1;
    tx.inputs[1].witnesses.clear();
    CHECK(!SigningMessage(tx, PROFILE, chain, resolved, 1, 0, 0, delta, message,
                          error));
    tx.inputs[1].flags = 0;
    Hash coins;
    CHECK(!ComputeCoinsRoot(tx, resolved, coins, error));
}

void BatchSigCollectorVerificationAndBisection() {
    std::array<uint8_t, 32> secret{};
    secret[31] = 3;
    std::array<uint8_t, 32> aux{};
    const auto pubkey =
        Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");

    constexpr size_t kBatchCount = 256;
    BatchSigCollector collector;
    collector.Reserve(kBatchCount);
    std::vector<Hash> messages(kBatchCount);
    std::vector<std::vector<uint8_t>> sigs(kBatchCount);
    std::string error;

    for (size_t i = 0; i < kBatchCount; ++i) {
        messages[i].fill(0);
        messages[i][0] = uint8_t(i & 0xff);
        messages[i][1] = uint8_t((i >> 8) & 0xff);
        messages[i][2] = 0x5a;
        aux[0] = uint8_t(i & 0xff);
        CHECK(SignBip340Message(secret, messages[i], 0, aux, sigs[i], error));
        CHECK(collector.Add(pubkey, sigs[i], messages[i]));
    }
    CHECK(collector.Size() == kBatchCount);
    CHECK(collector.VerifyAll(1));
    CHECK(collector.VerifyAll(4));
    CHECK(!collector.FirstFailingIndex(1).has_value());
    CHECK(!collector.FirstFailingIndex(4).has_value());

    // Reject malformed public key or short signature in Add()
    auto bad_key = pubkey;
    bad_key.assign(32, 0xff);
    CHECK(!collector.Add(bad_key, sigs[0], messages[0]));
    CHECK(!collector.Add(pubkey, std::span<const uint8_t>(sigs[0].data(), 63),
                        messages[0]));

    // Single-bit-flip detection and exact failing index bisection
    for (size_t bad_idx : {size_t(0), size_t(1), size_t(73), size_t(128),
                           size_t(255)}) {
        BatchSigCollector corrupted;
        corrupted.Reserve(kBatchCount);
        for (size_t i = 0; i < kBatchCount; ++i) {
            auto s = sigs[i];
            if (i == bad_idx) {
                s[37] ^= (1u << (bad_idx % 8));
            }
            CHECK(corrupted.Add(pubkey, s, messages[i]));
        }
        CHECK(!corrupted.VerifyAll(1));
        CHECK(!corrupted.VerifyAll(4));
        const auto found_st = corrupted.FirstFailingIndex(1);
        const auto found_mt = corrupted.FirstFailingIndex(4);
        CHECK(found_st.has_value() && *found_st == bad_idx);
        CHECK(found_mt.has_value() && *found_mt == bad_idx);
    }
}
} // namespace

int main() {
    BIP340OfficialVector();
    PaymentFixture();
    MintMessage();
    BatchSigCollectorVerificationAndBisection();
    std::cout << "Lotus V2 signing identities and BIP340 vectors pass\n";
}

