// Copyright (c) 2026 The Lotus developers
// In-memory ConnectOrdinaryBlock spend of one BIP340 CHECKSIG witness.
// Not lotusd ConnectTip and not a claim that lotusd accepted a block.
#include "block.h"

#include "commitment.h"
#include "signing.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) throw std::runtime_error(message);
}

// 0x4e is the numeric literal 1, used only as the created output's branch.
// The spent coin commits the CHECKSIG script below, not this byte.
const std::vector<uint8_t> TRUE_SCRIPT{0x4e};
const MonetaryProfile kMonetary{2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, Hash{9}};
// BIP340 test-vector secret (scalar 3). Mode 0 is a 64-byte signature; a
// trailing sighash byte is only present for modes 1 and 2.
const std::array<uint8_t, 32> kAux{};

OrdinaryCandidateProfile MakeProfile() {
    OrdinaryCandidateProfile profile{
        TxProfile{32, 32, 8, 512, 8, 8192, 64},
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 100000},
        VmCostProfile{}, 100, 50000, 2, 3, 1000000};
    profile.vm_cost.max_invocation_cost = 1000000;
    profile.vm_cost.structural_byte_cost = 1;
    for (auto &opcode : profile.vm_cost.opcode) opcode = {1, 1, 1};
    return profile;
}

Hash Chain() {
    Hash chain{};
    for (size_t i = 0; i < chain.size(); ++i)
        chain[i] = static_cast<uint8_t>(i);
    return chain;
}

std::array<uint8_t, 32> SecretKey() {
    std::array<uint8_t, 32> secret{};
    secret[31] = 3;
    return secret;
}

std::vector<uint8_t> XOnlyPublicKey(const std::array<uint8_t, 32> &secret) {
    using ContextPtr =
        std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>;
    ContextPtr ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN),
                   secp256k1_context_destroy);
    Check(static_cast<bool>(ctx), "secp256k1 context");
    secp256k1_keypair pair;
    Check(secp256k1_keypair_create(ctx.get(), &pair, secret.data()) == 1,
          "BIP340 secret rejected by the linked library");
    secp256k1_xonly_pubkey xonly;
    Check(secp256k1_keypair_xonly_pub(ctx.get(), &xonly, nullptr, &pair) == 1,
          "x-only public key");
    std::vector<uint8_t> pubkey(32);
    Check(secp256k1_xonly_pubkey_serialize(ctx.get(), pubkey.data(), &xonly) ==
              1,
          "serialize x-only public key");
    return pubkey;
}

// Push the 32-byte x-only key, then CHECKSIG (0xbb). The signature is a
// witness argument: the script leaf is inside the sighash, so the signature
// cannot live in the script.
std::vector<uint8_t> ChecksigScript(const std::vector<uint8_t> &pubkey) {
    Check(pubkey.size() == 32, "pubkey width");
    std::vector<uint8_t> script;
    script.reserve(34);
    script.push_back(0x20);
    script.insert(script.end(), pubkey.begin(), pubkey.end());
    script.push_back(0xbb);
    return script;
}

MonetaryState InitialMoney() {
    MonetaryState money;
    money.bootstrap_reserve = 9;
    money.tail_subsidy = 200;
    money.prev_work[0] = 9;
    money.ema_block_cost = 4;
    return money;
}

Coin MakeFunding(const Hash &branch) {
    Coin coin;
    coin.outpoint.tx_id[0] = 0x71;
    coin.outpoint.index = 3;
    coin.output.flags = 0;
    coin.output.value = 20000;
    coin.output.branches = {branch};
    coin.output.paths = {{0}};
    coin.creation_height = 90;
    coin.creation_parent_mtp = 49000;
    coin.coinbase = false;
    return coin;
}

struct World {
    DevelopmentUtxoView view;
    IncrementalUtxoSet utxo;
    MonetaryState monetary = InitialMoney();
    OrdinaryParentContext parent;
    Coin funding;
    explicit World(const std::vector<uint8_t> &locking_script) {
        funding = MakeFunding(BranchLeaf(locking_script));
        Check(view.emplace(funding.outpoint, funding).second &&
                  utxo.Insert(funding),
              "parent coin");
        parent.chain_id = Chain();
        parent.monetary = monetary;
        parent.header.height = 99;
        parent.header.time = 50000;
        parent.header.version = 1;
        parent.header.size = HEADER_SIZE;
        parent.header.state_root = StateRoot(
            parent.chain_id, parent.header.height, utxo.Root(), monetary);
    }
};

struct ParentBytes {
    std::vector<std::vector<uint8_t>> coins;
    Hash utxo{};
    std::array<uint8_t, 56> monetary{};
    Hash state{};
};

ParentBytes Capture(const World &world) {
    ParentBytes snap;
    for (const auto &entry : world.view) {
        Check(entry.first == entry.second.outpoint, "view outpoint");
        std::vector<uint8_t> encoded;
        Check(EncodeCoin(entry.second, encoded), "encode parent coin");
        snap.coins.push_back(std::move(encoded));
    }
    snap.utxo = world.utxo.Root();
    snap.monetary = EncodeMonetaryState(world.monetary);
    snap.state = world.parent.header.state_root;
    return snap;
}

void ExpectParent(const World &world, const ParentBytes &parent,
                  const std::string &where) {
    const ParentBytes now = Capture(world);
    Check(now.coins == parent.coins, where + " view is not the parent coins");
    Check(now.utxo == parent.utxo, where + " utxo root moved");
    Check(now.monetary == parent.monetary, where + " monetary bytes moved");
    Check(StateRoot(world.parent.chain_id, world.parent.header.height,
                    world.utxo.Root(), world.monetary) == parent.state,
          where + " state root moved");
}

bool Connect(World &world, const Transaction &tx,
             const OrdinaryCandidateProfile &profile,
             OrdinaryBlockConnected &connected, std::string &error) {
    return ConnectOrdinaryBlock({tx}, world.parent, profile, kMonetary,
                                world.view, world.utxo, world.monetary,
                                connected, error);
}

Transaction Spend(const Outpoint &spent, const std::vector<uint8_t> &script,
                  const std::vector<uint8_t> &signature) {
    Transaction tx;
    Input input;
    input.prev_txid = spent.tx_id;
    input.prev_index = spent.index;
    input.sequence = UINT32_MAX;
    input.flags = 1;
    input.path_index = 0;
    input.witnesses = {BranchWitness{script, {}, {signature}}};
    tx.inputs.push_back(input);
    Output output;
    output.value = 15000;
    output.branches = {BranchLeaf(TRUE_SCRIPT)};
    output.paths = {{0}};
    tx.outputs.push_back(output);
    return tx;
}

struct SignedSpend {
    Transaction tx;
    Hash message{};
    std::vector<uint8_t> signature;
};

SignedSpend SignSpend(const World &world, const std::vector<uint8_t> &script,
                      const std::vector<uint8_t> &pubkey,
                      const OrdinaryCandidateProfile &profile) {
    SignedSpend spend;
    spend.tx = Spend(world.funding.outpoint, script, std::vector<uint8_t>(64));
    Check(spend.tx.inputs[0].witnesses[0].script == script &&
              world.funding.output.branches.size() == 1 &&
              world.funding.output.branches[0] == BranchLeaf(script),
          "parent locking script is not the executed witness script");
    const ResolvedCoins resolved{world.funding.output};
    std::string error;
    Check(SigningMessage(spend.tx, profile.transaction, world.parent.chain_id,
                         resolved, 0, 0, 0, std::nullopt, spend.message, error),
          "sighash: " + error);
    Check(SignBip340Message(SecretKey(), spend.message, 0, kAux,
                            spend.signature, error),
          "SignBip340Message: " + error);
    Check(spend.signature.size() == 64, "mode 0 signature width");
    Check(VerifyBip340Signature(pubkey, spend.signature, spend.message,
                                false) == SignatureStatus::Valid,
          "VerifyBip340Signature rejected the signature just produced");
    spend.tx.inputs[0].witnesses[0].arguments = {spend.signature};
    Hash again{};
    Check(SigningMessage(spend.tx, profile.transaction, world.parent.chain_id,
                         resolved, 0, 0, 0, std::nullopt, again, error),
          "sighash after signature: " + error);
    Check(again == spend.message, "witness signature changed the sighash");
    return spend;
}

void ChecksigSpendConnectsAndMutationRestoresParent() {
    const std::vector<uint8_t> pubkey = XOnlyPublicKey(SecretKey());
    const auto vector_key = std::vector<uint8_t>{
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f,
        0x85, 0xf8, 0x9d, 0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f,
        0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9};
    Check(pubkey == vector_key, "linked library x-only key is not BIP340 vector 0");
    const std::vector<uint8_t> script = ChecksigScript(pubkey);
    const OrdinaryCandidateProfile profile = MakeProfile();
    World world(script);
    const ParentBytes parent = Capture(world);
    const SignedSpend spend = SignSpend(world, script, pubkey, profile);

    Transaction mutated = spend.tx;
    mutated.inputs[0].witnesses[0].arguments[0][0] ^= 0x01;
    Check(VerifyBip340Signature(
              pubkey, mutated.inputs[0].witnesses[0].arguments[0],
              spend.message, false) == SignatureStatus::InvalidSignature,
          "mutated signature was still valid");
    OrdinaryBlockConnected discarded;
    std::string error;
    Check(!Connect(world, mutated, profile, discarded, error),
          "mutated CHECKSIG signature was accepted");
    Check(error == "witness VM invalid/unsupported: CHECKSIG NULLFAIL",
          "mutated CHECKSIG rejection: " + error);
    ExpectParent(world, parent, "mutated signature");

    OrdinaryBlockConnected connected;
    error.clear();
    if (!Connect(world, spend.tx, profile, connected, error)) {
        throw std::runtime_error(
            "VerifyBip340Signature accepted the signature but "
            "ConnectOrdinaryBlock rejected it: " +
            error);
    }
    Check(world.utxo.Root() == connected.utxo_root &&
              world.utxo.Root() != parent.utxo,
          "CHECKSIG spend did not move the utxo root");
    Check(EncodeMonetaryState(world.monetary) == connected.monetary_bytes &&
              connected.monetary_bytes != parent.monetary,
          "CHECKSIG spend did not move monetary bytes");
    Check(world.view.count(world.funding.outpoint) == 0,
          "parent CHECKSIG coin was not spent");
    IdentityDigests ids;
    Check(ComputeIdentities(spend.tx, profile.transaction, world.parent.chain_id,
                            ids, error),
          "CHECKSIG spend identity");
    Check(world.view.count(Outpoint{ids.txid, 0}) == 1 && world.view.size() == 1,
          "CHECKSIG output missing");
    Check(connected.invocation_cost > 0, "CHECKSIG invocation was free");
}
} // namespace

int main() {
    try {
        ChecksigSpendConnectsAndMutationRestoresParent();
        std::cout << "ordinary CHECKSIG connect checks passed\n";
        return 0;
    } catch (const std::exception &failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
