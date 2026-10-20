// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "psbt_signing.h"

#include "address.h"
#include "commitment.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
PsbtBytes Hex(const char *text) {
    auto digit = [](char c) -> uint8_t {
        return c <= '9' ? c - '0' : c - 'a' + 10;
    };
    PsbtBytes result;
    for (size_t i = 0; text[i]; i += 2) {
        result.push_back(uint8_t(digit(text[i]) * 16 + digit(text[i + 1])));
    }
    return result;
}

OrdinaryCandidateProfile Profile() {
    OrdinaryCandidateProfile result{
        DefaultTxProfile,
        VmProfile{10000, 65535, 8192, 65535, 65535, 1048576, 64, 100000},
        VmCostProfile{},
        100,
        50000,
        2,
        100,
        10000000};
    result.vm_cost.max_invocation_cost = 1000000;
    result.vm_cost.structural_byte_cost = 1;
    for (auto &opcode : result.vm_cost.opcode)
        opcode = {1, 1, 1};
    return result;
}

struct Fixture {
    std::vector<PsbtBytes> public_keys{
        Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        Hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179"
            "8")};
    std::vector<Coin> coins;
    NativePsbt psbt;
    ChainId chain{};

    explicit Fixture(uint8_t mode = 0, bool keyhash = false) {
        chain.fill(0x42);
        Transaction tx;
        for (size_t i = 0; i < 2; ++i) {
            const std::span<const uint8_t, 32> key(public_keys[i].data(), 32);
            PsbtBytes script;
            if (keyhash) {
                script = KeyHashProgram(NativeKeyHash(key));
            } else {
                script = {32};
                script.insert(script.end(), key.begin(), key.end());
                script.push_back(0xbb);
            }
            Hash sibling{};
            sibling.fill(0x50 + uint8_t(i));
            Input input;
            input.prev_txid.fill(0x11 + uint8_t(i));
            input.flags = 1;
            input.sequence = 0xffffffff;
            input.path_index = 1;
            input.witnesses = {{script, {sibling}, {}}};
            tx.inputs.push_back(input);
            Output output;
            output.value = 90000;
            output.branches = {BranchLeaf(PsbtBytes{0x4e}),
                               BranchNode(BranchLeaf(script), sibling)};
            output.paths = {{0}, {1}};
            tx.outputs.push_back(output);
            Coin coin;
            coin.outpoint = {input.prev_txid, 0};
            coin.output = output;
            coin.output.value = 100000;
            coin.output.flags = OUTPUT_FLAG_HAS_STATE;
            coin.output.state_root.fill(0x70 + uint8_t(i));
            coin.creation_height = 1;
            coin.creation_parent_mtp = 1000;
            coin.fee_per_output = 10;
            coins.push_back(coin);
        }
        std::string error;
        CHECK(CreateNativePsbt(tx, chain, psbt, error));
        for (size_t i = 0; i < coins.size(); ++i) {
            CHECK(EncodeCoin(coins[i], psbt.inputs[i][NativePsbtKey(1)]));
            PsbtArguments args{{}};
            if (keyhash) args.push_back(public_keys[i]);
            psbt.inputs[i][NativePsbtKey(2, EncodePsbtWitness(0))] =
                EncodePsbtArguments(args);
            PsbtBytes request{0, mode};
            request.insert(request.end(), public_keys[i].begin(),
                           public_keys[i].end());
            psbt.inputs[i][NativePsbtKey(3, EncodePsbtSlot({0, 0}))] = request;
            psbt.inputs[i][NativePsbtKey(0x80)] = {0, 0xff};
        }
    }

    NativePsbtContext Context() {
        return {chain, Profile(),
                [this](const Outpoint &outpoint, Coin &coin, std::string &) {
                    for (const auto &trusted : coins) {
                        if (trusted.outpoint == outpoint) {
                            coin = trusted;
                            return CoinReadResult::Found;
                        }
                    }
                    return CoinReadResult::Missing;
                },
                std::nullopt, false};
    }

    NativePsbtKeyLookup Keys(size_t index) {
        return [this, index](std::span<const uint8_t> key,
                             std::array<uint8_t, 32> &secret) {
            if (!std::ranges::equal(key, public_keys[index])) return false;
            secret.fill(0);
            secret[31] = index == 0 ? 3 : 1;
            return true;
        };
    }
};

void TwoSigners(uint8_t mode, bool keyhash) {
    Fixture fixture(mode, keyhash);
    auto context = fixture.Context();
    std::string error;
    size_t slots;
    std::array<uint8_t, 32> aux{}; // Fixed test entropy only.
    auto first = fixture.psbt;
    auto second = fixture.psbt;
    const auto template_wire = first.global.at(NativePsbtKey(2));
    if (mode != 0) {
        CHECK(!SignNativePsbt(first, context, fixture.Keys(0), aux, slots,
                              error));
        context.allow_partial_modes = true;
    }
    NativePsbtReview review;
    CHECK(ReviewNativePsbt(first, context, review, error));
    CHECK(review.native_fee == 20000);
    CHECK(SignNativePsbt(first, context, fixture.Keys(0), aux, slots, error) &&
          slots == 1);
    Transaction extracted;
    CHECK(!FinalizeNativePsbt(first, context, extracted, error));
    CHECK(SignNativePsbt(second, context, fixture.Keys(1), aux, slots, error) &&
          slots == 1);
    CHECK(first.Merge(second, error));
    CHECK(FinalizeNativePsbt(first, context, extracted, error));
    CHECK(first.global.at(NativePsbtKey(2)) == template_wire);
    CHECK(first.inputs[0].at(NativePsbtKey(0x80)) == PsbtBytes({0, 0xff}));
    CHECK(extracted.inputs[0].witnesses[0].siblings.size() == 1);
    CHECK(extracted.inputs[0].path_index == 1);
    CHECK(!extracted.outputs[0].HasState());
    CHECK(extracted.inputs[0].witnesses[0].arguments[0].size() ==
          (mode ? 65 : 64));
    NativePsbtData data;
    CHECK(first.Inspect(data, error));
    CHECK(data.inputs[0].coin->output.HasState());
    IdentityDigests before, after;
    CHECK(ComputeIdentities(data.tx_template, DefaultTxProfile, fixture.chain,
                            before, error));
    CHECK(ComputeIdentities(extracted, DefaultTxProfile, fixture.chain, after,
                            error));
    CHECK(before.txid == after.txid && before.txhash != after.txhash);
    CHECK(FinalizeNativePsbt(first, context, extracted, error));

    auto tampered = first;
    auto &signature =
        tampered.inputs[0][NativePsbtKey(4, EncodePsbtSlot({0, 0}))];
    signature[0] ^= 1;
    CHECK(!FinalizeNativePsbt(tampered, context, extracted, error));
    tampered = first;
    tampered.inputs[0][NativePsbtKey(5, EncodePsbtWitness(0))].back() ^= 1;
    CHECK(!FinalizeNativePsbt(tampered, context, extracted, error));
    tampered = fixture.psbt;
    context.chain_id[0] ^= 1;
    CHECK(
        !SignNativePsbt(tampered, context, fixture.Keys(0), aux, slots, error));
}

void AuthenticationAndFailures() {
    Fixture fixture;
    auto context = fixture.Context();
    std::string error;
    size_t slots;
    std::array<uint8_t, 32> aux{};
    auto psbt = fixture.psbt;
    auto counterfeit = fixture.coins[0];
    ++counterfeit.fee_per_output;
    CHECK(EncodeCoin(counterfeit, psbt.inputs[0][NativePsbtKey(1)]));
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    CHECK(slots == 0);
    psbt = fixture.psbt;
    context.lookup = {};
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    context = fixture.Context();
    context.profile.candidate_height =
        ComputeUtxoExpirationHeight(fixture.coins[0]);
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));

    // Proofs authenticate exactly the complete Coin-v2 bytes to an external
    // root. Supplying that same root inside the PSBT alone gives no trust.
    UtxoSet set;
    for (const auto &coin : fixture.coins)
        CHECK(set.Insert(coin));
    const auto root = set.Root();
    psbt.global[NativePsbtKey(3)] = PsbtBytes(root.begin(), root.end());
    for (size_t i = 0; i < fixture.coins.size(); ++i) {
        auto proof = set.Prove(fixture.coins[i].outpoint);
        PsbtBytes wire(proof.bitmap.begin(), proof.bitmap.end());
        psbt_detail::Compact(proof.siblings.size(), wire);
        for (const auto &sibling : proof.siblings)
            wire.insert(wire.end(), sibling.begin(), sibling.end());
        psbt.inputs[i][NativePsbtKey(6)] = wire;
    }
    context = fixture.Context();
    context.lookup = {};
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    context.trusted_utxo_root = root;
    CHECK(SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    CHECK(slots == 1);
    psbt.inputs[0][NativePsbtKey(6)].back() ^= 1;
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(1), aux, slots, error));

    // Update adds authentic metadata but cannot replace coordinator-supplied
    // conflicts. Incomplete metadata is allowed in transport, not signing.
    psbt = fixture.psbt;
    psbt.inputs[0].erase(NativePsbtKey(1));
    context = fixture.Context();
    CHECK(!SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    CHECK(UpdateNativePsbt(psbt, context, error));
    CHECK(SignNativePsbt(psbt, context, fixture.Keys(0), aux, slots, error));
    psbt = fixture.psbt;
    CHECK(EncodeCoin(counterfeit, psbt.inputs[0][NativePsbtKey(1)]));
    CHECK(!UpdateNativePsbt(psbt, context, error));

    // A key provider returning the wrong private key cannot add a signature.
    psbt = fixture.psbt;
    auto wrong_key = [](std::span<const uint8_t>,
                        std::array<uint8_t, 32> &secret) {
        secret.fill(0);
        secret[31] = 9;
        return true;
    };
    CHECK(!SignNativePsbt(psbt, context, wrong_key, aux, slots, error));
    CHECK(slots == 0);
}
} // namespace

int main() {
    try {
        for (uint8_t mode = 0; mode < 3; ++mode) {
            TwoSigners(mode, false);
            TwoSigners(mode, true);
        }
        AuthenticationAndFailures();
        std::cout << "Lotus V2 authenticated PSBT signing tests passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
