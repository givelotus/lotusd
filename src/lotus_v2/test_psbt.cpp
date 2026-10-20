// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "commitment.h"
#include "psbt.h"

#include <iostream>
#include <stdexcept>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
using namespace lotus::v2::psbt_detail;
using namespace lotus::v2;

Bytes Hex(const std::string &value) {
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("invalid hex");
    };
    CHECK(value.size() % 2 == 0);
    Bytes result;
    for (size_t i = 0; i < value.size(); i += 2) {
        result.push_back(uint8_t(digit(value[i]) * 16 + digit(value[i + 1])));
    }
    return result;
}

std::string HexStr(const Bytes &value) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    for (auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 15]);
    }
    return result;
}

void Maps() {
    const Map original{{{0x01}, {0, 1, 0xff}},
                       {{0xfd, 0xfd, 0}, {0x80, 0}},
                       {{0xfc, 1, 'x', 1, 0}, {}}};
    Bytes wire;
    WriteMap(original, wire);
    Reader reader(wire);
    Map decoded;
    std::string error = "stale";
    CHECK(reader.ReadMap(decoded, 1024, 8192, 4096, error));
    CHECK(reader.Empty() && error.empty() && decoded == original);
    Bytes encoded;
    WriteMap(decoded, encoded);
    CHECK(encoded == wire);

    auto reject = [&](const Bytes &bad, size_t keys = 1024,
                      size_t values = 8192, size_t entries = 4096) {
        const Map saved = decoded;
        Reader invalid(bad);
        CHECK(!invalid.ReadMap(decoded, keys, values, entries, error));
        CHECK(!error.empty() && decoded == saved);
    };
    reject({1, 1, 0, 1, 1, 0, 0}); // Duplicate key, including empty value.
    reject({0xfd, 1, 0, 1, 0, 0}); // Noncanonical key length.
    reject({1, 1, 0xfd, 0, 0, 0}); // Noncanonical value length.
    reject({3, 0xfd, 1, 0, 0, 0}); // Noncanonical key type.
    reject({1, 1, 0});             // No map separator.
    reject({1, 1, 3, 1, 2});       // Truncated value.
    reject({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    reject(wire, 1);
    reject(wire, 1024, 1);
    reject(wire, 1024, 8192, 1);

    Map merged = original;
    CHECK(MergeMap(merged, original, error));
    CHECK(merged == original && error.empty());
    CHECK(MergeMap(merged, Map{{{2}, {3}}}, error));
    const Map saved = merged;
    CHECK(!MergeMap(merged, Map{{{0}, {}}, {{1}, {9}}}, error));
    CHECK(merged == saved && !error.empty());
}

struct Fixture {
    Bytes pubkey =
        Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    Transaction tx;
    Coin coin;
    ChainId chain{};
    NativePsbt psbt;

    Fixture() {
        auto script = pubkey;
        script.insert(script.begin(), 32);
        script.push_back(0xbb);
        Input input;
        input.prev_txid.fill(0x11);
        input.sequence = 0xffffffff;
        input.flags = 1;
        input.witnesses.push_back({script, {}, {}});
        tx.inputs.push_back(input);
        Output output;
        output.value = 90000;
        output.branches = {BranchLeaf(script)};
        output.paths = {{0}};
        tx.outputs.push_back(output);
        coin.outpoint = {input.prev_txid, 0};
        coin.output = output;
        coin.output.value = 100000;
        coin.creation_height = 1;
        coin.creation_parent_mtp = 1000;
        coin.fee_per_output = 100;
        chain.fill(0x42);
        std::string error;
        CHECK(CreateNativePsbt(tx, chain, psbt, error));
    }

    void Fund() {
        CHECK(EncodeCoin(coin, psbt.inputs[0][NativePsbtKey(1)]));
        psbt.inputs[0][NativePsbtKey(2, EncodePsbtWitness(0))] =
            EncodePsbtArguments({{}});
        Bytes request{0, 0};
        request.insert(request.end(), pubkey.begin(), pubkey.end());
        psbt.inputs[0][NativePsbtKey(3, EncodePsbtSlot({0, 0}))] = request;
    }
};

void Codec() {
    Fixture fixture;
    fixture.Fund();
    std::string error;
    NativePsbtData data;
    CHECK(fixture.psbt.Inspect(data, error));
    CHECK(data.inputs[0].coin->creation_parent_mtp == 1000);
    CHECK(data.inputs[0].coin->fee_per_output == 100);
    CHECK(data.inputs[0].coin->expiration_height ==
          ComputeUtxoExpirationHeight(fixture.coin));
    const Bytes opaque_key{0xfc, 1, 'x', 1, 2};
    fixture.psbt.global[opaque_key] = {0, 0xff, 3};
    fixture.psbt.inputs[0][NativePsbtKey(0x80)] = {0xff, 0};
    Bytes wire;
    CHECK(fixture.psbt.Serialize(wire, error));
    NativePsbt decoded;
    CHECK(DecodeNativePsbt(wire, decoded, error));
    Bytes again;
    CHECK(decoded.Serialize(again, error) && again == wire);
    CHECK(decoded.global.at(opaque_key) == Bytes({0, 0xff, 3}));

    auto reject = [&](NativePsbt bad) {
        CHECK(!bad.Inspect(data, error));
        CHECK(!error.empty());
    };
    auto bad = fixture.psbt;
    bad.global[{0}] = {};
    reject(bad);
    bad = fixture.psbt;
    bad.global[NativePsbtKey(0x7f)] = {};
    reject(bad);
    bad = fixture.psbt;
    bad.inputs[0][NativePsbtKey(2, EncodePsbtWitness(1))] = {0};
    reject(bad);
    bad = fixture.psbt;
    bad.inputs[0][NativePsbtKey(2, EncodePsbtWitness(0))] =
        EncodePsbtArguments({{1}});
    reject(bad);
    bad = fixture.psbt;
    auto wrong_coin = fixture.coin;
    wrong_coin.outpoint.index = 1;
    CHECK(EncodeCoin(wrong_coin, bad.inputs[0][NativePsbtKey(1)]));
    reject(bad);
    bad = fixture.psbt;
    bad.global[{4}] = {0xfd, 1, 0};
    reject(bad);
    bad = fixture.psbt;
    bad.inputs[0][NativePsbtKey(4, EncodePsbtSlot({0, 0}))] = Bytes(65);
    reject(bad); // Explicit zero appended mode is not canonical.
    bad = fixture.psbt;
    bad.outputs[0][{1}] = {};
    reject(bad);

    auto nonempty = fixture.tx;
    nonempty.inputs[0].witnesses[0].arguments = {{1}};
    CHECK(!CreateNativePsbt(nonempty, fixture.chain, decoded, error));
    auto coinbase = fixture.tx;
    coinbase.inputs[0].flags = 2;
    CHECK(!CreateNativePsbt(coinbase, fixture.chain, decoded, error));

    auto conflict = fixture.psbt;
    conflict.global[opaque_key] = {4};
    const auto original = fixture.psbt.global;
    CHECK(!fixture.psbt.Merge(conflict, error));
    CHECK(fixture.psbt.global == original);
    conflict = fixture.psbt;
    conflict.global[NativePsbtKey(1)][0] ^= 1;
    CHECK(!fixture.psbt.Merge(conflict, error));
    conflict = fixture.psbt;
    conflict.inputs[0][NativePsbtKey(0x81)] = {4};
    CHECK(fixture.psbt.Merge(conflict, error));
    CHECK(fixture.psbt.inputs[0].contains(NativePsbtKey(0x81)));

    wire.push_back(0);
    CHECK(!DecodeNativePsbt(wire, decoded, error));
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--roundtrip") {
            NativePsbt psbt;
            Bytes wire;
            std::string error;
            if (!DecodeNativePsbt(Hex(argv[2]), psbt, error) ||
                !psbt.Serialize(wire, error))
                throw std::runtime_error(error);
            std::cout << HexStr(wire) << '\n';
            return 0;
        }
        Maps();
        Codec();
        std::cout << "Lotus V2 PSBT tests passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
