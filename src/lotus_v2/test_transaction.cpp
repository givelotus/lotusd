#include "transaction.h"

#include <algorithm>
#include <fstream>
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
std::vector<uint8_t> FromHex(const std::string &hex) {
    CHECK(hex.size() % 2 == 0);
    auto digit = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        throw std::runtime_error("bad hex");
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back((digit(hex[i]) << 4) | digit(hex[i + 1]));
    return out;
}

const TxProfile PROFILE{32, 32, 8, 8192, 16, 8192, 64};

void Accept(const std::vector<uint8_t> &wire) {
    Transaction decoded;
    std::string error;
    CHECK(DecodeTransaction(wire, PROFILE, decoded, error));
    CHECK(error.empty());
    std::vector<uint8_t> encoded;
    CHECK(EncodeTransaction(decoded, PROFILE, encoded, error));
    CHECK(encoded == wire);
}

void Reject(const std::vector<uint8_t> &wire) {
    Transaction unchanged;
    unchanged.lock = 99;
    std::string error;
    CHECK(!DecodeTransaction(wire, PROFILE, unchanged, error));
    CHECK(!error.empty());
    CHECK(unchanged.lock == 99);
}

void FixedPayment() {
    // Literal P01 assembly, also checked by independent Python reference.
    const auto wire = FromHex(
        "07000000000000000000000001000100"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000ffffffff010001014e00010161"
        "00e80300000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec5"
        "3a416a148f0605010100");
    Accept(wire);
    Transaction tx;
    std::string error;
    CHECK(DecodeTransaction(wire, PROFILE, tx, error));
    CHECK(tx.inputs.size() == 1 && tx.outputs.size() == 1);
    CHECK(tx.inputs[0].witnesses[0].arguments[0] == std::vector<uint8_t>{'a'});
    std::vector<uint8_t> core;
    CHECK(EncodeInputCore(tx.inputs[0], PROFILE, core, error));
    CHECK(core ==
          FromHex(std::string(64, '1') + "00000000ffffffff010001014e00"));
    std::vector<uint8_t> full_input;
    CHECK(EncodeInputFull(tx.inputs[0], PROFILE, full_input, error));
    CHECK(std::equal(full_input.begin(), full_input.end(), wire.begin() + 16));
    CHECK(full_input != core);
    tx.inputs[0].witnesses[0].arguments[0] = {'b'};
    std::vector<uint8_t> mutated;
    CHECK(EncodeTransaction(tx, PROFILE, mutated, error));
    CHECK(mutated != wire);
    std::vector<uint8_t> new_core;
    CHECK(EncodeInputCore(tx.inputs[0], PROFILE, new_core, error));
    CHECK(new_core == core);

    for (size_t n = 0; n < wire.size(); ++n)
        Reject({wire.begin(), wire.begin() + n});
    auto invalid = wire;
    invalid.push_back(0);
    Reject(invalid);
    invalid = wire;
    invalid[0] = 1;
    Reject(invalid);
    invalid = wire;
    invalid[4] = 3;
    Reject(invalid);
    invalid = wire;
    invalid[5] = 1;
    Reject(invalid);
    invalid = wire;
    invalid[12] = 255;
    invalid[13] = 255;
    Reject(invalid);
    invalid = wire;
    invalid[14] = 255;
    invalid[15] = 255;
    Reject(invalid);
    invalid = wire;
    invalid[56] = 2;
    Reject(invalid); // malformed coinbase shape
    invalid = wire;
    invalid[57] = 253;
    invalid.insert(invalid.begin() + 58, {0, 0});
    Reject(invalid);
    invalid = wire;
    invalid[58] = 0;
    Reject(invalid); // missing spend witness
    invalid = wire;
    invalid[58] = 17;
    Reject(invalid); // witness cap

    tx.inputs.push_back(tx.inputs[0]);
    CHECK(
        !EncodeTransaction(tx, PROFILE, mutated, error)); // duplicate outpoint
}

void ArgumentElementBound() {
    Transaction tx;
    Input spend;
    spend.prev_txid[0] = 1;
    spend.sequence = UINT32_MAX;
    spend.flags = 1;
    spend.witnesses.resize(1);
    spend.witnesses[0].script = {0x51};
    spend.witnesses[0].arguments = {std::vector<uint8_t>(8192, 0x41)};
    tx.inputs.push_back(spend);
    std::vector<uint8_t> wire;
    std::string error;
    CHECK(EncodeTransaction(tx, PROFILE, wire, error));
    Transaction decoded;
    CHECK(DecodeTransaction(wire, PROFILE, decoded, error));
    CHECK(decoded.inputs[0].witnesses[0].arguments[0].size() == 8192);

    tx.inputs[0].witnesses[0].arguments[0].push_back(0x41);
    CHECK(!EncodeTransaction(tx, PROFILE, wire, error));
    TxProfile excessive = PROFILE;
    excessive.max_argument_bytes = 8193;
    CHECK(!EncodeTransaction(tx, excessive, wire, error));
    CHECK(!DecodeTransaction(wire, excessive, decoded, error));
}

void Mint() {
    const auto payment = FromHex(
        "07000000000000000000000001000100"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000ffffffff010001014e00010161"
        "00e80300000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec5"
        "3a416a148f0605010100");
    Transaction tx;
    std::string error;
    CHECK(DecodeTransaction(payment, PROFILE, tx, error));
    Input mint;
    const auto root = FromHex(
        "a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605");
    std::copy(root.begin(), root.end(), mint.prev_txid.begin());
    mint.sequence = UINT32_MAX;
    mint.flags = 3;
    mint.witnesses.push_back(BranchWitness{{0x4e}, {}, {{'b'}}});
    tx.inputs.push_back(mint);
    tx.lock = 2;
    std::vector<uint8_t> wire;
    CHECK(EncodeTransaction(tx, PROFILE, wire, error));
    Accept(wire);
    for (size_t n = 0; n < wire.size(); ++n)
        Reject({wire.begin(), wire.begin() + n});
    const auto core = [&] {
        std::vector<uint8_t> bytes;
        CHECK(EncodeInputCore(mint, PROFILE, bytes, error));
        return bytes;
    }();
    tx.inputs[1].witnesses[0].arguments[0] = {'c'};
    std::vector<uint8_t> different;
    CHECK(EncodeTransaction(tx, PROFILE, different, error) &&
          different != wire);
    std::vector<uint8_t> same_core;
    CHECK(EncodeInputCore(tx.inputs[1], PROFILE, same_core, error) &&
          same_core == core);
    tx.inputs[1].prev_index = 1;
    CHECK(!EncodeTransaction(tx, PROFILE, different, error));
    tx.inputs[1].prev_index = 0;
    tx.inputs[1].sequence = 0;
    CHECK(!EncodeTransaction(tx, PROFILE, different, error));
}

void Coinbase() {
    const auto payment = FromHex(
        "07000000000000000000000001000100"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000ffffffff010001014e00010161"
        "00e80300000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec5"
        "3a416a148f0605010100");
    Transaction tx;
    std::string error;
    CHECK(DecodeTransaction(payment, PROFILE, tx, error));
    tx.lock = 0;
    tx.inputs[0].flags = 2;
    tx.inputs[0].path_index = 0;
    tx.inputs[0].prev_index = 12;
    tx.inputs[0].prev_txid.fill(7);
    tx.inputs[0].witnesses.clear();
    std::vector<uint8_t> absent;
    CHECK(EncodeTransaction(tx, PROFILE, absent, error));
    CHECK(absent[57] == 0);
    Accept(absent);
    std::vector<uint8_t> core;
    CHECK(EncodeInputCore(tx.inputs[0], PROFILE, core, error));
    CHECK(std::equal(core.begin(), core.end(), absent.begin() + 16));
    CHECK(CheckCoinbaseContext(tx, tx.inputs[0].prev_txid, 12, error));
    CHECK(!CheckCoinbaseContext(tx, tx.inputs[0].prev_txid,
                                uint64_t(UINT32_MAX) + 1, error));
    Hash32 wrong{};
    CHECK(!CheckCoinbaseContext(tx, wrong, 12, error));

    tx.inputs[0].has_coinbase_data = true;
    tx.inputs[0].coinbase_data = {0x5e, 0x4c, 0x00}; // opaque opcode-like bytes
    std::vector<uint8_t> present;
    CHECK(EncodeTransaction(tx, PROFILE, present, error));
    CHECK(present[57] == 1 && present[58] == 3);
    CHECK(present != absent);
    CHECK(present ==
          FromHex(
              "07000000000000000000000001000100"
              "0707070707070707070707070707070707070707070707070707070707070707"
              "0c000000ffffffff0201035e4c00"
              "00e80300000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea"
              "972ec53a416a148f0605010100"));
    Accept(present);
    std::vector<uint8_t> present_core;
    CHECK(EncodeInputCore(tx.inputs[0], PROFILE, present_core, error));
    CHECK(present_core != core);
    CHECK(std::equal(present_core.begin(), present_core.end(),
                     present.begin() + 16));
    tx.inputs[0].coinbase_data.assign(8192, 0x5e);
    std::vector<uint8_t> maximum;
    CHECK(EncodeTransaction(tx, PROFILE, maximum, error));
    Accept(maximum);
    tx.inputs[0].coinbase_data.push_back(0);
    CHECK(!EncodeTransaction(tx, PROFILE, maximum, error));
    tx.inputs[0].coinbase_data.clear();
    CHECK(!EncodeTransaction(tx, PROFILE, maximum, error));

    auto invalid = absent;
    invalid[57] = 2;
    Reject(invalid);
    invalid = absent;
    invalid[57] = 1;
    invalid.insert(invalid.begin() + 58, 0);
    Reject(invalid); // present empty data
    invalid = present;
    invalid[58] = 253;
    invalid.insert(invalid.begin() + 59, {3, 0});
    Reject(invalid); // nonminimal Bytes length
    for (size_t n = 0; n < present.size(); ++n)
        Reject({present.begin(), present.begin() + n});
    tx.inputs[0].coinbase_data = {'x'};
    tx.outputs[0].flags = 1;
    tx.outputs[0].token_id[0] = 1;
    CHECK(!EncodeTransaction(tx, PROFILE, maximum, error));
}

void Corpus(const char *path) {
    std::ifstream file(path);
    CHECK(file.good());
    std::string line;
    size_t count = 0;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            Accept(FromHex(line));
            ++count;
        }
    }
    CHECK(count == 128);
}
} // namespace

// Consensus caps inputs and outputs at 256 each (I-6); profiles may only
// tighten them, and the u16 wire count does not raise them.
void CountCaps() {
    const auto wire = FromHex(
        "07000000000000000000000001000100"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000ffffffff010001014e00010161"
        "00e80300000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec5"
        "3a416a148f0605010100");
    Transaction tx;
    std::string error;
    CHECK(DecodeTransaction(wire, DefaultTxProfile, tx, error));
    CHECK(DefaultTxProfile.max_inputs == 256 &&
          DefaultTxProfile.max_outputs == 256 && MAX_TX_INPUTS == 256 &&
          MAX_TX_OUTPUTS == 256);
    tx.outputs.resize(256, tx.outputs[0]);
    std::vector<uint8_t> encoded;
    CHECK(EncodeTransaction(tx, DefaultTxProfile, encoded, error));
    Transaction decoded;
    CHECK(DecodeTransaction(encoded, DefaultTxProfile, decoded, error));
    tx.outputs.push_back(tx.outputs[0]);
    CHECK(!EncodeTransaction(tx, DefaultTxProfile, encoded, error));
    // The 256-output wire with its u16 count bumped to 257 and one more
    // output appended is rejected by the count check.
    tx.outputs.pop_back();
    CHECK(EncodeTransaction(tx, DefaultTxProfile, encoded, error));
    // Output count is the u16 at offset 14 (after version and lock).
    CHECK(encoded[14] == 0x00 && encoded[15] == 0x01);
    std::vector<uint8_t> over = encoded;
    over[14] = 0x01;
    const auto first_output =
        std::vector<uint8_t>(encoded.end() - 45, encoded.end());
    over.insert(over.end(), first_output.begin(), first_output.end());
    CHECK(!DecodeTransaction(over, DefaultTxProfile, decoded, error) &&
          error == "transaction count");
    TxProfile loose = DefaultTxProfile;
    loose.max_inputs = 257;
    CHECK(!EncodeTransaction(tx, loose, encoded, error) && error == "profile");
    loose = DefaultTxProfile;
    loose.max_outputs = 65535;
    CHECK(!DecodeTransaction(wire, loose, decoded, error) &&
          error == "profile");
}
int main(int argc, char **argv) {
    CountCaps();
    FixedPayment();
    ArgumentElementBound();
    Mint();
    Coinbase();
    if (argc > 1) Corpus(argv[1]);
    std::cout
        << "Lotus V2 transaction framing: native vectors and rejections pass\n";
}
