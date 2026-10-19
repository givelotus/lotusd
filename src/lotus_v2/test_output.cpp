#include "output.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);             \
    } while (false)

namespace {
std::vector<uint8_t> FromHex(const std::string &hex) {
    if (hex.size() & 1) throw std::runtime_error("odd hex");
    auto digit = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        throw std::runtime_error("bad hex");
    };
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back((digit(hex[i]) << 4) | digit(hex[i + 1]));
    return bytes;
}

void Accept(const std::vector<uint8_t> &wire) {
    Output parsed;
    std::string error;
    CHECK(DecodeOutput(wire, parsed, error));
    CHECK(error.empty());
    std::vector<uint8_t> roundtrip;
    CHECK(EncodeOutput(parsed, roundtrip, error));
    CHECK(roundtrip == wire);
}

void Reject(const std::vector<uint8_t> &wire) {
    Output parsed;
    parsed.value = 777;
    std::string error;
    CHECK(!DecodeOutput(wire, parsed, error));
    CHECK(!error.empty());
    CHECK(parsed.value == 777);
}

void FixedVectors() {
    // Fixed Python-reference v1 fixture wires, checked as literal expectations.
    const auto native = FromHex("00e80300000000000001a88cef369f758aec3e594eaa4e"
                                "8d08c9f12ef3f11bea972ec53a416a148f0605010100");
    const auto burn = FromHex("02f40100000000000001a88cef369f758aec3e594eaa4e8d"
                              "08c9f12ef3f11bea972ec53a416a148f060500");
    const auto token =
        FromHex("01ffffffffffffffff01000000000000000000000000000000000000000000"
                "00000000000000000000020000000000000000000000000000000000000000"
                "00000000000000000000000001000000000000000000000000000000000000"
                "000000000000000000000000000301000200010101");
    const auto token_burn =
        FromHex("03000000000000000001000000000000000000000000000000000000000000"
                "00000000000000000000010000000000000000000000000000000000000000"
                "00000000000000000000000000");
    for (const auto &wire : {native, burn, token, token_burn})
        Accept(wire);

    for (const auto &wire : {native, burn, token, token_burn}) {
        for (size_t n = 0; n < wire.size(); ++n)
            Reject({wire.begin(), wire.begin() + n});
    }
    auto extra = native;
    extra.push_back(0);
    Reject(extra);
    auto invalid = native;
    invalid[0] = 4;
    Reject(invalid);
    invalid = native;
    invalid[9] = 17;
    Reject(invalid);
    invalid = native;
    invalid[9] = 0;
    Reject(invalid);
    invalid = native;
    invalid.back() = 1;
    Reject(invalid);
    invalid = native;
    invalid[43] = 0;
    Reject(invalid); // empty spendable path
    invalid = native;
    invalid.insert(invalid.begin() + 9, {253, 1, 0});
    invalid.erase(invalid.begin() + 12);
    Reject(invalid);
    invalid = native;
    invalid[42] = 253;
    invalid.insert(invalid.begin() + 43, {1, 0});
    Reject(invalid); // nonminimal path count
    invalid = native;
    invalid[0] = 1;
    invalid.insert(invalid.begin() + 9, 32, 0);
    Reject(invalid);
    invalid = native;
    invalid[0] = 2;
    Reject(invalid); // burn with path
    invalid = native;
    invalid[9] = 2;
    invalid.insert(invalid.begin() + 42, native.begin() + 10,
                   native.begin() + 42);
    Reject(invalid); // duplicate branch
    invalid = native;
    invalid[42] = 2;
    Reject(invalid); // too many paths for bytes

    // Maximum 844-byte output (token + state root): 16 branches; 15 unique 15-index subsets plus
    // the full 16-index path produce 16 lexicographically ordered paths.
    Output largest;
    largest.flags = 1;
    largest.value = UINT64_MAX;
    largest.token_id[0] = 1;
    for (uint8_t i = 0; i < 16; ++i) {
        Hash32 b{};
        b[0] = i;
        largest.branches.push_back(b);
    }
    for (uint8_t missing = 0; missing < 15; ++missing) {
        std::vector<uint8_t> path;
        for (uint8_t i = 0; i < 16; ++i)
            if (i != missing) path.push_back(i);
        largest.paths.push_back(std::move(path));
    }
    std::vector<uint8_t> full;
    for (uint8_t i = 0; i < 16; ++i)
        full.push_back(i);
    largest.paths.push_back(std::move(full));
    std::sort(largest.paths.begin(), largest.paths.end());
    std::vector<uint8_t> encoded;
    std::string error;
    CHECK(EncodeOutput(largest, encoded, error));
    CHECK(encoded.size() == 812); // largest stateless output
    largest.flags = 5;
    largest.state_root[31] = 9;
    CHECK(EncodeOutput(largest, encoded, error));
    CHECK(encoded.size() == MAX_OUTPUT_BYTES && MAX_OUTPUT_BYTES == 844);
    Accept(encoded);
    auto over = encoded;
    over.push_back(0);
    Reject(over);
    std::swap(largest.paths[0], largest.paths[1]);
    CHECK(!EncodeOutput(largest, encoded, error));
    std::swap(largest.paths[0], largest.paths[1]);
    largest.paths[0][1] = largest.paths[0][0];
    CHECK(!EncodeOutput(largest, encoded, error));
    largest.paths[0][1] = 2;
    largest.paths.push_back({0});
    CHECK(!EncodeOutput(largest, encoded, error));
}

void StateRoot() {
    // HAS_STATE (0x04): the 32-byte state root follows the token id.
    const auto native = FromHex("00e80300000000000001a88cef369f758aec3e594eaa4e"
                                "8d08c9f12ef3f11bea972ec53a416a148f0605010100");
    Hash32 root{};
    root[0] = 0x5a;
    root[31] = 0x01;
    auto stateful = native;
    stateful[0] = 4;
    stateful.insert(stateful.begin() + 9, root.begin(), root.end());
    Accept(stateful);
    Output parsed;
    std::string error;
    CHECK(DecodeOutput(stateful, parsed, error));
    CHECK(parsed.HasState() && !parsed.HasToken() && parsed.state_root == root);
    for (size_t n = 0; n < stateful.size(); ++n)
        Reject({stateful.begin(), stateful.begin() + n});

    // Token + state (0x05): flags | value | token | state root | ...
    Hash32 token{};
    token[0] = 1;
    auto both = stateful;
    both[0] = 5;
    both.insert(both.begin() + 9, token.begin(), token.end());
    Accept(both);
    CHECK(DecodeOutput(both, parsed, error));
    CHECK(parsed.token_id == token && parsed.state_root == root);

    // A zero state root is ambiguous with "no state" and is invalid.
    auto zero = native;
    zero[0] = 4;
    zero.insert(zero.begin() + 9, 32, 0);
    Reject(zero);
    // Burn outputs never carry state: 0x06 and 0x07 are invalid.
    const auto burn = FromHex("02f40100000000000001a88cef369f758aec3e594eaa4e8d"
                              "08c9f12ef3f11bea972ec53a416a148f060500");
    auto state_burn = burn;
    state_burn[0] = 6;
    state_burn.insert(state_burn.begin() + 9, root.begin(), root.end());
    Reject(state_burn);
    auto token_state_burn = state_burn;
    token_state_burn[0] = 7;
    token_state_burn.insert(token_state_burn.begin() + 9, token.begin(),
                            token.end());
    Reject(token_state_burn);
    for (unsigned flag = 8; flag < 256; flag <<= 1) {
        auto high = stateful;
        high[0] = uint8_t(4 | flag);
        Reject(high);
    }
    // 0xf8 alone (and every high bit) is rejected.
    auto f8 = native;
    f8[0] = 0xf8;
    Reject(f8);

    // Encoder rejects a state root without the flag and a flag without root.
    Output model;
    CHECK(DecodeOutput(native, model, error));
    model.state_root = root;
    std::vector<uint8_t> out;
    CHECK(!EncodeOutput(model, out, error));
    model.state_root = Hash32{};
    model.flags = 4;
    CHECK(!EncodeOutput(model, out, error));
    model.state_root = root;
    CHECK(EncodeOutput(model, out, error) && out == stateful);
    // Distinct state roots give distinct output bytes.
    Output other = model;
    other.state_root[5] ^= 1;
    std::vector<uint8_t> other_out;
    CHECK(EncodeOutput(other, other_out, error) && other_out != out);
}

void Corpus(const char *path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open corpus");
    std::string line;
    size_t count = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        Accept(FromHex(line));
        ++count;
    }
    if (count != 256) throw std::runtime_error("corpus count mismatch");
}
} // namespace

int main(int argc, char **argv) {
    FixedVectors();
    StateRoot();
    if (argc > 1) Corpus(argv[1]);
    std::cout
        << "Lotus V2 output codec: native vectors and rejection cases pass\n";
}
