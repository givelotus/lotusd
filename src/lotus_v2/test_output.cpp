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

    // Maximum 812-byte output: 16 branches; 15 unique 15-index subsets plus
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
    CHECK(encoded.size() == MAX_OUTPUT_BYTES);
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
    if (argc > 1) Corpus(argv[1]);
    std::cout
        << "Lotus V2 output codec: native vectors and rejection cases pass\n";
}
