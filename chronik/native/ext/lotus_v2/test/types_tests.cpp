// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the bitcoinsuite-core/src/lotus_v2.rs tests, against the same
// fixtures (lotus_v2/fixtures/native_outputs.json).

#include <chronik/native/codec/hex.h>
#include <ext/lotus_v2/types.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <map>
#include <sstream>
#include <string>

using namespace chronik::native;
using namespace chronik::native::lotus_v2;

namespace {

/** The flat {"name": "hex"} JSON object of native output vectors. */
std::map<std::string, Bytes> Fixtures() {
    std::ifstream in(std::string(CHRONIK_NATIVE_LOTUS_V2_FIXTURES_DIR) +
                     "/native_outputs.json");
    BOOST_REQUIRE_MESSAGE(in, "missing lotus_v2/fixtures/native_outputs.json");
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string s = ss.str();
    std::map<std::string, Bytes> out;
    size_t pos = 0;
    while (true) {
        const size_t k0 = s.find('"', pos);
        if (k0 == std::string::npos) {
            break;
        }
        const size_t k1 = s.find('"', k0 + 1);
        const size_t v0 = s.find('"', k1 + 1);
        const size_t v1 = s.find('"', v0 + 1);
        BOOST_REQUIRE(k1 != std::string::npos && v1 != std::string::npos);
        auto bytes = HexDecode(s.substr(v0 + 1, v1 - v0 - 1));
        BOOST_REQUIRE(bytes);
        out[s.substr(k0 + 1, k1 - k0 - 1)] = *bytes;
        pos = v1 + 1;
    }
    BOOST_REQUIRE_EQUAL(out.size(), 4u);
    return out;
}

Hash32 Fill(uint8_t b) {
    Hash32 h;
    h.b.fill(b);
    return h;
}

std::optional<std::string_view> DecodeError(ByteView bytes) {
    OutputError err;
    if (Output::Decode(bytes, &err)) {
        return std::nullopt;
    }
    return err.category;
}

std::optional<std::string_view> ValidateError(const Output &output) {
    auto err = output.Validate();
    return err ? std::optional<std::string_view>(err->category) : std::nullopt;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_types_tests)

BOOST_AUTO_TEST_CASE(native_reference_roundtrips) {
    for (const auto &[name, bytes] : Fixtures()) {
        BOOST_TEST_CONTEXT(name) {
            auto output = Output::Decode(bytes);
            BOOST_REQUIRE(output);
            BOOST_CHECK(*output->Encode() == bytes);
            BOOST_CHECK_EQUAL(output->IsBurn(),
                              name.find("burn") != std::string::npos);
            BOOST_CHECK_EQUAL(output->HasToken(),
                              name.find("token") != std::string::npos);
            if (name == "token") {
                BOOST_CHECK_EQUAL(output->value, UINT64_MAX);
            }
            for (size_t end = 0; end < bytes.size(); ++end) {
                BOOST_CHECK(!Output::Decode(ByteView(bytes).first(end)));
            }
            Bytes extra = bytes;
            extra.push_back(0);
            BOOST_CHECK(DecodeError(extra) == "trailing bytes");
        }
    }
}

BOOST_AUTO_TEST_CASE(structural_bounds_and_order) {
    Output output;
    output.flags = 1;
    output.value = UINT64_MAX;
    output.token_id = Fill(1);
    for (uint8_t i = 0; i < 16; ++i) {
        output.branches.push_back(Fill(i));
        output.paths.push_back({i});
    }
    BOOST_CHECK(Output::Decode(*output.Encode()) == output);
    std::vector<uint8_t> all;
    for (uint8_t i = 0; i < 16; ++i) {
        all.push_back(i);
    }
    output.paths = {all};
    BOOST_CHECK(output.Encode());
    output.paths = {{1, 0}};
    BOOST_CHECK(ValidateError(output) == "path index");
    output.paths = {{1}, {0}};
    BOOST_CHECK(ValidateError(output) == "path order");
    output.paths = {{16}};
    BOOST_CHECK(ValidateError(output) == "path index");
    output.paths = {{0}};
    output.branches[1] = output.branches[0];
    BOOST_CHECK(ValidateError(output) == "duplicate branch");
    BOOST_CHECK(DecodeError(Bytes(813, 0)) == "output bytes");
}

BOOST_AUTO_TEST_CASE(validation_rejects_non_native_models) {
    const auto base = *Output::Decode(Fixtures().at("native"));
    const struct {
        uint8_t flags;
        Hash32 token_id;
        std::string_view expected;
    } cases[] = {
        {4, Hash32{}, "flags"},
        {1, Hash32{}, "zero token"},
        {0, Fill(1), "native token field"},
        {2, Hash32{}, "burn paths"},
    };
    for (const auto &c : cases) {
        Output bad = base;
        bad.flags = c.flags;
        bad.token_id = c.token_id;
        BOOST_CHECK(ValidateError(bad) == c.expected);
    }
    {
        Output bad = base;
        bad.branches.clear();
        BOOST_CHECK(ValidateError(bad) == "branch count");
        for (uint8_t i = 0; i < 17; ++i) {
            bad.branches.push_back(Fill(i));
        }
        BOOST_CHECK(ValidateError(bad) == "branch count");
    }
    {
        Output bad = base;
        bad.paths.clear();
        BOOST_CHECK(ValidateError(bad) == "path count");
        bad.paths.assign(17, {0});
        BOOST_CHECK(ValidateError(bad) == "path count");
    }
    Transaction tx;
    tx.lock = UINT64_MAX;
    BOOST_CHECK_EQUAL(tx.lock, UINT64_MAX);
    BOOST_CHECK_EQUAL(OutputError{"flags"}.Message(),
                      "invalid Lotus V2 output: flags");
}

BOOST_AUTO_TEST_CASE(malformed_native_frames) {
    const Bytes bytes = Fixtures().at("native");
    const struct {
        size_t offset;
        uint8_t value;
        std::string_view error;
    } cases[] = {
        {0, 4, "flags"},
        {9, 17, "branch count"},
        {9, 0, "path count"},
        {44, 1, "path index"},
        {43, 0, "trailing bytes"},
    };
    for (const auto &c : cases) {
        Bytes bad = bytes;
        bad[c.offset] = c.value;
        BOOST_CHECK(DecodeError(bad) == c.error);
    }
    Bytes bad = bytes;
    bad.erase(bad.begin() + 9);
    const uint8_t compact[] = {253, 1, 0};
    bad.insert(bad.begin() + 9, std::begin(compact), std::end(compact));
    BOOST_CHECK(DecodeError(bad) == "branch count");
    Bytes burn = bytes;
    burn[0] = 2;
    BOOST_CHECK(DecodeError(burn) == "burn paths");
}

BOOST_AUTO_TEST_SUITE_END()
