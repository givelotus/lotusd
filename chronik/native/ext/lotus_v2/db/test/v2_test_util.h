// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_TEST_V2_TEST_UTIL_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_TEST_V2_TEST_UTIL_H

#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/db/model.h>

#include <atomic>
#include <filesystem>
#include <functional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

/**
 * Fixtures of the Rust V2 tests: v2_branch.rs fixture_header/fixture_witness/
 * fixture_facts/fixture_genesis and the tests' binding/output/block/op.
 */
namespace chronik::native::lotus_v2::test {

// Test files use lotus_v2 and this namespace, not chronik::native, since
// chronik::native has its own OutPoint/TxId.
using native::Bytes;
using native::ByteView;
namespace postcard = native::postcard;

/** Fresh temporary directory, removed on destruction. */
struct V2TempDir {
    std::filesystem::path path;
    explicit V2TempDir(const std::string &name) {
        static std::atomic<int> counter{0};
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("chronik-native-v2-" + name + "-" + std::to_string(rd()) +
                "-" + std::to_string(counter++));
        std::filesystem::remove_all(path);
    }
    ~V2TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

inline Bytes32 B32(uint8_t b) {
    Bytes32 a;
    a.fill(b);
    return a;
}
inline Hash32 Fill(uint8_t b) { return Hash32{B32(b)}; }

inline ByteView Str(std::string_view s) {
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

/** Whether f() throws a V2Error (optionally of kind/detail). */
inline bool ThrowsV2(const std::function<void()> &f) {
    try {
        f();
    } catch (const V2Error &) {
        return true;
    }
    return false;
}
inline bool ThrowsInvalid(const std::function<void()> &f,
                          std::string_view detail) {
    try {
        f();
    } catch (const V2Error &e) {
        return e.IsInvalid(detail);
    }
    return false;
}
inline bool ThrowsCorrupt(const std::function<void()> &f) {
    try {
        f();
    } catch (const V2Error &e) {
        return e.kind() == V2Error::Kind::Corrupt;
    }
    return false;
}

inline Binding TestBinding() { return Binding{B32(1), B32(2), B32(3)}; }

inline ExplorerBlockFacts FixtureHeader(const Anchor &anchor,
                                        const Anchor &parent) {
    ExplorerBlockFacts facts;
    if (anchor.height > 0) {
        std::copy(parent.block_id.begin(), parent.block_id.end(),
                  facts.header_wire.begin());
    }
    for (int i = 0; i < 8; ++i) {
        facts.header_wire[62 + i] = uint8_t(anchor.height >> (8 * i));
        facts.header_wire[54 + i] = uint8_t(uint64_t(134) >> (8 * i));
    }
    return facts;
}

inline WitnessFact FixtureWitness() {
    return WitnessFact{WireRange{0, 0}, WireRange{0, 1}, 0, WireRange{0, 1},
                       0};
}

inline InputFact CoinbaseInput() {
    InputFact i;
    i.sequence = UINT32_MAX;
    i.flags = 2;
    return i;
}

inline ExplorerTxFacts FixtureFacts(const std::vector<SpentInput> &spends,
                                    const std::vector<Output> &outputs) {
    std::vector<InputFact> inputs;
    for (const SpentInput &spend : spends) {
        while (inputs.size() < spend.input_index) {
            inputs.push_back(CoinbaseInput());
        }
        InputFact i;
        i.prev_txid = spend.outpoint.txid.hash.b;
        i.prev_index = spend.outpoint.out_idx;
        i.sequence = 0;
        i.flags = 1;
        i.witnesses = {FixtureWitness()};
        inputs.push_back(std::move(i));
    }
    if (spends.empty()) {
        for (const Output &output : outputs) {
            if (!output.HasToken()) {
                continue;
            }
            if (std::any_of(inputs.begin(), inputs.end(),
                            [&](const InputFact &i) {
                                return i.prev_txid == output.token_id.b;
                            })) {
                continue;
            }
            InputFact i;
            i.prev_txid = output.token_id.b;
            i.sequence = UINT32_MAX;
            i.flags = 3;
            i.witnesses = {FixtureWitness()};
            inputs.push_back(std::move(i));
        }
    }
    return ExplorerTxFacts{Bytes{0}, 0, std::move(inputs)};
}

inline CommittedBlock FixtureGenesis(std::vector<ConfirmedTx> transactions) {
    const Anchor anchor{B32(2), 0};
    return CommittedBlock{anchor, anchor, std::move(transactions),
                          FixtureHeader(anchor, anchor)};
}

inline Output TestOutput(uint8_t root, bool burn) {
    Output o;
    o.flags = burn ? 2 : 0;
    o.value = 100;
    o.branches = {Fill(root)};
    if (!burn) {
        o.paths = {{0}};
    }
    return o;
}

inline OutPoint Op(uint8_t txid, uint32_t index) {
    return OutPoint{TxId{Fill(txid)}, index};
}

inline CommittedBlock TestBlock(const Anchor &parent, uint8_t id,
                                uint8_t txid, std::vector<Output> outputs,
                                const std::vector<OutPoint> &spent) {
    const Anchor anchor{B32(id), parent.height + 1};
    std::vector<SpentInput> spends;
    for (size_t i = 0; i < spent.size(); ++i) {
        spends.push_back(SpentInput{spent[i], uint32_t(i)});
    }
    ExplorerTxFacts explorer = FixtureFacts(spends, outputs);
    ConfirmedTx tx{TxLocation{H(anchor.block_id), anchor.height, 0,
                              TxId{Fill(txid)}, TxHash{Fill(txid + 1)}},
                   std::move(outputs), std::move(spends), std::move(explorer)};
    return CommittedBlock{anchor, parent, {std::move(tx)},
                          FixtureHeader(anchor, parent)};
}

} // namespace chronik::native::lotus_v2::test

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_TEST_V2_TEST_UTIL_H
