// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-lib/src/v2tests/tests.rs tests that do not need the
// HTTP server (start_v2_server is not part of this port).

#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/service/service.h>
#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <thread>

using namespace chronik::native::lotus_v2;
namespace f = chronik::native::lotus_v2::ffi;
using chronik::native::lotus_v2::test::Fill;
using chronik::native::lotus_v2::test::V2TempDir;

namespace {

f::ServiceLimits Limits() {
    return f::ServiceLimits{32'000'000, 4096, 65536, 256, 16,
                            1,          4096, 8192,  4096};
}

f::Binding TestBinding() {
    f::Binding b;
    b.chain_id.fill(1);
    b.genesis.fill(2);
    b.profile.fill(3);
    return b;
}

f::Bytes32 Fill32(uint8_t b) {
    f::Bytes32 a;
    a.fill(b);
    return a;
}

f::Anchor Tip(uint8_t id, uint64_t height) {
    return f::Anchor{Fill32(id), height};
}

std::array<uint8_t, 134> Header(uint64_t height, uint8_t parent) {
    std::array<uint8_t, 134> h{};
    if (height > 0) {
        std::fill(h.begin(), h.begin() + 32, parent);
    }
    for (int i = 0; i < 8; ++i) {
        h[62 + i] = uint8_t(height >> (8 * i));
        h[54 + i] = uint8_t(uint64_t(134) >> (8 * i));
    }
    return h;
}

f::WireRange Range(uint64_t offset, uint64_t length) {
    return f::WireRange{offset, length};
}

std::vector<f::NativeFullInput> FullInputs(const std::vector<f::Input> &inputs) {
    std::vector<f::NativeFullInput> full;
    for (const f::Input &i : inputs) {
        while (full.size() < i.input_index) {
            f::NativeFullInput pad;
            pad.sequence = UINT32_MAX;
            pad.flags = 2;
            full.push_back(pad);
        }
        f::NativeFullInput spend;
        spend.prev_txid = i.txid;
        spend.prev_index = i.out_idx;
        spend.flags = 1;
        spend.witnesses = {
            f::NativeWitness{Range(0, 0), Range(0, 1), 0, Range(0, 1), 0}};
        full.push_back(spend);
    }
    return full;
}

f::NativeBlock Block(uint8_t id, uint64_t height, uint8_t parent, uint8_t tx,
                     const std::vector<f::Input> &inputs) {
    Output output;
    output.value = UINT64_MAX;
    output.branches = {Fill(9)};
    output.paths = {{0}};
    f::NativeTx native;
    native.txid = Fill32(tx);
    native.txhash = Fill32(tx + 1);
    native.inputs = inputs;
    native.full_inputs = FullInputs(inputs);
    native.wire = {0};
    native.outputs = {f::NativeOutput{*output.Encode()}};
    return f::NativeBlock{Tip(id, height),
                          Tip(parent, height == 0 ? 0 : height - 1),
                          {native},
                          Header(height, parent)};
}

f::BranchRequest Request(bool utxos) {
    return f::BranchRequest{
        {f::Root{Fill32(9)}}, {}, utxos, false, EmptyContinuation()};
}

std::unique_ptr<V2Service> Open(const V2TempDir &dir, const f::Binding &binding,
                                bool fresh, const f::ServiceLimits &limits) {
    return V2Service::Open(dir.path.string(), binding, fresh, limits,
                           chronik::native::test::TestSha256);
}

bool Fails(const std::function<void()> &fn) {
    try {
        fn();
    } catch (const V2ServiceError &) {
        return true;
    }
    return false;
}

/**
 * Independent canonical transport encoder: exercise each actual field,
 * rather than duplicating the service's fixed-overhead accounting constants.
 */
std::vector<uint8_t> EncodedPage(const f::BranchPage &page) {
    std::vector<uint8_t> out;
    const auto raw = [&](const auto &bytes) {
        out.insert(out.end(), bytes.begin(), bytes.end());
    };
    const auto le = [&](auto v) {
        for (size_t i = 0; i < sizeof(v); ++i) {
            out.push_back(uint8_t(uint64_t(v) >> (8 * i)));
        }
    };
    const auto anchor = [&](const f::Anchor &a) {
        raw(a.block_id);
        le(a.height);
    };
    const auto loc = [&](const f::Location &l) {
        anchor(l.anchor);
        le(l.tx_index);
        raw(l.txid);
        raw(l.txhash);
    };
    const auto vec = [&](const std::vector<uint8_t> &b) {
        le(uint32_t(b.size()));
        raw(b);
    };
    anchor(page.anchor);
    raw(page.chain_id);
    raw(page.profile);
    le(uint32_t(page.matches.size()));
    for (const f::OutputMatch &m : page.matches) {
        raw(m.txid);
        le(m.out_idx);
        vec(m.wire);
        loc(m.creation);
        out.push_back(m.spent);
        loc(m.spend);
        le(m.input_index);
        vec(m.matching_positions);
    }
    const f::Continuation &c = page.cursor;
    out.push_back(c.present);
    out.push_back(c.version);
    raw(c.chain_id);
    raw(c.profile);
    anchor(c.anchor);
    raw(c.filter_digest);
    out.push_back(c.has_last);
    raw(c.last_txid);
    le(c.last_out_idx);
    le(page.posting_reads);
    le(page.work);
    le(page.encoded_bytes);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_service_tests)

BOOST_AUTO_TEST_CASE(explicit_genesis_complete_spend_disconnect_reopen) {
    V2TempDir path("service");
    BOOST_CHECK(Fails([&] { Open(path, TestBinding(), false, Limits()); }));
    auto service = Open(path, TestBinding(), true, Limits());
    BOOST_CHECK(!service->GetStatus(Tip(2, 0)).initialized);
    BOOST_CHECK(Fails([&] { service->QueryBranches(Request(true)); }));
    BOOST_CHECK(Fails(
        [&] { service->InitializeGenesis(Block(99, 0, 99, 10, {})); }));
    service->InitializeGenesis(Block(2, 0, 2, 10, {}));
    const f::BranchPage page = service->QueryBranches(Request(true));
    BOOST_REQUIRE_EQUAL(page.matches.size(), 1u);
    BOOST_CHECK_EQUAL(Output::Decode(page.matches[0].wire)->value, UINT64_MAX);
    BOOST_CHECK(page.encoded_bytes <= 4096);
    const f::Continuation cursor = page.cursor;
    BOOST_CHECK(service->GetStatus(Tip(2, 0)).ready);
    BOOST_CHECK(!service->GetStatus(Tip(4, 1)).ready);
    const f::Input input{Fill32(10), 0, 3};
    service->ConnectBlock(Block(4, 1, 2, 12, {input}));
    f::BranchRequest stale = Request(true);
    stale.cursor = cursor;
    BOOST_CHECK(Fails([&] { service->QueryBranches(stale); }));
    const f::BranchPage history = service->QueryBranches(Request(false));
    BOOST_CHECK_EQUAL(history.encoded_bytes, EncodedPage(history).size());
    BOOST_CHECK(history.matches[0].spent);
    BOOST_CHECK_EQUAL(history.matches[0].input_index, 3u);
    BOOST_CHECK(service->QueryBranches(Request(true)).matches[0].txid ==
                Fill32(12));
    {
        // Rust moves the clone into the thread; it must not outlive it.
        const V2Service shared = service->CloneShared();
        bool shared_ready = false;
        std::thread([&] { shared_ready = shared.GetStatus(Tip(4, 1)).ready; })
            .join();
        BOOST_CHECK(shared_ready);
    }
    service->DisconnectBlock(Tip(4, 1));
    BOOST_CHECK(service->QueryBranches(Request(true)).matches[0].txid ==
                Fill32(10));
    service.reset();
    service = Open(path, TestBinding(), false, Limits());
    BOOST_CHECK(service->GetStatus(Tip(2, 0)).ready);
    service.reset();
    f::Binding foreign = TestBinding();
    foreign.profile.fill(42);
    BOOST_CHECK(Fails([&] { Open(path, foreign, false, Limits()); }));
    BOOST_CHECK(Fails([&] { Open(path, TestBinding(), true, Limits()); }));
}

BOOST_AUTO_TEST_CASE(input_and_response_caps_preserve_checkpoint) {
    V2TempDir path("service");
    f::ServiceLimits caps = Limits();
    caps.changes = 1;
    auto service = Open(path, TestBinding(), true, caps);
    service->InitializeGenesis(Block(2, 0, 2, 10, {}));
    f::NativeBlock large = Block(4, 1, 2, 12, {});
    large.transactions[0].outputs.push_back(
        f::NativeOutput{std::vector<uint8_t>(MAX_COIN_OUTPUT_BYTES + 1, 0)});
    BOOST_CHECK(Fails([&] { service->ConnectBlock(large); }));
    f::NativeBlock oversized = Block(4, 1, 2, 12, {});
    oversized.transactions[0].outputs[0].wire =
        std::vector<uint8_t>(MAX_COIN_OUTPUT_BYTES + 1, 0);
    BOOST_CHECK(Fails([&] { service->ConnectBlock(oversized); }));
    f::NativeBlock malformed = Block(4, 1, 2, 12, {});
    malformed.transactions[0].index = 7;
    BOOST_CHECK(Fails([&] { service->ConnectBlock(malformed); }));
    BOOST_CHECK(service->GetStatus(Tip(2, 0)).ready);
    f::BranchRequest invalid = Request(true);
    invalid.positions = {f::Position{16, {f::Root{Fill32(9)}}}};
    BOOST_CHECK(Fails([&] { service->QueryBranches(invalid); }));
    f::BranchRequest many = Request(true);
    many.any_branch = std::vector<f::Root>(257, f::Root{Fill32(9)});
    BOOST_CHECK(Fails([&] { service->QueryBranches(many); }));
    service.reset();
    caps = Limits();
    caps.response_bytes = 512;
    service = Open(path, TestBinding(), false, caps);
    BOOST_CHECK(Fails([&] { service->QueryBranches(Request(true)); }));
}

BOOST_AUTO_TEST_CASE(exact_transport_response_and_block_boundaries) {
    V2TempDir path("service");
    auto service = Open(path, TestBinding(), true, Limits());
    const f::NativeBlock genesis = Block(2, 0, 2, 10, {});
    BOOST_CHECK_EQUAL(genesis.transactions[0].outputs[0].wire.size(), 45u);
    service->InitializeGenesis(genesis);
    const f::BranchPage page = service->QueryBranches(Request(true));
    const auto encoded = EncodedPage(page);
    BOOST_CHECK_EQUAL(encoded.size(), 618u);
    BOOST_CHECK_EQUAL(page.encoded_bytes, encoded.size());
    service.reset();
    for (const auto &[cap, ok] : std::vector<std::pair<uint32_t, bool>>{
             {600, false}, {617, false}, {618, true}, {619, true}}) {
        f::ServiceLimits caps = Limits();
        caps.response_bytes = cap;
        const auto capped = Open(path, TestBinding(), false, caps);
        std::optional<f::BranchPage> result;
        try {
            result = capped->QueryBranches(Request(true));
        } catch (const V2ServiceError &) {
        }
        BOOST_CHECK_MESSAGE(result.has_value() == ok, "cap " << cap);
        if (result) {
            const auto bytes = EncodedPage(*result);
            BOOST_CHECK_EQUAL(result->encoded_bytes, bytes.size());
            BOOST_CHECK(bytes.size() <= cap);
        }
    }
    // block_bytes is the consensus block-size limit: a header-only block
    // needs 134 wire bytes.
    f::ServiceLimits caps = Limits();
    caps.block_bytes = 133;
    caps.transactions = 1;
    caps.changes = 1;
    // Counts above what a block within the limit can hold are refused.
    f::ServiceLimits over = caps;
    over.transactions = 3;
    V2TempDir refused("service");
    BOOST_CHECK(Fails([&] { Open(refused, TestBinding(), true, over); }));
    over = caps;
    over.changes = uint32_t(Bounds(caps.block_bytes).Changes() + 1);
    V2TempDir refused_changes("service");
    BOOST_CHECK(
        Fails([&] { Open(refused_changes, TestBinding(), true, over); }));
    V2TempDir other("service");
    service = Open(other, TestBinding(), true, caps);
    const f::NativeBlock empty{Tip(2, 0), Tip(2, 0), {}, Header(0, 2)};
    BOOST_CHECK(Fails([&] { service->InitializeGenesis(empty); }));
    BOOST_CHECK(!service->GetStatus(Tip(2, 0)).initialized);
    service.reset();
    caps.block_bytes = 134;
    service = Open(other, TestBinding(), false, caps);
    service->InitializeGenesis(empty);
    BOOST_CHECK(service->GetStatus(Tip(2, 0)).ready);
}

BOOST_AUTO_TEST_SUITE_END()
