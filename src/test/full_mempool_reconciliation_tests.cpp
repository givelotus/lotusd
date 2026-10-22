// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license. See COPYING.
#include <net/full_mempool_reconciliation.h>
#include <arith_uint256.h>
#include <net/v2_protocol_handler.h>
#include <test/util/setup_common.h>
#include <test/util/random.h>
#include <script/script.h>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <set>

using namespace lotus::v2::net;
using V2Hash = lotus::v2::Hash;
namespace {
CTransactionRef Member(FastRandomContext &rng) {
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.emplace_back(COutPoint(TxId{rng.rand256()}, 0));
    tx.vin.front().scriptSig = CScript() << OP_TRUE;
    tx.vout.emplace_back(10000 * SATOSHI, CScript() << OP_TRUE);
    return MakeTransactionRef(std::move(tx));
}
V2Hash Identity(const uint256 &id) {
    V2Hash out;
    std::copy(id.begin(), id.end(), out.begin());
    return out;
}
}
namespace lotus::v2::net::fullrecon {
struct SnapshotIdentityFixture {
    static Snapshot Index(const std::vector<TxIdentityPair> &identities) {
        Snapshot out{{}, 64 * 1024 * 1024};
        out.m_items.reserve(identities.size());
        out.m_nodes.reserve(identities.size() * 2);
        for (const auto &identity : identities)
            out.m_items.push_back({identity.tx_id, identity.tx_hash, {}});
        auto less = [](const Snapshot::Item &a, const Snapshot::Item &b) {
            for (unsigned bit = 0; bit < 256; ++bit) {
                const auto left{(a.id[bit / 8] >> (bit % 8)) & 1};
                const auto right{(b.id[bit / 8] >> (bit % 8)) & 1};
                if (left != right) return left < right;
            }
            return false;
        };
        std::sort(out.m_items.begin(), out.m_items.end(), less);
        if (!out.m_items.empty()) out.Build(0, out.m_items.size());
        return out;
    }
};
}
BOOST_FIXTURE_TEST_SUITE(full_mempool_reconciliation_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(complete_snapshot_native_root_and_generation_lifetime) {
    FastRandomContext rng{uint256{0x98}};
    std::vector<CTransactionRef> txs;
    for (size_t count : {size_t{0}, size_t{1}, size_t{2}, size_t{17}, size_t{4097}}) {
        while (txs.size() < count) txs.push_back(Member(rng));
        const fullrecon::Snapshot snapshot{txs, 32 * 1024 * 1024};
        BOOST_CHECK_EQUAL(snapshot.Root().count, count);
        std::vector<lotus::v2::TxIdentityPair> identities;
        for (const auto &tx : txs)
            identities.push_back({Identity(tx->GetHash()), Identity(tx->GetId())});
        BOOST_CHECK(snapshot.Root().digest == lotus::v2::BuildTxSubtreeA(identities));
        BOOST_CHECK(snapshot.At(fullrecon::Prefix{}).digest == snapshot.Root().digest);
        const auto root_before{snapshot.Root().digest};
        if (count > 1) {
            auto next{txs};
            next.erase(next.begin());
            next.push_back(Member(rng));
            const fullrecon::Snapshot changed{next, 32 * 1024 * 1024};
            BOOST_CHECK(changed.Root().digest != root_before);
            BOOST_CHECK(snapshot.Root().digest == root_before);
        }
    }
}
BOOST_AUTO_TEST_CASE(prefix_pages_are_complete_authenticated_and_bounded) {
    FastRandomContext rng{uint256{0x99}};
    std::vector<CTransactionRef> txs;
    for (size_t i = 0; i < 4097; ++i) txs.push_back(Member(rng));
    const fullrecon::Snapshot snapshot{txs, 32 * 1024 * 1024};
    BOOST_CHECK(!snapshot.Page(fullrecon::Prefix{}, fullrecon::MAX_FRAME_BYTES));
    std::vector<fullrecon::Prefix> pending{fullrecon::Prefix{}};
    std::set<TxId> found;
    while (!pending.empty()) {
        const auto prefix{pending.back()};
        pending.pop_back();
        const auto page{snapshot.Page(prefix, fullrecon::MAX_FRAME_BYTES)};
        if (page) {
            BOOST_CHECK_LE(page->size(), fullrecon::MAX_PAGE_BODIES);
            BOOST_CHECK(fullrecon::Snapshot::PageDigest(prefix, *page) ==
                        snapshot.At(prefix).digest);
            for (const auto &tx : *page) BOOST_CHECK(found.insert(tx->GetId()).second);
        } else {
            BOOST_REQUIRE_LT(prefix.depth, 256U);
            const auto children{snapshot.Children(prefix)};
            BOOST_CHECK(fullrecon::Fold(children, prefix.depth).digest ==
                        snapshot.At(prefix).digest);
            for (unsigned i = 0; i < 16; ++i)
                if (children[i].count) pending.push_back(prefix.Child(i));
        }
    }
    BOOST_CHECK_EQUAL(found.size(), txs.size());
    const fullrecon::Snapshot single{{txs[0]}, 32 * 1024 * 1024};
    BOOST_CHECK(!single.Page(fullrecon::Prefix{}, 1));
    BOOST_CHECK_THROW(fullrecon::Snapshot(txs, 1), std::length_error);
    auto duplicate{txs};
    duplicate.push_back(txs[0]);
    BOOST_CHECK_THROW(fullrecon::Snapshot(duplicate, 32 * 1024 * 1024), std::invalid_argument);
    auto corrupt{txs};
    corrupt[0] = Member(rng);
    BOOST_CHECK(fullrecon::Snapshot(corrupt, 32 * 1024 * 1024).Root().digest != snapshot.Root().digest);
}
BOOST_AUTO_TEST_CASE(adversarial_full_identity_prefixes_and_u64_counts) {
    std::vector<lotus::v2::TxIdentityPair> identities;
    for (uint64_t i = 0; i < 65537; ++i) {
        lotus::v2::TxIdentityPair pair{};
        for (unsigned byte = 0; byte < 8; ++byte)
            pair.tx_id[2 + byte] = pair.tx_hash[byte] = (i >> (8 * byte)) & 255;
        identities.push_back(pair);
    }
    const auto index{fullrecon::SnapshotIdentityFixture::Index(identities)};
    BOOST_CHECK_EQUAL(index.Root().count, 65537U);
    BOOST_CHECK(index.Root().digest == lotus::v2::BuildTxSubtreeA(identities));
    fullrecon::Prefix old_terminal;
    old_terminal.depth = 16;
    BOOST_CHECK_EQUAL(index.At(old_terminal).count, 65537U);
    const auto children{index.Children(old_terminal)};
    BOOST_CHECK(fullrecon::Fold(children, 16).digest == index.At(old_terminal).digest);
    uint64_t total{0};
    for (const auto &child : children) total += child.count;
    BOOST_CHECK_EQUAL(total, 65537U);
    identities.resize(2);
    identities[0].tx_id = {};
    identities[1].tx_id = {};
    identities[1].tx_id[31] = 128; // First differing canonical bit255.
    const auto deepest{fullrecon::SnapshotIdentityFixture::Index(identities)};
    BOOST_CHECK(deepest.Root().digest == lotus::v2::BuildTxSubtreeA(identities));
    fullrecon::Prefix last;
    last.depth = 252;
    BOOST_CHECK_EQUAL(deepest.At(last).count, 2U);
    BOOST_CHECK(fullrecon::Fold(deepest.Children(last), 252).digest == deepest.At(last).digest);
    BOOST_CHECK_EQUAL(deepest.At(last.Child(0)).count, 1U);
    BOOST_CHECK_EQUAL(deepest.At(last.Child(8)).count, 1U);
}
BOOST_AUTO_TEST_CASE(page_decode_exposure_counts_empty_arguments_before_allocation) {
    using namespace fullrecon;
    DataStream frame;
    Header header; header.context = uint256::ONE;
    frame << header << uint64_t{1} << Prefix{} << uint8_t(Work::PAGE) << uint8_t(Status::OK);
    WriteCompactSize(frame, 1);
    frame << uint32_t{7} << uint64_t{0} << uint16_t{2} << uint16_t{0};
    const std::vector<uint8_t> empty_arguments(65535, 0);
    for (int input = 0; input < 2; ++input) {
        frame << TxId{ArithToUint256(arith_uint256(input + 1))} << uint32_t{0}
              << uint32_t{UINT32_MAX} << uint8_t{1};
        WriteCompactSize(frame, 0); // path
        const unsigned witnesses{input ? 15U : 16U};
        WriteCompactSize(frame, witnesses);
        for (unsigned witness = 0; witness < witnesses; ++witness) {
            WriteCompactSize(frame, 0); // script
            WriteCompactSize(frame, 0); // sibling count
            WriteCompactSize(frame, 65535);
            frame.write(AsBytes(Span{empty_arguments}));
        }
    }
    BOOST_REQUIRE_LT(frame.size(), MAX_FRAME_BYTES);
    const auto bytes{Span<const uint8_t>{UCharCast(frame.data()), frame.size()}};
    // One small wire frame can transiently duplicate almost100MB of vector
    // headers. The preflight walks bytes without constructing those vectors.
    BOOST_CHECK_GT(PageDecodeExposure(bytes), 128U * 1024 * 1024);
    DataStream truncated;
    truncated << header << uint64_t{1} << Prefix{} << uint8_t(Work::PAGE) << uint8_t(Status::OK);
    WriteCompactSize(truncated, 1);
    truncated << uint32_t{7} << uint64_t{0} << uint16_t{65535} << uint16_t{65535};
    BOOST_CHECK_THROW(PageDecodeExposure(Span<const uint8_t>{UCharCast(truncated.data()), truncated.size()}), std::ios_base::failure);
    DataStream legacy;
    legacy << header << uint64_t{1} << Prefix{} << uint8_t(Work::PAGE) << uint8_t(Status::OK);
    WriteCompactSize(legacy, 1);
    legacy << uint32_t{2};
    WriteCompactSize(legacy, 0x02000000); // No bytes for even one input.
    BOOST_CHECK_THROW(PageDecodeExposure(Span<const uint8_t>{UCharCast(legacy.data()), legacy.size()}), std::ios_base::failure);
    auto tiny_arguments = [&](bool nonempty) {
        DataStream page;
        page << header << uint64_t{1} << Prefix{} << uint8_t(Work::PAGE) << uint8_t(Status::OK);
        WriteCompactSize(page, 1);
        page << uint32_t{7} << uint64_t{0} << uint16_t{1} << uint16_t{0}
             << TxId{uint256::ONE} << uint32_t{0} << uint32_t{UINT32_MAX} << uint8_t{1};
        WriteCompactSize(page, 0); WriteCompactSize(page, 1);
        WriteCompactSize(page, 0); WriteCompactSize(page, 0);
        WriteCompactSize(page, 512);
        for (int i = 0; i < 512; ++i) {
            WriteCompactSize(page, nonempty ? 1 : 0);
            if (nonempty) page << uint8_t{1};
        }
        return PageDecodeExposure(Span<const uint8_t>{UCharCast(page.data()), page.size()});
    };
    // Heap rounding is charged separately for every one-byte allocation;
    // counting only total payload bytes would badly undercharge this case.
    BOOST_CHECK_GE(tiny_arguments(true) - tiny_arguments(false), 512U * 4U * 8U);
}
BOOST_AUTO_TEST_CASE(native_witness_variants_preserve_exact_hash_identity) {
    CMutableTransaction tx;
    tx.nVersion = 7;
    tx.vin.emplace_back(COutPoint(TxId{uint256::ONE}, 0));
    tx.vin.front().nFlags = 1;
    lotus::v2::BranchWitness witness;
    witness.script = {0x4e};
    witness.arguments = {{1}};
    tx.vin.front().vWitnesses = {witness};
    lotus::v2::Output output;
    output.value = 1000;
    output.branches = {lotus::v2::BranchLeaf(witness.script)};
    output.paths = {{0}};
    tx.vout = {CTxOut::FromV2Output(output)};
    const auto first{MakeTransactionRef(tx)};
    tx.vin.front().vWitnesses.front().arguments = {{2}};
    const auto second{MakeTransactionRef(tx)};
    BOOST_REQUIRE(first->GetId() == second->GetId());
    BOOST_REQUIRE(first->GetHash() != second->GetHash());
    const fullrecon::Snapshot a{{first}, 1024 * 1024}, b{{second}, 1024 * 1024};
    BOOST_CHECK(a.Root().digest != b.Root().digest);
    BOOST_CHECK(fullrecon::Snapshot::PageDigest(fullrecon::Prefix{}, {second}) != a.Root().digest);
    BOOST_CHECK_THROW(fullrecon::Snapshot({first, second}, 1024 * 1024), std::invalid_argument);
}
BOOST_AUTO_TEST_SUITE_END()
