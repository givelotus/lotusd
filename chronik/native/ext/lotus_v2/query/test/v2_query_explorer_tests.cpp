// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-indexer/src/query/v2_explorer_query_tests.rs tests.

#include <ext/lotus_v2/db/explorer.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/query/explorer.h>

#include <boost/test/unit_test.hpp>

#include <map>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::query_explorer;
using chronik::native::lotus_v2::test::B32;
using chronik::native::lotus_v2::test::Bytes;
using chronik::native::lotus_v2::test::Fill;
using chronik::native::lotus_v2::test::ThrowsV2;

namespace {

struct Fixture final : ExplorerSource {
    std::optional<TxMeta> tx;
    Bytes wire;
    mutable size_t reads = 0;
    std::map<uint64_t, BlockMeta> blocks;

    Fixture() {
        const TxLocation location{Fill(1), 2, 0, TxId{Fill(2)},
                                  TxHash{Fill(3)}};
        for (size_t i = 0; i < WIRE_CHUNK_BYTES * 2 + 7; ++i) {
            wire.push_back(uint8_t(i % 251));
        }
        tx = TxMeta{location, UINT64_MAX, 0, 0, 0, 0, wire.size(), 0};
        for (uint64_t height = 0; height < 3; ++height) {
            BlockMeta b;
            b.anchor = Anchor{height == 2 ? B32(1) : B32(uint8_t(height + 5)),
                              height};
            b.tx_count = height == 2 ? 1 : 0;
            blocks[height] = b;
        }
    }

    std::optional<BlockMeta> Block(const Hash32 &id) const override {
        for (const auto &[h, b] : blocks) {
            if (b.anchor.block_id == id.b) {
                return b;
            }
        }
        return std::nullopt;
    }
    std::optional<BlockMeta> BlockAtHeight(uint64_t h) const override {
        const auto it = blocks.find(h);
        if (it == blocks.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    std::optional<TxMeta> Transaction(const TxId &id) const override {
        if (tx && tx->location.txid == id) {
            return tx;
        }
        return std::nullopt;
    }
    std::optional<TxMeta> TransactionByHash(const TxHash &h) const override {
        if (tx && tx->location.txhash == h) {
            return tx;
        }
        return std::nullopt;
    }
    std::optional<std::pair<TxId, TxHash>>
    BlockTransaction(const Hash32 &b, uint32_t i) const override {
        if (tx && tx->location.block_id == b && tx->location.tx_index == i) {
            return std::make_pair(tx->location.txid, tx->location.txhash);
        }
        return std::nullopt;
    }
    std::optional<InputMeta> GetInput(const TxId &, uint32_t) const override {
        return std::nullopt;
    }
    std::optional<WitnessFact> Witness(const TxId &, uint32_t,
                                       uint32_t) const override {
        return std::nullopt;
    }
    std::optional<OutputRecord> GetOutput(const OutPoint &) const override {
        return std::nullopt;
    }
    std::optional<Bytes> Wire(const TxId &, uint32_t chunk) const override {
        ++reads;
        const size_t start = size_t(chunk) * WIRE_CHUNK_BYTES;
        if (start >= wire.size()) {
            return std::nullopt;
        }
        const size_t end = std::min(wire.size(), start + WIRE_CHUNK_BYTES);
        return Bytes(wire.begin() + start, wire.begin() + end);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_query_explorer_tests)

BOOST_AUTO_TEST_CASE(exact_chunks_reconstruct_frame_with_at_most_two_reads) {
    const Fixture f;
    const TxId id = f.tx->location.txid;
    Bytes full;
    uint64_t offset = 0;
    while (true) {
        const size_t before = f.reads;
        const WireChunk chunk = *GetWireChunk(f, id, offset, 32768);
        BOOST_CHECK(f.reads - before <= 2);
        full.insert(full.end(), chunk.bytes.begin(), chunk.bytes.end());
        if (!chunk.next_offset) {
            break;
        }
        BOOST_CHECK(*chunk.next_offset > offset);
        offset = *chunk.next_offset;
    }
    BOOST_CHECK(full == f.wire);
    const WireChunk cross = *GetWireChunk(f, id, 32767, 32768);
    BOOST_CHECK(cross.bytes ==
                Bytes(f.wire.begin() + 32767, f.wire.begin() + 65535));
    const WireChunk end = *GetWireChunk(f, id, f.wire.size(), 1);
    BOOST_CHECK(end.bytes.empty());
    BOOST_CHECK(!end.next_offset);
    BOOST_CHECK(ThrowsV2([&] { GetWireChunk(f, id, f.wire.size() + 1, 1); }));
    BOOST_CHECK(ThrowsV2([&] { GetWireChunk(f, id, 0, 0); }));
    BOOST_CHECK(ThrowsV2([&] { GetWireChunk(f, id, 0, 32769); }));
}

BOOST_AUTO_TEST_CASE(typed_identity_and_decimal_integers_are_exact) {
    const Fixture f;
    const TxMeta &tx = *f.tx;
    BOOST_CHECK(f.TransactionByHash(tx.location.txhash) == tx);
    BOOST_CHECK(!f.Transaction(TxId{tx.location.txhash.hash}));
    BOOST_CHECK_EQUAL(UnsignedDecimal(UINT64_MAX), "18446744073709551615");
    BOOST_CHECK_EQUAL(UnsignedDecimal(~U128(0)),
                      "340282366920938463463374607431768211455");
    BOOST_CHECK_EQUAL(Confirmations(2, 2), 1u);
    BOOST_CHECK(ThrowsV2([&] { Confirmations(1, 2); }));
    BOOST_CHECK(ThrowsV2([&] { Confirmations(UINT64_MAX, 0); }));
}

BOOST_AUTO_TEST_CASE(pages_advance_and_reorg_removes_canonical_objects) {
    Fixture f;
    const TxMeta tx = *f.tx;
    const auto first = BlocksPage(f, 2, std::nullopt, 1);
    BOOST_CHECK_EQUAL(first.items[0].anchor.height, 2u);
    BOOST_CHECK(first.next_index == uint64_t(2));
    const auto second = BlocksPage(f, 2, first.next_index, 2);
    BOOST_REQUIRE_EQUAL(second.items.size(), 2u);
    BOOST_CHECK_EQUAL(second.items[0].anchor.height, 1u);
    BOOST_CHECK_EQUAL(second.items[1].anchor.height, 0u);
    BOOST_CHECK(second.exhausted);
    const auto txs =
        BlockTransactionsPage(f, tx.location.block_id, std::nullopt, 1);
    BOOST_REQUIRE(txs);
    BOOST_CHECK(txs->items == std::vector<TxMeta>{tx});
    BOOST_CHECK(txs->exhausted);
    BOOST_CHECK(ThrowsV2([&] { BlocksPage(f, 2, std::nullopt, 101); }));
    f.tx.reset();
    f.blocks.erase(2);
    BOOST_CHECK(!GetWireChunk(f, tx.location.txid, 0, 32));
    BOOST_CHECK(
        !BlockTransactionsPage(f, tx.location.block_id, std::nullopt, 1));
    BOOST_CHECK(ThrowsV2([&] { BlocksPage(f, 2, std::nullopt, 1); }));
}

BOOST_AUTO_TEST_CASE(oversize_indivisible_record_errors_without_stuck_cursor) {
    // Rust's `()` item is uint32_t here (explicitly instantiated types only).
    BOOST_CHECK(ThrowsV2([&] {
        OrdinalPage<uint32_t>(1, std::nullopt, 1, 0, 1, [](uint32_t) {
            return std::make_pair(uint32_t(0), MAX_PAGE_BYTES + 1);
        });
    }));
    const auto page =
        OrdinalPage<uint32_t>(3, std::nullopt, 3, 0, 1, [](uint32_t i) {
            return std::make_pair(i, MAX_PAGE_BYTES / 2);
        });
    BOOST_CHECK(page.items == (std::vector<uint32_t>{0, 1}));
    BOOST_CHECK_EQUAL(page.examined, 3u);
    BOOST_CHECK_EQUAL(page.key_reads, 3u);
    BOOST_CHECK(page.next_index == uint64_t(1));
    BOOST_CHECK(!page.exhausted);
    BOOST_CHECK(ThrowsV2([&] {
        OrdinalPage<uint32_t>(2, uint64_t(2), 1, 0, 1, [](uint32_t) {
            return std::make_pair(uint32_t(0), size_t(1));
        });
    }));
}

BOOST_AUTO_TEST_SUITE_END()
