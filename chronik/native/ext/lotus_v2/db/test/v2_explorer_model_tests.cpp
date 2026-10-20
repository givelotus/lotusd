// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-db/src/v2_explorer_model_tests.rs tests.

#include <chronik/native/codec/seahash.h>
#include <ext/lotus_v2/db/explorer.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::test;

namespace {

CommittedBlock Fixture() {
    const Anchor anchor{B32(3), 1};
    const Anchor parent{B32(2), 0};
    ExplorerBlockFacts header;
    std::copy(parent.block_id.begin(), parent.block_id.end(),
              header.header_wire.begin());
    header.header_wire[62] = 1;
    const TxLocation location{H(anchor.block_id), 1, 0, TxId{Fill(4)},
                              TxHash{Fill(5)}};
    InputFact input;
    input.prev_txid = B32(2);
    input.prev_index = 1;
    input.sequence = UINT32_MAX;
    input.flags = 2;
    input.path_index = 255;
    input.has_coinbase_data = true;
    input.coinbase_data = WireRange{WIRE_CHUNK_BYTES, 3};
    input.witnesses = {WitnessFact{WireRange{20, 0}, WireRange{21, 1}, 0,
                                   WireRange{22, 1}, 0}};
    ConfirmedTx tx{location,
                   {},
                   {},
                   ExplorerTxFacts{Bytes(WIRE_CHUNK_BYTES + 3, 42), UINT64_MAX,
                                   {input}},
                   TxPos{3, 128}};
    return CommittedBlock{anchor, parent, {tx}, header};
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_explorer_model_tests)

BOOST_AUTO_TEST_CASE(complete_native_facts_and_chunk_entries_roundtrip) {
    const CommittedBlock block = Fixture();
    const ExplorerTxFacts &facts = block.transactions[0].explorer;
    BOOST_CHECK(codec::Decode<ExplorerTxFacts>(codec::Encode(facts)) == facts);
    BOOST_CHECK(codec::Decode<ExplorerBlockFacts>(
                    codec::Encode(block.explorer)) == block.explorer);
    const std::vector<std::pair<Bytes, Bytes>> entries =
        PlanExplorerBlock(block);
    const TxId id = block.transactions[0].location.txid;
    const auto find = [&](const Bytes &key) {
        const auto it =
            std::find_if(entries.begin(), entries.end(),
                         [&](const auto &kv) { return kv.first == key; });
        BOOST_REQUIRE(it != entries.end());
        return it->second;
    };
    const TxMeta tx_meta = DecodeRecord<TxMeta>(find(TxKey(id)));
    BOOST_CHECK_EQUAL(tx_meta.file_num, 3u);
    BOOST_CHECK_EQUAL(tx_meta.data_pos, 128u);
    BOOST_CHECK_EQUAL(tx_meta.wire_size, facts.wire.size());
    BOOST_CHECK_EQUAL(tx_meta.wire_checksum, chronik::native::SeaHash(facts.wire));
    BOOST_CHECK(std::none_of(
        entries.begin(), entries.end(), [](const auto &kv) {
            return kv.first.size() >= 2 && kv.first[0] == 'e' &&
                   kv.first[1] == 'R';
        }));
    BOOST_CHECK(id.hash != block.transactions[0].location.txhash.hash);
    const Bytes by_hash =
        find(TxHashKey(block.transactions[0].location.txhash));
    BOOST_CHECK(Bytes(id.hash.b.begin(), id.hash.b.end()) == by_hash);
    const StoredInputMeta input =
        DecodeRecord<StoredInputMeta>(find(InputKey(id, 0)));
    BOOST_CHECK_EQUAL(input.sequence, UINT32_MAX);
    BOOST_CHECK_EQUAL(input.witness_count, 1u);
    BOOST_CHECK_EQUAL(input.coinbase_data.offset, WIRE_CHUNK_BYTES);
    BOOST_CHECK(PreflightExplorerBlock(block) > facts.wire.size() * 3);
}

BOOST_AUTO_TEST_CASE(ranges_and_incomplete_spends_fail_before_entries) {
    CommittedBlock block = Fixture();
    block.transactions[0].explorer.inputs[0].coinbase_data =
        WireRange{UINT64_MAX, 2};
    BOOST_CHECK(ThrowsV2([&] { PlanExplorerBlock(block); }));
    block = Fixture();
    block.transactions[0].explorer.inputs[0].flags = 1;
    BOOST_CHECK_NO_THROW(PreflightExplorerBlock(block));
    BOOST_CHECK(ThrowsV2([&] { PlanExplorerBlock(block); }));
    block = Fixture();
    block.explorer.header_wire[62] = 2;
    BOOST_CHECK(ThrowsV2([&] { PlanExplorerBlock(block); }));
}

BOOST_AUTO_TEST_CASE(spend_input_metadata_does_not_copy_the_spent_output) {
    CommittedBlock block = Fixture();
    InputFact &input = block.transactions[0].explorer.inputs[0];
    input.flags = 1;
    Output output;
    output.value = UINT64_MAX;
    output.branches = {Fill(7)};
    output.paths = {{0}};
    const ResolvedCreation coin{
        OutPoint{TxId{H(input.prev_txid)}, input.prev_index}, output,
        TxLocation{Fill(2), 0, 2, TxId{H(input.prev_txid)}, TxHash{Fill(8)}}};
    block.transactions[0].spends.push_back(SpentInput{coin.outpoint, 0});
    const TxId id = block.transactions[0].location.txid;
    const std::vector<std::pair<Bytes, Bytes>> entries =
        PlanExplorerBlock(block);
    const auto it =
        std::find_if(entries.begin(), entries.end(), [&](const auto &kv) {
            return kv.first == InputKey(id, 0);
        });
    BOOST_REQUIRE(it != entries.end());
    BOOST_CHECK_EQUAL(DecodeRecord<StoredInputMeta>(it->second).flags, 1u);
    BOOST_CHECK_LT(it->second.size(), 64u);
    const Bytes encoded = EncodeRecord(coin);
    BOOST_CHECK(DecodeRecord<ResolvedCreation>(encoded) == coin);
    BOOST_CHECK_EQUAL(coin.output.value, UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(reservation_and_metadata_bounds_reject_oversize) {
    const Bounds bounds(4096);
    CommittedBlock block = Fixture();
    block.transactions[0].explorer.wire.resize(
        bounds.BatchBytes() / RESERVE_EXPLORER_PER_WIRE_BYTE + 1, 0);
    BOOST_CHECK(PreflightExplorerBlock(block) > bounds.BatchBytes());
    BOOST_CHECK(ThrowsV2([&] {
        DecodeRecord<TxMeta>(Bytes(MAX_EXPLORER_RECORD_BYTES + 1, 0));
    }));
}

BOOST_AUTO_TEST_CASE(
    valid_postcard_corrupt_input_fields_are_rejected_at_read_validation) {
    InputMeta input;
    input.prev_txid = B32(2);
    input.prev_index = 1;
    input.sequence = UINT32_MAX;
    input.flags = 2;
    input.has_coinbase_data = true;
    input.coinbase_data = WireRange{20, 3};
    ValidateInputMeta(input, 100);
    InputMeta bad = input;
    bad.flags = 255;
    bad = DecodeRecord<InputMeta>(EncodeRecord(bad));
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateInputMeta(bad, 100); }));
    bad = input;
    bad.coinbase_data = WireRange{UINT64_MAX, 1};
    bad = DecodeRecord<InputMeta>(EncodeRecord(bad));
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateInputMeta(bad, 100); }));
    bad = input;
    bad.witness_count = 1;
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateInputMeta(bad, 100); }));
    bad = input;
    bad.flags = 1;
    bad.has_coinbase_data = false;
    bad.coinbase_data = WireRange{};
    bad.witness_count = 1;
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateInputMeta(bad, 100); }));
}

BOOST_AUTO_TEST_CASE(
    valid_postcard_corrupt_witness_tables_are_rejected_at_read_validation) {
    const WitnessFact witness{WireRange{5, 3}, WireRange{9, 1}, 0,
                              WireRange{10, 1}, 0};
    ValidateWitnessFact(witness, 20);
    WitnessFact bad = witness;
    bad.arguments_table = WireRange{UINT64_MAX, 1};
    bad = DecodeRecord<WitnessFact>(EncodeRecord(bad));
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateWitnessFact(bad, 20); }));
    bad = witness;
    bad.siblings_table.length = 0;
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateWitnessFact(bad, 20); }));
    bad = witness;
    bad.arguments_count = 1;
    BOOST_CHECK(ThrowsCorrupt([&] { ValidateWitnessFact(bad, 20); }));
}

BOOST_AUTO_TEST_SUITE_END()
