// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-db/src/v2_branch.rs tests (and crash_tests).

#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/db/explorer.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>

#include <boost/test/unit_test.hpp>

#include <sys/wait.h>
#include <unistd.h>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::test;

namespace {

/**
 * Flip a byte of a spent token coin record: postcard {flags, value varint,
 * Some(token_id), Some((spender txid, input index))}. Offset 1 is the value
 * (a one-byte varint in the fixture) and offset 36 the spender txid.
 */
Bytes TamperSpentTokenCoin(ByteView saved, size_t offset) {
    BOOST_REQUIRE(saved.size() > 68 && saved[2] == 1 && saved[35] == 1);
    Bytes out(saved.begin(), saved.end());
    out[offset] ^= 1;
    return out;
}

/** The private v2_branch.rs Undo with one extra (key, Some(value)) entry. */
Bytes UndoWithExtraEntry(ByteView saved, ByteView key, ByteView value) {
    postcard::Reader r(saved);
    Binding binding;
    Anchor anchor;
    std::optional<Anchor> parent;
    codec::Read(r, binding);
    codec::Read(r, anchor);
    codec::Read(r, parent);
    const uint64_t n = r.SeqLen();
    Bytes out;
    postcard::Writer w(out);
    codec::Write(w, binding);
    codec::Write(w, anchor);
    codec::Write(w, parent);
    w.SeqLen(n + 1);
    w.Raw(r.Remaining());
    w.ByteVec(key);
    w.OptionTag(true);
    w.ByteVec(value);
    return out;
}

/** Undo's binding is its first field: 3 raw 32-byte arrays. */
Bytes UndoWithProfile(ByteView saved, uint8_t profile) {
    Bytes out(saved.begin(), saved.end());
    std::fill(out.begin() + 64, out.begin() + 96, profile);
    return out;
}

Bytes RecordKey(const OutPoint &op) {
    return PrefixKey('o', OutPointBytes(op));
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_branch_tests)

BOOST_AUTO_TEST_CASE(schema4_complete_facts_atomic_replay_and_tamper) {
    V2TempDir dir("v2-schema4");
    const auto mem = std::make_shared<MemTxSource>();
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding(), TestBounds(), mem);
    db->InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = *db->Checkpoint();
    Output token = TestOutput(5, false);
    token.flags = 1;
    token.token_id = Fill(77);
    const auto baseline = db->Env().DumpAll();
    CommittedBlock first = TestBlock(genesis, 10, 20, {token}, {});
    first.transactions[0].explorer.wire = Bytes(65537, 0);
    db->Connect(first);
    const CommittedBlock second =
        TestBlock(first.anchor, 11, 22, {}, {Op(20, 0)});
    db->Connect(second);
    db->Connect(second); // frozen inputs must survive exact replay
    {
        const ReadSnapshot view = db->Snapshot();
        BOOST_CHECK(view.ExplorerBlockAtHeight(2)->anchor == second.anchor);
        BOOST_CHECK(view.ExplorerTxByHash(TxHash{Fill(23)})->location.txid ==
                    TxId{Fill(22)});
        const InputMeta input = *view.ExplorerInput(TxId{Fill(22)}, 0);
        BOOST_CHECK(input.resolved_creation->output == token);
        BOOST_CHECK_EQUAL(view.GetAssetSummary(Fill(77))->event_count, 2u);
    }
    V2Env &env = db->Env();

    const Bytes input_key = InputKey(TxId{Fill(22)}, 0);
    Bytes saved = *env.Get(input_key);
    StoredInputMeta corrupted_input = DecodeRecord<StoredInputMeta>(saved);
    corrupted_input.flags = 255;
    env.Put(input_key, EncodeRecord(corrupted_input));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerInput(TxId{Fill(22)}, 0); }));
    env.Put(input_key, saved);
    corrupted_input = DecodeRecord<StoredInputMeta>(saved);
    corrupted_input.coinbase_data = WireRange{UINT64_MAX, 1};
    env.Put(input_key, EncodeRecord(corrupted_input));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerInput(TxId{Fill(22)}, 0); }));
    env.Put(input_key, saved);

    const Bytes witness_key = WitnessKey(TxId{Fill(20)}, 0, 0);
    saved = *env.Get(witness_key);
    WitnessFact corrupted_witness = DecodeRecord<WitnessFact>(saved);
    corrupted_witness.script = WireRange{65537, 1};
    env.Put(witness_key, EncodeRecord(corrupted_witness));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerWitness(TxId{Fill(20)}, 0, 0); }));
    env.Put(witness_key, saved);

    const Bytes block_key = BlockKey(H(second.anchor.block_id));
    saved = *env.Get(block_key);
    BlockMeta corrupted_block = DecodeRecord<BlockMeta>(saved);
    corrupted_block.header_wire[0] ^= 1;
    env.Put(block_key, EncodeRecord(corrupted_block));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerBlock(H(second.anchor.block_id)); }));
    env.Put(block_key, saved);

    const Bytes record_key = RecordKey(Op(20, 0));
    saved = *env.Get(record_key);
    for (const size_t offset : {size_t(36), size_t(1)}) {
        env.Put(record_key, TamperSpentTokenCoin(saved, offset));
        BOOST_CHECK(ThrowsV2([&] { db->Snapshot().GetOutput(Op(20, 0)); }));
    }
    env.Put(record_key, saved);

    const Bytes summary_key = AssetSummaryKey(Fill(77));
    saved = *env.Get(summary_key);
    AssetSummary corrupted_summary = DecodeAssetSummary(saved);
    corrupted_summary.first_seen.txhash = TxHash{Fill(88)};
    env.Put(summary_key, EncodeAssetSummary(corrupted_summary));
    BOOST_CHECK(
        ThrowsV2([&] { db->Snapshot().GetAssetSummary(Fill(77)); }));
    env.Put(summary_key, saved);

    const Bytes event_key =
        AssetEventKey(Fill(77), second.transactions[0].location);
    saved = *env.Get(event_key);
    AssetEvent corrupted_event = DecodeRecord<AssetEvent>(saved);
    corrupted_event.location.block_id = Fill(88);
    env.Put(event_key, EncodeRecord(corrupted_event));
    const Bytes previous =
        AssetEventKey(Fill(77), first.transactions[0].location);
    BOOST_CHECK(ThrowsV2([&] {
        db->Snapshot().NextAssetEvent(Fill(77), ByteView(previous));
    }));
    env.Put(event_key, saved);

    CommittedBlock conflicting = second;
    conflicting.transactions[0].explorer.wire.push_back(1);
    BOOST_CHECK(ThrowsV2([&] { db->Connect(conflicting); }));
    // The node's bytes no longer match the recorded wire checksum: reads and
    // the undo check fail closed.
    const auto flip = [](NodeTx &tx) { tx.explorer.wire[0] ^= 1; };
    BOOST_CHECK(mem->Modify(TxId{Fill(22)}, flip));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerWireSlice(TxId{Fill(22)}, 0, 1); }));
    BOOST_CHECK(ThrowsV2([&] { db->Disconnect(second.anchor); }));
    BOOST_CHECK(db->Checkpoint() == second.anchor);
    BOOST_CHECK(mem->Modify(TxId{Fill(22)}, flip));
    db->Disconnect(second.anchor);
    BOOST_CHECK(!db->Snapshot().ExplorerTx(TxId{Fill(22)}));
    BOOST_CHECK(!env.Get(
        AssetEventKey(Fill(77), second.transactions[0].location)));
    BOOST_CHECK_EQUAL(db->Snapshot().GetAssetSummary(Fill(77))->event_count,
                      1u);
    db->Connect(second);
    db->Disconnect(second.anchor);
    db->Disconnect(first.anchor);
    BOOST_CHECK(!db->Snapshot().GetAssetSummary(Fill(77)));
    auto after = env.DumpAll();
    const Bytes disconnected{'d', 'i', 's', 'c', 'o', 'n',
                             'n', 'e', 'c', 't', 'e', 'd'};
    std::erase_if(after,
                  [&](const auto &kv) { return kv.first == disconnected; });
    // Every e-family, receipt and undo restored exactly.
    BOOST_CHECK(after == baseline);

    db.reset();
    // An index of an older schema is refused with a reindex instruction,
    // never read with this build's layouts.
    for (const uint32_t old : {2u, 3u}) {
        {
            V2Env raw(dir.path);
            Bytes identity;
            postcard::Writer w(identity);
            w.U32(old);
            codec::Write(w, TestBinding());
            raw.Put(Str("v2-binding"), identity);
        }
        bool refused = false;
        try {
            V2Db(dir.path, TestBinding(), TestBounds());
        } catch (const V2Error &e) {
            refused = e.kind() == V2Error::Kind::Schema &&
                      std::string_view(e.what()).find("-chronikreindex") !=
                          std::string_view::npos &&
                      std::string_view(e.what()).find(
                          "schema version " + std::to_string(old)) !=
                          std::string_view::npos;
        }
        BOOST_CHECK(refused);
    }
}

BOOST_AUTO_TEST_CASE(restart_inverse_burns_and_replay) {
    V2TempDir dir("v2-index");
    // The node's block files outlive a restart: share one source.
    const auto mem = std::make_shared<MemTxSource>();
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding(), TestBounds(), mem);
    db->InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = db->Snapshot().anchor;
    const CommittedBlock first = TestBlock(
        genesis, 10, 20, {TestOutput(5, false), TestOutput(6, true)}, {});
    db->Connect(first);
    db->Connect(first);
    std::optional<OutputRecord> original;
    {
        const ReadSnapshot before = db->Snapshot();
        original = before.GetOutput(Op(20, 0));
        BOOST_REQUIRE(original);
        BOOST_CHECK(before.Utxo(Op(20, 0)));
        BOOST_CHECK(!before.Utxo(Op(20, 1)));
        BOOST_CHECK(before.NextPosting(Fill(6), std::nullopt, std::nullopt) ==
                    Op(20, 1));
    }
    const CommittedBlock second = TestBlock(
        first.anchor, 11, 22, {TestOutput(7, false)}, {Op(20, 0)});
    db->Connect(second);
    {
        const ReadSnapshot anchored = db->Snapshot();
        const OutputRecord spent = *anchored.GetOutput(Op(20, 0));
        BOOST_CHECK(!anchored.Utxo(Op(20, 0)));
        BOOST_CHECK(spent.spend->transaction.txid == TxId{Fill(22)});
        BOOST_CHECK(anchored.NextPosting(Fill(5), 0, std::nullopt) ==
                    Op(20, 0));
    }
    db.reset();
    db.emplace(dir.path, TestBinding(), TestBounds(), mem);
    BOOST_CHECK(db->Snapshot().anchor == second.anchor);
    db->Connect(second);
    db->Disconnect(second.anchor);
    db->Disconnect(second.anchor);
    BOOST_CHECK(db->Snapshot().GetOutput(Op(20, 0)) == original);
    BOOST_CHECK(!db->Snapshot().GetOutput(Op(22, 0)));
    db->Connect(second);
    db->Disconnect(second.anchor);
    db->Disconnect(first.anchor);
    BOOST_CHECK(db->Snapshot().anchor == genesis);
    BOOST_CHECK(
        !db->Snapshot().NextPosting(Fill(6), std::nullopt, std::nullopt));
    db.reset();
    Binding other = TestBinding();
    other.profile = B32(4);
    BOOST_CHECK(ThrowsInvalid([&] { V2Db(dir.path, other, TestBounds()); },
                              "binding/schema mismatch"));
}

BOOST_AUTO_TEST_CASE(explicit_genesis_history_and_coins) {
    V2TempDir dir("v2-genesis");
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding(), TestBounds());
    BOOST_CHECK(!db->Checkpoint());
    BOOST_CHECK(ThrowsV2([&] { db->Snapshot(); }));
    const Anchor genesis{TestBinding().genesis, 0};
    ConfirmedTx tx =
        TestBlock(genesis, 10, 20, {TestOutput(5, false), TestOutput(6, true)},
                  {})
            .transactions[0];
    const ConfirmedTx wrong = tx;
    BOOST_CHECK(
        ThrowsV2([&] { db->InitializeGenesis(FixtureGenesis({wrong})); }));
    BOOST_CHECK(!db->Checkpoint());
    tx.location.block_id = H(TestBinding().genesis);
    tx.location.height = 0;
    db->InitializeGenesis(FixtureGenesis({tx}));
    db->InitializeGenesis(FixtureGenesis({tx}));
    BOOST_CHECK(db->Snapshot().NextPosting(Fill(6), std::nullopt,
                                           std::nullopt) == Op(20, 1));
    BOOST_CHECK(!db->Snapshot().Utxo(Op(20, 1)));
    const CommittedBlock child = TestBlock(genesis, 11, 22, {}, {Op(20, 0)});
    db->Connect(child);
    db->Disconnect(child.anchor);
    BOOST_CHECK(db->Snapshot().Utxo(Op(20, 0)));
    BOOST_CHECK(ThrowsV2([&] { db->Disconnect(genesis); }));
    db.reset();
    BOOST_CHECK(V2Db(dir.path, TestBinding(), TestBounds()).Checkpoint() ==
                genesis);
}

BOOST_AUTO_TEST_CASE(early_capacity_and_corrupt_storage_fail_closed) {
    V2TempDir dir("v2-capacity");
    V2Db db(dir.path, TestBinding(), TestBounds());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = *db.Checkpoint();
    Output wide = TestOutput(5, false);
    wide.branches.clear();
    for (uint8_t i = 0; i < 16; ++i) {
        wide.branches.push_back(Fill(i));
    }
    wide.paths = {{0}};
    // 2000 sixteen-branch outputs need more than a 32 KB block.
    V2TempDir small_dir("v2-capacity-small");
    V2Db small(small_dir.path, TestBinding(), Bounds(32'768));
    small.InitializeGenesis(FixtureGenesis({}));
    const CommittedBlock oversized =
        TestBlock(genesis, 10, 20, std::vector<Output>(2000, wide), {});
    BOOST_CHECK(
        ThrowsInvalid([&] { small.Connect(oversized); }, "staging capacity"));
    BOOST_CHECK(small.Checkpoint() == genesis);
    db.Connect(oversized);
    db.Disconnect(oversized.anchor);
    BOOST_CHECK(db.Checkpoint() == genesis);
    const CommittedBlock first =
        TestBlock(genesis, 10, 20, {TestOutput(5, false)}, {});
    db.Connect(first);
    V2Env &env = db.Env();
    const Bytes record_key = RecordKey(Op(20, 0));
    const Bytes original = *env.Get(record_key);
    env.Put(record_key, Bytes(MAX_BRANCH_RECORD_BYTES + 1, 0));
    BOOST_CHECK(ThrowsCorrupt([&] { db.Snapshot().GetOutput(Op(20, 0)); }));
    env.Put(record_key, original);
    const Bytes undo_key = PrefixKey('u', first.anchor.block_id);
    const Bytes original_undo = *env.Get(undo_key);
    env.Put(undo_key, UndoWithExtraEntry(original_undo, Str("tip"),
                                         codec::Encode(genesis)));
    BOOST_CHECK(ThrowsCorrupt([&] { db.Disconnect(first.anchor); }));
    BOOST_CHECK(db.Checkpoint() == first.anchor);
    env.Put(undo_key, UndoWithProfile(original_undo, 99));
    BOOST_CHECK(ThrowsCorrupt([&] { db.Disconnect(first.anchor); }));
    env.Put(undo_key, original_undo);
    db.Disconnect(first.anchor);
}

BOOST_AUTO_TEST_CASE(complete_token_policy_and_sixteen_positions) {
    V2TempDir dir("v2-policy");
    V2Db db(dir.path, TestBinding(), TestBounds());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = db.Snapshot().anchor;
    Output policy;
    policy.flags = 1;
    policy.value = UINT64_MAX;
    policy.token_id = Fill(77);
    std::vector<uint8_t> path;
    for (uint8_t i = 0; i < 16; ++i) {
        policy.branches.push_back(Fill(i));
        path.push_back(i);
    }
    policy.paths = {path};
    const CommittedBlock first = TestBlock(genesis, 10, 20, {policy}, {});
    db.Connect(first);
    for (uint8_t position = 0; position < 16; ++position) {
        BOOST_CHECK(db.Snapshot().NextPosting(Fill(position), position,
                                              std::nullopt) == Op(20, 0));
    }
    const CommittedBlock second =
        TestBlock(first.anchor, 11, 22, {}, {Op(20, 0)});
    db.Connect(second);
    db.Disconnect(second.anchor);
    const OutputRecord restored = *db.Snapshot().GetOutput(Op(20, 0));
    BOOST_CHECK(restored.output == policy);
    BOOST_CHECK(!restored.spend);
}

BOOST_AUTO_TEST_CASE(invalid_transitions_leave_checkpoint_unchanged) {
    V2TempDir dir("v2-invalid");
    V2Db db(dir.path, TestBinding(), TestBounds());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = db.Snapshot().anchor;
    const CommittedBlock first = TestBlock(
        genesis, 10, 20, {TestOutput(5, false), TestOutput(6, true)}, {});
    db.Connect(first);
    for (const auto &inputs : std::vector<std::vector<OutPoint>>{
             {Op(20, 0), Op(20, 0)}, {Op(20, 1)}, {Op(99, 0)}}) {
        BOOST_CHECK(ThrowsV2(
            [&] { db.Connect(TestBlock(first.anchor, 11, 22, {}, inputs)); }));
        BOOST_CHECK(db.Snapshot().anchor == first.anchor);
        BOOST_CHECK(!db.Snapshot().GetOutput(Op(20, 0))->spend);
    }
    CommittedBlock malformed = TestBlock(first.anchor, 11, 22, {}, {});
    malformed.transactions[0].location.block_id = Fill(99);
    BOOST_CHECK(ThrowsV2([&] { db.Connect(malformed); }));
    CommittedBlock replay = first;
    replay.transactions[0].outputs[0].value = 101;
    BOOST_CHECK(ThrowsV2([&] { db.Connect(replay); }));
    const CommittedBlock duplicate = TestBlock(first.anchor, 11, 20, {}, {});
    BOOST_CHECK(ThrowsV2([&] { db.Connect(duplicate); }));
    // More transactions than a block within the size limit can hold.
    V2TempDir small_dir("v2-small");
    V2Db small(small_dir.path, TestBinding(), Bounds(4 * MIN_TX_WIRE_BYTES));
    small.InitializeGenesis(FixtureGenesis({}));
    CommittedBlock overflow = TestBlock(genesis, 11, 22, {}, {});
    overflow.transactions = std::vector<ConfirmedTx>(
        small.GetBounds().Transactions() + 1, overflow.transactions[0]);
    BOOST_CHECK(
        ThrowsInvalid([&] { small.Connect(overflow); }, "transaction bound"));
    BOOST_CHECK(ThrowsV2([&] {
        db.Snapshot().NextPosting(Fill(5), 16, std::nullopt);
    }));
}

/**
 * The staging reserved for any element, charged to its shortest wire
 * encoding, stays within STAGING_PER_WIRE_BYTE: a block within the consensus
 * size limit always fits Bounds::BatchBytes (Rust
 * staging_covers_shortest_encodings).
 */
BOOST_AUTO_TEST_CASE(staging_covers_shortest_encodings) {
    // Charged to every wire byte: explorer entries and started chunks.
    const size_t per_byte =
        RESERVE_EXPLORER_PER_WIRE_BYTE +
        (RESERVE_EXPLORER_CHUNK + WIRE_CHUNK_BYTES - 1) / WIRE_CHUNK_BYTES;
    const size_t budget = STAGING_PER_WIRE_BYTE - per_byte;
    const size_t tx = RESERVE_TX + RESERVE_EXPLORER_TX + RESERVE_EXPLORER_CHUNK;
    BOOST_CHECK(tx <= budget * MIN_TX_HEADER_WIRE_BYTES);
    // A spend is an input, a spend and an asset element twice.
    const size_t spend =
        2 * RESERVE_ASSET_ELEMENT + RESERVE_SPEND + RESERVE_EXPLORER_INPUT;
    BOOST_CHECK(spend <= budget * MIN_SPEND_WIRE_BYTES);
    const size_t input = RESERVE_ASSET_ELEMENT + RESERVE_EXPLORER_INPUT;
    BOOST_CHECK(input <= budget * MIN_INPUT_WIRE_BYTES);
    BOOST_CHECK(RESERVE_EXPLORER_WITNESS <= budget * MIN_WITNESS_WIRE_BYTES);
    // The shortest output has one branch; each further one is 32 bytes.
    const size_t output =
        RESERVE_ASSET_ELEMENT + RESERVE_OUTPUT + RESERVE_BRANCH;
    BOOST_CHECK(output <= budget * MIN_OUTPUT_WIRE_BYTES);
    BOOST_CHECK(RESERVE_BRANCH <= budget * 32);
    BOOST_CHECK(1024 + RESERVE_EXPLORER_BLOCK <= STAGING_PER_BLOCK);
    const Bounds bounds(32'000'000);
    BOOST_CHECK_EQUAL(bounds.Transactions(), 32'000'000 / MIN_TX_WIRE_BYTES);
    BOOST_CHECK_EQUAL(bounds.Changes(), 32'000'000 / MIN_INPUT_WIRE_BYTES);
    BOOST_CHECK(ThrowsInvalid([] { Bounds(0); }, "block size limit"));
    BOOST_CHECK(ThrowsInvalid([] { Bounds(Bounds::MAX_BLOCK_BYTES + 1); },
                              "block size limit"));
}

/**
 * A block over the former fixed bounds (4096 transactions, 32 MiB of
 * staging) but within the consensus size limit is indexed and undone (Rust
 * block_over_former_fixed_bounds_is_indexed).
 */
BOOST_AUTO_TEST_CASE(block_over_former_fixed_bounds_is_indexed) {
    constexpr uint32_t TXS = 4100;
    V2TempDir dir("v2-large");
    V2Db db(dir.path, TestBinding(), TestBounds());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = *db.Checkpoint();
    const CommittedBlock fan = TestBlock(
        genesis, 10, 20, std::vector<Output>(TXS, TestOutput(5, false)), {});
    db.Connect(fan);
    const Anchor anchor{B32(11), 2};
    // Each spends one fan output to one output: the shortest encodings, as
    // in a real block of this many transactions.
    const size_t wire_len = MIN_TX_HEADER_WIRE_BYTES + MIN_SPEND_WIRE_BYTES +
                            MIN_WITNESS_WIRE_BYTES + MIN_OUTPUT_WIRE_BYTES;
    auto numbered = [](uint8_t fill, uint32_t i) {
        Bytes32 id = B32(fill);
        for (size_t j = 0; j < 4; ++j) {
            id[j] = uint8_t(i >> (8 * (3 - j)));
        }
        return Hash32{id};
    };
    auto txid = [&](uint32_t i) { return TxId{numbered(0x60, i)}; };
    CommittedBlock large{
        anchor, fan.anchor, {}, FixtureHeader(anchor, fan.anchor)};
    for (uint32_t i = 0; i < TXS; ++i) {
        std::vector<SpentInput> spends{SpentInput{Op(20, i), 0}};
        std::vector<Output> outputs{TestOutput(6, false)};
        ExplorerTxFacts explorer = FixtureFacts(spends, outputs);
        explorer.wire = Bytes(wire_len, 0);
        large.transactions.push_back(ConfirmedTx{
            TxLocation{H(anchor.block_id), anchor.height, i, txid(i),
                       TxHash{numbered(0x61, i)}},
            std::move(outputs), std::move(spends), std::move(explorer)});
    }
    // Over the former bounds by count and by reserved staging.
    BOOST_CHECK(large.transactions.size() > 4096);
    BOOST_CHECK(PreflightExplorerBlock(large) > 32 * 1024 * 1024);
    BOOST_CHECK(TXS * wire_len <= TestBounds().BlockBytes());
    db.Connect(large);
    BOOST_CHECK(db.Checkpoint() == anchor);
    {
        const ReadSnapshot snapshot = db.Snapshot();
        for (uint32_t i : {0u, TXS / 2, TXS - 1}) {
            const auto spent = snapshot.GetOutput(Op(20, i));
            BOOST_REQUIRE(spent && spent->spend);
            BOOST_CHECK(spent->spend->transaction.txid == txid(i));
            BOOST_CHECK(snapshot.Utxo(OutPoint{txid(i), 0}));
        }
    }
    db.Disconnect(anchor);
    BOOST_CHECK(db.Checkpoint() == fan.anchor);
    BOOST_CHECK(!db.Snapshot().GetOutput(Op(20, TXS - 1))->spend);
}

BOOST_AUTO_TEST_CASE(intra_block_spend_and_snapshot_isolation) {
    V2TempDir dir("v2-intra");
    V2Db db(dir.path, TestBinding(), TestBounds());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = db.Snapshot().anchor;
    CommittedBlock first =
        TestBlock(genesis, 10, 20, {TestOutput(5, false)}, {});
    ConfirmedTx child = first.transactions[0];
    child.location.tx_index = 1;
    child.location.txid = TxId{Fill(22)};
    child.location.txhash = TxHash{Fill(23)};
    child.spends = {SpentInput{Op(20, 0), 3}};
    child.explorer = FixtureFacts(child.spends, child.outputs);
    first.transactions.push_back(child);
    db.Connect(first);
    BOOST_CHECK_EQUAL(db.Snapshot().GetOutput(Op(20, 0))->spend->input_index,
                      3u);
    {
        const ReadSnapshot snapshot = db.Snapshot();
        BOOST_CHECK(snapshot.NextPosting(Fill(5), std::nullopt, Op(20, 0)) ==
                    Op(22, 0));
        BOOST_CHECK(!snapshot.NextPosting(Fill(5), std::nullopt, Op(22, 0)));
    }
    db.Disconnect(first.anchor);
    BOOST_CHECK(!db.Snapshot().GetOutput(Op(20, 0)));
    BOOST_CHECK(!db.Snapshot().GetOutput(Op(22, 0)));
}

// Hosts may confirm blocks in canonical (txid) order, where a child precedes
// the in-block parent whose output it spends.
BOOST_AUTO_TEST_CASE(canonical_order_block_spends_later_parents) {
    auto tx = [](const Anchor &anchor, uint32_t index, uint8_t txid,
                 std::vector<Output> outputs,
                 const std::vector<OutPoint> &spent) {
        std::vector<SpentInput> spends;
        for (size_t i = 0; i < spent.size(); ++i) {
            spends.push_back(SpentInput{spent[i], uint32_t(i)});
        }
        ExplorerTxFacts explorer = FixtureFacts(spends, outputs);
        return ConfirmedTx{TxLocation{H(anchor.block_id), anchor.height, index,
                                      TxId{Fill(txid)},
                                      TxHash{Fill(uint8_t(txid ^ 0xff))}},
                           std::move(outputs), std::move(spends),
                           std::move(explorer)};
    };
    Output token = TestOutput(5, false);
    token.flags = 1;
    token.token_id = Fill(77);
    Output minted = token;
    minted.token_id = Fill(78);
    // 0x20 -> 0x30 -> 0x40 -> 0x21, carrying a token; 0x31 mints a second
    // token that 0x22 spends. Canonical order is 0x21, 0x22, 0x30, 0x31,
    // 0x40; the topological order is 0x30, 0x31, 0x22, 0x40, 0x21.
    struct Spec {
        uint8_t txid;
        Output output;
        std::optional<OutPoint> spend;
    };
    const Anchor anchor{B32(11), 2};
    auto second_block = [&](const CommittedBlock &first, bool canonical) {
        std::vector<Spec> specs{{0x30, token, Op(0x20, 0)},
                                {0x31, minted, std::nullopt},
                                {0x22, minted, Op(0x31, 0)},
                                {0x40, token, Op(0x30, 0)},
                                {0x21, token, Op(0x40, 0)}};
        if (canonical) {
            std::sort(specs.begin(), specs.end(),
                      [](const Spec &a, const Spec &b) {
                          return a.txid < b.txid;
                      });
        }
        CommittedBlock block{anchor, first.anchor, {},
                             FixtureHeader(anchor, first.anchor)};
        for (size_t i = 0; i < specs.size(); ++i) {
            std::vector<OutPoint> spent;
            if (specs[i].spend) {
                spent.push_back(*specs[i].spend);
            }
            block.transactions.push_back(
                tx(anchor, uint32_t(i), specs[i].txid, {specs[i].output},
                   spent));
        }
        return block;
    };
    V2TempDir topo_dir("v2-topo");
    V2TempDir dir("v2-ctor");
    V2Db topo(topo_dir.path, TestBinding(), TestBounds());
    V2Db db(dir.path, TestBinding(), TestBounds());
    CommittedBlock second;
    for (V2Db *d : {&topo, &db}) {
        d->InitializeGenesis(FixtureGenesis({}));
        const Anchor genesis = *d->Checkpoint();
        const CommittedBlock first = TestBlock(genesis, 10, 0x20, {token}, {});
        d->Connect(first);
        second = second_block(first, d == &db);
        d->Connect(second);
        d->Connect(second); // exact replay is a no-op
    }
    BOOST_CHECK(second.transactions[0].location.txid == TxId{Fill(0x21)});
    {
        const ReadSnapshot view = db.Snapshot();
        for (const auto &[parent, child] :
             std::vector<std::pair<uint8_t, uint8_t>>{
                 {0x20, 0x30}, {0x30, 0x40}, {0x40, 0x21}, {0x31, 0x22}}) {
            const auto record = view.GetOutput(Op(parent, 0));
            BOOST_REQUIRE(record && record->spend);
            BOOST_CHECK(record->spend->transaction.txid == TxId{Fill(child)});
        }
        BOOST_CHECK(!view.GetOutput(Op(0x21, 0))->spend);
        const auto input = view.ExplorerInput(TxId{Fill(0x21)}, 0);
        BOOST_REQUIRE(input && input->resolved_creation);
        BOOST_CHECK(input->resolved_creation->outpoint == Op(0x40, 0));
        const ReadSnapshot topo_view = topo.Snapshot();
        for (uint8_t token_id : {77, 78}) {
            const auto summary = view.GetAssetSummary(Fill(token_id));
            const auto expected = topo_view.GetAssetSummary(Fill(token_id));
            BOOST_REQUIRE(summary && expected);
            BOOST_CHECK_EQUAL(summary->event_count, expected->event_count);
            BOOST_CHECK_EQUAL(summary->output_count, expected->output_count);
        }
        // The mint stays the first seen location, after its spender.
        const auto minted_summary = view.GetAssetSummary(Fill(78));
        BOOST_CHECK(minted_summary->first_seen.txid == TxId{Fill(0x31)});
        BOOST_CHECK_EQUAL(minted_summary->first_seen.tx_index, 3u);
        const auto minted_input = view.ExplorerInput(TxId{Fill(0x22)}, 0);
        BOOST_REQUIRE(minted_input && minted_input->resolved_creation);
        BOOST_CHECK(minted_input->resolved_creation->outpoint == Op(0x31, 0));
    }
    db.Disconnect(second.anchor);
    {
        const ReadSnapshot view = db.Snapshot();
        BOOST_CHECK(!view.GetOutput(Op(0x20, 0))->spend);
        for (uint8_t txid : {0x21, 0x22, 0x30, 0x31, 0x40}) {
            BOOST_CHECK(!view.GetOutput(Op(txid, 0)));
        }
    }
    db.Connect(second);

    // A dependency cycle cannot be resolved.
    const Anchor cycle_anchor{B32(12), 3};
    const CommittedBlock cycle{
        cycle_anchor,
        second.anchor,
        {tx(cycle_anchor, 0, 0x50, {TestOutput(6, false)}, {Op(0x51, 0)}),
         tx(cycle_anchor, 1, 0x51, {TestOutput(6, false)}, {Op(0x50, 0)})},
        FixtureHeader(cycle_anchor, second.anchor)};
    BOOST_CHECK(ThrowsInvalid([&] { db.Connect(cycle); }, "missing coin"));
    BOOST_CHECK(db.Checkpoint() == second.anchor);
}

BOOST_AUTO_TEST_CASE(processing_order_places_parents_first) {
    auto tx = [](uint8_t txid, std::vector<uint8_t> parents) {
        ConfirmedTx out;
        out.location.txid = TxId{Fill(txid)};
        for (uint8_t parent : parents) {
            out.spends.push_back(
                SpentInput{Op(parent, 0), uint32_t(out.spends.size())});
        }
        return out;
    };
    // Topological blocks keep their order.
    BOOST_CHECK(ProcessingOrder({tx(1, {}), tx(2, {1}), tx(3, {1, 2})}) ==
                (std::vector<size_t>{0, 1, 2}));
    // Children move after parents; ties keep block order.
    BOOST_CHECK(ProcessingOrder({tx(1, {4}), tx(2, {9}), tx(3, {}),
                                 tx(4, {3, 3})}) ==
                (std::vector<size_t>{1, 2, 3, 0}));
    // Cycles keep block order at the end.
    BOOST_CHECK(ProcessingOrder({tx(1, {2}), tx(2, {1}), tx(3, {})}) ==
                (std::vector<size_t>{2, 0, 1}));
    BOOST_CHECK(ProcessingOrder({}).empty());
}

// crash_tests::durable_checkpoint_without_clean_shutdown: the Rust test
// re-executes itself; here a fork()ed child commits then _exit(77)s,
// bypassing destructors, so durability must come from the synced commit.
BOOST_AUTO_TEST_CASE(durable_checkpoint_without_clean_shutdown) {
    const Binding binding = TestBinding();
    const Anchor parent{binding.genesis, 0};
    const Anchor anchor{B32(8), 1};
    const CommittedBlock block{anchor, parent, {},
                               FixtureHeader(anchor, parent)};
    V2TempDir dir("v2-durable");
    const pid_t pid = fork();
    BOOST_REQUIRE(pid >= 0);
    if (pid == 0) {
        int code = 1;
        try {
            // Deliberately leaked: no destructor may run before _exit.
            auto *db = new V2Db(dir.path, binding, TestBounds());
            db->InitializeGenesis(FixtureGenesis({}));
            db->Connect(block);
            code = 77;
        } catch (...) {
        }
        _exit(code);
    }
    int status = 0;
    BOOST_REQUIRE(waitpid(pid, &status, 0) == pid);
    BOOST_REQUIRE(WIFEXITED(status));
    BOOST_CHECK_EQUAL(WEXITSTATUS(status), 77);
    V2Db db(dir.path, binding, TestBounds());
    BOOST_CHECK(db.Snapshot().anchor == block.anchor);
    db.Connect(block);
    db.Disconnect(block.anchor);
    BOOST_CHECK(db.Snapshot().anchor == parent);
}

BOOST_AUTO_TEST_SUITE_END()
