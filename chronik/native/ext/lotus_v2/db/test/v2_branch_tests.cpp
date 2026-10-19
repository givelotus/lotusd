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

/** The private v2_branch.rs Record: re-encode with its creation tampered. */
Bytes TamperRecordCreationHash(ByteView saved) {
    postcard::Reader r(saved);
    const Bytes output = r.ByteVec();
    TxLocation creation;
    codec::Read(r, creation);
    creation.txhash.hash.b[0] ^= 1;
    Bytes out;
    postcard::Writer w(out);
    w.ByteVec(output);
    codec::Write(w, creation);
    w.Raw(r.Remaining());
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
    const uint32_t file_num = r.U32();
    const uint64_t pos = r.U64();
    const uint64_t n = r.SeqLen();
    Bytes out;
    postcard::Writer w(out);
    codec::Write(w, binding);
    codec::Write(w, anchor);
    codec::Write(w, parent);
    w.U32(file_num);
    w.U64(pos);
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

BOOST_AUTO_TEST_CASE(schema3_complete_facts_atomic_replay_and_tamper) {
    V2TempDir dir("v2-schema3");
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding());
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
    InputMeta corrupted_input = DecodeRecord<InputMeta>(saved);
    corrupted_input.flags = 255;
    env.Put(input_key, EncodeRecord(corrupted_input));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerInput(TxId{Fill(22)}, 0); }));
    env.Put(input_key, saved);
    corrupted_input = DecodeRecord<InputMeta>(saved);
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
    env.Put(record_key, TamperRecordCreationHash(saved));
    BOOST_CHECK(ThrowsV2([&] { db->Snapshot().GetOutput(Op(20, 0)); }));
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
    const TxMeta tx_meta =
        DecodeRecord<TxMeta>(*env.Get(TxKey(TxId{Fill(22)})));
    const Bytes original = env.Flat().ReadAt(
        tx_meta.file_num, tx_meta.data_pos, size_t(tx_meta.wire_size));
    const uint8_t one = 1;
    env.Flat().WriteAt(tx_meta.file_num, tx_meta.data_pos, ByteView(&one, 1));
    BOOST_CHECK(ThrowsV2(
        [&] { db->Snapshot().ExplorerWireSlice(TxId{Fill(22)}, 0, 1); }));
    BOOST_CHECK(ThrowsV2([&] { db->Disconnect(second.anchor); }));
    BOOST_CHECK(db->Checkpoint() == second.anchor);
    env.Flat().WriteAt(tx_meta.file_num, tx_meta.data_pos, original);
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
    {
        V2Env raw(dir.path);
        Bytes identity;
        postcard::Writer w(identity);
        w.U32(2);
        codec::Write(w, TestBinding());
        raw.Put(Str("v2-binding"), identity);
    }
    BOOST_CHECK(ThrowsInvalid([&] { V2Db(dir.path, TestBinding()); },
                              "binding/schema mismatch"));
}

BOOST_AUTO_TEST_CASE(restart_inverse_burns_and_replay) {
    V2TempDir dir("v2-index");
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding());
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
    db.emplace(dir.path, TestBinding());
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
    BOOST_CHECK(ThrowsInvalid([&] { V2Db(dir.path, other); },
                              "binding/schema mismatch"));
}

BOOST_AUTO_TEST_CASE(explicit_genesis_history_and_coins) {
    V2TempDir dir("v2-genesis");
    std::optional<V2Db> db;
    db.emplace(dir.path, TestBinding());
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
    BOOST_CHECK(V2Db(dir.path, TestBinding()).Checkpoint() == genesis);
}

BOOST_AUTO_TEST_CASE(early_capacity_and_corrupt_storage_fail_closed) {
    V2TempDir dir("v2-capacity");
    V2Db db(dir.path, TestBinding());
    db.InitializeGenesis(FixtureGenesis({}));
    const Anchor genesis = *db.Checkpoint();
    Output wide = TestOutput(5, false);
    wide.branches.clear();
    for (uint8_t i = 0; i < 16; ++i) {
        wide.branches.push_back(Fill(i));
    }
    wide.paths = {{0}};
    const CommittedBlock oversized =
        TestBlock(genesis, 10, 20, std::vector<Output>(2000, wide), {});
    BOOST_CHECK(
        ThrowsInvalid([&] { db.Connect(oversized); }, "staging capacity"));
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
    V2Db db(dir.path, TestBinding());
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
    V2Db db(dir.path, TestBinding());
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
    CommittedBlock overflow = TestBlock(first.anchor, 11, 22, {}, {});
    overflow.transactions = std::vector<ConfirmedTx>(
        MAX_TRANSACTIONS + 1, overflow.transactions[0]);
    BOOST_CHECK(ThrowsV2([&] { db.Connect(overflow); }));
    BOOST_CHECK(ThrowsV2([&] {
        db.Snapshot().NextPosting(Fill(5), 16, std::nullopt);
    }));
}

BOOST_AUTO_TEST_CASE(intra_block_spend_and_snapshot_isolation) {
    V2TempDir dir("v2-intra");
    V2Db db(dir.path, TestBinding());
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
    V2Db topo(topo_dir.path, TestBinding());
    V2Db db(dir.path, TestBinding());
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
            auto *db = new V2Db(dir.path, binding);
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
    V2Db db(dir.path, binding);
    BOOST_CHECK(db.Snapshot().anchor == block.anchor);
    db.Connect(block);
    db.Disconnect(block.anchor);
    BOOST_CHECK(db.Snapshot().anchor == parent);
}

BOOST_AUTO_TEST_SUITE_END()
