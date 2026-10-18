// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/block_assembler_test/fixtures.h>
#include <lotus_v2/fast_sync.h>
#include <primitives/block.h>
#include <protocol.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <filesystem>

using namespace lotus::v2;

namespace {

Output MakeSpendableOutput(uint64_t value) {
    Output o;
    o.value = value;
    o.flags = 0;
    o.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    o.paths = {{0}};
    return o;
}

lotus::v2::Coin MakeCoinWithIndex(uint8_t tx_seed, uint32_t index,
                                  uint64_t value, uint64_t height = 10) {
    lotus::v2::Coin c;
    c.outpoint.tx_id.fill(0);
    c.outpoint.tx_id[0] = tx_seed;
    c.outpoint.tx_id[1] = static_cast<uint8_t>((index * 37u + tx_seed) & 0xFFu);
    c.outpoint.tx_id[2] = static_cast<uint8_t>((index >> 8) & 0xFFu);
    c.outpoint.index = index;
    c.output = MakeSpendableOutput(value);
    c.creation_height = height;
    c.creation_parent_mtp = 1000 + height * 120;
    c.coinbase = (index == 0);
    return c;
}

MonetaryState MakeTestMonetaryState() {
    MonetaryState m{};
    m.bootstrap_reserve = 500000000;
    m.tail_subsidy = 94;
    m.prev_work[0] = 2;
    m.ema_block_cost = 4000;
    return m;
}

Header MakePivotHeader(const ChainId &chain_id, uint64_t height,
                       const lotus::v2::Hash &utxo_root,
                       const MonetaryState &monetary) {
    Header h{};
    h.version = 2;
    h.prev_id.fill(0x11);
    h.bits = 0x207fffff;
    h.time = 1000 + height * 120;
    h.nonce = 42;
    h.size = HEADER_SIZE + 4;
    h.height = height;
    h.tx_root.fill(0x22);
    h.state_root = StateRoot(chain_id, height, utxo_root, monetary);
    return h;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fast_sync_shard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(protocol_message_types_and_wire_roundtrip) {
    const auto &all_types = getAllNetMessageTypes();
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::GETUTXOROOTS)) !=
                all_types.end());
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::UTXOROOTS)) !=
                all_types.end());
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::GETUTXOSHARD)) !=
                all_types.end());
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::UTXOSHARD)) !=
                all_types.end());

    GetUtxoRootsRequest req{};
    req.pivot_block_id.fill(0xAB);
    const auto req_bytes = EncodeGetUtxoRootsRequest(req);
    GetUtxoRootsRequest decoded_req{};
    std::string error;
    BOOST_CHECK(DecodeGetUtxoRootsRequest(req_bytes, decoded_req, error));
    BOOST_CHECK(decoded_req == req);

    GetUtxoShardRequest sreq{};
    sreq.pivot_block_id.fill(0xCD);
    sreq.prefix_depth = 11;
    sreq.prefix_bits = 0x05A2;
    std::vector<uint8_t> sreq_bytes;
    BOOST_CHECK(EncodeGetUtxoShardRequest(sreq, sreq_bytes, error));
    GetUtxoShardRequest decoded_sreq{};
    BOOST_CHECK(DecodeGetUtxoShardRequest(sreq_bytes, decoded_sreq, error));
    BOOST_CHECK(decoded_sreq == sreq);
}

BOOST_AUTO_TEST_CASE(depth8_shard_roots_export_fold_and_adaptive_subshards) {
    ChainId chain_id{};
    chain_id[0] = 0x77;
    const uint64_t pivot_height = 150;
    const MonetaryState monetary = MakeTestMonetaryState();

    UtxoSet utxo;
    // Populate shard 0x05 with a single leaf (cardinality_tag = 1).
    BOOST_REQUIRE(utxo.Insert(MakeCoinWithIndex(0x05, 1, 1000, 10)));
    // Populate shard 0x2A with 20 leaves so we can test adaptive splitting at max_shard_leaves = 6.
    for (uint32_t i = 0; i < 20; ++i) {
        BOOST_REQUIRE(utxo.Insert(MakeCoinWithIndex(0x2A, i + 1, 500 + i, 20)));
    }
    // Populate shard 0xFE with 3 leaves (cardinality_tag = 2).
    for (uint32_t i = 0; i < 3; ++i) {
        BOOST_REQUIRE(utxo.Insert(MakeCoinWithIndex(0xFE, i + 1, 900 + i, 30)));
    }

    const Header pivot_header =
        MakePivotHeader(chain_id, pivot_height, utxo.Root(), monetary);

    UtxoRootsMessage roots_msg{};
    std::string error;
    BOOST_REQUIRE(ExportUtxoRoots(utxo, chain_id, pivot_header, monetary,
                                  roots_msg, error));
    BOOST_CHECK_EQUAL(roots_msg.shards[0x05].cardinality_tag, 1);
    BOOST_CHECK_EQUAL(roots_msg.shards[0x2A].cardinality_tag, 2);
    BOOST_CHECK_EQUAL(roots_msg.shards[0xFE].cardinality_tag, 2);
    BOOST_CHECK_EQUAL(roots_msg.shards[0x00].cardinality_tag, 0);

    // Wire roundtrip of UtxoRootsMessage.
    const auto roots_wire = EncodeUtxoRootsMessage(roots_msg);
    UtxoRootsMessage decoded_roots{};
    BOOST_REQUIRE(DecodeUtxoRootsMessage(roots_wire, decoded_roots, error));
    BOOST_REQUIRE(VerifyUtxoRootsAgainstHeader(pivot_header, chain_id,
                                               decoded_roots, error));

    // Export adaptive sub-shards with max_shard_leaves = 6 so shard 0x2A splits to depth > 8.
    std::vector<UtxoShardMessage> shards;
    BOOST_REQUIRE(ExportAdaptiveUtxoShards(utxo, roots_msg.pivot_block_id,
                                           shards, error,
                                           /*max_shard_leaves=*/6));
    bool saw_deeper_subshard = false;
    for (const auto &s : shards) {
        if (s.prefix_depth > 8) saw_deeper_subshard = true;
        std::vector<uint8_t> swire;
        BOOST_REQUIRE(EncodeUtxoShardMessage(s, swire, error));
        UtxoShardMessage sdecoded{};
        BOOST_REQUIRE(DecodeUtxoShardMessage(swire, sdecoded, error));
        const uint8_t d8 = static_cast<uint8_t>(sdecoded.prefix_bits & 0xFFu);
        BOOST_REQUIRE(VerifyAndBuildUtxoShard(decoded_roots.shards[d8],
                                              pivot_height, sdecoded, nullptr,
                                              error));
    }
    BOOST_CHECK(saw_deeper_subshard);

    // Assemble full pivot UtxoSet and import into DiskStateStore.
    UtxoSet assembled;
    MonetaryState assembled_monetary{};
    BOOST_REQUIRE(AssembleAndVerifyFastSyncPivot(
        pivot_header, chain_id, decoded_roots, shards, assembled,
        assembled_monetary, error));
    BOOST_CHECK(assembled.Root() == utxo.Root());
    BOOST_CHECK_EQUAL(assembled.Size(), utxo.Size());

    const auto temp_dir = m_args.GetDataDirNet() / "fast_sync_disk_test";
    std::filesystem::create_directories(temp_dir);
    DiskStateOptions opts{};
    opts.identity = chain_id;
    opts.profile_digest.fill(0x33);
    DiskStateStore store;
    DiskStateError disk_err{};
    BOOST_REQUIRE(
        DiskStateStore::Open(temp_dir.string(), opts, {}, store, disk_err));
    BOOST_REQUIRE(ImportVerifiedFastSyncPivotToDisk(
        pivot_header, chain_id, {}, decoded_roots, shards, store, error));
    BOOST_CHECK(store.Root() == utxo.Root());

    UtxoRootsMessage exported_from_disk{};
    BOOST_REQUIRE(
        ExportDiskUtxoRoots(store, chain_id, exported_from_disk, error));
    BOOST_CHECK(exported_from_disk == decoded_roots);
}

BOOST_AUTO_TEST_CASE(adversarial_hole_11_13_14_15_defenses) {
    ChainId chain_id{};
    chain_id[0] = 0x99;
    const uint64_t pivot_height = 200;
    const MonetaryState monetary = MakeTestMonetaryState();

    UtxoSet utxo;
    const lotus::v2::Coin coin_s1 = MakeCoinWithIndex(0x01, 1, 2000, 50);
    const lotus::v2::Coin coin_s2_a = MakeCoinWithIndex(0x02, 1, 3000, 60);
    const lotus::v2::Coin coin_s2_b = MakeCoinWithIndex(0x02, 2, 4000, 70);
    BOOST_REQUIRE(utxo.Insert(coin_s1));
    BOOST_REQUIRE(utxo.Insert(coin_s2_a));
    BOOST_REQUIRE(utxo.Insert(coin_s2_b));

    const Header pivot_header =
        MakePivotHeader(chain_id, pivot_height, utxo.Root(), monetary);
    UtxoRootsMessage roots_msg{};
    std::string error;
    BOOST_REQUIRE(ExportUtxoRoots(utxo, chain_id, pivot_header, monetary,
                                  roots_msg, error));

    // Hole 11a: Spoofing cardinality_tag (1 -> 2) on single-leaf shard 0x01 must fail header verification.
    {
        UtxoRootsMessage spoofed = roots_msg;
        spoofed.shards[0x01].cardinality_tag = 2;
        BOOST_CHECK(!VerifyUtxoRootsAgainstHeader(pivot_header, chain_id,
                                                  spoofed, error));
    }

    UtxoShardMessage shard_s2{};
    BOOST_REQUIRE(ExportUtxoShard(utxo, roots_msg.pivot_block_id, 8, 0x02,
                                  shard_s2, error));

    // Hole 11b: Cross-shard key smuggling (injecting coin from shard 0x01 into shard 0x02).
    {
        UtxoShardMessage smuggled = shard_s2;
        smuggled.coins.push_back(coin_s1);
        BOOST_CHECK(!VerifyAndBuildUtxoShard(
            roots_msg.shards[0x02], pivot_height, smuggled, nullptr, error));
    }

    // Hole 11c: Unsorted / duplicate coin keys in shard.
    {
        UtxoShardMessage unsorted = shard_s2;
        std::reverse(unsorted.coins.begin(), unsorted.coins.end());
        BOOST_CHECK(!VerifyAndBuildUtxoShard(
            roots_msg.shards[0x02], pivot_height, unsorted, nullptr, error));
    }

    // Hole 11d: Burn output (flags & 0x02) smuggled in shard.
    {
        UtxoShardMessage burned = shard_s2;
        burned.coins[0].output.flags = 0x02;
        burned.coins[0].output.paths.clear();
        BOOST_CHECK(!VerifyAndBuildUtxoShard(
            roots_msg.shards[0x02], pivot_height, burned, nullptr, error));
    }

    // Hole 11e: Coin creation_height > pivot_height.
    {
        UtxoShardMessage future_coin = shard_s2;
        future_coin.coins[0].creation_height = pivot_height + 1;
        BOOST_CHECK(!VerifyAndBuildUtxoShard(roots_msg.shards[0x02],
                                             pivot_height, future_coin, nullptr,
                                             error));
    }

    // Hole 15: Exceeding 4096 leaves or invalid prefix_depth.
    {
        UtxoShardMessage oversized = shard_s2;
        oversized.coins.resize(kMaxUtxoShardLeaves + 1, coin_s2_a);
        BOOST_CHECK(!VerifyAndBuildUtxoShard(
            roots_msg.shards[0x02], pivot_height, oversized, nullptr, error));

        UtxoShardMessage bad_depth = shard_s2;
        bad_depth.prefix_depth = 17;
        BOOST_CHECK(!VerifyAndBuildUtxoShard(
            roots_msg.shards[0x02], pivot_height, bad_depth, nullptr, error));
    }

    // Holes 13 & 14: Dual Pivot Authentication Gate and 10-block Pivot Safety Cushion.
    {
        FastSyncPivotCandidate cand{};
        cand.pivot_height = 500;
        cand.best_header_height = 600;
        cand.has_minimum_chain_work = false;
        cand.is_avalanche_finalized = true;
        BOOST_CHECK(!CheckFastSyncPivotEligibility(cand, error));

        cand.has_minimum_chain_work = true;
        cand.is_avalanche_finalized = false;
        cand.buried_blocks = 99;
        cand.distinct_netgroup_confirmations = 3;
        BOOST_CHECK(!CheckFastSyncPivotEligibility(cand, error));

        cand.buried_blocks = 100;
        cand.distinct_netgroup_confirmations = 2;
        BOOST_CHECK(!CheckFastSyncPivotEligibility(cand, error));

        cand.distinct_netgroup_confirmations = 3;
        cand.pivot_height = 595; // Only 5 blocks below tip (< 10 cushion).
        BOOST_CHECK(!CheckFastSyncPivotEligibility(cand, error));

        cand.pivot_height = 500;
        BOOST_CHECK(CheckFastSyncPivotEligibility(cand, error));
    }
}

BOOST_AUTO_TEST_CASE(bijective_reverse_block_peeling_and_hole_12_intra_block_spends) {
    const auto &all_types = getAllNetMessageTypes();
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::GETBLOCKUNDO)) !=
                all_types.end());
    BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                          std::string(NetMsgType::BLOCKUNDO)) !=
                all_types.end());

    GetBlockUndoRequest ureq{};
    ureq.block_id.fill(0x55);
    const auto ureq_wire = EncodeGetBlockUndoRequest(ureq);
    GetBlockUndoRequest ureq_decoded{};
    std::string error;
    BOOST_REQUIRE(DecodeGetBlockUndoRequest(ureq_wire, ureq_decoded, error));
    BOOST_CHECK(ureq_decoded == ureq);

    // Build a 4-block V2 chain B0 -> B1 -> B2 -> B3 where B3 contains an
    // intra-block parent-child spend (Hole 12 test).
    assembler_fixture::Home home;
    const auto &p = home.p;

    auto read_store_state = [&](UtxoSet &out_utxo, Header &out_hdr,
                                MonetaryState &out_mon,
                                std::vector<uint8_t> &out_hdr_bytes) {
        std::vector<lotus::v2::Coin> coins;
        DiskStateError derr{};
        BOOST_REQUIRE(home.store.ExportCoins(coins, derr));
        out_utxo = UtxoSet{};
        for (const auto &c : coins) {
            BOOST_REQUIRE(out_utxo.Insert(c));
        }
        const auto meta = home.store.Metadata();
        out_hdr_bytes = meta.header;
        BOOST_REQUIRE(
            ParseHeader(meta.header.data(), meta.header.size(), out_hdr));
        BOOST_REQUIRE_EQUAL(meta.monetary.size(), 56U);
        out_mon = DecodeMonetaryState(meta.monetary);
    };

    // B0 (genesis)
    UtxoSet utxo_0;
    Header hdr_0{};
    MonetaryState mon_0{};
    std::vector<uint8_t> hdr_bytes_0;
    read_store_state(utxo_0, hdr_0, mon_0, hdr_bytes_0);

    // B1 (funding block)
    auto b1_mined = assembler_fixture::Mine(
        assembler_fixture::Build(home, assembler_fixture::Request(home, 100000)),
        p);
    BlockUndoMessage undo_1{};
    BOOST_REQUIRE(BuildBlockUndoMessage(b1_mined.wire, p.header.chain_id,
                                        p.ordinary.transaction, mon_0, utxo_0,
                                        undo_1, error));
    BOOST_CHECK(undo_1.prior_spent_coins.empty());
    assembler_fixture::Connect(home, b1_mined);

    UtxoSet utxo_1;
    Header hdr_1{};
    MonetaryState mon_1{};
    std::vector<uint8_t> hdr_bytes_1;
    read_store_state(utxo_1, hdr_1, mon_1, hdr_bytes_1);

    // B2 (second block to mature B1 coinbase)
    auto b2_mined = assembler_fixture::Mine(
        assembler_fixture::Build(home, assembler_fixture::Request(home, 100000)),
        p);
    BlockUndoMessage undo_2{};
    BOOST_REQUIRE(BuildBlockUndoMessage(b2_mined.wire, p.header.chain_id,
                                        p.ordinary.transaction, mon_1, utxo_1,
                                        undo_2, error));
    BOOST_CHECK(undo_2.prior_spent_coins.empty());
    assembler_fixture::Connect(home, b2_mined);

    UtxoSet utxo_2;
    Header hdr_2{};
    MonetaryState mon_2{};
    std::vector<uint8_t> hdr_bytes_2;
    read_store_state(utxo_2, hdr_2, mon_2, hdr_bytes_2);

    // B3: intra-block parent-child spend!
    // parent spends B1 coinbase (in I_3^prior); child spends parent output[0] (in I_3^intra).
    lotus::v2::Coin funding_coin =
        assembler_fixture::CoinAt(b1_mined, 0, p, true);
    std::optional<lotus::v2::Coin> auth_coin;
    DiskStateError derr{};
    BOOST_REQUIRE(home.store.ReadCoin(funding_coin.outpoint, auth_coin, derr) &&
                  auth_coin.has_value());
    funding_coin = *auth_coin;

    Transaction parent_tx = assembler_fixture::Spend(funding_coin, 95000, p);
    IdentityDigests parent_ids{};
    BOOST_REQUIRE(ComputeIdentities(parent_tx, p.ordinary.transaction,
                                    p.header.chain_id, parent_ids, error));
    lotus::v2::Coin intermediate_coin{};
    intermediate_coin.outpoint = {parent_ids.txid, 0};
    intermediate_coin.output = parent_tx.outputs[0];
    intermediate_coin.creation_height = 3;
    intermediate_coin.creation_parent_mtp = hdr_2.time;
    intermediate_coin.coinbase = false;
    Transaction child_tx =
        assembler_fixture::Spend(intermediate_coin, 90000, p);

    auto req_3 = assembler_fixture::Request(home);
    req_3.ordinary = {parent_tx, child_tx};
    auto b3_mined =
        assembler_fixture::Mine(assembler_fixture::Build(home, req_3), p);
    const FramedBlock b3_block = assembler_fixture::Decode(b3_mined, p);

    BlockUndoMessage undo_3{};
    BOOST_REQUIRE(BuildBlockUndoMessage(b3_mined.wire, p.header.chain_id,
                                        p.ordinary.transaction, mon_2, utxo_2,
                                        undo_3, error));
    // Hole 12 check: undo_3.prior_spent_coins must contain ONLY I_3^prior (funding_coin),
    // and NOT the intra-block intermediate_coin!
    BOOST_REQUIRE_EQUAL(undo_3.prior_spent_coins.size(), 1U);
    BOOST_CHECK(undo_3.prior_spent_coins[0].outpoint == funding_coin.outpoint);
    BOOST_CHECK_EQUAL(undo_3.prior_spent_coins[0].output.value,
                      funding_coin.output.value);

    // Wire roundtrip of BlockUndoMessage.
    std::vector<uint8_t> undo_3_wire;
    BOOST_REQUIRE(EncodeBlockUndoMessage(undo_3, undo_3_wire, error));
    BlockUndoMessage undo_3_decoded{};
    BOOST_REQUIRE(DecodeBlockUndoMessage(undo_3_wire, undo_3_decoded, error));
    BOOST_CHECK(undo_3_decoded.block_id == undo_3.block_id);
    BOOST_CHECK(undo_3_decoded.parent_monetary_state ==
                undo_3.parent_monetary_state);
    BOOST_REQUIRE_EQUAL(undo_3_decoded.prior_spent_coins.size(), 1U);
    BOOST_CHECK(undo_3_decoded.prior_spent_coins[0].outpoint ==
                funding_coin.outpoint);

    assembler_fixture::Connect(home, b3_mined);
    UtxoSet utxo_3;
    Header hdr_3{};
    MonetaryState mon_3{};
    std::vector<uint8_t> hdr_bytes_3;
    read_store_state(utxo_3, hdr_3, mon_3, hdr_bytes_3);

    // Export fast-sync pivot at B3 and import into both in-memory UtxoSet and fresh DiskStateStore.
    UtxoRootsMessage pivot_roots{};
    BOOST_REQUIRE(
        ExportDiskUtxoRoots(home.store, p.header.chain_id, pivot_roots, error));
    std::vector<UtxoShardMessage> pivot_shards;
    BOOST_REQUIRE(ExportAdaptiveUtxoShards(
        utxo_3, pivot_roots.pivot_block_id, pivot_shards, error));

    UtxoSet peel_utxo;
    MonetaryState peel_mon{};
    BOOST_REQUIRE(AssembleAndVerifyFastSyncPivot(
        hdr_3, p.header.chain_id, pivot_roots, pivot_shards, peel_utxo,
        peel_mon, error));

    const auto peel_dir = m_args.GetDataDirNet() / "fast_sync_peel_disk_test";
    std::filesystem::create_directories(peel_dir);
    DiskStateOptions disk_opts{};
    disk_opts.identity = p.header.chain_id;
    disk_opts.profile_digest =
        BlockValidationProfileDigest(p.header, p.ordinary, p.monetary, p.cost);
    DiskStateStore peel_store;
    BOOST_REQUIRE_MESSAGE(
        DiskStateStore::Open(peel_dir.string(), disk_opts, {}, peel_store, derr),
        derr.message);
    BOOST_REQUIRE(ImportVerifiedFastSyncPivotToDisk(
        hdr_3, p.header.chain_id, {hdr_3, hdr_2, hdr_1, hdr_0},
        pivot_roots, pivot_shards, peel_store, error));
    BOOST_CHECK(peel_store.Root() == utxo_3.Root());

    const std::vector<Header> history_b3 = {hdr_2, hdr_1, hdr_0};
    const std::vector<Header> history_b2 = {hdr_1, hdr_0};
    const std::vector<Header> history_b1 = {hdr_0};

    // Adversarial Hole 12 tests before peeling B3:
    // 1. Smuggling the intra-block intermediate_coin into undo_3.prior_spent_coins must fail.
    {
        UtxoSet tmp_utxo = peel_utxo;
        MonetaryState tmp_mon = peel_mon;
        BlockUndoMessage bad_undo = undo_3;
        bad_undo.prior_spent_coins.push_back(intermediate_coin);
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_undo, hdr_2, history_b3,
                                      p.header, p.ordinary, p.monetary, p.cost,
                                      tmp_utxo, tmp_mon, error));
    }
    // 2. Corrupting the spent coin value in undo_3 must fail parent state_root authentication.
    {
        UtxoSet tmp_utxo = peel_utxo;
        MonetaryState tmp_mon = peel_mon;
        BlockUndoMessage bad_undo = undo_3;
        bad_undo.prior_spent_coins[0].output.value += 1;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_undo, hdr_2, history_b3,
                                      p.header, p.ordinary, p.monetary, p.cost,
                                      tmp_utxo, tmp_mon, error));
    }
    // 3. Corrupting child_tx signature in B3 must fail forward validation during PeelBlockReverse.
    {
        UtxoSet tmp_utxo = peel_utxo;
        MonetaryState tmp_mon = peel_mon;
        FramedBlock bad_b3 = b3_block;
        bad_b3.transactions[2].inputs[0].witnesses[0].arguments[0][0] ^= 0x01;
        std::vector<uint8_t> bad_b3_wire;
        BOOST_REQUIRE(EncodeBlockWire(bad_b3.header, bad_b3.transactions,
                                      p.ordinary.transaction, bad_b3_wire,
                                      error));
        BOOST_CHECK(!PeelBlockReverse(bad_b3_wire, undo_3, hdr_2, history_b3,
                                      p.header, p.ordinary, p.monetary, p.cost,
                                      tmp_utxo, tmp_mon, error));
    }

    // 4. Exercise InMemoryBlockStateTx::Abort() and forward stage failure in
    // PeelBlockReverse and PeelDiskBlockReverse, plus all reverse peel gates:
    {
        UtxoSet tmp_utxo = peel_utxo;
        MonetaryState tmp_mon = peel_mon;
        BlockCostProfile bad_cost = p.cost;
        bad_cost.hash_base = 1000000000ULL; // Triggers StageCompleteBlock failure & InMemoryBlockStateTx::Abort()
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, undo_3, hdr_2, history_b3,

                                      p.header, p.ordinary, p.monetary,
                                      bad_cost, tmp_utxo, tmp_mon, error));
        BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2,
                                          history_b3, p.header, p.ordinary,
                                          p.monetary, bad_cost, peel_store,
                                          error));

        // Mismatched undo block_id
        BlockUndoMessage bad_id_undo = undo_3;
        bad_id_undo.block_id[0] ^= 0xFF;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_id_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // Mismatched parent_header height
        Header bad_parent_hdr = hdr_2;
        bad_parent_hdr.height = 99;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, undo_3, bad_parent_hdr,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // Mismatched starting state_at_h root
        UtxoSet empty_utxo;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, undo_3, hdr_2, history_b3,
                                      p.header, p.ordinary, p.monetary, p.cost,
                                      empty_utxo, tmp_mon, error));

        // Empty history (ParentMedianTime failure)
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, undo_3, hdr_2, {},
                                      p.header, p.ordinary, p.monetary, p.cost,
                                      tmp_utxo, tmp_mon, error));
        BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2, {},
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, peel_store, error));

        // Truncated block_wire in BuildBlockUndoMessage & PeelDiskBlockReverse
        BlockUndoMessage dummy_undo{};
        BOOST_CHECK(!BuildBlockUndoMessage({0x01, 0x02}, p.header.chain_id,
                                           p.ordinary.transaction, mon_2,
                                           utxo_2, dummy_undo, error));
        BOOST_CHECK(!BuildBlockUndoMessage(b3_mined.wire, p.header.chain_id,
                                           p.ordinary.transaction, mon_2,
                                           empty_utxo, dummy_undo, error));
        BOOST_CHECK(!PeelDiskBlockReverse({0x01, 0x02}, undo_3, hdr_2,
                                          history_b3, p.header, p.ordinary,
                                          p.monetary, p.cost, peel_store,
                                          error));

        // PartitionBlockOutputsAndSpends checks via PeelBlockReverse / PeelDiskBlockReverse:
        // a) missing prior spent coin
        BlockUndoMessage empty_undo = undo_3;
        empty_undo.prior_spent_coins.clear();
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, empty_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));
        BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, empty_undo, hdr_2,
                                          history_b3, p.header, p.ordinary,
                                          p.monetary, p.cost, peel_store,
                                          error));

        // b) outpoint mismatch in prior_spent_coins
        BlockUndoMessage bad_op_undo = undo_3;
        bad_op_undo.prior_spent_coins[0].outpoint.index = 999;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_op_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // c) creation_height >= block.header.height
        BlockUndoMessage bad_ht_undo = undo_3;
        bad_ht_undo.prior_spent_coins[0].creation_height = 3;
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_ht_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // d) burn output in prior_spent_coins
        BlockUndoMessage burn_undo = undo_3;
        burn_undo.prior_spent_coins[0].output.flags = 0x02;
        burn_undo.prior_spent_coins[0].output.paths.clear();
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, burn_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // e) invalid UtxoLeaf (empty branches on non-burn output) in prior_spent_coins
        BlockUndoMessage zero_val_undo = undo_3;
        zero_val_undo.prior_spent_coins[0].output.branches.clear();
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, zero_val_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // f) invalid parent_monetary_state (zero work) in undo_msg
        BlockUndoMessage bad_mon_undo = undo_3;
        bad_mon_undo.parent_monetary_state.fill(0);
        BOOST_CHECK(!PeelBlockReverse(b3_mined.wire, bad_mon_undo, hdr_2,
                                      history_b3, p.header, p.ordinary,
                                      p.monetary, p.cost, tmp_utxo, tmp_mon,
                                      error));

        // g) state_at_h missing surviving O_h^net, modified O_h^net bytes, or containing I_h^prior
        auto make_custom_b3 = [&](const std::vector<Transaction> &txs,
                                  const UtxoSet &st) {
            Header chdr = hdr_3;
            BOOST_REQUIRE(CompleteTransactionRoot(txs, p.ordinary.transaction,
                                                  p.header.chain_id,
                                                  chdr.tx_root, error));
            chdr.state_root =
                StateRoot(p.header.chain_id, chdr.height, st.Root(), mon_3);
            uint64_t sz = HEADER_SIZE + 4;
            for (const auto &t : txs) {
                std::vector<uint8_t> raw;
                BOOST_REQUIRE(
                    EncodeTransaction(t, p.ordinary.transaction, raw, error));
                sz += CompactSizeWidth(raw.size()) + raw.size();
            }
            chdr.size = sz;
            std::vector<uint8_t> cwire;
            BOOST_REQUIRE(EncodeBlockWire(chdr, txs, p.ordinary.transaction,
                                          cwire, error));
            BlockUndoMessage cundo = undo_3;
            BOOST_REQUIRE(BlockId(p.header.chain_id, chdr, cundo.block_id));
            return std::pair{cwire, cundo};
        };
        FramedBlock b3_framed;
        BOOST_REQUIRE(DecodeBlockWire(b3_mined.wire, p.ordinary.transaction,
                                      p.header.chain_id, b3_framed, error));
        {
            // Missing surviving O_h^net in state_at_h (lines 1386-1388)
            UtxoSet missing_net_utxo;
            auto [cwire, cundo] =
                make_custom_b3(b3_framed.transactions, missing_net_utxo);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, missing_net_utxo, tmp_mon,
                                          error));
        }
        {
            // Surviving O_h^net coin bytes mismatch in state_at_h (lines 1392-1394)
            UtxoSet mismatch_net_utxo;
            for (lotus::v2::Coin c : utxo_3.Coins()) {
                if (c.creation_height == 3) c.output.value += 1;
                BOOST_REQUIRE(mismatch_net_utxo.Insert(c));
            }
            auto [cwire, cundo] =
                make_custom_b3(b3_framed.transactions, mismatch_net_utxo);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, mismatch_net_utxo, tmp_mon,
                                          error));
        }
        {
            // Prior spent coin already exists in state_at_h (lines 1398-1400)
            UtxoSet has_prior_utxo = utxo_3;
            BOOST_REQUIRE(has_prior_utxo.Insert(undo_3.prior_spent_coins[0]));
            auto [cwire, cundo] =
                make_custom_b3(b3_framed.transactions, has_prior_utxo);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, has_prior_utxo, tmp_mon,
                                          error));
        }
        {
            // Prior spent coin OutpointKey collision in peeled_state.Insert (lines 1414-1416)
            UtxoSet key_collision_utxo = utxo_3;
            lotus::v2::Coin colliding_coin = undo_3.prior_spent_coins[0];
            colliding_coin.outpoint.index ^= 1u;
            colliding_coin.outpoint.tx_id[28] ^= 1u;
            BOOST_REQUIRE(key_collision_utxo.Insert(colliding_coin));
            auto [cwire, cundo] =
                make_custom_b3(b3_framed.transactions, key_collision_utxo);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, key_collision_utxo, tmp_mon,
                                          error));
        }
        {
            // Duplicate input spend inside block (lines 1114-1116)
            auto dup_in_txs = b3_framed.transactions;
            Transaction extra_tx = dup_in_txs[1];
            extra_tx.outputs[0].value -= 1;
            dup_in_txs.push_back(extra_tx);
            auto [cwire, cundo] = make_custom_b3(dup_in_txs, utxo_3);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, tmp_utxo, tmp_mon, error));
        }
        {
            // Intra-block spend references later transaction (lines 1122-1124)
            auto reverse_intra_txs = b3_framed.transactions;
            std::swap(reverse_intra_txs[1], reverse_intra_txs[2]);
            auto [cwire, cundo] = make_custom_b3(reverse_intra_txs, utxo_3);
            BOOST_CHECK(!PeelBlockReverse(cwire, cundo, hdr_2, history_b3,
                                          p.header, p.ordinary, p.monetary,
                                          p.cost, tmp_utxo, tmp_mon, error));
        }
        // Closed DiskStateStore and corrupted metadata checks
        DiskStateStore closed_store;
        UtxoRootsMessage closed_roots{};
        BOOST_CHECK(!ExportDiskUtxoRoots(closed_store, p.header.chain_id,
                                         closed_roots, error));
        BOOST_CHECK(!ImportVerifiedFastSyncPivotToDisk(
            hdr_3, p.header.chain_id, history_b3, pivot_roots, pivot_shards,
            closed_store, error));
        BOOST_CHECK(!ImportVerifiedFastSyncPivotToDisk(
            hdr_3, p.header.chain_id, history_b3, pivot_roots, {}, closed_store,
            error));
        // Re-importing into non-empty peel_store fails store.ImportFastSyncPivot (lines 1015-1016)
        BOOST_CHECK(!ImportVerifiedFastSyncPivotToDisk(
            hdr_3, p.header.chain_id, history_b3, pivot_roots, pivot_shards,
            peel_store, error));
        // Invalid history (> 11 headers) in ImportVerifiedFastSyncPivotToDisk (lines 1008-1010)
        std::vector<Header> long_history(12, hdr_2);
        BOOST_CHECK(!ImportVerifiedFastSyncPivotToDisk(
            hdr_3, p.header.chain_id, long_history, pivot_roots, pivot_shards,
            peel_store, error));
        BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2,
                                          history_b3, p.header, p.ordinary,
                                          p.monetary, p.cost, closed_store,
                                          error));
        // Active transaction on peel_store causes store.PeelBlockStateReverse to fail (lines 1547-1549)
        {
            DiskStateTransaction active_tx;
            BOOST_REQUIRE(peel_store.Begin(active_tx, derr));
            BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2,
                                              history_b3, p.header, p.ordinary,
                                              p.monetary, p.cost, peel_store,
                                              error));
            active_tx.Abort();
        }

        // Open a temporary DiskStateStore with empty header/monetary metadata to exercise
        // ExportDiskUtxoRoots (lines 956-971) and PeelDiskBlockReverse (lines 1475-1483)
        const auto bad_meta_dir =
            m_args.GetDataDirNet() / "fast_sync_bad_meta_store";
        std::filesystem::create_directories(bad_meta_dir);
        {
            DiskStateStore bm_store;
            DiskStateError bm_err{};
            BOOST_REQUIRE(DiskStateStore::Open(bad_meta_dir.string(), disk_opts,
                                               {}, bm_store, bm_err));
            BOOST_CHECK(!ExportDiskUtxoRoots(bm_store, p.header.chain_id,
                                             closed_roots, error));
            BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2,
                                              history_b3, p.header, p.ordinary,
                                              p.monetary, p.cost, bm_store,
                                              error));
        }
        const auto bad_mon_dir =
            m_args.GetDataDirNet() / "fast_sync_bad_mon_store";
        std::filesystem::create_directories(bad_mon_dir);
        {
            DiskStateStore bmon_store;
            DiskStateError bm_err{};
            DiskStateMetadata partial_meta{};
            std::array<uint8_t, HEADER_SIZE> raw_h3{};
            BOOST_REQUIRE(SerializeHeader(hdr_3, raw_h3));
            partial_meta.header.assign(raw_h3.begin(), raw_h3.end());
            BOOST_REQUIRE(DiskStateStore::Open(bad_mon_dir.string(), disk_opts,
                                               partial_meta, bmon_store,
                                               bm_err));
            BOOST_CHECK(!ExportDiskUtxoRoots(bmon_store, p.header.chain_id,
                                             closed_roots, error));
        }
        const auto corrupt_coins_dir =
            m_args.GetDataDirNet() / "fast_sync_corrupt_coins_store";
        std::filesystem::create_directories(corrupt_coins_dir);
        {
            DiskStateStore cc_store;
            DiskStateError bm_err{};
            DiskStateMetadata valid_meta{};
            std::array<uint8_t, HEADER_SIZE> raw_h3{};
            BOOST_REQUIRE(SerializeHeader(hdr_3, raw_h3));
            valid_meta.header.assign(raw_h3.begin(), raw_h3.end());
            valid_meta.monetary.assign(pivot_roots.monetary_state.begin(),
                                       pivot_roots.monetary_state.end());
            BOOST_REQUIRE(DiskStateStore::Open(corrupt_coins_dir.string(),
                                               disk_opts, valid_meta, cc_store,
                                               bm_err));
            cc_store = {};
            std::string raw_err;
            BOOST_REQUIRE(RawDiskStateAccess(
                corrupt_coins_dir.string(), std::nullopt, nullptr,
                {{std::string(37, 'C'), std::string("corrupt")}}, &raw_err));
            BOOST_REQUIRE(DiskStateStore::Open(corrupt_coins_dir.string(),
                                               disk_opts, valid_meta, cc_store,
                                               bm_err));
            BOOST_CHECK(!ExportDiskUtxoRoots(cc_store, p.header.chain_id,
                                             closed_roots, error));
            BOOST_CHECK(!PeelDiskBlockReverse(b3_mined.wire, undo_3, hdr_2,
                                              history_b3, p.header, p.ordinary,
                                              p.monetary, p.cost, cc_store,
                                              error));
        }
    }

    // Peel B3 -> B2
    BOOST_REQUIRE(PeelBlockReverse(b3_mined.wire, undo_3, hdr_2, history_b3,
                                   p.header, p.ordinary, p.monetary, p.cost,
                                   peel_utxo, peel_mon, error));
    BOOST_CHECK(peel_utxo.Root() == utxo_2.Root());
    BOOST_CHECK(EncodeMonetaryState(peel_mon) == EncodeMonetaryState(mon_2));

    BOOST_REQUIRE(PeelDiskBlockReverse(
        b3_mined.wire, undo_3, hdr_2, history_b3, p.header, p.ordinary,
        p.monetary, p.cost, peel_store, error));
    BOOST_CHECK(peel_store.Root() == utxo_2.Root());

    // Peel B2 -> B1
    BOOST_REQUIRE(PeelBlockReverse(b2_mined.wire, undo_2, hdr_1, history_b2,
                                   p.header, p.ordinary, p.monetary, p.cost,
                                   peel_utxo, peel_mon, error));
    BOOST_CHECK(peel_utxo.Root() == utxo_1.Root());
    BOOST_CHECK(EncodeMonetaryState(peel_mon) == EncodeMonetaryState(mon_1));

    BOOST_REQUIRE(PeelDiskBlockReverse(
        b2_mined.wire, undo_2, hdr_1, history_b2, p.header, p.ordinary,
        p.monetary, p.cost, peel_store, error));
    BOOST_CHECK(peel_store.Root() == utxo_1.Root());

    // Peel B1 -> B0 (genesis)
    BOOST_REQUIRE(PeelBlockReverse(b1_mined.wire, undo_1, hdr_0, history_b1,
                                   p.header, p.ordinary, p.monetary, p.cost,
                                   peel_utxo, peel_mon, error));
    BOOST_CHECK(peel_utxo.Root() == utxo_0.Root());
    BOOST_CHECK(EncodeMonetaryState(peel_mon) == EncodeMonetaryState(mon_0));

    BOOST_REQUIRE(PeelDiskBlockReverse(
        b1_mined.wire, undo_1, hdr_0, history_b1, p.header, p.ordinary,
        p.monetary, p.cost, peel_store, error));
    BOOST_CHECK(peel_store.Root() == utxo_0.Root());
    BOOST_CHECK(peel_store.Metadata().tip == p.header.genesis_id);
}

BOOST_AUTO_TEST_CASE(fast_sync_wire_and_validation_edge_cases) {
    std::string error;
    ChainId chain_id{};
    chain_id[0] = 0x42;
    const uint64_t pivot_height = 100;
    const MonetaryState monetary = MakeTestMonetaryState();

    // 1. CheckFastSyncPivotEligibility: pivot_height > best_header_height
    {
        FastSyncPivotCandidate cand{};
        cand.has_minimum_chain_work = true;
        cand.pivot_height = 700;
        cand.best_header_height = 600;
        BOOST_CHECK(!CheckFastSyncPivotEligibility(cand, error));
    }

    // 2. FoldShardPair & FoldDepth8ShardRoots invalid entry checks
    {
        ShardRootEntry invalid_entry{3, EmptyUtxoRoot()};
        ShardRootEntry valid_empty{0, EmptyUtxoRoot()};
        ShardRootEntry out_entry{};
        BOOST_CHECK(!FoldShardPair(0, invalid_entry, valid_empty, out_entry));

        std::array<ShardRootEntry, kFastSyncShardCount> bad_shards{};
        for (auto &s : bad_shards) {
            s = valid_empty;
        }
        bad_shards[0] = invalid_entry;
        BOOST_CHECK(!FoldDepth8ShardRoots(bad_shards, &error).has_value());
    }

    // 3. Wire decode/encode validation gates
    {
        GetUtxoRootsRequest rreq{};
        BOOST_CHECK(!DecodeGetUtxoRootsRequest({0x01, 0x02}, rreq, error));

        UtxoRootsMessage rmsg{};
        BOOST_CHECK(!DecodeUtxoRootsMessage({0x01, 0x02}, rmsg, error));
        auto valid_roots_wire = EncodeUtxoRootsMessage(rmsg);
        // Set invalid cardinality_tag = 3 on shard 0
        valid_roots_wire[96] = 3;
        BOOST_CHECK(!DecodeUtxoRootsMessage(valid_roots_wire, rmsg, error));

        GetUtxoShardRequest sreq{};
        std::vector<uint8_t> sbytes;
        sreq.prefix_depth = 7;
        BOOST_CHECK(!EncodeGetUtxoShardRequest(sreq, sbytes, error));
        sreq.prefix_depth = 8;
        sreq.prefix_bits = 0x0100;
        BOOST_CHECK(!EncodeGetUtxoShardRequest(sreq, sbytes, error));
        BOOST_CHECK(!DecodeGetUtxoShardRequest({0x01}, sreq, error));
        std::vector<uint8_t> bad_sreq(35, 0);
        bad_sreq[32] = 7;
        BOOST_CHECK(!DecodeGetUtxoShardRequest(bad_sreq, sreq, error));
        bad_sreq[32] = 8;
        bad_sreq[34] = 1; // prefix_bits = 0x0100
        BOOST_CHECK(!DecodeGetUtxoShardRequest(bad_sreq, sreq, error));

        UtxoShardMessage smsg{};
        smsg.prefix_depth = 7;
        BOOST_CHECK(!EncodeUtxoShardMessage(smsg, sbytes, error));
        smsg.prefix_depth = 8;
        smsg.prefix_bits = 0x0100;
        BOOST_CHECK(!EncodeUtxoShardMessage(smsg, sbytes, error));
        smsg.prefix_bits = 0;
        smsg.prefix_depth = 9; // expects 1 boundary sibling
        BOOST_CHECK(!EncodeUtxoShardMessage(smsg, sbytes, error));
        smsg.prefix_depth = 8;
        smsg.coins.resize(kMaxUtxoShardLeaves + 1);
        BOOST_CHECK(!EncodeUtxoShardMessage(smsg, sbytes, error));
        smsg.coins.resize(1); // empty branches -> EncodeCoin fails
        BOOST_CHECK(!EncodeUtxoShardMessage(smsg, sbytes, error));

        // Encode & decode 260 coins (exercises 2-byte CompactSize 253..65535)
        smsg.coins.clear();
        for (uint32_t i = 0; i < 260; ++i) {
            smsg.coins.push_back(MakeCoinWithIndex(0x01, i + 1, 1000 + i, 10));
        }
        BOOST_REQUIRE(EncodeUtxoShardMessage(smsg, sbytes, error));
        UtxoShardMessage sdecoded{};
        BOOST_REQUIRE(DecodeUtxoShardMessage(sbytes, sdecoded, error));
        BOOST_CHECK_EQUAL(sdecoded.coins.size(), 260U);

        // ReadCompactSize (253, 254, 255) and DecodeCanonicalCoinBytes edge cases
        auto make_shard_hdr = [](const std::vector<uint8_t> &tail) {
            std::vector<uint8_t> b(35, 0);
            b[32] = 8;
            b.insert(b.end(), tail.begin(), tail.end());
            return b;
        };
        // 253 with < 2 bytes and non-canonical < 253
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({253, 0}), sdecoded, error));
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({253, 10, 0}), sdecoded, error));
        // 254 with < 4 bytes, non-canonical < 0x10000, and valid 0x10000 (> max 4096)
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({254, 1, 2}), sdecoded, error));
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({254, 1, 0, 0, 0}), sdecoded, error));
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({254, 0, 0, 1, 0}), sdecoded, error));
        // 255 with < 8 bytes, non-canonical < 0x100000000, and valid 0x100000000 (> max 4096)
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({255, 1, 2, 3}), sdecoded, error));
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({255, 1, 0, 0, 0, 0, 0, 0, 0}), sdecoded, error));
        BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr({255, 0, 0, 0, 0, 1, 0, 0, 0}), sdecoded, error));
        // Coin record with coin_len = 10 (< 54 -> invalid coin byte length, lines 90-92)
        {
            std::vector<uint8_t> short_coin = {1, 10};
            short_coin.resize(12, 0);
            BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr(short_coin), sdecoded, error));
        }
        // Coin record with coin_len = 54, output length = 20 (invalid coin output framing, lines 104-106)
        {
            std::vector<uint8_t> bad_frame_coin = {1, 54};
            bad_frame_coin.resize(2 + 54, 0);
            bad_frame_coin[2 + 36] = 20;
            BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr(bad_frame_coin), sdecoded, error));
        }
        // Coin record with coin_len = 55, output length = 1, invalid output byte 0xFF (lines 110-111)
        {
            std::vector<uint8_t> bad_out_coin = {1, 55};
            bad_out_coin.resize(2 + 55, 0);
            bad_out_coin[2 + 36] = 1;
            bad_out_coin[2 + 37] = 0xFF;
            BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr(bad_out_coin), sdecoded, error));
        }
        // Coin record with valid burn output (passes DecodeOutput, fails EncodeCoin in DecodeCanonicalCoinBytes, lines 124-126)
        {
            Output burn_out = MakeSpendableOutput(500);
            burn_out.flags = 0x02;
            burn_out.paths.clear();
            std::vector<uint8_t> burn_out_bytes;
            BOOST_REQUIRE(EncodeOutput(burn_out, burn_out_bytes, error));
            std::vector<uint8_t> burn_coin_rec(36, 0x11);
            burn_coin_rec.push_back(static_cast<uint8_t>(burn_out_bytes.size()));
            burn_coin_rec.insert(burn_coin_rec.end(), burn_out_bytes.begin(),
                                 burn_out_bytes.end());
            burn_coin_rec.resize(burn_coin_rec.size() + 17, 0);
            std::vector<uint8_t> tail = {1, static_cast<uint8_t>(burn_coin_rec.size())};
            tail.insert(tail.end(), burn_coin_rec.begin(), burn_coin_rec.end());
            BOOST_CHECK(!DecodeUtxoShardMessage(make_shard_hdr(tail), sdecoded, error));
        }

        // Trailing bytes in utxoshard
        auto trailing_sbytes = sbytes;
        trailing_sbytes.push_back(0x00);
        BOOST_CHECK(!DecodeUtxoShardMessage(trailing_sbytes, sdecoded, error));

        // Truncated utxoshard cases
        BOOST_CHECK(!DecodeUtxoShardMessage({0x01, 0x02}, sdecoded, error));
        std::vector<uint8_t> bad_smsg(36, 0);
        bad_smsg[32] = 7;
        BOOST_CHECK(!DecodeUtxoShardMessage(bad_smsg, sdecoded, error));
        bad_smsg[32] = 8;
        bad_smsg[34] = 1;
        BOOST_CHECK(!DecodeUtxoShardMessage(bad_smsg, sdecoded, error));
        bad_smsg[34] = 0;
        bad_smsg[32] = 10; // expects 2 siblings (64 bytes), only 1 byte left
        BOOST_CHECK(!DecodeUtxoShardMessage(bad_smsg, sdecoded, error));

        // Corrupt coin_base flag (last byte of first coin record in sbytes)
        auto bad_cb_sbytes = sbytes;
        bad_cb_sbytes.back() = 2;
        BOOST_CHECK(!DecodeUtxoShardMessage(bad_cb_sbytes, sdecoded, error));

        // Truncated coin record
        auto trunc_coin_sbytes = sbytes;
        trunc_coin_sbytes.pop_back();
        BOOST_CHECK(!DecodeUtxoShardMessage(trunc_coin_sbytes, sdecoded, error));

        // GetBlockUndoRequest / BlockUndoMessage wire errors
        GetBlockUndoRequest ureq{};
        BOOST_CHECK(!DecodeGetBlockUndoRequest({0x01}, ureq, error));
        BlockUndoMessage umsg{};
        umsg.prior_spent_coins.resize(1); // empty branches -> EncodeCoin fails
        std::vector<uint8_t> ubytes;
        BOOST_CHECK(!EncodeBlockUndoMessage(umsg, ubytes, error));
        umsg.prior_spent_coins[0] = MakeCoinWithIndex(0x01, 1, 1000, 10);
        BOOST_REQUIRE(EncodeBlockUndoMessage(umsg, ubytes, error));
        // Encode & decode 65536 coins in BlockUndoMessage (exercises 4-byte WriteCompactSize/ReadCompactSize 254)
        {
            BlockUndoMessage big_umsg{};
            big_umsg.prior_spent_coins.assign(65536, umsg.prior_spent_coins[0]);
            std::vector<uint8_t> big_ubytes;
            BOOST_REQUIRE(EncodeBlockUndoMessage(big_umsg, big_ubytes, error));
            BlockUndoMessage big_udecoded{};
            BOOST_REQUIRE(DecodeBlockUndoMessage(big_ubytes, big_udecoded, error));
            BOOST_CHECK_EQUAL(big_udecoded.prior_spent_coins.size(), 65536U);
            // Exceed kMaxBlockUndoCoins (1,000,000) in EncodeBlockUndoMessage (lines 1196-1198) & DecodeBlockUndoMessage (lines 1232-1234)
            big_umsg.prior_spent_coins.resize(1000001);
            BOOST_CHECK(!EncodeBlockUndoMessage(big_umsg, big_ubytes, error));
            std::vector<uint8_t> bad_count_ubytes(88, 0);
            bad_count_ubytes.insert(bad_count_ubytes.end(), {255, 0, 0, 0, 0, 1, 0, 0, 0});
            BOOST_CHECK(!DecodeBlockUndoMessage(bad_count_ubytes, big_udecoded, error));
        }
        auto trailing_ubytes = ubytes;
        trailing_ubytes.push_back(0);
        BlockUndoMessage udecoded{};
        BOOST_CHECK(!DecodeBlockUndoMessage(trailing_ubytes, udecoded, error));
        auto bad_cb_ubytes = ubytes;
        bad_cb_ubytes.back() = 2;
        BOOST_CHECK(!DecodeBlockUndoMessage(bad_cb_ubytes, udecoded, error));
        auto trunc_ubytes = ubytes;
        trunc_ubytes.pop_back();
        BOOST_CHECK(!DecodeBlockUndoMessage(trunc_ubytes, udecoded, error));
        BOOST_CHECK(!DecodeBlockUndoMessage({0x01, 0x02}, udecoded, error));
    }

    // 4. VerifyUtxoRootsAgainstHeader, VerifyAndBuildUtxoShard, Export*, AssembleAndVerifyFastSyncPivot
    {
        UtxoSet utxo;
        const auto c1 = MakeCoinWithIndex(0x01, 1, 1000, 10);
        const auto c2 = MakeCoinWithIndex(0x02, 1, 2000, 10);
        const auto c3 = MakeCoinWithIndex(0x02, 2, 3000, 10);
        BOOST_REQUIRE(utxo.Insert(c1));
        BOOST_REQUIRE(utxo.Insert(c2));
        BOOST_REQUIRE(utxo.Insert(c3));

        const Header pivot_hdr =
            MakePivotHeader(chain_id, pivot_height, utxo.Root(), monetary);
        UtxoRootsMessage roots{};
        BOOST_REQUIRE(
            ExportUtxoRoots(utxo, chain_id, pivot_hdr, monetary, roots, error));

        Header bad_ver_hdr = pivot_hdr;
        bad_ver_hdr.time = MAX_TIME + 1;
        BOOST_CHECK(
            !ExportUtxoRoots(utxo, chain_id, bad_ver_hdr, monetary, roots, error));
        Header bad_sr_hdr = pivot_hdr;
        bad_sr_hdr.state_root[0] ^= 0xFF;
        BOOST_CHECK(
            !ExportUtxoRoots(utxo, chain_id, bad_sr_hdr, monetary, roots, error));

        UtxoRootsMessage bad_id_roots = roots;
        bad_id_roots.pivot_block_id[0] ^= 0xFF;
        BOOST_CHECK(!VerifyUtxoRootsAgainstHeader(pivot_hdr, chain_id,
                                                  bad_id_roots, error));
        UtxoRootsMessage bad_ht_roots = roots;
        bad_ht_roots.height = pivot_height + 1;
        BOOST_CHECK(!VerifyUtxoRootsAgainstHeader(pivot_hdr, chain_id,
                                                  bad_ht_roots, error));
        UtxoRootsMessage bad_mon_roots = roots;
        bad_mon_roots.monetary_state.fill(0);
        BOOST_CHECK(!VerifyUtxoRootsAgainstHeader(pivot_hdr, chain_id,
                                                  bad_mon_roots, error));
        UtxoRootsMessage bad_tag_roots = roots;
        bad_tag_roots.shards[0].cardinality_tag = 3;
        BOOST_CHECK(!VerifyUtxoRootsAgainstHeader(pivot_hdr, chain_id,
                                                  bad_tag_roots, error));

        // Shard 0x01 has 1 coin (cardinality_tag == 1), shard 0x02 has 2 coins (cardinality_tag == 2),
        // shard 0x00 has 0 coins (cardinality_tag == 0).
        const uint16_t tag1_s = 0x01;
        const uint16_t tag2_s = 0x02;
        const uint16_t empty_s = 0x00;

        UtxoShardMessage s_out{};
        BOOST_CHECK(!ExportUtxoShard(utxo, roots.pivot_block_id, 7, 0, s_out,
                                     error));
        BOOST_CHECK(!ExportUtxoShard(utxo, roots.pivot_block_id, 8, 0x0100,
                                     s_out, error));
        BOOST_CHECK(!ExportUtxoShard(utxo, roots.pivot_block_id, 8, tag2_s,
                                     s_out, error, /*max_shard_leaves=*/1));
        std::vector<UtxoShardMessage> adaptive_out;
        BOOST_CHECK(!ExportAdaptiveUtxoShards(utxo, roots.pivot_block_id,
                                              adaptive_out, error, 0));

        // SplitAndExportShardsRecursive empty branch (lines 173-174) and depth-16 limit (lines 185-187):
        // Two coins with identical tx_id[0..1] share all 16 prefix bits of OutpointKey!
        {
            UtxoSet same16_utxo;
            lotus::v2::Coin sc1 = MakeCoinWithIndex(0x09, 1, 1000, 10);
            lotus::v2::Coin sc2 = MakeCoinWithIndex(0x09, 2, 2000, 10);
            sc2.outpoint.tx_id[1] = sc1.outpoint.tx_id[1];
            BOOST_REQUIRE(same16_utxo.Insert(sc1));
            BOOST_REQUIRE(same16_utxo.Insert(sc2));
            std::vector<UtxoShardMessage> fail_adaptive;
            BOOST_CHECK(!ExportAdaptiveUtxoShards(same16_utxo,
                                                  roots.pivot_block_id,
                                                  fail_adaptive, error, 1));

            // Exercise ComputeSubtreeEntry failure paths (lines 146-147, 162-163, 179-180, 781-783)
            auto &mutable_coins =
                const_cast<std::vector<lotus::v2::Coin> &>(same16_utxo.Coins());
            mutable_coins.push_back(sc1); // duplicate OutpointKey -> depth >= 256 in ComputeSubtreeEntry
            const uint16_t opp_prefix9 = static_cast<uint16_t>(
                OutpointPrefixBits(OutpointKey(sc1.outpoint), 9) ^ 0x0100u);
            BOOST_CHECK(!ExportUtxoShard(same16_utxo, roots.pivot_block_id, 9,
                                         opp_prefix9, s_out, error));
            mutable_coins.pop_back();
            mutable_coins[0].output.branches.clear(); // UtxoLeaf fails on sc1
            mutable_coins[1].outpoint.tx_id[1] ^= 1u; // differ at depth 8 so depth-9 split calls ExportUtxoShard
            BOOST_CHECK(!ExportAdaptiveUtxoShards(same16_utxo,
                                                  roots.pivot_block_id,
                                                  fail_adaptive, error, 1));
        }

        // VerifyAndBuildUtxoShard edge cases: invalid expected entry, prefix_bits out of range,
        // boundary_siblings mismatch, unencodable coin (empty branches), and empty sub-shard sibling folding
        BOOST_REQUIRE(ExportUtxoShard(utxo, roots.pivot_block_id, 8, tag1_s,
                                      s_out, error));
        ShardRootEntry bad_expected{3, EmptyUtxoRoot()};
        BOOST_CHECK(!VerifyAndBuildUtxoShard(bad_expected, pivot_height, s_out,
                                             nullptr, error));
        UtxoShardMessage bad_bits_shard = s_out;
        bad_bits_shard.prefix_bits = 0x0100;
        BOOST_CHECK(!VerifyAndBuildUtxoShard(roots.shards[tag1_s],
                                             pivot_height, bad_bits_shard,
                                             nullptr, error));
        UtxoShardMessage bad_sib_shard = s_out;
        bad_sib_shard.boundary_siblings.push_back(EmptyUtxoRoot());
        BOOST_CHECK(!VerifyAndBuildUtxoShard(roots.shards[tag1_s],
                                             pivot_height, bad_sib_shard,
                                             nullptr, error));
        UtxoShardMessage bad_leaf_shard = s_out;
        bad_leaf_shard.coins[0].output.branches.clear();
        BOOST_CHECK(!VerifyAndBuildUtxoShard(roots.shards[tag1_s],
                                             pivot_height, bad_leaf_shard,
                                             nullptr, error));

        // Empty sub-shard with non-empty boundary siblings (exercises lines 431 and 441-453)
        UtxoShardMessage empty_sub{};
        empty_sub.pivot_block_id = roots.pivot_block_id;
        empty_sub.prefix_depth = 10;
        empty_sub.prefix_bits = tag1_s;
        empty_sub.boundary_siblings = {EmptyUtxoRoot(),
                                       roots.shards[tag1_s].subtree_root};
        BOOST_CHECK(VerifyAndBuildUtxoShard(roots.shards[tag1_s],
                                            pivot_height, empty_sub, nullptr,
                                            error));
        empty_sub.boundary_siblings = {roots.shards[tag1_s].subtree_root,
                                       roots.shards[tag1_s].subtree_root};
        BOOST_CHECK(!VerifyAndBuildUtxoShard(roots.shards[tag1_s],
                                             pivot_height, empty_sub, nullptr,
                                             error));

        // AssembleAndVerifyFastSyncPivot error branches
        BOOST_REQUIRE(ExportAdaptiveUtxoShards(utxo, roots.pivot_block_id,
                                               adaptive_out, error));
        UtxoSet out_u;
        MonetaryState out_m{};
        // Invalid roots_msg (lines 849-850)
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, bad_id_roots, adaptive_out, out_u, out_m, error));
        // Missing shards
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, {}, out_u, out_m, error));
        // Duplicate shard prefix
        auto dup_shards = adaptive_out;
        dup_shards.push_back(adaptive_out[0]);
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, dup_shards, out_u, out_m, error));
        // Overlapping coin across distinct-prefix subshards (depth 8 and depth 9 for tag1_s, lines 911-913)
        {
            UtxoShardMessage s_depth9{};
            const uint16_t prefix9 =
                OutpointPrefixBits(OutpointKey(c1.outpoint), 9);
            BOOST_REQUIRE(ExportUtxoShard(utxo, roots.pivot_block_id, 9,
                                          prefix9, s_depth9, error));
            auto overlap_shards = adaptive_out;
            overlap_shards.push_back(s_depth9);
            BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
                pivot_hdr, chain_id, roots, overlap_shards, out_u, out_m,
                error));
        }
        // Mismatched pivot_block_id in shard
        auto bad_pid_shards = adaptive_out;
        bad_pid_shards[0].pivot_block_id[0] ^= 0xFF;
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, bad_pid_shards, out_u, out_m, error));
        // Invalid prefix_depth in shard
        auto bad_pdepth_shards = adaptive_out;
        bad_pdepth_shards[0].prefix_depth = 7;
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, bad_pdepth_shards, out_u, out_m, error));
        // Invalid subshard inside non-empty depth-8 shard (lines 907-908)
        auto bad_sub_shards = adaptive_out;
        bad_sub_shards[0].boundary_siblings.push_back(EmptyUtxoRoot());
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, bad_sub_shards, out_u, out_m, error));
        // Incomplete subshard coverage for split depth-8 shard (lines 926-929)
        std::vector<UtxoShardMessage> split_shards;
        BOOST_REQUIRE(ExportAdaptiveUtxoShards(utxo, roots.pivot_block_id,
                                               split_shards, error,
                                               /*max_shard_leaves=*/1));
        BOOST_REQUIRE_GT(split_shards.size(), adaptive_out.size());
        split_shards.pop_back();
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, split_shards, out_u, out_m, error));
        // Valid empty depth-8 shard supplied in shards list, plus invalid empty subshard (lines 877-878)
        UtxoShardMessage empty_s0{};
        BOOST_REQUIRE(ExportUtxoShard(utxo, roots.pivot_block_id, 8, empty_s,
                                      empty_s0, error));
        auto with_empty_s0 = adaptive_out;
        with_empty_s0.push_back(empty_s0);
        BOOST_CHECK(AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, with_empty_s0, out_u, out_m, error));
        auto with_bad_empty_s0 = adaptive_out;
        UtxoShardMessage bad_empty_s0 = empty_s0;
        bad_empty_s0.boundary_siblings.push_back(EmptyUtxoRoot());
        with_bad_empty_s0.push_back(bad_empty_s0);
        BOOST_CHECK(!AssembleAndVerifyFastSyncPivot(
            pivot_hdr, chain_id, roots, with_bad_empty_s0, out_u, out_m, error));
    }
}

BOOST_AUTO_TEST_CASE(parallel_smt_batch_import_and_circulating_supply) {
    UtxoSet utxo;
    for (uint32_t i = 0; i < 64; ++i) {
        BOOST_REQUIRE(utxo.Insert(
            MakeCoinWithIndex(static_cast<uint8_t>(i * 3 + 1), i + 1,
                              1000 + i * 10, 25)));
    }
    const MonetaryState mon = MakeTestMonetaryState();
    uint256 raw_hash{};
    raw_hash.begin()[0] = 0x58;
    const BlockHash pivot_hash{raw_hash};

    ImportV2BlockStateCoinsAndMonetary(pivot_hash, utxo.Coins(), mon,
                                       /*is_tip=*/true);

    std::vector<lotus::v2::Coin> exported_coins;
    MonetaryState exported_mon{};
    BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(pivot_hash, 25,
                                                  exported_coins,
                                                  exported_mon));
    BOOST_CHECK_EQUAL(exported_coins.size(), 64U);
    BOOST_CHECK(EncodeMonetaryState(exported_mon) == EncodeMonetaryState(mon));

    UtxoSet reconstructed;
    for (const auto &c : exported_coins) {
        BOOST_REQUIRE(reconstructed.Insert(c));
    }
    BOOST_CHECK(reconstructed.Root() == utxo.Root());
}

BOOST_AUTO_TEST_SUITE_END()

