// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/commitment.h>
#include <lotus_v2/sparse_state.h>
#include <lotus_v2/disk_state.h>
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/block.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <undo.h>
#include <kernel/coinstats.h>
#include <node/utxo_snapshot.h>
#include <primitives/v2_outputs.h>

#include <boost/test/unit_test.hpp>
#include <filesystem>

BOOST_FIXTURE_TEST_SUITE(native_coin_provenance_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(authenticated_coin_preserves_fee_backed_lifetime) {
    using namespace lotus::v2;
    lotus::v2::Coin baseline;
    baseline.outpoint.tx_id[0] = 1;
    baseline.output.value = 10000;
    baseline.output.branches = {BranchLeaf(std::array<uint8_t, 1>{0x4e})};
    baseline.output.paths = {{0}};
    baseline.creation_height = 100;
    baseline.creation_parent_mtp = 1000;
    baseline.expiration_height = ComputeUtxoExpirationHeight(baseline);

    auto paid = baseline;
    paid.fee_per_output = 1000;
    paid.expiration_height = ComputeUtxoExpirationHeight(
        paid.creation_height, paid.coinbase, paid.fee_per_output);
    const auto first_expiry = ComputeUtxoExpirationHeight(baseline);
    BOOST_REQUIRE(IsUtxoExpired(baseline, first_expiry));
    BOOST_REQUIRE(!IsUtxoExpired(paid, first_expiry));

    lotus::v2::Hash baseline_leaf, paid_leaf;
    BOOST_REQUIRE(UtxoLeaf(baseline, baseline_leaf));
    BOOST_REQUIRE(UtxoLeaf(paid, paid_leaf));
    BOOST_CHECK(baseline_leaf != paid_leaf);

    std::vector<uint8_t> wire;
    BOOST_REQUIRE(EncodeCoin(paid, wire));
    lotus::v2::Coin restored;
    BOOST_REQUIRE(DecodeCoinBytes(wire, restored));
    BOOST_CHECK_EQUAL(ComputeUtxoExpirationHeight(restored),
                      ComputeUtxoExpirationHeight(paid));
    BOOST_CHECK(!IsUtxoExpired(restored, first_expiry));
    BOOST_CHECK_EQUAL(restored.fee_per_output, paid.fee_per_output);
    // Historical uncommitted records and unknown codec versions fail closed.
    auto old_wire = wire;
    old_wire.resize(old_wire.size() - 17);
    BOOST_CHECK(!DecodeCoinBytes(old_wire, restored));
    auto unknown = wire;
    unknown[unknown.size() - 17] = 0xff;
    BOOST_CHECK(!DecodeCoinBytes(unknown, restored));

    UtxoSet set;
    BOOST_REQUIRE(set.Insert(paid));
    auto proof = set.Prove(paid.outpoint);
    BOOST_REQUIRE(VerifyCoinProof(paid.outpoint, proof, set.Root()));
    proof.coin->fee_per_output = baseline.fee_per_output;
    proof.coin->expiration_height = baseline.expiration_height;
    BOOST_CHECK(!VerifyCoinProof(paid.outpoint, proof, set.Root()));

    auto different_expiry = paid;
    ++different_expiry.expiration_height;
    lotus::v2::Hash changed_leaf;
    BOOST_CHECK(!UtxoLeaf(different_expiry, changed_leaf) ||
                changed_leaf != paid_leaf);

    // Explicit expiry is supported too, and must survive both wire parsers.
    BOOST_REQUIRE(EncodeCoin(different_expiry, wire));
    BOOST_REQUIRE(DecodeCoinBytes(wire, restored));
    BOOST_CHECK_EQUAL(restored.expiration_height, different_expiry.expiration_height);
    UtxoShardMessage shard;
    shard.coins = {different_expiry};
    std::string error;
    BOOST_REQUIRE(EncodeUtxoShardMessage(shard, wire, error));
    UtxoShardMessage decoded;
    BOOST_REQUIRE(DecodeUtxoShardMessage(wire, decoded, error));
    BOOST_REQUIRE_EQUAL(decoded.coins.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.coins[0].fee_per_output, paid.fee_per_output);
    BOOST_CHECK_EQUAL(decoded.coins[0].expiration_height, different_expiry.expiration_height);
    BlockUndoMessage undo;
    undo.prior_spent_coins = {paid};
    undo.expired_swept_coins = {different_expiry};
    BOOST_REQUIRE(EncodeBlockUndoMessage(undo, wire, error));
    BlockUndoMessage decoded_undo;
    BOOST_REQUIRE(DecodeBlockUndoMessage(wire, decoded_undo, error));
    BOOST_CHECK_EQUAL(decoded_undo.prior_spent_coins[0].expiration_height, paid.expiration_height);
    BOOST_CHECK_EQUAL(decoded_undo.expired_swept_coins[0].expiration_height, different_expiry.expiration_height);
    wire.back() ^= 1; // Redundant expired-coin fee must agree with committed data.
    BOOST_CHECK(!DecodeBlockUndoMessage(wire, decoded_undo, error));
    DevelopmentUtxoView snapshot_view;
    snapshot_view.emplace(different_expiry.outpoint, different_expiry);
    MonetaryState monetary{};
    monetary.tail_subsidy = 94;
    monetary.prev_work[0] = 2;
    monetary.ema_block_cost = 4000;
    BOOST_REQUIRE(WriteInMemorySnapshot(snapshot_view, monetary, wire, error));
    DevelopmentUtxoView loaded_view;
    IncrementalUtxoSet loaded_utxo;
    BOOST_REQUIRE_MESSAGE(LoadInMemorySnapshot(wire, loaded_view, loaded_utxo, monetary, error), error);
    BOOST_CHECK_EQUAL(loaded_view.at(paid.outpoint).fee_per_output, paid.fee_per_output);
    BOOST_CHECK_EQUAL(loaded_view.at(paid.outpoint).expiration_height, different_expiry.expiration_height);

    // The third parser is the durable store: verify after closing/reopening.
    const auto directory = (m_path_root / "paid-coin-store").string();
    DiskStateOptions options;
    DiskStateMetadata initial;
    DiskStateError disk_error;
    {
        DiskStateStore store;
        BOOST_REQUIRE(DiskStateStore::Open(directory, options, initial, store, disk_error));
        DiskStateTransaction tx;
        BOOST_REQUIRE(store.Begin(tx, disk_error));
        BOOST_REQUIRE(tx.Insert(different_expiry, disk_error));
        auto next = initial;
        next.tip[0] = 1;
        BOOST_REQUIRE(tx.Commit(next, disk_error));
    }
    {
        DiskStateStore store;
        BOOST_REQUIRE(DiskStateStore::Open(directory, options, initial, store, disk_error));
        std::optional<lotus::v2::Coin> coin;
        BOOST_REQUIRE(store.ReadCoin(paid.outpoint, coin, disk_error));
        BOOST_REQUIRE(coin.has_value());
        BOOST_CHECK_EQUAL(coin->fee_per_output, paid.fee_per_output);
        BOOST_CHECK_EQUAL(coin->expiration_height, different_expiry.expiration_height);
        CoinProof durable;
        BOOST_REQUIRE(store.Prove(paid.outpoint, durable, disk_error));
        BOOST_REQUIRE(VerifyCoinProof(paid.outpoint, durable, store.Root()));
        ++durable.coin->expiration_height;
        BOOST_CHECK(!VerifyCoinProof(paid.outpoint, durable, store.Root()));
    }
    std::optional<std::string> schema;
    BOOST_REQUIRE(RawDiskStateAccess(directory, std::string("V"), &schema, {}, &error));
    BOOST_REQUIRE(schema && schema->size() > 12);
    BOOST_CHECK_EQUAL(uint8_t((*schema)[12]), 5);
    (*schema)[12] = 1;
    BOOST_REQUIRE(RawDiskStateAccess(directory, std::nullopt, nullptr,
                                    {{"V", schema}}, &error));
    DiskStateStore rejected;
    BOOST_CHECK(!DiskStateStore::Open(directory, options, initial, rejected, disk_error));
    BOOST_CHECK(disk_error.code == DiskStateErrorCode::ProfileMismatch);
}

BOOST_AUTO_TEST_CASE(chainstate_and_spent_undo_preserve_authenticated_lifetime) {
    const ::Coin paid{CTxOut{10000 * SATOSHI, CScript() << OP_TRUE},
                      100, false, 1000, 132500};
    auto changed = paid;
    changed.nExpirationHeight += 7;
    auto check_lifetime = [&](const ::Coin &actual) {
        BOOST_CHECK_EQUAL(actual.GetFeePerOutput(), paid.GetFeePerOutput());
        BOOST_CHECK_EQUAL(actual.GetExpirationHeight(), changed.GetExpirationHeight());
    };
    DataStream record;
    record << changed;
    ::Coin decoded;
    record >> decoded;
    check_lifetime(decoded);
    CTxUndo undo;
    undo.vprevout.push_back(changed);
    record << undo;
    CTxUndo restored;
    record >> restored;
    BOOST_REQUIRE_EQUAL(restored.vprevout.size(), 1U);
    check_lifetime(restored.vprevout[0]);
    const COutPoint outpoint{TxId{uint256{81}}, 0};
    const auto paid_stats = kernel::TxOutSer(outpoint, paid);
    const auto changed_stats = kernel::TxOutSer(outpoint, changed);
    BOOST_CHECK(paid_stats.size() != changed_stats.size() ||
                !std::equal(paid_stats.begin(), paid_stats.end(), changed_stats.begin()));
    const DBParams params{.path = m_path_root / "chainstate-paid-reopen",
        .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false,
        .obfuscate = true};
    {
        CCoinsViewDB db(params, {});
        db.InstallFastSyncSnapshot(BlockHash{uint256{82}}, uint256{83},
                                   {{outpoint, changed}});
    }
    {
        CCoinsViewDB db(params, {});
        auto coin = db.GetCoin(outpoint);
        BOOST_REQUIRE(coin);
        check_lifetime(*coin);
    }
    // Normal cache flushing uses BatchWrite rather than pivot replacement.
    {
        CCoinsViewDB db(params, {});
        CCoinsViewCache cache(&db);
        cache.AddCoin(COutPoint{outpoint.GetTxId(), 1}, ::Coin(changed), false);
        cache.SetBestBlock(BlockHash{uint256{85}});
        BOOST_REQUIRE_NO_THROW(cache.Flush());
    }
    {
        CCoinsViewDB db(params, {});
        auto coin = db.GetCoin(COutPoint{outpoint.GetTxId(), 1});
        BOOST_REQUIRE(coin);
        check_lifetime(*coin);
    }
    ExpiredCoinUndo expired{outpoint, changed};
    record << expired;
    ExpiredCoinUndo restored_expired;
    record >> restored_expired;
    check_lifetime(restored_expired.coin);
    BOOST_CHECK(record.empty());

    lotus::v2::Output native;
    native.flags = 1;
    native.value = 10000;
    native.token_id[0] = 99;
    native.branches = {lotus::v2::BranchLeaf(std::array<uint8_t, 1>{0x4e})};
    native.paths = {{0}};
    ::Coin token{CTxOut::FromV2Output(native), 100, false, 1000, 132507};
    record << token;
    record >> decoded;
    check_lifetime(decoded);
    const auto native_decoded = decoded.GetTxOut().ToV2Output();
    BOOST_CHECK(native_decoded.flags == native.flags);
    BOOST_CHECK(native_decoded.token_id == native.token_id);
    BOOST_CHECK(native_decoded.branches == native.branches);
    BOOST_CHECK(native_decoded.paths == native.paths);

    DataStream old_coin;
    uint32_t old_height = 200;
    old_coin << VARINT(old_height) << Using<TxOutCompression>(paid.GetTxOut());
    BOOST_CHECK_THROW(old_coin >> decoded, std::ios_base::failure);
    const CMessageHeader::MessageMagic magic{1, 2, 3, 4};
    node::SnapshotMetadata snapshot_metadata(magic, BlockHash{uint256{86}}, 1);
    record << snapshot_metadata;
    node::SnapshotMetadata read_metadata(magic);
    BOOST_CHECK_NO_THROW(record >> read_metadata);
    DataStream old_snapshot;
    old_snapshot << SNAPSHOT_MAGIC_BYTES << uint16_t{2} << magic
                 << BlockHash{uint256{86}} << uint64_t{1};
    BOOST_CHECK_THROW(old_snapshot >> read_metadata, std::ios_base::failure);

    // A V2 output whose scriptPubKey holds a raw program instead of its V2
    // encoding (as the removed AdaptLegacyOutputToV7 produced).
    CTxOut raw_program = V0LeafOutput(10000 * SATOSHI, CScript() << OP_TRUE);
    raw_program.scriptPubKey = CScript() << OP_TRUE;
    const ::Coin raw_view{raw_program, 100, false, 1000, 132507};
    const ::Coin canonical_view{CTxOut::FromV2Output(raw_program.ToV2Output()),
                                100, false, 1000, 132507};
    BOOST_REQUIRE(raw_view.GetTxOut().scriptPubKey != canonical_view.GetTxOut().scriptPubKey);
    const auto raw_stats = kernel::TxOutSer(outpoint, raw_view);
    const auto canonical_stats = kernel::TxOutSer(outpoint, canonical_view);
    BOOST_CHECK_EQUAL(HexStr(raw_stats), HexStr(canonical_stats));

    // A database without the new native format identity must fail closed.
    const DBParams old_params{.path = m_path_root / "chainstate-old-format",
        .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false};
    {
        CDBWrapper old(old_params);
        old.Write(uint8_t{'B'}, BlockHash{uint256{84}}, true);
    }
    BOOST_CHECK_THROW(CCoinsViewDB(old_params, {}), std::runtime_error);
    const DBParams old_index{.path = m_path_root / "index-old-format",
        .cache_bytes = 1 << 20, .memory_only = false, .wipe_data = false};
    {
        CDBWrapper old(old_index);
        old.Write(uint8_t{'b'}, BlockHash{uint256{87}}, true);
    }
    BOOST_CHECK_THROW(CBlockTreeDB{old_index}, std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
