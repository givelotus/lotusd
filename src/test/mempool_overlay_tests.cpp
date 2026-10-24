// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <key.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/disk_state.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/signing.h>
#include <lotus_v2/utxo_fast_filter.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstring>
#include <future>
#include <random>
#include <thread>
#include <vector>
#include <stdexcept>

BOOST_FIXTURE_TEST_SUITE(mempool_overlay_tests, BasicTestingSetup)

namespace {

CTransactionRef MakeCoinbaseTx(uint32_t height, Amount subsidy = 200 * SATOSHI) {
    CMutableTransaction cb;
    cb.nVersion = 2;
    cb.vin.resize(1);
    cb.vin[0].prevout = COutPoint();
    cb.vin[0].scriptSig = CScript() << height << OP_0;
    cb.vout.resize(1);
    cb.vout[0].nValue = subsidy;
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(std::move(cb));
}

CTransactionRef MakeSpendTx(const COutPoint &prevout, uint32_t salt,
                            Amount out_val, size_t num_outputs = 2) {
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = salt;
    tx.vin.resize(1);
    tx.vin[0].prevout = prevout;
    tx.vin[0].scriptSig = CScript() << int64_t(salt) << OP_TRUE;
    tx.vout.resize(num_outputs);
    for (size_t i = 0; i < num_outputs; ++i) {
        tx.vout[i].nValue = out_val;
        tx.vout[i].scriptPubKey = CScript() << int64_t(salt + i) << OP_EQUAL;
    }
    return MakeTransactionRef(std::move(tx));
}

} // namespace

BOOST_AUTO_TEST_CASE(utxo_arena_reuses_imported_subtrees_and_invalidates_mutations) {
    using namespace lotus::v2;
    std::vector<lotus::v2::Coin> coins(64);
    std::shared_ptr<const SmtNode> base;
    for (size_t i = 0; i < coins.size(); ++i) {
        coins[i].outpoint.tx_id[0] = static_cast<uint8_t>(i);
        coins[i].output.value = 100 + i;
        coins[i].output.legacy_script = std::vector<uint8_t>{OP_TRUE};
        SmtInsert(base, coins[i]);
    }
    const auto original_root = SmtRoot(base);
    UtxoOverlayArena arena(base);
    // Loading the path for an idempotent insertion must preserve the imported
    // immutable node rather than allocate an equivalent exported tree.
    arena.InsertCoin(coins[0]);
    BOOST_CHECK(arena.GetSmtRoot() == base);
    auto absent = coins[0].outpoint;
    absent.index = 1;
    arena.EraseOutpoint(absent);
    BOOST_CHECK(arena.GetSmtRoot() == base);

    auto changed = coins[0];
    changed.output.value += 1;
    auto reference = base;
    SmtInsert(reference, changed);
    arena.InsertCoin(changed);
    BOOST_CHECK(arena.GetSmtRoot() != base);
    BOOST_CHECK(SmtRoot(arena.GetSmtRoot()) == SmtRoot(reference));
    BOOST_REQUIRE(SmtFind(arena.GetSmtRoot(), changed.outpoint));
    BOOST_CHECK_EQUAL(SmtFind(arena.GetSmtRoot(), changed.outpoint)->output.value,
                      changed.output.value);
    BOOST_CHECK(SmtRoot(base) == original_root);

    arena.Reset(base);
    std::vector<Outpoint> erased;
    std::vector<lotus::v2::Coin> inserted;
    reference = base;
    for (size_t i = 0; i < 32; ++i) {
        erased.push_back(coins[i].outpoint);
        SmtErase(reference, coins[i].outpoint);
        auto replacement = coins[i];
        replacement.outpoint.index = 2;
        inserted.push_back(replacement);
        SmtInsert(reference, replacement);
    }
    arena.BatchUpdateParallel(erased, inserted);
    BOOST_CHECK(SmtRoot(arena.GetSmtRoot()) == SmtRoot(reference));
    for (const auto &coin : inserted) {
        BOOST_REQUIRE(SmtFind(arena.GetSmtRoot(), coin.outpoint));
        BOOST_CHECK_EQUAL(SmtFind(arena.GetSmtRoot(), coin.outpoint)->output.value,
                          coin.output.value);
    }
    BOOST_CHECK(SmtRoot(base) == original_root);
}

BOOST_AUTO_TEST_CASE(smt_lookup_preserves_pinned_snapshot_and_returned_coin) {
    using namespace lotus::v2;
    std::vector<lotus::v2::Coin> coins(128);
    std::shared_ptr<const SmtNode> live;
    BOOST_CHECK(!SmtFind(live, Outpoint{}));
    for (size_t i = 0; i < coins.size(); ++i) {
        auto &coin = coins[i];
        coin.outpoint.tx_id[0] = static_cast<uint8_t>(i);
        coin.outpoint.tx_id[31] = static_cast<uint8_t>(255 - i);
        coin.output.value = 1000 + i;
        coin.output.legacy_script = std::vector<uint8_t>{OP_TRUE};
        coin.creation_height = 10;
        coin.expiration_height = 100010;
    }
    SmtBatchUpdateParallel(live, {}, coins);
    auto pinned = live;
    const auto original_digest = SmtRoot(pinned);
    const auto retained = SmtFind(pinned, coins[0].outpoint);
    BOOST_REQUIRE(retained);
    for (const auto &coin : coins) {
        const auto found = SmtFind(pinned, coin.outpoint);
        BOOST_REQUIRE(found);
        BOOST_CHECK(found->outpoint == coin.outpoint);
        BOOST_CHECK_EQUAL(found->output.value, coin.output.value);
        auto missing = coin.outpoint;
        missing.index = 1;
        BOOST_CHECK(!SmtFind(pinned, missing));
    }
    auto replacement = coins[0];
    replacement.output.value += 500;
    SmtInsert(live, replacement);
    SmtErase(live, coins[1].outpoint);
    auto added = coins[1];
    added.outpoint.index = 1;
    SmtBatchUpdateParallel(live, {}, std::span(&added, 1));
    const auto replaced = SmtFind(live, replacement.outpoint);
    BOOST_REQUIRE(replaced);
    BOOST_CHECK_EQUAL(replaced->output.value, replacement.output.value);
    BOOST_CHECK(!SmtFind(live, coins[1].outpoint));
    BOOST_CHECK(SmtFind(live, added.outpoint));
    BOOST_CHECK(!SmtFind(pinned, added.outpoint));
    const auto original = SmtFind(pinned, coins[0].outpoint);
    BOOST_REQUIRE(original);
    BOOST_CHECK_EQUAL(original->output.value, coins[0].output.value);
    BOOST_REQUIRE(SmtFind(pinned, coins[1].outpoint));
    BOOST_CHECK(SmtRoot(pinned) == original_digest);
    std::weak_ptr<const SmtNode> old_root = pinned;
    pinned.reset();
    live.reset();
    BOOST_CHECK(old_root.expired());
    // The result retains the Coin, not the traversed nodes: no root or node
    // ownership remains, but its complete immutable value is still valid.
    BOOST_CHECK(retained->outpoint == coins[0].outpoint);
    BOOST_CHECK_EQUAL(retained->output.value, coins[0].output.value);
    BOOST_CHECK_EQUAL(retained->expiration_height, coins[0].expiration_height);
}

BOOST_AUTO_TEST_CASE(smt_lookup_parallel_owned_snapshots_during_updates) {
    using namespace lotus::v2;
    std::vector<lotus::v2::Coin> coins(128);
    for (size_t i = 0; i < coins.size(); ++i) {
        coins[i].outpoint.tx_id[0] = static_cast<uint8_t>(i);
        coins[i].output.value = 1000 + i;
        coins[i].output.legacy_script = std::vector<uint8_t>{OP_TRUE};
        coins[i].expiration_height = 100010;
    }
    std::shared_ptr<const SmtNode> live;
    SmtBatchUpdateParallel(live, {}, coins);
    const auto snapshot = live;
    const auto digest = SmtRoot(snapshot);
    std::atomic<size_t> errors{0};
    std::barrier rounds(5);
    std::array<std::jthread, 4> readers;
    for (auto &reader : readers) {
        reader = std::jthread([owned = snapshot, &coins, &errors, &rounds] {
            for (size_t round = 0; round < 8; ++round) {
                rounds.arrive_and_wait();
                for (const auto &coin : coins) {
                    const auto found = SmtFind(owned, coin.outpoint);
                    auto missing = coin.outpoint;
                    missing.index = 99;
                    if (!found || found->outpoint != coin.outpoint ||
                        found->output.value != coin.output.value ||
                        SmtFind(owned, missing)) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                rounds.arrive_and_wait();
            }
        });
    }
    for (size_t round = 0; round < 8; ++round) {
        rounds.arrive_and_wait();
        auto replacement = coins;
        for (auto &coin : replacement) coin.output.value += 100 + round;
        SmtBatchUpdateParallel(live, {}, replacement);
        rounds.arrive_and_wait();
    }
    for (auto &reader : readers) reader.join();
    BOOST_CHECK_EQUAL(errors.load(std::memory_order_relaxed), 0U);
    BOOST_CHECK(SmtRoot(snapshot) == digest);
    BOOST_CHECK(SmtRoot(live) != digest);
}

BOOST_AUTO_TEST_CASE(transaction_subtree_rejects_duplicate_ids) {
    lotus::v2::TxIdentityPair a{}, b{};
    a.tx_id.fill(0x42);
    a.tx_hash.fill(0x17);
    b = a;
    b.tx_hash.fill(0x18);
    BOOST_CHECK_THROW(lotus::v2::BuildTxSubtreeA(std::vector{a, a}),
                      std::invalid_argument);
    BOOST_CHECK_THROW(lotus::v2::BuildTxSubtreeA(std::vector{a, b}),
                      std::invalid_argument);
    // The final key bit is legal: depth 255 may split two distinct keys.
    b.tx_id[31] ^= 0x80;
    const auto expected = lotus::v2::BuildTxSubtreeA(std::vector{a, b});
    BOOST_CHECK(expected == lotus::v2::BuildTxSubtreeA(std::vector{b, a}));
    BOOST_CHECK(expected != lotus::v2::BuildTxSubtreeA(std::vector{a}));
}

BOOST_AUTO_TEST_CASE(tx_overlay_arena_matches_block_merkle_root) {
    lotus::v2::TxOverlayArena arena;
    uint32_t root_idx = lotus::v2::TxOverlayArena::kNullIdx;
    BOOST_CHECK(arena.SubtreeARoot(root_idx) == lotus::v2::EmptyTxRoot());

    const CTransactionRef cb = MakeCoinbaseTx(1);
    CBlock empty_block;
    empty_block.vtx.push_back(cb);
    BOOST_CHECK_EQUAL(
        ComputeV2TxRootFromSubtreeA(*cb, arena.SubtreeARoot(root_idx)),
        BlockMerkleRoot(empty_block));

    std::vector<CTransactionRef> txs;
    txs.reserve(100);
    std::vector<uint32_t> historical_roots;
    for (uint32_t i = 0; i < 100; ++i) {
        TxId dummy_prev{m_rng.rand256()};
        CTransactionRef ptx =
            MakeSpendTx(COutPoint(dummy_prev, i % 4), i + 1, 1000 * SATOSHI);
        txs.push_back(ptx);

        lotus::v2::Hash tx_id{};
        lotus::v2::Hash tx_hash{};
        std::memcpy(tx_id.data(), ptx->GetId().begin(), 32);
        std::memcpy(tx_hash.data(), ptx->GetHash().begin(), 32);
        root_idx = arena.InsertTxLeaf(root_idx, tx_id, tx_hash);
        historical_roots.push_back(root_idx);
    }

    BOOST_CHECK_EQUAL(arena.Count(root_idx), 100U);

    // Build a block with all 100 transactions sorted in CTOR order
    CBlock full_block;
    full_block.vtx.push_back(cb);
    std::vector<CTransactionRef> sorted_txs = txs;
    std::sort(sorted_txs.begin(), sorted_txs.end(),
              [](const CTransactionRef &a, const CTransactionRef &b) {
                  return a->GetId() < b->GetId();
              });
    full_block.vtx.insert(full_block.vtx.end(), sorted_txs.begin(),
                          sorted_txs.end());

    const uint256 expected_merkle = BlockMerkleRoot(full_block);
    const uint256 overlay_merkle =
        ComputeV2TxRootFromSubtreeA(*cb, arena.SubtreeARoot(root_idx));
    BOOST_CHECK_EQUAL(overlay_merkle, expected_merkle);

    // Path-copying persistence check: snapshot at 50 txs must still match a
    // 50-tx block even after 50 more txs were inserted.
    const lotus::v2::Hash root50_before =
        arena.SubtreeARoot(historical_roots[49]);
    CBlock block50;
    block50.vtx.push_back(cb);
    std::vector<CTransactionRef> first50(txs.begin(), txs.begin() + 50);
    std::sort(first50.begin(), first50.end(),
              [](const CTransactionRef &a, const CTransactionRef &b) {
                  return a->GetId() < b->GetId();
              });
    block50.vtx.insert(block50.vtx.end(), first50.begin(), first50.end());
    BOOST_CHECK_EQUAL(ComputeV2TxRootFromSubtreeA(*cb, root50_before),
                      BlockMerkleRoot(block50));

    // Erase the last 50 transactions from root_idx and verify it matches root50
    uint32_t pruned_idx = root_idx;
    for (size_t i = 50; i < 100; ++i) {
        lotus::v2::Hash tx_id{};
        std::memcpy(tx_id.data(), txs[i]->GetId().begin(), 32);
        pruned_idx = arena.EraseTxLeaf(pruned_idx, tx_id);
    }
    BOOST_CHECK_EQUAL(arena.Count(pruned_idx), 50U);
    BOOST_CHECK(arena.SubtreeARoot(pruned_idx) == root50_before);

    // Erase the remaining 50 transactions and verify EmptyTxRoot is restored
    for (size_t i = 0; i < 50; ++i) {
        lotus::v2::Hash tx_id{};
        std::memcpy(tx_id.data(), txs[i]->GetId().begin(), 32);
        pruned_idx = arena.EraseTxLeaf(pruned_idx, tx_id);
    }
    BOOST_CHECK_EQUAL(arena.Count(pruned_idx), 0U);
    BOOST_CHECK(arena.SubtreeARoot(pruned_idx) == lotus::v2::EmptyTxRoot());
}

BOOST_AUTO_TEST_CASE(mempool_overlay_layer_matches_full_block_state_root) {
    // 1. Create a base block at height 1 with 50 spendable outputs
    CBlock base_block;
    base_block.nHeaderVersion = lotus::v2::kHeaderVersion;
    base_block.nHeight = 1;
    base_block.nBits = 0x207fffff;
    base_block.SetBlockTime(1700000000);

    CMutableTransaction base_cb;
    base_cb.nVersion = 2;
    base_cb.vin.resize(1);
    base_cb.vin[0].prevout = COutPoint();
    base_cb.vin[0].scriptSig = CScript() << 1 << OP_0;
    base_cb.vout.resize(60);
    for (size_t i = 0; i < 60; ++i) {
        base_cb.vout[i].nValue = 100000 * SATOSHI;
        base_cb.vout[i].scriptPubKey = CScript() << int64_t(i) << OP_TRUE;
    }
    base_block.vtx.push_back(MakeTransactionRef(std::move(base_cb)));
    base_block.hashMerkleRoot = BlockMerkleRoot(base_block);
    base_block.hashStateRoot = ComputeV2BlockStateRoot(
        base_block, BlockHash(), 1, 1699999000, /*record=*/false);
    const BlockHash base_hash = base_block.GetHash();
    RecordV2BlockState(base_block, base_hash, BlockHash(), 1, 1699999000);

    std::shared_ptr<const lotus::v2::SmtNode> base_utxo_root;
    lotus::v2::MonetaryState base_mon_state{};
    BOOST_REQUIRE(
        GetV2BlockStateSnapshot(base_hash, base_utxo_root, base_mon_state));

    lotus::v2::Hash base_id_hash{};
    std::memcpy(base_id_hash.data(), base_hash.begin(), 32);

    const uint64_t next_height = 2;
    const uint64_t parent_mtp = 1700000000;

    lotus::v2::MerklixOverlayManager manager;
    manager.ResetToTip(base_id_hash, base_utxo_root, base_mon_state,
                       next_height, parent_mtp);

    // 2. Build 100 transactions:
    //    - 50 root transactions spending base_block coinbase outputs [0..49]
    //    - 50 child transactions spending outputs of the first 50 transactions
    //      (creates intra-template parent-child chains where ~half have
    //      child.GetId() < parent.GetId() in CTOR order!)
    std::vector<CTransactionRef> parent_txs;
    std::vector<CTransactionRef> child_txs;
    const TxId base_cb_txid = base_block.vtx[0]->GetId();

    for (uint32_t i = 0; i < 50; ++i) {
        CTransactionRef ptx = MakeSpendTx(COutPoint(base_cb_txid, i),
                                          1000 + i, 40000 * SATOSHI, 2);
        parent_txs.push_back(ptx);
        BOOST_CHECK(AddTransactionToOverlay(manager, ptx, 20000, 1));
    }

    // Freeze Epoch 1 after 50 parent transactions
    const auto &epoch1 = manager.FreezeEpochBatch();
    BOOST_CHECK_EQUAL(epoch1.GetTxCount(), 50U);
    const lotus::v2::Hash epoch1_tx_root = epoch1.GetSubtreeARoot();
    const lotus::v2::Hash epoch1_utxo_root = epoch1.GetUtxoRootDigest();

    for (uint32_t i = 0; i < 50; ++i) {
        CTransactionRef ctx = MakeSpendTx(COutPoint(parent_txs[i]->GetId(), 0),
                                          2000 + i, 15000 * SATOSHI, 2);
        child_txs.push_back(ctx);
        BOOST_CHECK(AddTransactionToOverlay(manager, ctx, 10000, 1));
    }

    // Verify frozen Epoch 1 roots were not mutated by speculative additions
    BOOST_CHECK(manager.GetFrozenEpochs().front().GetSubtreeARoot() ==
                epoch1_tx_root);
    BOOST_CHECK(manager.GetFrozenEpochs().front().GetUtxoRootDigest() ==
                epoch1_utxo_root);

    // 3. Remove 10 child transactions and their 10 parent transactions to test
    //    both intra-overlay spend restoration and base-chain UTXO restoration
    for (size_t i = 40; i < 50; ++i) {
        BOOST_CHECK(RemoveTransactionFromOverlay(manager, *child_txs[i]));
        BOOST_CHECK(RemoveTransactionFromOverlay(manager, *parent_txs[i]));
    }

    const auto &spec_overlay = manager.GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(spec_overlay.GetTxCount(), 80U);

    // 4. Assemble the full block using the surviving 80 transactions in CTOR
    //    order and compare both hashMerkleRoot and hashStateRoot against
    //    from-scratch full block computation.
    const CTransactionRef cb2 = MakeCoinbaseTx(next_height);
    CBlock block2;
    block2.nHeaderVersion = lotus::v2::kHeaderVersion;
    block2.hashPrevBlock = base_hash;
    block2.nHeight = next_height;
    block2.nBits = 0x207fffff;
    block2.SetBlockTime(1700000120);
    block2.vtx.push_back(cb2);
    for (const auto &[tx_id, entry] : spec_overlay.GetOrderedTxs()) {
        auto ptx = std::static_pointer_cast<const CTransaction>(entry.tx_ref);
        BOOST_REQUIRE(ptx != nullptr);
        block2.vtx.push_back(ptx);
    }
    BOOST_CHECK_EQUAL(block2.vtx.size(), 81U);

    // Verify CTOR sorting invariant on GetOrderedTxs()
    for (size_t i = 2; i < block2.vtx.size(); ++i) {
        BOOST_CHECK(block2.vtx[i - 1]->GetId() < block2.vtx[i]->GetId());
    }

    const uint256 expected_merkle = BlockMerkleRoot(block2);
    const uint256 fast_merkle =
        ComputeV2TxRootFromSubtreeA(*cb2, spec_overlay.GetSubtreeARoot());
    BOOST_CHECK_EQUAL(fast_merkle, expected_merkle);

    const uint256 expected_state_root = ComputeV2BlockStateRoot(
        block2, base_hash, next_height, parent_mtp, /*record=*/false);
    const uint256 fast_state_root = ComputeV2StateRootFromOverlay(
        *cb2, spec_overlay, block2.nBits, next_height, parent_mtp);
    BOOST_CHECK_EQUAL(fast_state_root, expected_state_root);
}

BOOST_AUTO_TEST_CASE(disk_state_commit_finalized_overlay) {
    const fs::path db_dir = m_args.GetDataDirNet() / "v2_overlay_commit_test";
    fs::create_directories(db_dir);

    lotus::v2::DiskStateOptions opts{};
    opts.identity[0] = 0x11;
    opts.profile_digest[0] = 0x22;

    lotus::v2::DiskStateMetadata genesis_meta{};
    genesis_meta.tip[0] = 0x01;

    lotus::v2::DiskStateStore store;
    lotus::v2::DiskStateError err;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        genesis_meta, store, err),
        err.message);

    // Commit Block 1 with 10 base coins into both DiskStateStore and SmtNode
    std::shared_ptr<const lotus::v2::SmtNode> base_utxo_root;
    std::vector<lotus::v2::Coin> base_coins;
    {
        lotus::v2::DiskStateTransaction txn;
        BOOST_REQUIRE(store.Begin(txn, err));
        for (uint32_t i = 0; i < 10; ++i) {
            lotus::v2::Hash txid{};
            txid[0] = 0xa0;
            txid[1] = static_cast<uint8_t>(i);
            lotus::v2::Coin coin{};
            coin.outpoint = {txid, 0};
            coin.output.value = 50000;
            coin.output.branches = {lotus::v2::Hash32{1}};
            coin.output.paths = {{0}};
            coin.creation_height = 1;
            coin.creation_parent_mtp = 1000;
            coin.coinbase = false;
            BOOST_REQUIRE(txn.Insert(coin, err));
            lotus::v2::SmtInsert(base_utxo_root, coin);
            base_coins.push_back(coin);
        }
        lotus::v2::DiskStateMetadata b1_meta{};
        b1_meta.tip[0] = 0x02;
        BOOST_REQUIRE(txn.Commit(b1_meta, err));
    }
    const lotus::v2::Hash b1_root = store.Root();
    BOOST_CHECK(b1_root == lotus::v2::SmtRoot(base_utxo_root));

    // Build an overlay spending base_coins[0..4] in parent txs, and spending
    // parent_tx[0..4] output 0 in child txs (intra-overlay ephemeral UTXOs).
    lotus::v2::Hash b1_tip{};
    b1_tip[0] = 0x02;
    lotus::v2::MempoolOverlayLayer overlay(
        b1_tip, base_utxo_root, lotus::v2::GetInitialV2MonetaryState(),
        /*height=*/2, /*parent_mtp=*/1120);

    std::vector<lotus::v2::Outpoint> ephemeral_outpoints;
    std::vector<lotus::v2::Outpoint> surviving_outpoints;
    for (uint32_t i = 0; i < 5; ++i) {
        lotus::v2::Hash p_txid{}, p_txhash{};
        p_txid[0] = 0xb0;
        p_txid[1] = static_cast<uint8_t>(i);
        p_txhash = p_txid;

        lotus::v2::Coin p_out0{};
        p_out0.outpoint = {p_txid, 0};
        p_out0.output.value = 25000;
        p_out0.output.branches = {lotus::v2::Hash32{1}};
        p_out0.output.paths = {{0}};
        p_out0.creation_height = 2;
        p_out0.creation_parent_mtp = 1120;

        lotus::v2::Coin p_out1 = p_out0;
        p_out1.outpoint = {p_txid, 1};

        BOOST_REQUIRE(overlay.AddTransaction(
            p_txid, p_txhash, 200, {base_coins[i].outpoint}, {p_out0, p_out1}));
        ephemeral_outpoints.push_back(p_out0.outpoint);
        surviving_outpoints.push_back(p_out1.outpoint);

        // Child tx spends p_out0 in the same overlay
        lotus::v2::Hash c_txid{}, c_txhash{};
        c_txid[0] = 0xc0;
        c_txid[1] = static_cast<uint8_t>(i);
        c_txhash = c_txid;

        lotus::v2::Coin c_out0{};
        c_out0.outpoint = {c_txid, 0};
        c_out0.output.value = 24000;
        c_out0.output.branches = {lotus::v2::Hash32{1}};
        c_out0.output.paths = {{0}};
        c_out0.creation_height = 2;
        c_out0.creation_parent_mtp = 1120;

        BOOST_REQUIRE(overlay.AddTransaction(
            c_txid, c_txhash, 200, {p_out0.outpoint}, {c_out0}));
        surviving_outpoints.push_back(c_out0.outpoint);
    }

    // Intra-overlay ephemeral outputs must be elided from net deltas
    BOOST_CHECK_EQUAL(overlay.GetNetErasedOutpoints().size(), 5U);
    BOOST_CHECK_EQUAL(overlay.GetNetInsertedCoins().size(), 10U);

    // Add a coinbase coin for Block 2
    lotus::v2::Coin cb_coin{};
    cb_coin.outpoint.tx_id[0] = 0xd0;
    cb_coin.outpoint.index = 0;
    cb_coin.output.value = 200;
    cb_coin.output.branches = {lotus::v2::Hash32{1}};
    cb_coin.output.paths = {{0}};
    cb_coin.creation_height = 2;
    cb_coin.creation_parent_mtp = 1120;
    cb_coin.coinbase = true;

    std::shared_ptr<const lotus::v2::SmtNode> expected_root_node =
        overlay.GetUtxoRoot();
    lotus::v2::SmtInsert(expected_root_node, cb_coin);
    const lotus::v2::Hash expected_b2_root =
        lotus::v2::SmtRoot(expected_root_node);

    lotus::v2::DiskStateMetadata b2_meta{};
    b2_meta.tip[0] = 0x03;
    BOOST_REQUIRE_MESSAGE(
        store.CommitFinalizedOverlay(overlay, {cb_coin}, b2_meta, err),
        err.message);

    // Verify DiskStateStore root matches the overlay's post-coinbase UTXO root
    BOOST_CHECK(store.Root() == expected_b2_root);

    // Ephemeral coins must not exist in DiskStateStore; surviving coins must exist
    for (const auto &ephem : ephemeral_outpoints) {
        std::optional<lotus::v2::Coin> read_coin;
        BOOST_REQUIRE(store.ReadCoin(ephem, read_coin, err));
        BOOST_CHECK(!read_coin.has_value());
    }
    for (const auto &surv : surviving_outpoints) {
        std::optional<lotus::v2::Coin> read_coin;
        BOOST_REQUIRE(store.ReadCoin(surv, read_coin, err));
        BOOST_CHECK(read_coin.has_value());
    }

    // Disconnect Block 2 and verify exact restoration of Block 1 state
    BOOST_REQUIRE_MESSAGE(store.Disconnect(b2_meta.tip, err), err.message);
    BOOST_CHECK(store.Root() == b1_root);
}

BOOST_FIXTURE_TEST_CASE(txmempool_speculative_merklix_overlay, TestingSetup) {
    CBlock b1;
    b1.nHeaderVersion = 1;
    b1.nHeight = 1;
    b1.nBits = 0x207fffff;
    b1.SetBlockTime(1000);
    b1.vtx.push_back(MakeCoinbaseTx(1));
    std::vector<COutPoint> b1_coins;
    for (uint32_t i = 0; i < 12; ++i) {
        TxId dummy_prev{FastRandomContext().rand256()};
        auto tx = MakeSpendTx(COutPoint(dummy_prev, 0), i + 1, 100 * SATOSHI, 2);
        b1.vtx.push_back(tx);
        b1_coins.emplace_back(tx->GetId(), 0);
    }
    std::sort(b1.vtx.begin() + 1, b1.vtx.end(),
              [](const CTransactionRef &a, const CTransactionRef &b) {
                  return a->GetId() < b->GetId();
              });
    b1.hashMerkleRoot = BlockMerkleRoot(b1);
    b1.hashStateRoot = ComputeV2BlockStateRoot(b1, BlockHash{}, 1, 900, false);
    b1.nSize = ::GetSerializeSize(b1);
    const BlockHash b1_hash = b1.GetHash();
    RecordV2BlockState(b1, b1_hash, BlockHash{}, 1, 900);

    CTxMemPool &pool = *m_node.mempool;
    TestMemPoolEntryHelper entry;
    LOCK2(cs_main, pool.cs);
    pool.clear();
    pool.ConnectBlockReset(b1_hash, /*next_height=*/2, /*next_mtp=*/1000);

    std::vector<CTransactionRef> epoch1_txs;
    for (size_t i = 0; i < 6; ++i) {
        auto tx = MakeSpendTx(b1_coins[i], static_cast<uint32_t>(100 + i),
                              40 * SATOSHI, 2);
        pool.addUnchecked(entry.Fee(20 * SATOSHI).FromTx(tx));
        epoch1_txs.push_back(tx);
    }

    const auto &frozen_epoch1 = pool.FreezeEpochBatch();
    BOOST_CHECK_EQUAL(frozen_epoch1.GetTxCount(), 6U);

    // Add 4 more txs (including a child of epoch1_txs[0]) and remove 1 tx
    std::vector<CTransactionRef> extra_txs;
    auto child_tx = MakeSpendTx(COutPoint(epoch1_txs[0]->GetId(), 0), 200,
                                35 * SATOSHI, 1);
    pool.addUnchecked(entry.Fee(5 * SATOSHI).FromTx(child_tx));
    extra_txs.push_back(child_tx);

    for (size_t i = 6; i < 9; ++i) {
        auto tx = MakeSpendTx(b1_coins[i], static_cast<uint32_t>(300 + i),
                              40 * SATOSHI, 2);
        pool.addUnchecked(entry.Fee(20 * SATOSHI).FromTx(tx));
        extra_txs.push_back(tx);
    }

    // Remove extra_txs.back() from mempool and verify overlay reflects removal
    pool.removeRecursive(*extra_txs.back(), MemPoolRemovalReason::CONFLICT);
    extra_txs.pop_back();

    // Frozen epoch 1 must remain unaffected at 6 txs
    BOOST_CHECK_EQUAL(
        pool.GetMerklixOverlay().GetFrozenEpochs().front().GetTxCount(), 6U);

    // Speculative overlay must have 6 + 3 = 9 txs in exact CTOR order
    const auto &spec = pool.GetMerklixOverlay().GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(spec.GetTxCount(), 9U);

    CBlock b2;
    b2.nHeaderVersion = 1;
    b2.hashPrevBlock = b1_hash;
    b2.nHeight = 2;
    b2.nBits = 0x207fffff;
    b2.SetBlockTime(1120);
    b2.vtx.push_back(MakeCoinbaseTx(2));
    for (const auto &[_, oentry] : spec.GetOrderedTxs()) {
        b2.vtx.push_back(
            std::static_pointer_cast<const CTransaction>(oentry.tx_ref));
    }

    const uint256 expected_merkle = BlockMerkleRoot(b2);
    const uint256 overlay_merkle =
        ComputeV2TxRootFromSubtreeA(*b2.vtx[0], spec.GetSubtreeARoot());
    BOOST_CHECK_EQUAL(overlay_merkle, expected_merkle);

    const uint256 expected_state =
        ComputeV2BlockStateRoot(b2, b1_hash, 2, 1000, false);
    const uint256 overlay_state =
        ComputeV2StateRootFromOverlay(*b2.vtx[0], spec, b2.nBits, 2, 1000);
    BOOST_CHECK_EQUAL(overlay_state, expected_state);

    // Exercise arena Reserve, UtxoOverlayArena(root) constructor,
    // GetDefaultV2MonetaryProfile, and MerklixOverlayManager::RemoveTransaction
    BOOST_CHECK_EQUAL(lotus::v2::GetDefaultV2MonetaryProfile().ema_min, 4U);
    lotus::v2::TxOverlayArena tx_arena;
    tx_arena.Reserve(64);
    lotus::v2::UtxoOverlayArena utxo_arena(spec.GetUtxoRoot());
    utxo_arena.Reserve(64);
    BOOST_CHECK(utxo_arena.RootDigest() == spec.GetUtxoRootDigest());

    lotus::v2::Hash rem_txid{};
    std::memcpy(rem_txid.data(), extra_txs.back()->GetId().begin(), 32);
    BOOST_CHECK(pool.GetOverlayManager().RemoveTransaction(rem_txid));
    BOOST_CHECK(!pool.GetOverlayManager().RemoveTransaction(rem_txid));

    // Exercise SmtInsert/SmtErase duplicate/noop paths, invalid coin rejection,
    // TxOverlayArena/UtxoOverlayArena duplicate/noop paths, and frozen epoch re-anchoring
    {
        std::shared_ptr<const lotus::v2::SmtNode> smt_root;
        lotus::v2::Coin invalid_coin{};
        lotus::v2::SmtInsert(smt_root, invalid_coin);
        BOOST_CHECK(smt_root == nullptr);

        const auto net_coins = spec.GetNetInsertedCoins();
        BOOST_REQUIRE_GE(net_coins.size(), 2U);
        const lotus::v2::Coin c1 = net_coins[0];
        const lotus::v2::Coin c2 = net_coins[1];
        lotus::v2::SmtInsert(smt_root, c1);
        // Re-inserting identical single leaf returns the same node
        lotus::v2::SmtInsert(smt_root, c1);
        // Erasing non-existent outpoint on single leaf returns the same node
        lotus::v2::SmtErase(smt_root, c2.outpoint);
        lotus::v2::SmtInsert(smt_root, c2);
        // Re-inserting identical leaf in branch returns the same node
        lotus::v2::SmtInsert(smt_root, c2);
        // Erasing non-existent outpoint in branch returns the same node
        lotus::v2::SmtErase(smt_root, lotus::v2::Outpoint{lotus::v2::Hash{}, 999});

        lotus::v2::Hash h1{}, h2{}, h3{}, h_alt{};
        h1[0] = 1;
        h2[0] = 2;
        h3[0] = 3;
        h_alt[0] = 9;
        uint32_t tx_root = lotus::v2::TxOverlayArena::kNullIdx;
        BOOST_CHECK_EQUAL(tx_arena.EraseTxLeaf(tx_root, h1),
                          lotus::v2::TxOverlayArena::kNullIdx);
        tx_root = tx_arena.InsertTxLeaf(tx_root, h1, h1);
        // Duplicate same tx_hash on single leaf
        tx_root = tx_arena.InsertTxLeaf(tx_root, h1, h1);
        // Updated tx_hash on single leaf
        tx_root = tx_arena.InsertTxLeaf(tx_root, h1, h_alt);
        // Erase non-existent on single leaf
        BOOST_CHECK_EQUAL(tx_arena.EraseTxLeaf(tx_root, h2), tx_root);
        tx_root = tx_arena.InsertTxLeaf(tx_root, h2, h2);
        // Duplicate same tx_hash on branch
        BOOST_CHECK_EQUAL(tx_arena.InsertTxLeaf(tx_root, h2, h2), tx_root);
        // Erase non-existent on branch
        BOOST_CHECK_EQUAL(tx_arena.EraseTxLeaf(tx_root, h3), tx_root);

        lotus::v2::UtxoOverlayArena u_arena;
        u_arena.InsertCoin(invalid_coin);
        u_arena.InsertCoin(c1);
        // Duplicate same coin on single leaf
        u_arena.InsertCoin(c1);
        lotus::v2::Coin c1_mod = c1;
        c1_mod.output.value += 500;
        // Updated coin on single leaf
        u_arena.InsertCoin(c1_mod);
        u_arena.InsertCoin(c2);
        // Duplicate same coin on branch
        u_arena.InsertCoin(c2);

        // Frozen epoch re-anchoring on same-tip / unset-tip overlay manager
        lotus::v2::MerklixOverlayManager mgr;
        BOOST_CHECK(mgr.AddTransaction(h1, h1, 100, {c1.outpoint}, {c2}, 10, 1));
        BOOST_CHECK(!mgr.AddTransaction(h1, h1, 100, {c1.outpoint}, {c2}, 10, 1));
        mgr.FreezeEpochBatch();
        BOOST_CHECK_EQUAL(mgr.GetFrozenEpochs().size(), 1U);
        mgr.ReanchorExistingTxs(h3, smt_root,
                                lotus::v2::GetInitialV2MonetaryState(), 10,
                                2000);
        // Re-anchoring with identical anchor parameters is a no-op
        mgr.ReanchorExistingTxs(h3, smt_root,
                                lotus::v2::GetInitialV2MonetaryState(), 10,
                                2000);
        BOOST_CHECK_EQUAL(mgr.GetFrozenEpochs().size(), 1U);
        BOOST_CHECK_EQUAL(mgr.GetFrozenEpochs()[0].GetHeight(), 10U);
    }
}

BOOST_FIXTURE_TEST_CASE(utxo_fast_filter_hamilton_uhs, TestingSetup) {
    lotus::v2::UtxoFastFilter filter;
    filter.ReservePerShard(256, 64);

    constexpr size_t kNumUnspent = 10000;
    constexpr size_t kNumSpent = 2000;
    std::vector<lotus::v2::Outpoint> unspent_ops;
    unspent_ops.reserve(kNumUnspent);
    for (size_t i = 0; i < kNumUnspent; ++i) {
        lotus::v2::Outpoint op{};
        uint64_t seed = 0x9e3779b97f4a7c15ULL * (i + 1);
        std::memcpy(op.tx_id.data(), &seed, sizeof(seed));
        op.tx_id[0] = static_cast<uint8_t>((i * 7) & 0xFF);
        op.tx_id[31] = static_cast<uint8_t>((i >> 8) & 0xFF);
        op.index = static_cast<uint32_t>(i % 4);
        unspent_ops.push_back(op);
        filter.AddUnspent(op);
    }

    BOOST_CHECK_EQUAL(filter.UnspentCount(), kNumUnspent);
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), 0U);

    for (size_t i = 0; i < kNumSpent; ++i) {
        filter.MarkSpentInMempool(unspent_ops[i]);
    }
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), kNumSpent);

    for (size_t i = 0; i < kNumUnspent; ++i) {
        BOOST_CHECK(filter.MayExistInChainOrMempool(unspent_ops[i]));
        if (i < kNumSpent) {
            BOOST_CHECK(filter.IsSpentInMempool(unspent_ops[i]));
        } else {
            BOOST_CHECK(!filter.IsSpentInMempool(unspent_ops[i]));
        }
    }

    // Verify non-existent outpoints are rejected and measure lookup latency
    const auto t0 = std::chrono::steady_clock::now();
    size_t false_positives = 0;
    for (size_t i = 0; i < kNumUnspent; ++i) {
        lotus::v2::Outpoint missing = unspent_ops[i];
        missing.tx_id[15] ^= 0xFF;
        missing.index += 10;
        if (filter.IsSpentInMempool(missing) ||
            filter.MayExistInChainOrMempool(missing)) {
            ++false_positives;
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ns_per_check =
        std::chrono::duration<double, std::nano>(t1 - t0).count() /
        static_cast<double>(kNumUnspent * 2);
    BOOST_CHECK_EQUAL(false_positives, 0U);
    BOOST_TEST_MESSAGE("UtxoFastFilter average negative lookup: " << ns_per_check << " ns");

    // Unmark half of the spent outpoints and remove 500 unspent outpoints
    for (size_t i = 0; i < kNumSpent / 2; ++i) {
        BOOST_CHECK(filter.UnmarkSpentInMempool(unspent_ops[i]));
        BOOST_CHECK(!filter.IsSpentInMempool(unspent_ops[i]));
    }
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), kNumSpent / 2);

    for (size_t i = kNumUnspent - 500; i < kNumUnspent; ++i) {
        BOOST_CHECK(filter.RemoveUnspent(unspent_ops[i]));
        BOOST_CHECK(!filter.MayExistInChainOrMempool(unspent_ops[i]));
    }
    BOOST_CHECK_EQUAL(filter.UnspentCount(), kNumUnspent - 500);

    filter.ClearMempool();
    BOOST_CHECK_EQUAL(filter.MempoolSpentCount(), 0U);
    BOOST_CHECK_EQUAL(filter.UnspentCount(), kNumUnspent - 500);

    filter.ClearAll();
    BOOST_CHECK_EQUAL(filter.UnspentCount(), 0U);

    // Verify CTxMemPool integration
    CTxMemPool &pool = *m_node.mempool;
    TestMemPoolEntryHelper entry;
    LOCK2(cs_main, pool.cs);
    pool.clear();

    TxId parent_txid{FastRandomContext().rand256()};
    COutPoint spent_prevout(parent_txid, 0);
    COutPoint unspent_prevout(parent_txid, 1);
    pool.GetUtxoFastFilter().AddUnspent(parent_txid.begin(), 0);
    pool.GetUtxoFastFilter().AddUnspent(parent_txid.begin(), 1);

    BOOST_CHECK(!pool.isSpent(spent_prevout));
    BOOST_CHECK(!pool.IsSpentFast(spent_prevout));
    BOOST_CHECK(pool.MayExistInChainOrMempoolFast(spent_prevout));

    auto tx1 = MakeSpendTx(spent_prevout, 42, 50 * SATOSHI, 2);
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));

    COutPoint tx1_out0(tx1->GetId(), 0);
    BOOST_CHECK(pool.isSpent(spent_prevout));
    BOOST_CHECK(pool.IsSpentFast(spent_prevout));
    BOOST_CHECK(!pool.isSpent(unspent_prevout));
    BOOST_CHECK(pool.MayExistInChainOrMempoolFast(tx1_out0));

    // Removing due to CONFLICT should unmark spent_prevout and remove tx1_out0 from UHS
    pool.removeRecursive(*tx1, MemPoolRemovalReason::CONFLICT);
    BOOST_CHECK(!pool.isSpent(spent_prevout));
    BOOST_CHECK(!pool.IsSpentFast(spent_prevout));
    BOOST_CHECK(!pool.MayExistInChainOrMempoolFast(tx1_out0));
    BOOST_CHECK(pool.MayExistInChainOrMempoolFast(spent_prevout));

    // Re-add and remove due to BLOCK confirmation: spent_prevout is consumed from UHS,
    // while tx1_out0 remains unspent in the chain UHS.
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
    pool.removeRecursive(*tx1, MemPoolRemovalReason::BLOCK);
    BOOST_CHECK(!pool.isSpent(spent_prevout));
    BOOST_CHECK(!pool.MayExistInChainOrMempoolFast(spent_prevout));
    BOOST_CHECK(pool.MayExistInChainOrMempoolFast(tx1_out0));
}

BOOST_AUTO_TEST_CASE(monaddb_16_shard_parallel_merklix_and_prefetch) {
    // 1. Verify TxOverlayArena::InsertBatchParallel produces 100% bit-identical
    //    SubtreeARoot to serial InsertTxLeaf across edge cases and 800-tx batches.
    {
        std::vector<std::pair<lotus::v2::Hash, lotus::v2::Hash>> all_txs;
        all_txs.reserve(800);
        for (uint32_t i = 0; i < 800; ++i) {
            lotus::v2::Hash txid{}, txhash{};
            uint256 r1 = m_rng.rand256();
            uint256 r2 = m_rng.rand256();
            std::memcpy(txid.data(), r1.begin(), 32);
            std::memcpy(txhash.data(), r2.begin(), 32);
            all_txs.emplace_back(txid, txhash);
        }
        // Force first two txs into the exact same depth-4 shard (shard 0x05)
        all_txs[0].first[0] = (all_txs[0].first[0] & 0xF0u) | 0x05u;
        all_txs[1].first[0] = (all_txs[1].first[0] & 0xF0u) | 0x05u;

        // Case 1a: 1 tx
        lotus::v2::TxOverlayArena serial_arena, parallel_arena;
        uint32_t s_root = serial_arena.InsertTxLeaf(
            lotus::v2::TxOverlayArena::kNullIdx, all_txs[0].first,
            all_txs[0].second);
        uint32_t p_root = parallel_arena.InsertBatchParallel(
            lotus::v2::TxOverlayArena::kNullIdx,
            std::span<const std::pair<lotus::v2::Hash, lotus::v2::Hash>>(
                all_txs.data(), 1));
        BOOST_CHECK_EQUAL(parallel_arena.Count(p_root), 1U);
        BOOST_CHECK(parallel_arena.SubtreeARoot(p_root) ==
                    serial_arena.SubtreeARoot(s_root));

        // Case 1b: 2nd tx in the SAME shard (incremental batch onto single-leaf root)
        s_root = serial_arena.InsertTxLeaf(s_root, all_txs[1].first,
                                           all_txs[1].second);
        p_root = parallel_arena.InsertBatchParallel(
            p_root,
            std::span<const std::pair<lotus::v2::Hash, lotus::v2::Hash>>(
                all_txs.data() + 1, 1));
        BOOST_CHECK_EQUAL(parallel_arena.Count(p_root), 2U);
        BOOST_CHECK(parallel_arena.SubtreeARoot(p_root) ==
                    serial_arena.SubtreeARoot(s_root));

        // Case 1c: Batch of next 498 txs (total 500)
        for (size_t i = 2; i < 500; ++i) {
            s_root = serial_arena.InsertTxLeaf(s_root, all_txs[i].first,
                                               all_txs[i].second);
        }
        p_root = parallel_arena.InsertBatchParallel(
            p_root,
            std::span<const std::pair<lotus::v2::Hash, lotus::v2::Hash>>(
                all_txs.data() + 2, 498));
        BOOST_CHECK_EQUAL(parallel_arena.Count(p_root), 500U);
        BOOST_CHECK(parallel_arena.SubtreeARoot(p_root) ==
                    serial_arena.SubtreeARoot(s_root));

        // Case 1d: Incremental batch of remaining 300 txs (total 800)
        for (size_t i = 500; i < 800; ++i) {
            s_root = serial_arena.InsertTxLeaf(s_root, all_txs[i].first,
                                               all_txs[i].second);
        }
        p_root = parallel_arena.InsertBatchParallel(
            p_root,
            std::span<const std::pair<lotus::v2::Hash, lotus::v2::Hash>>(
                all_txs.data() + 500, 300));
        BOOST_CHECK_EQUAL(parallel_arena.Count(p_root), 800U);
        BOOST_CHECK(parallel_arena.SubtreeARoot(p_root) ==
                    serial_arena.SubtreeARoot(s_root));
    }

    // 2. Verify SmtBatchUpdateParallel and UtxoOverlayArena::BatchUpdateParallel
    //    produce 100% bit-identical UtxoRoot digests to serial SmtErase/SmtInsert.
    std::vector<lotus::v2::Coin> base_coins;
    base_coins.reserve(600);
    for (uint32_t i = 0; i < 600; ++i) {
        lotus::v2::Coin coin{};
        uint256 r = m_rng.rand256();
        std::memcpy(coin.outpoint.tx_id.data(), r.begin(), 32);
        coin.outpoint.index = i % 4;
        coin.output.value = 10000 + i * 10;
        coin.output.branches = {lotus::v2::Hash32{1}};
        coin.output.paths = {{0}};
        coin.creation_height = 1;
        coin.creation_parent_mtp = 1000;
        coin.coinbase = (i == 0);
        base_coins.push_back(coin);
    }

    std::shared_ptr<const lotus::v2::SmtNode> serial_smt_root;
    for (const auto &c : base_coins) {
        lotus::v2::SmtInsert(serial_smt_root, c);
    }

    std::shared_ptr<const lotus::v2::SmtNode> parallel_smt_root;
    lotus::v2::SmtBatchUpdateParallel(parallel_smt_root, {}, base_coins);
    BOOST_REQUIRE(parallel_smt_root != nullptr);
    BOOST_CHECK_EQUAL(parallel_smt_root->count, 600U);
    BOOST_CHECK(lotus::v2::SmtRoot(parallel_smt_root) ==
                lotus::v2::SmtRoot(serial_smt_root));

    lotus::v2::UtxoOverlayArena serial_utxo_arena(serial_smt_root);
    lotus::v2::UtxoOverlayArena parallel_utxo_arena(parallel_smt_root);

    // Prepare 250 erasures from base_coins and 400 new coin insertions
    std::vector<lotus::v2::Outpoint> batch_erased;
    batch_erased.reserve(250);
    for (size_t i = 0; i < 250; ++i) {
        batch_erased.push_back(base_coins[i * 2].outpoint);
    }
    std::vector<lotus::v2::Coin> batch_inserted;
    batch_inserted.reserve(400);
    for (uint32_t i = 0; i < 400; ++i) {
        lotus::v2::Coin coin{};
        uint256 r = m_rng.rand256();
        std::memcpy(coin.outpoint.tx_id.data(), r.begin(), 32);
        coin.outpoint.index = i % 3;
        coin.output.value = 5000 + i * 5;
        coin.output.branches = {lotus::v2::Hash32{1}};
        coin.output.paths = {{0}};
        coin.creation_height = 2;
        coin.creation_parent_mtp = 1120;
        coin.coinbase = false;
        batch_inserted.push_back(coin);
    }

    for (const auto &op : batch_erased) {
        lotus::v2::SmtErase(serial_smt_root, op);
        serial_utxo_arena.EraseOutpoint(op);
    }
    for (const auto &c : batch_inserted) {
        lotus::v2::SmtInsert(serial_smt_root, c);
        serial_utxo_arena.InsertCoin(c);
    }

    lotus::v2::SmtBatchUpdateParallel(parallel_smt_root, batch_erased,
                                      batch_inserted);
    parallel_utxo_arena.BatchUpdateParallel(batch_erased, batch_inserted);

    BOOST_CHECK(lotus::v2::SmtRoot(parallel_smt_root) ==
                lotus::v2::SmtRoot(serial_smt_root));
    BOOST_CHECK(parallel_utxo_arena.RootDigest() ==
                serial_utxo_arena.RootDigest());
    BOOST_CHECK(parallel_utxo_arena.RootDigest() ==
                lotus::v2::SmtRoot(parallel_smt_root));
    BOOST_CHECK(lotus::v2::SmtRoot(parallel_utxo_arena.GetSmtRoot()) ==
                lotus::v2::SmtRoot(serial_smt_root));

    // 3. Verify DiskStateStore::PrefetchOutpointsAsync on a live MDBX store
    const fs::path db_dir = m_args.GetDataDirNet() / "v2_prefetch_async_test";
    fs::create_directories(db_dir);

    lotus::v2::DiskStateOptions opts{};
    opts.identity[0] = 0x33;
    opts.profile_digest[0] = 0x44;

    lotus::v2::DiskStateMetadata genesis_meta{};
    genesis_meta.tip[0] = 0x01;

    lotus::v2::DiskStateStore store;
    lotus::v2::DiskStateError err;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        genesis_meta, store, err),
        err.message);

    {
        lotus::v2::DiskStateTransaction txn;
        BOOST_REQUIRE(store.Begin(txn, err));
        for (size_t i = 0; i < 64; ++i) {
            BOOST_REQUIRE(txn.Insert(base_coins[i], err));
        }
        lotus::v2::DiskStateMetadata b1_meta{};
        b1_meta.tip[0] = 0x02;
        BOOST_REQUIRE(txn.Commit(b1_meta, err));
    }

    std::vector<lotus::v2::Outpoint> prefetch_ops;
    prefetch_ops.reserve(64);
    for (size_t i = 0; i < 64; ++i) {
        prefetch_ops.push_back(base_coins[i].outpoint);
    }
    BOOST_REQUIRE_MESSAGE(store.PrefetchOutpointsAsync(prefetch_ops, err),
                          err.message);

    for (size_t i = 0; i < 64; ++i) {
        std::optional<lotus::v2::Coin> found;
        BOOST_REQUIRE(store.ReadCoin(prefetch_ops[i], found, err));
        BOOST_CHECK(found.has_value());
    }
}

BOOST_AUTO_TEST_CASE(kaspa_finality_horizon_undo_pruning) {
    const fs::path db_dir = m_args.GetDataDirNet() / "v2_kaspa_undo_prune_test";
    fs::create_directories(db_dir);

    lotus::v2::DiskStateOptions opts{};
    opts.identity[0] = 0x55;
    opts.profile_digest[0] = 0x66;

    const lotus::v2::MonetaryState mon = lotus::v2::GetInitialV2MonetaryState();
    const auto mon_bytes = lotus::v2::EncodeMonetaryState(mon);

    auto make_header_and_meta = [&](uint64_t height,
                                    const lotus::v2::Hash &prev_id,
                                    const lotus::v2::Hash &utxo_root,
                                    lotus::v2::Header &hdr_out,
                                    lotus::v2::DiskStateMetadata &meta_out) {
        hdr_out = lotus::v2::Header{};
        hdr_out.prev_id = prev_id;
        hdr_out.bits = 0x207fffff;
        hdr_out.time = 1000 + height * 120;
        hdr_out.nonce = height;
        hdr_out.version = lotus::v2::kHeaderVersion;
        hdr_out.size = 200;
        hdr_out.height = height;
        hdr_out.tx_root[0] = static_cast<uint8_t>(height + 1);
        hdr_out.state_root =
            lotus::v2::StateRoot(opts.identity, height, utxo_root, mon);

        std::array<uint8_t, lotus::v2::HEADER_SIZE> hdr_bytes{};
        BOOST_REQUIRE(lotus::v2::SerializeHeader(hdr_out, hdr_bytes));
        lotus::v2::Hash bid{};
        BOOST_REQUIRE(lotus::v2::BlockId(opts.identity, hdr_out, bid));

        meta_out = lotus::v2::DiskStateMetadata{};
        meta_out.tip = bid;
        meta_out.header.assign(hdr_bytes.begin(), hdr_bytes.end());
        meta_out.monetary.assign(mon_bytes.begin(), mon_bytes.end());
    };

    std::vector<lotus::v2::Header> headers(6);
    std::vector<lotus::v2::DiskStateMetadata> metas(6);
    std::vector<lotus::v2::Hash> roots(6);
    std::vector<lotus::v2::Coin> coins(6);

    std::shared_ptr<const lotus::v2::SmtNode> running_smt;
    roots[0] = lotus::v2::EmptyUtxoRoot();
    make_header_and_meta(0, lotus::v2::Hash{}, roots[0], headers[0], metas[0]);

    lotus::v2::DiskStateStore store;
    lotus::v2::DiskStateError err;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        metas[0], store, err),
        err.message);
    BOOST_CHECK_EQUAL(store.PrunedUndoHorizonHeight(), 0U);

    // Connect blocks 1..5, each spending the previous block's coin (for h >= 2)
    // and inserting a new coin.
    for (uint64_t h = 1; h <= 5; ++h) {
        lotus::v2::Coin c{};
        c.outpoint.tx_id[0] = static_cast<uint8_t>(0x80 + h);
        c.outpoint.index = 0;
        c.output.value = 50000 + h * 1000;
        c.output.branches = {lotus::v2::Hash32{1}};
        c.output.paths = {{0}};
        c.creation_height = h;
        c.creation_parent_mtp = 900 + h * 120;
        c.coinbase = false;
        coins[h] = c;

        if (h >= 2) {
            lotus::v2::SmtErase(running_smt, coins[h - 1].outpoint);
        }
        lotus::v2::SmtInsert(running_smt, c);
        roots[h] = lotus::v2::SmtRoot(running_smt);
        make_header_and_meta(h, metas[h - 1].tip, roots[h], headers[h],
                             metas[h]);

        lotus::v2::DiskStateTransaction txn;
        BOOST_REQUIRE_MESSAGE(store.Begin(txn, err), err.message);
        if (h >= 2) {
            BOOST_REQUIRE_MESSAGE(txn.Erase(coins[h - 1].outpoint, err),
                                  err.message);
        }
        BOOST_REQUIRE_MESSAGE(txn.Insert(c, err), err.message);
        BOOST_REQUIRE_MESSAGE(txn.Commit(metas[h], err), err.message);
        BOOST_CHECK(store.Root() == roots[h]);
    }

    // Verify undo locations exist for all blocks 1..5 before pruning
    for (uint64_t h = 1; h <= 5; ++h) {
        std::optional<lotus::v2::DiskUndoLocation> uloc;
        BOOST_REQUIRE(store.ReadUndoLocation(metas[h].tip, uloc, err));
        BOOST_CHECK(uloc.has_value());
    }

    // Prune finalized undo records up to cutoff = 5 - 2 = 3 (heights 1, 2, 3)
    uint64_t pruned_count = 0;
    BOOST_REQUIRE_MESSAGE(
        store.PruneFinalizedUndoHorizon(5, 2, err, &pruned_count), err.message);
    BOOST_CHECK_EQUAL(pruned_count, 3U);
    BOOST_CHECK_EQUAL(store.PrunedUndoHorizonHeight(), 3U);
    BOOST_CHECK(store.Root() == roots[5]);

    // Idempotent second call prunes 0 additional records
    uint64_t second_pruned = 99;
    BOOST_REQUIRE_MESSAGE(
        store.PruneFinalizedUndoHorizon(5, 2, err, &second_pruned),
        err.message);
    BOOST_CHECK_EQUAL(second_pruned, 0U);

    // Undo locations for h = 1, 2, 3 are pruned; h = 4, 5 remain intact
    for (uint64_t h = 1; h <= 5; ++h) {
        std::optional<lotus::v2::DiskUndoLocation> uloc;
        BOOST_REQUIRE(store.ReadUndoLocation(metas[h].tip, uloc, err));
        if (h <= 3) {
            BOOST_CHECK(!uloc.has_value());
        } else {
            BOOST_CHECK(uloc.has_value());
        }
    }

    // Reverse-peel from h=5 -> h=4 and h=4 -> h=3 (above horizon) succeeds
    BOOST_REQUIRE_MESSAGE(
        store.PeelBlockStateReverse(metas[5].tip, metas[4], headers[4],
                                    {coins[5].outpoint}, {coins[4]}, err),
        err.message);
    BOOST_CHECK(store.Root() == roots[4]);

    BOOST_REQUIRE_MESSAGE(
        store.PeelBlockStateReverse(metas[4].tip, metas[3], headers[3],
                                    {coins[4].outpoint}, {coins[3]}, err),
        err.message);
    BOOST_CHECK(store.Root() == roots[3]);

    // Reverse-peel from h=3 -> h=2 (past pruned finality horizon) must fail cleanly
    BOOST_CHECK(!store.PeelBlockStateReverse(metas[3].tip, metas[2], headers[2],
                                             {coins[3].outpoint}, {coins[2]},
                                             err));
    BOOST_CHECK(err.code == lotus::v2::DiskStateErrorCode::UndoMismatch);
    BOOST_CHECK(store.Root() == roots[3]);

    // Disconnect at h=3 (pruned horizon) must also fail cleanly with Missing
    BOOST_CHECK(!store.Disconnect(metas[3].tip, err));
    BOOST_CHECK(err.code == lotus::v2::DiskStateErrorCode::Missing);
    BOOST_CHECK(store.Root() == roots[3]);

    // Reopen store from disk and verify pruned horizon metadata persists
    store = lotus::v2::DiskStateStore{};
    opts.existing_only = true;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        metas[0], store, err),
        err.message);
    BOOST_CHECK_EQUAL(store.PrunedUndoHorizonHeight(), 3U);
    BOOST_CHECK(store.Root() == roots[3]);
    BOOST_CHECK(!store.Disconnect(metas[3].tip, err));
    BOOST_CHECK(err.code == lotus::v2::DiskStateErrorCode::Missing);
}

BOOST_FIXTURE_TEST_CASE(phase2_hotspots_coalesced_batch_and_schnorr_msm, TestingSetup) {
    // 1. Coalesced 16-shard AddTransactionsToOverlayBatch vs serial AddTransactionToOverlay
    CBlock base_block;
    base_block.nHeaderVersion = lotus::v2::kHeaderVersion;
    base_block.nHeight = 1;
    base_block.nBits = 0x207fffff;
    base_block.SetBlockTime(1700000000);

    CMutableTransaction base_cb;
    base_cb.nVersion = 2;
    base_cb.vin.resize(1);
    base_cb.vin[0].prevout = COutPoint();
    base_cb.vin[0].scriptSig = CScript() << 1 << OP_0;
    base_cb.vout.resize(300);
    for (size_t i = 0; i < 300; ++i) {
        base_cb.vout[i].nValue = 100000 * SATOSHI;
        base_cb.vout[i].scriptPubKey = CScript() << int64_t(i) << OP_TRUE;
    }
    base_block.vtx.push_back(MakeTransactionRef(std::move(base_cb)));
    base_block.hashMerkleRoot = BlockMerkleRoot(base_block);
    base_block.hashStateRoot = ComputeV2BlockStateRoot(
        base_block, BlockHash(), 1, 1699999000, /*record=*/false);
    const BlockHash base_hash = base_block.GetHash();
    RecordV2BlockState(base_block, base_hash, BlockHash(), 1, 1699999000);

    std::shared_ptr<const lotus::v2::SmtNode> base_utxo_root;
    lotus::v2::MonetaryState base_mon_state{};
    BOOST_REQUIRE(
        GetV2BlockStateSnapshot(base_hash, base_utxo_root, base_mon_state));

    lotus::v2::Hash base_id_hash{};
    std::memcpy(base_id_hash.data(), base_hash.begin(), 32);

    const uint64_t next_height = 2;
    const uint64_t parent_mtp = 1700000000;

    std::vector<CTransactionRef> batch_txs;
    batch_txs.reserve(500);
    const TxId base_cb_txid = base_block.vtx[0]->GetId();
    for (uint32_t i = 0; i < 250; ++i) {
        auto ptx = MakeSpendTx(COutPoint(base_cb_txid, i), 1000 + i,
                               40000 * SATOSHI, 2);
        batch_txs.push_back(ptx);
    }
    // 250 child transactions spending outputs of the first 250 parent transactions
    for (uint32_t i = 0; i < 250; ++i) {
        auto ctx = MakeSpendTx(COutPoint(batch_txs[i]->GetId(), 0), 2000 + i,
                               15000 * SATOSHI, 2);
        batch_txs.push_back(ctx);
    }

    // These fixtures bypass admission: supply the actual input-minus-output
    // fee so their authenticated lifetime matches full block construction.
    auto actual_fee = [](const CTransactionRef &tx) -> int64_t {
        return tx->vout[0].nValue == 40000 * SATOSHI ? 20000 : 10000;
    };
    lotus::v2::MerklixOverlayManager serial_mgr;
    serial_mgr.ResetToTip(base_id_hash, base_utxo_root, base_mon_state,
                          next_height, parent_mtp);
    const auto t_serial_0 = std::chrono::steady_clock::now();
    for (const auto &ptx : batch_txs) {
        BOOST_CHECK(AddTransactionToOverlay(serial_mgr, ptx, actual_fee(ptx), 1));
    }
    const auto t_serial_1 = std::chrono::steady_clock::now();

    lotus::v2::MerklixOverlayManager batch_mgr;
    batch_mgr.ResetToTip(base_id_hash, base_utxo_root, base_mon_state,
                         next_height, parent_mtp);
    std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> batch_tuples;
    batch_tuples.reserve(batch_txs.size());
    for (size_t i = 0; i < batch_txs.size(); ++i) {
        batch_tuples.emplace_back(batch_txs[i], actual_fee(batch_txs[i]), 1);
    }
    const auto t_batch_0 = std::chrono::steady_clock::now();
    const size_t added =
        AddTransactionsToOverlayBatch(batch_mgr, batch_tuples);
    const auto t_batch_1 = std::chrono::steady_clock::now();
    BOOST_CHECK_EQUAL(added, 500U);

    const double serial_ms =
        std::chrono::duration<double, std::milli>(t_serial_1 - t_serial_0)
            .count();
    const double batch_ms =
        std::chrono::duration<double, std::milli>(t_batch_1 - t_batch_0)
            .count();
    BOOST_TEST_MESSAGE("Overlay 500-tx add: serial=" << serial_ms
                       << " ms, coalesced_batch=" << batch_ms
                       << " ms (speedup=" << (serial_ms / std::max(0.001, batch_ms))
                       << "x)");

    const auto &serial_spec = serial_mgr.GetSpeculativeOverlay();
    const auto &batch_spec = batch_mgr.GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(batch_spec.GetTxCount(), 500U);
    BOOST_CHECK(batch_spec.GetSubtreeARoot() == serial_spec.GetSubtreeARoot());
    BOOST_CHECK(batch_spec.GetUtxoRootDigest() ==
                serial_spec.GetUtxoRootDigest());
    BOOST_CHECK(lotus::v2::SmtRoot(batch_spec.GetUtxoRoot()) ==
                lotus::v2::SmtRoot(serial_spec.GetUtxoRoot()));

    const CTransactionRef cb2 = MakeCoinbaseTx(next_height);
    const uint256 serial_state_root = ComputeV2StateRootFromOverlay(
        *cb2, serial_spec, 0x207fffff, next_height, parent_mtp);
    const uint256 batch_state_root = ComputeV2StateRootFromOverlay(
        *cb2, batch_spec, 0x207fffff, next_height, parent_mtp);
    BOOST_CHECK_EQUAL(batch_state_root, serial_state_root);

    // Verify CTxMemPool ScopedSnapshotDefer coalesces addUnchecked into a single
    // 16-shard batch flush and produces the exact same overlay state root.
    CTxMemPool &pool = *m_node.mempool;
    TestMemPoolEntryHelper entry;
    {
        LOCK2(cs_main, pool.cs);
        pool.clear();
        pool.ConnectBlockReset(base_hash, next_height, parent_mtp);
        {
            CTxMemPool::ScopedSnapshotDefer defer(pool);
            for (const auto &ptx : batch_txs) {
                pool.addUnchecked(entry.Fee(actual_fee(ptx) * SATOSHI).FromTx(ptx));
            }
        }
        const auto &pool_spec = pool.GetMerklixOverlay().GetSpeculativeOverlay();
        BOOST_CHECK_EQUAL(pool_spec.GetTxCount(), 500U);
        BOOST_CHECK(pool_spec.GetSubtreeARoot() ==
                    serial_spec.GetSubtreeARoot());
        BOOST_CHECK(pool_spec.GetUtxoRootDigest() ==
                    serial_spec.GetUtxoRootDigest());
        const uint256 pool_state_root = ComputeV2StateRootFromOverlay(
            *cb2, pool_spec, 0x207fffff, next_height, parent_mtp);
        BOOST_CHECK_EQUAL(pool_state_root, serial_state_root);
    }

    // 2. BuildNextV2BlockState candidate cache speedup across 3 consecutive calls
    CBlock block2;
    block2.nHeaderVersion = lotus::v2::kHeaderVersion;
    block2.hashPrevBlock = base_hash;
    block2.nHeight = next_height;
    block2.nBits = 0x207fffff;
    block2.SetBlockTime(1700000120);
    block2.vtx.push_back(cb2);
    for (const auto &[_, oentry] : batch_spec.GetOrderedTxs()) {
        block2.vtx.push_back(
            std::static_pointer_cast<const CTransaction>(oentry.tx_ref));
    }
    const auto t_b2_first0 = std::chrono::steady_clock::now();
    const uint256 b2_state_1 = ComputeV2BlockStateRoot(
        block2, base_hash, next_height, parent_mtp, /*record=*/false);
    const auto t_b2_first1 = std::chrono::steady_clock::now();
    const uint256 b2_state_2 = ComputeV2BlockStateRoot(
        block2, base_hash, next_height, parent_mtp, /*record=*/false);
    const uint256 b2_state_3 = ComputeV2BlockStateRoot(
        block2, base_hash, next_height, parent_mtp, /*record=*/true);
    const auto t_b2_cached = std::chrono::steady_clock::now();
    BOOST_CHECK_EQUAL(b2_state_1, serial_state_root);
    BOOST_CHECK_EQUAL(b2_state_2, b2_state_1);
    BOOST_CHECK_EQUAL(b2_state_3, b2_state_1);
    const double first_b2_ms =
        std::chrono::duration<double, std::milli>(t_b2_first1 - t_b2_first0)
            .count();
    const double cached_b2_ms =
        std::chrono::duration<double, std::milli>(t_b2_cached - t_b2_first1)
            .count() /
        2.0;
    BOOST_TEST_MESSAGE("BuildNextV2BlockState 500-tx: uncached=" << first_b2_ms
                       << " ms, cached=" << cached_b2_ms << " ms");

    // 3. Legacy 64-byte Schnorr Multi-Scalar Multiplication Batch Verification
    constexpr size_t kNumSigs = 500;
    std::vector<CPubKey> pubkeys(kNumSigs);
    std::vector<uint256> msgs(kNumSigs);
    std::vector<std::array<uint8_t, 64>> sigs(kNumSigs);
    for (size_t i = 0; i < kNumSigs; ++i) {
        CKey key;
        key.MakeNewKey(/*fCompressed=*/true);
        pubkeys[i] = key.GetPubKey();
        msgs[i] = m_rng.rand256();
        BOOST_REQUIRE(key.SignSchnorr(msgs[i], sigs[i]));
    }

    const auto t_ind_0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kNumSigs; ++i) {
        BOOST_CHECK(pubkeys[i].VerifySchnorr(msgs[i], sigs[i]));
    }
    const auto t_ind_1 = std::chrono::steady_clock::now();

    lotus::v2::BatchSigCollector collector;
    const auto t_msm_0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kNumSigs; ++i) {
        BOOST_CHECK(collector.AddLegacySchnorr(
            std::span<const uint8_t>(pubkeys[i].data(), pubkeys[i].size()),
            std::span<const uint8_t>(sigs[i].data(), 64), msgs[i].begin()));
    }
    BOOST_CHECK(collector.VerifyAll());
    const auto t_msm_1 = std::chrono::steady_clock::now();

    const double ind_ms =
        std::chrono::duration<double, std::milli>(t_ind_1 - t_ind_0).count();
    const double msm_ms =
        std::chrono::duration<double, std::milli>(t_msm_1 - t_msm_0).count();
    BOOST_TEST_MESSAGE("Legacy 64B Schnorr 500-sig verify: individual="
                       << ind_ms << " ms, batch_msm=" << msm_ms
                       << " ms (speedup=" << (ind_ms / std::max(0.001, msm_ms))
                       << "x)");

    // Mutate one signature byte in the batch and verify VerifyAll() rejects it
    lotus::v2::BatchSigCollector bad_collector;
    for (size_t i = 0; i < kNumSigs; ++i) {
        auto sig_copy = sigs[i];
        if (i == kNumSigs / 2) {
            sig_copy[63] ^= 0x01;
        }
        BOOST_CHECK(bad_collector.AddLegacySchnorr(
            std::span<const uint8_t>(pubkeys[i].data(), pubkeys[i].size()),
            std::span<const uint8_t>(sig_copy.data(), 64), msgs[i].begin()));
    }
    BOOST_CHECK(!bad_collector.VerifyAll());
}

BOOST_AUTO_TEST_CASE(smt_node_pure_v7) {
    // Verify SmtNode and OverlayTxEntry no longer carry dual-state script_pubkey vectors
    static_assert(sizeof(lotus::v2::SmtNode) <= 128,
                  "SmtNode must remain compact without dual-state script_pubkey");

    const CTransactionRef legacy_cb = MakeCoinbaseTx(42, 500 * SATOSHI);
    // The V2 form of a legacy coinbase, built explicitly.
    const CTransaction v7_cb(
        CMutableTransaction::FromV2Transaction(legacy_cb->ToV2Transaction()));
    BOOST_CHECK_EQUAL(v7_cb.nVersion, 7U);
    BOOST_CHECK_EQUAL(v7_cb.nV2Lock, 0U);
    BOOST_CHECK(v7_cb.IsCoinBase());
    BOOST_REQUIRE_EQUAL(v7_cb.vin.size(), 1U);
    BOOST_CHECK_EQUAL(v7_cb.vin[0].nFlags, 2U);
    BOOST_CHECK(v7_cb.vin[0].fHasCoinbaseData);
    BOOST_CHECK(!v7_cb.vin[0].vCoinbaseData.empty());
    BOOST_REQUIRE_EQUAL(v7_cb.vout.size(), 1U);
    BOOST_CHECK(!v7_cb.vout[0].vBranches.empty());
    BOOST_CHECK_EQUAL(v7_cb.vout[0].vPaths.size(), 1U);

    // Pure v7 wire serialization roundtrip on adapted coinbase
    {
        DataStream ss{};
        ss << v7_cb;
        uint32_t wire_ver = 0;
        DataStream peek(ss);
        peek >> wire_ver;
        BOOST_CHECK_EQUAL(wire_ver, 7U);
        CTransaction roundtrip(deserialize, ss);
        BOOST_CHECK_EQUAL(roundtrip.nVersion, 7U);
        BOOST_CHECK_EQUAL(roundtrip.GetId(), v7_cb.GetId());
        BOOST_CHECK_EQUAL(roundtrip.GetHash(), v7_cb.GetHash());
    }

    // Spend transaction adaptation with height locktime and MTP locktime
    const COutPoint prevout(v7_cb.GetId(), 0);
    const CTransactionRef legacy_spend =
        MakeSpendTx(prevout, 12345, 200 * SATOSHI, 2);
    CMutableTransaction mtx_spend =
        CMutableTransaction::FromV2Transaction(legacy_spend->ToV2Transaction());
    BOOST_CHECK_EQUAL(mtx_spend.nVersion, 7U);
    BOOST_CHECK_EQUAL(mtx_spend.nV2Lock, (uint64_t(12345) << 8) | 1ULL);
    BOOST_CHECK_EQUAL(mtx_spend.vin[0].nFlags, 1U);
    BOOST_CHECK(!mtx_spend.vin[0].vWitnesses.empty());
    for (const auto &txout : mtx_spend.vout) {
        BOOST_CHECK(!txout.vBranches.empty());
        BOOST_CHECK_EQUAL(txout.vPaths.size(), 1U);
    }

    // Pure v7 wire roundtrip on adapted spend tx
    {
        DataStream ss{};
        ss << mtx_spend;
        uint32_t wire_ver = 0;
        DataStream peek(ss);
        peek >> wire_ver;
        BOOST_CHECK_EQUAL(wire_ver, 7U);
        CTransaction roundtrip(deserialize, ss);
        BOOST_CHECK_EQUAL(roundtrip.nVersion, 7U);
        BOOST_CHECK_EQUAL(roundtrip.GetId(), mtx_spend.GetId());
        BOOST_CHECK_EQUAL(roundtrip.GetHash(), mtx_spend.GetHash());
    }

    // LookupV2SmtCoin returns canonical FromV2Output CTxOut without dual-state script_pubkey
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::Hash txid{};
    std::memcpy(txid.data(), v7_cb.GetId().begin(), 32);
    lotus::v2::Coin coin{
        {txid, 0},
        v7_cb.vout[0].ToV2Output(),
        42,
        1700000000,
        true};
    lotus::v2::SmtInsert(root, coin);
    uint32_t looked_up_height = 0;
    bool looked_up_cb = false;
    auto looked_up = LookupV2SmtCoin(root, prevout, &looked_up_height,
                                     &looked_up_cb);
    BOOST_REQUIRE(looked_up.has_value());
    BOOST_CHECK_EQUAL(looked_up_height, 42U);
    BOOST_CHECK(looked_up_cb);
    BOOST_CHECK_EQUAL(looked_up->nValue, 500 * SATOSHI);
    BOOST_CHECK(looked_up->vBranches == v7_cb.vout[0].vBranches);
}

BOOST_FIXTURE_TEST_CASE(mempool_overlay_tracks_admission_removal_and_tip, TestingSetup) {
    auto &pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const BlockHash tip(uint256S("11"));
    pool.ConnectBlockReset(tip, 100, 1000);
    auto &manager = pool.GetMerklixOverlay();
    lotus::v2::Hash tip_id{};
    std::copy(tip.begin(), tip.end(), tip_id.begin());
    BOOST_CHECK(manager.IsAnchoredAt(tip_id, 100, 1000));
    const auto parent_tx = MakeSpendTx(COutPoint(TxId(uint256S("22")), 0),
                                          1, 10000 * SATOSHI);
    const auto child_tx = MakeSpendTx(COutPoint(parent_tx->GetId(), 0),
                                         2, 9000 * SATOSHI);
    TestMemPoolEntryHelper entry;
    pool.addUnchecked(entry.Fee(500 * SATOSHI).FromTx(parent_tx));
    pool.addUnchecked(entry.Fee(600 * SATOSHI).FromTx(child_tx));
    pool.FlushPendingOverlayAdds();
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), 2U);
    int64_t total_fees = 0;
    for (const auto &[id, entry] : manager.GetSpeculativeOverlay().GetOrderedTxs()) {
        total_fees += entry.fee_sats;
    }
    BOOST_CHECK_EQUAL(total_fees, 1100);
    const auto frozen_root = pool.FreezeEpochBatch().GetSubtreeARoot();
    pool.removeRecursive(*child_tx, MemPoolRemovalReason::CONFLICT);
    pool.FlushPendingOverlayAdds();
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), 1U);
    BOOST_REQUIRE_EQUAL(manager.GetFrozenEpochs().size(), 1U);
    BOOST_CHECK(manager.GetFrozenEpochs().back().GetSubtreeARoot() == frozen_root);
    const BlockHash next_tip(uint256S("33"));
    pool.ConnectBlockReset(next_tip, 101, 1010);
    BOOST_CHECK(manager.GetFrozenEpochs().empty());
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), 1U);
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetHeight(), 101U);
    pool.clear();
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), 0U);
}

BOOST_AUTO_TEST_CASE(batched_inserts_match_serial_inserts_while_growing) {
    // Many small batches into a growing overlay must give exactly the state
    // of inserting the same transactions one at a time. Native V2 always
    // commits the UTXO root; this covers arena and map growth between batches.
    {
        FastRandomContext rng(/*fDeterministic=*/true);
        auto random_hash = [&] {
            lotus::v2::Hash h;
            const uint256 r = rng.rand256();
            std::copy(r.begin(), r.end(), h.begin());
            return h;
        };
        std::vector<lotus::v2::OverlayTxEntry> all;
        std::vector<lotus::v2::Outpoint> unspent_created;
        for (size_t i = 0; i < 3000; ++i) {
            lotus::v2::OverlayTxEntry e;
            e.tx_id = random_hash();
            e.tx_hash = random_hash();
            e.linear_cost = 200 + i % 50;
            e.fee_sats = 300 + int64_t(i % 7);
            e.sigchecks = 1 + int64_t(i % 3);
            if (!unspent_created.empty() && i % 2 == 0) {
                // Spend an output created by an earlier transaction, which
                // may sit in the same batch or in an earlier one.
                const size_t pick = rng.randrange(unspent_created.size());
                e.spent_outpoints.push_back(unspent_created[pick]);
                unspent_created.erase(unspent_created.begin() + pick);
            } else {
                e.spent_outpoints.push_back({random_hash(), 0});
            }
            for (uint32_t n = 0; n < 2; ++n) {
                lotus::v2::Coin coin;
                coin.outpoint = {e.tx_id, n};
                coin.output.value = 1000 + n;
                coin.creation_height = 200;
                e.created_coins.push_back(coin);
                unspent_created.push_back(coin.outpoint);
            }
            all.push_back(std::move(e));
        }

        const lotus::v2::Hash parent{};
        lotus::v2::MempoolOverlayLayer serial(
            parent, nullptr, lotus::v2::GetInitialV2MonetaryState(), 200,
            1700000100);
        lotus::v2::MempoolOverlayLayer batched(
            parent, nullptr, lotus::v2::GetInitialV2MonetaryState(), 200,
            1700000100);
        for (const auto &e : all) {
            BOOST_CHECK(serial.AddTransaction(
                e.tx_id, e.tx_hash, e.linear_cost, e.spent_outpoints,
                e.created_coins, e.fee_sats, e.sigchecks));
        }
        size_t pos = 0;
        while (pos < all.size()) {
            const size_t n = std::min<size_t>(all.size() - pos,
                                              17 + rng.randrange(64));
            std::vector<lotus::v2::OverlayTxEntry> batch(
                all.begin() + pos, all.begin() + pos + n);
            BOOST_CHECK_EQUAL(batched.AddTransactionBatch(batch), n);
            pos += n;
        }
        BOOST_CHECK_EQUAL(serial.GetTxCount(), batched.GetTxCount());
        BOOST_CHECK(serial.GetSubtreeARoot() == batched.GetSubtreeARoot());
        BOOST_CHECK(serial.GetUtxoRootDigest() ==
                    batched.GetUtxoRootDigest());
        // Native overlays retain these counters in each transaction entry,
        // rather than exposing the shared miner's cached aggregate accessors.
        int64_t expected_fees{0}, expected_sigchecks{0};
        int64_t serial_fees{0}, serial_sigchecks{0};
        int64_t batch_fees{0}, batch_sigchecks{0};
        for (const auto &entry : all) {
            expected_fees += entry.fee_sats;
            expected_sigchecks += entry.sigchecks;
        }
        BOOST_REQUIRE_EQUAL(serial.GetOrderedTxs().size(), all.size());
        BOOST_REQUIRE_EQUAL(batched.GetOrderedTxs().size(), all.size());
        for (const auto &[id, entry] : serial.GetOrderedTxs()) {
            const auto it = batched.GetOrderedTxs().find(id);
            BOOST_REQUIRE(it != batched.GetOrderedTxs().end());
            BOOST_CHECK_EQUAL(entry.fee_sats, it->second.fee_sats);
            BOOST_CHECK_EQUAL(entry.sigchecks, it->second.sigchecks);
            serial_fees += entry.fee_sats;
            serial_sigchecks += entry.sigchecks;
            batch_fees += it->second.fee_sats;
            batch_sigchecks += it->second.sigchecks;
        }
        BOOST_CHECK_EQUAL(serial_fees, expected_fees);
        BOOST_CHECK_EQUAL(batch_fees, expected_fees);
        BOOST_CHECK_EQUAL(serial_sigchecks, expected_sigchecks);
        BOOST_CHECK_EQUAL(batch_sigchecks, expected_sigchecks);
        BOOST_CHECK_EQUAL(serial.GetSumNonCbEffectiveCost(),
                          batched.GetSumNonCbEffectiveCost());
        BOOST_CHECK(serial.GetNetErasedOutpoints() ==
                    batched.GetNetErasedOutpoints());
        BOOST_CHECK_EQUAL(serial.GetNetInsertedCoins().size(),
                          batched.GetNetInsertedCoins().size());
    }
}


BOOST_AUTO_TEST_CASE(transaction_subtree_span_partition_matches_arena) {
    using namespace lotus::v2;
    std::mt19937 random(0x718391);
    for (const size_t count : {size_t{0}, size_t{1}, size_t{2}, size_t{63},
                              size_t{64}, size_t{65}, size_t{255}, size_t{256},
                              size_t{1000}}) {
        for (const bool common_prefix : {false, true}) {
            std::vector<TxIdentityPair> identities(count);
            TxOverlayArena arena;
            auto root = TxOverlayArena::kNullIdx;
            for (size_t i = 0; i < count; ++i) {
                auto &identity = identities[i];
                for (auto &byte : identity.tx_id) byte = uint8_t(random());
                for (auto &byte : identity.tx_hash) byte = uint8_t(random());
                // Cover long unary chains, including byte/bit ordering, without
                // relying on finding particular hashed transaction fixtures.
                if (common_prefix) {
                    std::fill_n(identity.tx_id.begin(), 20, uint8_t{0x96});
                    for (unsigned byte = 0; byte < 8; ++byte) {
                        identity.tx_id[24 + byte] = uint8_t(uint64_t(i) >> (8 * byte));
                    }
                }
                root = arena.InsertTxLeaf(root, identity.tx_id, identity.tx_hash);
            }
            const auto saved = identities;
            const auto expected = arena.SubtreeARoot(root);
            BOOST_CHECK(BuildTxSubtreeA(identities) == expected);
            TxIdentityPair coinbase{};
            coinbase.tx_id.fill(0xff);
            coinbase.tx_hash.fill(0x73);
            std::vector<TxIdentityPair> block{coinbase};
            block.insert(block.end(), identities.begin(), identities.end());
            lotus::v2::Hash block_root{};
            BOOST_CHECK(TransactionRoot(block, block_root));
            BOOST_CHECK(block_root == CombineCoinbaseAndSubtreeA(coinbase, expected));
            BOOST_CHECK(std::equal(identities.begin(), identities.end(), saved.begin(),
                [](const auto &a, const auto &b) {
                    return a.tx_id == b.tx_id && a.tx_hash == b.tx_hash;
                }));
            // Multiple calls borrow the same const identities while each owns
            // a different pointer array. Their internal partitions must never
            // race with one another or change the caller's order/data.
            if (count == 65 || count == 1000) {
                std::vector<std::future<lotus::v2::Hash>> readers;
                for (unsigned i = 0; i < 4; ++i) {
                    readers.push_back(std::async(std::launch::async, [&identities] {
                        return BuildTxSubtreeA(identities);
                    }));
                }
                for (auto &reader : readers) BOOST_CHECK(reader.get() == expected);
                BOOST_CHECK(std::equal(identities.begin(), identities.end(), saved.begin(),
                    [](const auto &a, const auto &b) {
                        return a.tx_id == b.tx_id && a.tx_hash == b.tx_hash;
                    }));
            }
            std::reverse(identities.begin(), identities.end());
            BOOST_CHECK(BuildTxSubtreeA(identities) == expected);
            if (!identities.empty()) {
                auto duplicate = identities;
                duplicate.push_back(identities.front());
                duplicate.back().tx_hash[0] ^= 1;
                BOOST_CHECK_THROW(BuildTxSubtreeA(duplicate), std::invalid_argument);
                lotus::v2::Hash unchanged{};
                unchanged.fill(0xa5);
                block.push_back(identities.front());
                BOOST_CHECK(!TransactionRoot(block, unchanged));
                BOOST_CHECK(unchanged[0] == 0xa5);
                // Duplicate rejection does not corrupt a later valid call.
                BOOST_CHECK(BuildTxSubtreeA(identities) == expected);
            }
        }
    }
    TxIdentityPair left{}, right{};
    right.tx_id[31] = 0x80; // Two keys split at the last canonical bit.
    right.tx_hash[0] = 1;
    TxOverlayArena arena;
    auto root = arena.InsertTxLeaf(TxOverlayArena::kNullIdx, left.tx_id, left.tx_hash);
    root = arena.InsertTxLeaf(root, right.tx_id, right.tx_hash);
    BOOST_CHECK(BuildTxSubtreeA(std::vector{left, right}) == arena.SubtreeARoot(root));
}

BOOST_AUTO_TEST_SUITE_END()
