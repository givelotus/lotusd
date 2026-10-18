// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <lotus_v2/commitment.h>
#include <stdexcept>
#include <lotus_v2/mempool_overlay.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <future>
#include <random>
#include <vector>

namespace {

CTransactionRef MakeTestCoinbaseTx(int height, Amount value) {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint();
    mtx.vin[0].scriptSig =
        CScript() << height << OP_0 << std::vector<uint8_t>(64, 0x42);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = value;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakeTestSpendTx(const COutPoint &prevout, uint32_t locktime,
                                Amount value_out, size_t num_outputs = 1) {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = locktime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].scriptSig =
        CScript() << std::vector<uint8_t>(64, uint8_t(locktime & 0xff));
    mtx.vout.resize(num_outputs);
    for (size_t i = 0; i < num_outputs; ++i) {
        mtx.vout[i].nValue = value_out / int64_t(num_outputs);
        mtx.vout[i].scriptPubKey =
            CScript() << OP_DUP << OP_HASH160
                      << std::vector<uint8_t>(20, uint8_t((locktime + i) & 0xff))
                      << OP_EQUALVERIFY << OP_CHECKSIG;
    }
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mempool_overlay_tests, TestingSetup)

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

BOOST_AUTO_TEST_CASE(stacked_cow_overlays_and_chained_lookup) {
    lotus::v2::MerklixOverlayManager mgr;
    lotus::v2::Hash parent_id{};
    parent_id.fill(0x11);
    mgr.ResetToTip(parent_id, nullptr, lotus::v2::GetInitialV2MonetaryState(),
                   100, 1700000000);

    // Layer 1 (Epoch 1): tx1 spends external UTXO, creates 2 outputs
    COutPoint ext1(TxId(uint256S("0101010101010101010101010101010101010101010101010101010101010101")), 0);
    const CTransactionRef tx1 = MakeTestSpendTx(ext1, 1, 10000 * SATOSHI, 2);
    BOOST_CHECK(AddTransactionToOverlay(mgr, tx1, 500, 1));
    const auto &l1 = mgr.FreezeEpochBatch();
    BOOST_CHECK_EQUAL(l1.GetTxCount(), 1U);
    BOOST_CHECK_EQUAL(l1.GetTotalFeesSats(), 500);
    BOOST_CHECK_EQUAL(l1.GetTotalSigChecks(), 1);
    BOOST_CHECK(!l1.HasDoubleSpends());

    // Layer 2 (Epoch 2): tx2 spends tx1:0 (intra-overlay spend)
    const CTransactionRef tx2 =
        MakeTestSpendTx(COutPoint(tx1->GetId(), 0), 2, 9000 * SATOSHI, 1);
    BOOST_CHECK(AddTransactionToOverlay(mgr, tx2, 600, 2));
    const auto &l2 = mgr.FreezeEpochBatch();
    BOOST_CHECK_EQUAL(l2.GetTxCount(), 2U);
    BOOST_CHECK_EQUAL(l2.GetTotalFeesSats(), 1100);
    BOOST_CHECK_EQUAL(l2.GetTotalSigChecks(), 3);

    // Layer 3 (Speculative): tx3 spends tx2:0
    const CTransactionRef tx3 =
        MakeTestSpendTx(COutPoint(tx2->GetId(), 0), 3, 8000 * SATOSHI, 1);
    BOOST_CHECK(AddTransactionToOverlay(mgr, tx3, 700, 1));
    const auto &l3 = mgr.GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(l3.GetTxCount(), 3U);
    BOOST_CHECK_EQUAL(l3.GetTotalFeesSats(), 1800);
    BOOST_CHECK_EQUAL(l3.GetTotalSigChecks(), 4);
    BOOST_CHECK_EQUAL(mgr.GetFrozenEpochs().size(), 2U);

    // Verify O(1) chained LookupCoinInStack (L3 -> L2 -> L1):
    // - tx1:0 is spent by tx2 in L2/L3
    // - tx1:1 is unspent across the stack
    // - tx2:0 is spent by tx3 in L3
    // - tx3:0 is unspent in L3
    lotus::v2::Outpoint op_tx1_0{}, op_tx1_1{}, op_tx2_0{}, op_tx3_0{};
    std::memcpy(op_tx1_0.tx_id.data(), tx1->GetId().begin(), 32);
    op_tx1_0.index = 0;
    op_tx1_1 = op_tx1_0;
    op_tx1_1.index = 1;
    std::memcpy(op_tx2_0.tx_id.data(), tx2->GetId().begin(), 32);
    op_tx2_0.index = 0;
    std::memcpy(op_tx3_0.tx_id.data(), tx3->GetId().begin(), 32);
    op_tx3_0.index = 0;

    bool spent = false;
    lotus::v2::Coin coin_out{};
    BOOST_CHECK(!mgr.LookupCoinInStack(op_tx1_0, &coin_out, spent));
    BOOST_CHECK(spent);

    BOOST_CHECK(mgr.LookupCoinInStack(op_tx1_1, &coin_out, spent));
    BOOST_CHECK(!spent);
    BOOST_CHECK_EQUAL(coin_out.output.value, 5000U);

    BOOST_CHECK(!mgr.LookupCoinInStack(op_tx2_0, &coin_out, spent));
    BOOST_CHECK(spent);

    BOOST_CHECK(mgr.LookupCoinInStack(op_tx3_0, &coin_out, spent));
    BOOST_CHECK(!spent);
    BOOST_CHECK_EQUAL(coin_out.output.value, 8000U);

    // Net erased outpoints should elide ephemeral intra-overlay coins (tx1:0, tx2:0)
    // and only report the base-chain outpoint ext1
    const auto net_erased = l3.GetNetErasedOutpoints();
    BOOST_CHECK_EQUAL(net_erased.size(), 1U);
    const auto net_inserted = l3.GetNetInsertedCoins();
    BOOST_CHECK_EQUAL(net_inserted.size(), 2U); // tx1:1 and tx3:0
}

BOOST_AUTO_TEST_CASE(positional_merkle_root_and_syndromes) {
    lotus::v2::MerklixOverlayManager mgr_a;
    lotus::v2::MerklixOverlayManager mgr_b;
    lotus::v2::Hash parent_id{};
    parent_id.fill(0x22);
    mgr_a.ResetToTip(parent_id, nullptr, lotus::v2::GetInitialV2MonetaryState(),
                     200, 1700000100);
    mgr_b.ResetToTip(parent_id, nullptr, lotus::v2::GetInitialV2MonetaryState(),
                     200, 1700000100);

    constexpr size_t kNumTxs = 64;
    std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> batch_a;
    std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> batch_b;
    for (size_t i = 0; i < kNumTxs; ++i) {
        COutPoint prev(TxId(m_rng.rand256()), uint32_t(i));
        auto ptx = MakeTestSpendTx(prev, uint32_t(10 + i),
                                   int64_t(2000 + i) * SATOSHI);
        batch_a.emplace_back(ptx, 100 + int64_t(i), 1);
        if (i < kNumTxs - 2) {
            batch_b.emplace_back(ptx, 100 + int64_t(i), 1);
        }
    }

    BOOST_CHECK_EQUAL(AddTransactionsToOverlayBatch(mgr_a, batch_a), kNumTxs);
    BOOST_CHECK_EQUAL(AddTransactionsToOverlayBatch(mgr_b, batch_b),
                      kNumTxs - 2);

    const auto &spec_a = mgr_a.GetSpeculativeOverlay();
    const auto &spec_b = mgr_b.GetSpeculativeOverlay();

    // 1. Verify GF(2^64) algebraic syndrome (s1, s3, s5) recovers the exact 2 missing txs
    const auto delta_syn =
        spec_a.GetSyndrome().SymmetricDifference(spec_b.GetSyndrome());
    const auto decoded = lotus::v2::DecodeBucketSyndrome(delta_syn);
    BOOST_CHECK(decoded.status == lotus::v2::ReconcileStatus::Decoded);
    BOOST_REQUIRE_EQUAL(decoded.roots.size(), 2U);

    const auto [k0, k1] = spec_a.GetSipHashKey();
    lotus::v2::Hash id_missing_1{}, id_missing_2{};
    std::memcpy(id_missing_1.data(),
                std::get<0>(batch_a[kNumTxs - 2])->GetId().begin(), 32);
    std::memcpy(id_missing_2.data(),
                std::get<0>(batch_a[kNumTxs - 1])->GetId().begin(), 32);
    uint64_t s_missing_1 = lotus::v2::ComputeShortTxId(k0, k1, id_missing_1);
    uint64_t s_missing_2 = lotus::v2::ComputeShortTxId(k0, k1, id_missing_2);
    if (s_missing_1 > s_missing_2) {
        std::swap(s_missing_1, s_missing_2);
    }
    BOOST_CHECK_EQUAL(decoded.roots[0], s_missing_1);
    BOOST_CHECK_EQUAL(decoded.roots[1], s_missing_2);

    // 2. Verify O(log N) positional Merkle root matches standard BlockMerkleRoot
    const CTransactionRef cb = MakeTestCoinbaseTx(200, 50 * COIN);
    CBlock block;
    block.vtx.push_back(cb);
    for (const auto &[_, oentry] : spec_a.GetOrderedTxs()) {
        block.vtx.push_back(
            std::static_pointer_cast<const CTransaction>(oentry.tx_ref));
    }
    const uint256 expected_merkle = BlockMerkleRoot(block);

    lotus::v2::Hash cb_txid{};
    std::memcpy(cb_txid.data(), cb->GetId().begin(), 32);
    const lotus::v2::Hash fast_merkle =
        spec_a.ComputePositionalMerkleRoot(cb_txid);
    uint256 fast_merkle_u256;
    std::memcpy(fast_merkle_u256.begin(), fast_merkle.data(), 32);
    BOOST_CHECK_EQUAL(fast_merkle_u256, expected_merkle);

    // Verify left-spine branch authenticates both null_merkle_root and hashMerkleRoot
    const auto &branch = spec_a.GetCoinbaseMerkleBranch();
    BOOST_CHECK_LE(branch.size(), 16U);
    BOOST_CHECK(lotus::v2::ComputeMerkleRootFromLeftSpine(lotus::v2::Hash{},
                                                          branch) ==
                spec_a.GetNullMerkleRoot());
    BOOST_CHECK(lotus::v2::ComputeMerkleRootFromLeftSpine(cb_txid, branch) ==
                fast_merkle);

    // 3. Verify lazy UtxoRoot digest matches eager CommitStateRootInHeader mode
    lotus::v2::MempoolOverlayLayer eager_layer(
        parent_id, nullptr, lotus::v2::GetInitialV2MonetaryState(), 200,
        1700000100);
    eager_layer.SetCommitStateRootInHeader(true);
    for (const auto &[ptx, fee, sigops] : batch_a) {
        BOOST_CHECK(AddTransactionToOverlay(eager_layer, ptx, fee, sigops));
    }
    BOOST_CHECK(spec_a.GetSubtreeARoot() == eager_layer.GetSubtreeARoot());
    BOOST_CHECK(spec_a.GetUtxoRootDigest() == eager_layer.GetUtxoRootDigest());
}

BOOST_AUTO_TEST_CASE(mempool_overlay_tracks_admission_removal_and_tip) {
    auto &pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const BlockHash tip(uint256S("11"));
    pool.ConnectBlockReset(tip, 100, 1000);
    auto &manager = pool.GetMerklixOverlay();
    lotus::v2::Hash tip_id{};
    std::copy(tip.begin(), tip.end(), tip_id.begin());
    BOOST_CHECK(manager.IsAnchoredAt(tip_id, 100, 1000));
    const auto parent_tx = MakeTestSpendTx(COutPoint(TxId(uint256S("22")), 0),
                                          1, 10000 * SATOSHI);
    const auto child_tx = MakeTestSpendTx(COutPoint(parent_tx->GetId(), 0),
                                         2, 9000 * SATOSHI);
    TestMemPoolEntryHelper entry;
    pool.addUnchecked(entry.Fee(500 * SATOSHI).FromTx(parent_tx));
    pool.addUnchecked(entry.Fee(600 * SATOSHI).FromTx(child_tx));
    // Refresh through the public read API; the retained manager reference
    // does not materialize writes deferred by the mempool.
    pool.GetMerklixOverlay();
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTxCount(), 2U);
    BOOST_CHECK_EQUAL(manager.GetSpeculativeOverlay().GetTotalFeesSats(), 1100);
    const auto frozen_root = pool.FreezeEpochBatch().GetSubtreeARoot();
    pool.removeRecursive(*child_tx, MemPoolRemovalReason::CONFLICT);
    pool.GetMerklixOverlay();
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
    // of inserting the same transactions one at a time, in both UTXO-root
    // modes. This covers the arena and map growth between batches.
    for (const bool commit_state_root : {false, true}) {
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
        serial.SetCommitStateRootInHeader(commit_state_root);
        batched.SetCommitStateRootInHeader(commit_state_root);
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
        BOOST_CHECK_EQUAL(serial.GetTotalFeesSats(),
                          batched.GetTotalFeesSats());
        BOOST_CHECK_EQUAL(serial.GetTotalSigChecks(),
                          batched.GetTotalSigChecks());
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
