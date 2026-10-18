// Copyright (c) 2026 The Lotus developers
#include <primitives/block.h>
#include <lotus_v2/candidate_state_key.h>
#include <lotus_v2/mempool_overlay.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <stdexcept>
#include <type_traits>
#include <future>
#include <thread>
#include <fstream>
#include <filesystem>
#include <chrono>
#ifndef WIN32
#include <sys/stat.h>
#endif

template <typename Import> bool AttemptStateImport(Import &&import) {
    if constexpr (std::is_void_v<decltype(import())>) {
        import();
        return true;
    } else {
        return import();
    }
}

BOOST_FIXTURE_TEST_SUITE(v2_candidate_state_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(key_binds_bytes_ignored_by_old_fingerprint) {
    std::array<uint8_t, 32> parent{}, id{}, hash{};
    auto key = [&](const auto &p, const auto &i, const auto &h) {
        lotus::v2::CandidateStateHasher hasher(p);
        hasher.Add(i, h);
        return hasher.Finalize();
    };
    const auto original = key(parent, id, hash);
    // Each old fingerprint read only bytes0..7. These pairs collide exactly
    // under that mixer while differing in an authenticated identity byte.
    id[31] = 1;
    BOOST_CHECK(original != key(parent, id, hash));
    id[31] = 0;
    hash[31] = 1;
    BOOST_CHECK(original != key(parent, id, hash));
    hash[31] = 0;
    parent[31] = 1;
    BOOST_CHECK(original != key(parent, id, hash));
}
BOOST_AUTO_TEST_CASE(reject_mismatched_header_before_recording_candidate) {
    CBlock block;
    block.nBits = 0x207fffff;
    const auto correct = ComputeV2BlockStateRoot(block, BlockHash{}, 1, 0, false);
    block.hashStateRoot = correct;
    BOOST_CHECK_NO_THROW(RecordV2BlockState(block, block.GetHash(), BlockHash{}, 1, 0));
    block.hashStateRoot.begin()[0] ^= 1;
    // Warm candidate cache is hit in both calls. A hit still cannot authenticate
    // a header whose declared state root disagrees with the computed state.
    BOOST_CHECK_THROW(RecordV2BlockState(block, block.GetHash(), BlockHash{}, 1, 0),
                      std::invalid_argument);
    BOOST_CHECK(ComputeV2BlockStateRoot(block, BlockHash{}, 1, 0, true) == correct);
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_CHECK(!GetV2BlockStateSnapshot(block.GetHash(), root, monetary));
    BOOST_CHECK(ComputeV2BlockStateRoot(block, BlockHash{}, 1, 0, false) == correct);
}
BOOST_AUTO_TEST_CASE(accepted_zero_root_state_uses_actual_header_hash) {
    CBlock block;
    block.nBits = 0x207fffff;
    block.nNonce = 0x1003;
    const auto expected = ComputeV2BlockStateRoot(block, BlockHash{}, 1, 0, false);
    const auto actual_hash = block.GetHash();
    CBlock synthetic = block;
    synthetic.hashStateRoot = expected;
    BOOST_REQUIRE(actual_hash != synthetic.GetHash());
    BOOST_CHECK_THROW(RecordV2BlockState(block, actual_hash, BlockHash{}, 1, 0), std::invalid_argument);
    BOOST_CHECK_NO_THROW(RecordV2BlockState(block, actual_hash, BlockHash{}, 1, 0, true));
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_CHECK(GetV2BlockStateSnapshot(actual_hash, root, monetary));
    BOOST_CHECK(!GetV2BlockStateSnapshot(synthetic.GetHash(), root, monetary));
    block.hashStateRoot = expected;
    block.hashStateRoot.begin()[0] ^= 1;
    BOOST_CHECK_THROW(RecordV2BlockState(block, block.GetHash(), BlockHash{}, 1, 0, true), std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(overlay_mismatch_does_not_publish_state_or_supply) {
    SetV2StatePersistDir("");
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout = COutPoint();
    cb.vin[0].nFlags = 2;
    cb.vout.emplace_back(100 * SATOSHI, CScript() << OP_TRUE);
    const CTransaction coinbase{std::move(cb)};
    lotus::v2::MempoolOverlayLayer overlay;
    const auto expected = ComputeV2StateRootFromOverlay(coinbase, overlay, 0x207fffff, 1, 0);
    uint256 wrong = expected;
    wrong.begin()[0] ^= 1;
    const BlockHash hash{uint256::ONE};
    SetV2BlockCirculatingSupplyForTest(BlockHash{}, 777);
    BOOST_CHECK(ComputeV2StateRootFromOverlay(coinbase, overlay, 0x207fffff, 1, 0,
                                             true, &hash, &wrong) == expected);
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_CHECK(!GetV2BlockStateSnapshot(hash, root, monetary));
    BOOST_CHECK_EQUAL(GetV2BlockCirculatingSupply(BlockHash{}), 777);
    BOOST_CHECK(ComputeV2StateRootFromOverlay(coinbase, overlay, 0x207fffff, 1, 0,
                                             true, &hash, &expected) == expected);
    BOOST_CHECK(GetV2BlockStateSnapshot(hash, root, monetary));
}
BOOST_AUTO_TEST_CASE(child_of_reloaded_parent_is_persisted_on_eviction) {
    const auto dir = std::filesystem::temp_directory_path() /
        ("lotus-reloaded-parent-child-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    SetV2StatePersistDir(dir.string());
    CBlock parent;
    parent.nBits = 0x207fffff;
    parent.nHeight = 1;
    parent.nNonce = 0x5501;
    parent.hashStateRoot = ComputeV2BlockStateRoot(parent, BlockHash{}, 1, 0, false);
    const auto parent_hash = parent.GetHash();
    RecordV2BlockState(parent, parent_hash, BlockHash{}, 1, 0);
    BOOST_REQUIRE(FlushV2BlockStatesToDisk());
    SetV2StatePersistDir("");
    SetV2StatePersistDir(dir.string());
    std::shared_ptr<const lotus::v2::SmtNode> loaded;
    lotus::v2::MonetaryState monetary;
    BOOST_REQUIRE(GetV2BlockStateSnapshot(parent_hash, loaded, monetary));
    // Drop this read-back cache entry without deleting its complete file, so
    // deriving the new child has to load the already-persisted parent itself.
    SetV2StatePersistDir("");
    SetV2StatePersistDir(dir.string());
    CBlock child;
    child.nBits = 0x207fffff;
    child.nHeight = 2;
    child.nNonce = 0x5502;
    child.hashPrevBlock = parent_hash;
    child.hashStateRoot = ComputeV2BlockStateRoot(child, parent_hash, 2, 0, false);
    const auto child_hash = child.GetHash();
    RecordV2BlockState(child, child_hash, parent_hash, 2, 0);
    // Exceed the existing64-entry disk-backed cache without revisiting child.
    for (uint64_t i = 0; i < 65; ++i) {
        CBlock other;
        other.nBits = 0x207fffff;
        other.nHeight = 1;
        other.nNonce = 0x5600 + i;
        other.hashStateRoot = ComputeV2BlockStateRoot(other, BlockHash{}, 1, 0, false);
        RecordV2BlockState(other, other.GetHash(), BlockHash{}, 1, 0);
    }
    const auto child_file = dir / (child_hash.GetHex() + ".bin");
    const bool persisted = std::filesystem::is_regular_file(child_file);
    BOOST_CHECK_MESSAGE(persisted, "Missing newly derived child file: " << child_file.string());
    BOOST_CHECK(GetV2BlockStateSnapshot(child_hash, loaded, monetary));
    if (persisted) {
        const auto digest = lotus::v2::StateRoot(GetActiveV2ChainId(), 2,
                                                lotus::v2::SmtRoot(loaded), monetary);
        uint256 restored;
        std::copy_n(digest.begin(), 32, restored.begin());
        BOOST_CHECK(restored == child.hashStateRoot);
    }
    SetV2StatePersistDir("");
    if (persisted) std::filesystem::remove_all(dir);
}
BOOST_AUTO_TEST_CASE(failed_import_is_not_published_and_can_retry) {
    const auto dir = std::filesystem::temp_directory_path() /
        ("lotus-import-failure-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    { std::ofstream obstruction(dir); obstruction << "not a directory"; }
    SetV2StatePersistDir(dir.string());
    const BlockHash hash{uint256::ONE};
    SetV2BlockCirculatingSupplyForTest(BlockHash{}, 777);
    lotus::v2::MonetaryState monetary;
    std::shared_ptr<const lotus::v2::SmtNode> root;
    BOOST_REQUIRE(GetV2BlockStateSnapshot(BlockHash{}, root, monetary));
    BOOST_CHECK(!AttemptStateImport([&] { return ImportV2BlockStateCoinsAndMonetary(hash, {}, monetary, true); }));
    BOOST_CHECK(!GetV2BlockStateSnapshot(hash, root, monetary));
    BOOST_CHECK_EQUAL(GetV2BlockCirculatingSupply(BlockHash{}), 777);
    std::filesystem::remove(dir);
    std::filesystem::create_directory(dir);
    BOOST_REQUIRE(AttemptStateImport([&] { return ImportV2BlockStateCoinsAndMonetary(hash, {}, monetary, true); }));
    BOOST_CHECK(std::filesystem::exists(dir / (hash.GetHex() + ".bin")));
    SetV2StatePersistDir("");
    SetV2StatePersistDir(dir.string());
    BOOST_CHECK(GetV2BlockStateSnapshot(hash, root, monetary));
    SetV2StatePersistDir("");
    std::filesystem::remove_all(dir);
}
BOOST_AUTO_TEST_CASE(state_flush_reports_write_failure_and_retries) {
    const auto dir = std::filesystem::temp_directory_path() /
        ("lotus-flush-failure-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    { std::ofstream obstruction(dir); obstruction << "not a directory"; }
    SetV2StatePersistDir(dir.string());
    const BlockHash hash{uint256::ONE};
    SetV2BlockCirculatingSupplyForTest(hash, 42);
    BOOST_CHECK(!AttemptStateImport([] { return FlushV2BlockStatesToDisk(); }));
    BOOST_CHECK_EQUAL(GetV2BlockCirculatingSupply(hash), 42);
    std::filesystem::remove(dir);
    std::filesystem::create_directory(dir);
    BOOST_REQUIRE(AttemptStateImport([] { return FlushV2BlockStatesToDisk(); }));
    BOOST_CHECK(std::filesystem::exists(dir / (hash.GetHex() + ".bin")));
    SetV2StatePersistDir("");
    SetV2StatePersistDir(dir.string());
    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_CHECK(GetV2BlockStateSnapshot(hash, root, monetary));
    SetV2StatePersistDir("");
    std::filesystem::remove_all(dir);
}
BOOST_AUTO_TEST_CASE(repeated_failed_eviction_keeps_cache_bounded_and_supply_atomic) {
    const auto path = std::filesystem::temp_directory_path() /
        ("lotus-eviction-failure-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    { std::ofstream obstruction(path); obstruction << "not a directory"; }
    SetV2StatePersistDir(path.string());
    auto hash = [](unsigned n) { uint256 value; value.begin()[0] = n; value.begin()[1] = n >> 8; return BlockHash{value}; };
    for (unsigned n = 1; n <= 64; ++n) SetV2BlockCirculatingSupplyForTest(hash(n), n);
    for (unsigned n = 65; n <= 164; ++n) {
        BOOST_CHECK_THROW(SetV2BlockCirculatingSupplyForTest(hash(n), n), std::runtime_error);
        BOOST_CHECK_EQUAL(GetV2BlockCirculatingSupply(BlockHash{}), 64);
        std::shared_ptr<const lotus::v2::SmtNode> root;
        lotus::v2::MonetaryState monetary;
        BOOST_CHECK(!GetV2BlockStateSnapshot(hash(n), root, monetary));
    }
    for (unsigned n = 1; n <= 64; ++n)
        BOOST_CHECK_EQUAL(GetV2BlockCirculatingSupply(hash(n)), n);
    // Retrying after restoring writable storage can evict/persist the old entry.
    std::filesystem::remove(path);
    std::filesystem::create_directory(path);
    BOOST_CHECK_NO_THROW(SetV2BlockCirculatingSupplyForTest(hash(65), 65));
    BOOST_CHECK(std::filesystem::exists(path / (hash(1).GetHex() + ".bin")));
    SetV2StatePersistDir("");
    std::filesystem::remove_all(path);
}
#ifndef WIN32
BOOST_AUTO_TEST_CASE(snapshot_disk_read_does_not_hold_cache_mutex) {
    const auto dir = std::filesystem::temp_directory_path() /
        ("lotus-candidate-io-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(dir);
    const BlockHash hash{uint256::ONE};
    const auto path = dir / (hash.GetHex() + ".bin");
    BOOST_REQUIRE_EQUAL(mkfifo(path.c_str(), 0600), 0);
    SetV2StatePersistDir(dir.string());
    auto disk_read = std::async(std::launch::async, [&] {
        std::shared_ptr<const lotus::v2::SmtNode> root;
        lotus::v2::MonetaryState monetary;
        return GetV2BlockStateSnapshot(hash, root, monetary);
    });
    // FIFO open handshakes with the reader, which then blocks for bytes.
    std::ofstream release(path, std::ios::binary);
    auto cache_read = std::async(std::launch::async, [] {
        return GetV2BlockCirculatingSupply(BlockHash{});
    });
    const bool cache_available = cache_read.wait_for(std::chrono::milliseconds(100)) ==
        std::future_status::ready;
    // Release the blocked reader in both versions, so a failed assertion does
    // not leave a thread/fifo behind or turn a causal failure into a timeout.
    release.close();
    BOOST_CHECK(!disk_read.get());
    cache_read.get();
    BOOST_CHECK(cache_available);
    SetV2StatePersistDir("");
    std::filesystem::remove_all(dir);
}
#endif
BOOST_AUTO_TEST_SUITE_END()
