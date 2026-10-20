// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The native Chronik ABC host reads txs of complete blk/rev files through
// its descriptor cache (chronik/native/hosts/common/flat_file_reader.h),
// keeps BlockManager's path for the file the node writes to, and drops
// pruned files before the node deletes them.

#include <hosts/abc/abc_host.h>

#include <chronik/native/host.h>
#include <chronik/native/types.h>

#include <node/blockstorage.h>
#include <streams.h>
#include <script/script.h>
#include <script/standard.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstring>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace cn = chronik::native;
using cn::abc::AbcHost;

namespace {

cn::Hash32 ToHash(const uint256 &h) {
    cn::Hash32 out;
    std::memcpy(out.b.data(), h.begin(), 32);
    return out;
}

void CheckSameTx(const cn::Tx &left, const cn::Tx &right) {
    BOOST_CHECK_EQUAL(HexStr(left.txid.b), HexStr(right.txid.b));
    BOOST_CHECK_EQUAL(left.version, right.version);
    BOOST_CHECK_EQUAL(left.locktime, right.locktime);
    BOOST_CHECK(left.inputs == right.inputs);
    BOOST_CHECK(left.outputs == right.outputs);
    BOOST_CHECK_EQUAL(HexStr(left.raw), HexStr(right.raw));
    BOOST_CHECK_EQUAL(left.wire_size, right.wire_size);
}

struct BlockReaderSetup : public TestChain100Setup {
    CScript anyone_script = CScript() << OP_1;
    CScript anyone_p2sh = GetScriptForDestination(ScriptHash(anyone_script));
    /** Block in blk00000.dat with a coinbase and a tx with undo data. */
    CBlock spend_block;
    /** Block in blk00001.dat, the file the node writes to. */
    CBlock tip_block;

    BlockReaderSetup() {
        ChainstateManager &chainman = *Assert(m_node.chainman);
        const CBlock coins_block = CreateAndProcessBlock({}, anyone_p2sh);
        mineBlocks(100);
        const CTransactionRef coin_tx = coins_block.vtx[0];
        CMutableTransaction tx;
        tx.vin = {CTxIn(coin_tx->GetId(), 0,
                        CScript() << std::vector(anyone_script.begin(),
                                                 anyone_script.end()))};
        tx.vout = {
            CTxOut(1000 * SATOSHI, anyone_p2sh),
            CTxOut(coin_tx->vout[0].nValue - 10000 * SATOSHI, anyone_p2sh),
        };
        spend_block = CreateAndProcessBlock({tx}, anyone_p2sh);
        BOOST_REQUIRE_EQUAL(spend_block.vtx.size(), 2U);
        // Fill blk00000.dat so the next block starts blk00001.dat.
        WITH_LOCK(chainman.GetMutex(),
                  chainman.m_blockman.GetBlockFileInfo(0)->nSize =
                      node::MAX_BLOCKFILE_SIZE);
        tip_block = CreateAndProcessBlock({}, anyone_p2sh);
        BOOST_REQUIRE_EQUAL(FileOf(spend_block), 0);
        BOOST_REQUIRE_EQUAL(FileOf(tip_block), 1);
    }

    int FileOf(const CBlock &block) {
        LOCK(::cs_main);
        return Assert(m_node.chainman->m_blockman.LookupBlockIndex(
                          block.GetHash()))
            ->nFile;
    }

    /** Serialized txs of a block as stored on disk. */
    std::vector<std::string> StoredRawTxs(const CBlock &block) {
        CBlock stored;
        const CBlockIndex *index = WITH_LOCK(
            ::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(
                           block.GetHash()));
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlock(stored, *index));
        std::vector<std::string> out;
        for (const CTransactionRef &tx : stored.vtx) {
            DataStream ss{};
            ss << *tx;
            out.push_back(HexStr(MakeUCharSpan(ss)));
        }
        return out;
    }

    cn::Block Converted(const AbcHost &host, const CBlock &block) {
        std::optional<cn::BlockInfo> info =
            host.LookupBlock(ToHash(block.GetHash()));
        BOOST_REQUIRE(info);
        // LoadBlock reads the whole block through BlockManager.
        return host.LoadBlock(*info);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(chronik_native_blockreader_tests, BlockReaderSetup)

BOOST_AUTO_TEST_CASE(may_append_to_block_file) {
    node::BlockManager &blockman = m_node.chainman->m_blockman;
    BOOST_CHECK(!blockman.MayAppendToBlockFile(0));
    BOOST_CHECK(blockman.MayAppendToBlockFile(1)); // the cursor's file
    BOOST_CHECK(blockman.MayAppendToBlockFile(2)); // not created yet
    BOOST_CHECK(blockman.GetUndoPosFilename(FlatFilePos(0, 0)) !=
                blockman.GetBlockPosFilename(FlatFilePos(0, 0)));
    BOOST_CHECK(fs::exists(blockman.GetUndoPosFilename(FlatFilePos(0, 0))));
}

BOOST_AUTO_TEST_CASE(complete_file_reads_are_cached) {
    const AbcHost host(m_node, cn::HostCapabilities{});
    const cn::Block block = Converted(host, spend_block);
    BOOST_REQUIRE_EQUAL(block.info.file_num, 0U);
    BOOST_REQUIRE_EQUAL(block.txs.size(), 2U);
    BOOST_REQUIRE_NE(block.txs[1].undo_pos, 0U);
    const std::vector<std::string> stored = StoredRawTxs(spend_block);
    for (int round = 0; round < 3; ++round) {
        for (size_t i = 0; i < block.txs.size(); ++i) {
            const cn::BlockTx &btx = block.txs[i];
            CheckSameTx(host.LoadTx(block.info.file_num, btx.data_pos,
                                    btx.undo_pos),
                        *btx.tx);
            const cn::Bytes raw =
                host.LoadRawTx(block.info.file_num, btx.data_pos);
            BOOST_CHECK_EQUAL(HexStr(raw), stored[i]);
        }
    }
    const cn::hosts::FlatFileCacheStats stats = host.FileCacheStats();
    // blk00000.dat and rev00000.dat, opened once each.
    BOOST_CHECK_EQUAL(stats.misses, 2U);
    BOOST_CHECK_EQUAL(stats.open_files, 2U);
    // 3 rounds x (2 LoadTx blk + 1 LoadTx rev + 2 LoadRawTx) - 2 misses.
    BOOST_CHECK_EQUAL(stats.hits, 3U * 5U - 2U);
    BOOST_CHECK_EQUAL(stats.bypasses, 0U);
}

BOOST_AUTO_TEST_CASE(write_file_keeps_blockmanager_path) {
    const AbcHost host(m_node, cn::HostCapabilities{});
    const cn::Block block = Converted(host, tip_block);
    BOOST_REQUIRE_EQUAL(block.info.file_num, 1U);
    for (int round = 0; round < 2; ++round) {
        CheckSameTx(host.LoadTx(1, block.txs[0].data_pos, 0), *block.txs[0].tx);
        BOOST_CHECK_EQUAL(HexStr(host.LoadRawTx(1, block.txs[0].data_pos)),
                          StoredRawTxs(tip_block)[0]);
    }
    const cn::hosts::FlatFileCacheStats stats = host.FileCacheStats();
    BOOST_CHECK_EQUAL(stats.bypasses, 4U);
    BOOST_CHECK_EQUAL(stats.open_files, 0U);
    BOOST_CHECK_EQUAL(stats.misses, 0U);
    // Errors keep their message from the uncached path.
    BOOST_CHECK_EXCEPTION(host.LoadTx(1, 0x7ffffff0, 0), std::runtime_error,
                          [](const std::runtime_error &e) {
                              return std::string(e.what()) ==
                                     "Reading tx data from disk failed";
                          });
}

BOOST_AUTO_TEST_CASE(prune_invalidates_cached_files) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    node::BlockManager &blockman = chainman.m_blockman;
    std::optional<AbcHost> host;
    host.emplace(m_node, cn::HostCapabilities{});
    const cn::Block block = Converted(*host, spend_block);
    const cn::BlockTx &btx = block.txs[1];
    CheckSameTx(host->LoadTx(0, btx.data_pos, btx.undo_pos), *btx.tx);
    BOOST_CHECK_EQUAL(host->FileCacheStats().open_files, 2U);

    // Prune blk00000.dat/rev00000.dat, as FlushStateToDisk does.
    {
        LOCK(::cs_main);
        blockman.PruneOneBlockFile(0);
    }
    blockman.UnlinkPrunedFiles({0});
    BOOST_CHECK(!fs::exists(blockman.GetBlockPosFilename(FlatFilePos(0, 0))));
    cn::hosts::FlatFileCacheStats stats = host->FileCacheStats();
    BOOST_CHECK_EQUAL(stats.invalidations, 2U);
    BOOST_CHECK_EQUAL(stats.open_files, 0U);

    // The pruned tx is gone, not served from a stale descriptor.
    BOOST_CHECK_THROW(host->LoadTx(0, btx.data_pos, btx.undo_pos),
                      std::runtime_error);
    BOOST_CHECK_THROW(host->LoadRawTx(0, btx.data_pos), std::runtime_error);
    BOOST_CHECK_EQUAL(host->FileCacheStats().open_files, 0U);

    // A destroyed host is unregistered: later prunes don't reach it.
    host.reset();
    blockman.UnlinkPrunedFiles({0});
}

BOOST_AUTO_TEST_CASE(concurrent_loads) {
    // The query pool calls LoadTx from several threads at once.
    const AbcHost host(m_node, cn::HostCapabilities{});
    const cn::Block spend = Converted(host, spend_block);
    const cn::Block tip = Converted(host, tip_block);
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 200; ++i) {
                for (const cn::Block *b : {&spend, &tip}) {
                    for (const cn::BlockTx &btx : b->txs) {
                        const cn::Tx tx = host.LoadTx(
                            b->info.file_num, btx.data_pos, btx.undo_pos);
                        if (tx.raw != btx.tx->raw ||
                            tx.inputs != btx.tx->inputs) {
                            ++failures;
                        }
                    }
                }
            }
        });
    }
    for (std::thread &t : threads) {
        t.join();
    }
    BOOST_CHECK_EQUAL(failures.load(), 0);
    const cn::hosts::FlatFileCacheStats stats = host.FileCacheStats();
    BOOST_CHECK_EQUAL(stats.open_files, 2U);
    // 8 threads x 200 x (spend: 2 blk + 1 rev).
    BOOST_CHECK_EQUAL(stats.hits + stats.misses, 8U * 200U * 3U);
    BOOST_CHECK_EQUAL(stats.bypasses, 8U * 200U);
}

BOOST_AUTO_TEST_SUITE_END()
