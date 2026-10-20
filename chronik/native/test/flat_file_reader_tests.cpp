// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hosts/common/flat_file_reader.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace chronik::native::hosts;

namespace {

namespace fs = std::filesystem;

/** A temp dir with numbered blk/rev files of known contents. */
struct FlatFiles {
    fs::path dir;
    std::set<uint32_t> appendable;
    std::atomic<int> may_append_calls{0};

    FlatFiles() {
        std::random_device rd;
        dir = fs::temp_directory_path() /
              ("chronik-flatfile-test-" + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~FlatFiles() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    std::string Path(FlatFileKind kind, uint32_t n) const {
        char name[32];
        std::snprintf(name, sizeof(name), "%s%05u.dat",
                      kind == FlatFileKind::BLOCK ? "blk" : "rev", n);
        return (dir / name).string();
    }

    /** Byte i of file (kind, n). */
    static uint8_t Byte(FlatFileKind kind, uint32_t n, size_t i) {
        return uint8_t(i * 7 + n * 31 + (kind == FlatFileKind::UNDO ? 101 : 0));
    }

    void Write(FlatFileKind kind, uint32_t n, size_t size) const {
        std::ofstream f(Path(kind, n), std::ios::binary | std::ios::trunc);
        for (size_t i = 0; i < size; ++i) {
            f.put(char(Byte(kind, n, i)));
        }
    }

    FlatFileReadCache::Hooks Hooks() {
        return {
            .file_path = [this](FlatFileKind k,
                                uint32_t n) { return Path(k, n); },
            .may_append =
                [this](FlatFileKind, uint32_t n) {
                    ++may_append_calls;
                    return appendable.count(n) > 0;
                },
        };
    }
};

std::vector<uint8_t> ReadVia(const std::shared_ptr<const CachedFlatFile> &f,
                             uint64_t pos, size_t len, size_t chunk) {
    FlatFileCursor cursor(f, pos, chunk);
    std::vector<uint8_t> out(len);
    // Read in uneven pieces, like a deserializer does.
    size_t done = 0;
    size_t piece = 1;
    while (done < len) {
        const size_t n = std::min(piece, len - done);
        cursor.Read(std::span(out.data() + done, n));
        done += n;
        piece = piece * 3 % 97 + 1;
    }
    BOOST_CHECK_EQUAL(cursor.Pos(), pos + len);
    return out;
}

void CheckBytes(const std::vector<uint8_t> &got, FlatFileKind kind,
                uint32_t n, uint64_t pos) {
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != FlatFiles::Byte(kind, n, pos + i)) {
            BOOST_ERROR("byte " << pos + i << " of file " << n << " differs");
            return;
        }
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE(flat_file_reader_tests)

BOOST_AUTO_TEST_CASE(hits_and_reads) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    FlatFiles files;
    files.Write(FlatFileKind::BLOCK, 0, 20000);
    files.Write(FlatFileKind::UNDO, 0, 5000);
    FlatFileReadCache cache(files.Hooks(), 4);

    auto blk = cache.Acquire(FlatFileKind::BLOCK, 0);
    BOOST_REQUIRE(blk);
    auto rev = cache.Acquire(FlatFileKind::UNDO, 0);
    BOOST_REQUIRE(rev);
    BOOST_CHECK(blk != rev);
    BOOST_CHECK_EQUAL(files.may_append_calls.load(), 2);
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK(cache.Acquire(FlatFileKind::BLOCK, 0) == blk);
        BOOST_CHECK(cache.Acquire(FlatFileKind::UNDO, 0) == rev);
    }
    // Hits don't ask the node again.
    BOOST_CHECK_EQUAL(files.may_append_calls.load(), 2);
    FlatFileCacheStats stats = cache.Stats();
    BOOST_CHECK_EQUAL(stats.misses, 2U);
    BOOST_CHECK_EQUAL(stats.hits, 20U);
    BOOST_CHECK_EQUAL(stats.open_files, 2U);

    // Reads across chunk boundaries, for several chunk sizes.
    for (size_t chunk : {1, 7, 4096, 100000}) {
        CheckBytes(ReadVia(blk, 0, 20000, chunk), FlatFileKind::BLOCK, 0, 0);
        CheckBytes(ReadVia(blk, 12345, 3000, chunk), FlatFileKind::BLOCK, 0,
                   12345);
        CheckBytes(ReadVia(rev, 4000, 1000, chunk), FlatFileKind::UNDO, 0,
                   4000);
    }

    // Skip within and past the buffer.
    FlatFileCursor cursor(blk, 100, 64);
    uint8_t b;
    cursor.Read(std::span(&b, 1));
    BOOST_CHECK_EQUAL(b, FlatFiles::Byte(FlatFileKind::BLOCK, 0, 100));
    cursor.Skip(10);
    cursor.Read(std::span(&b, 1));
    BOOST_CHECK_EQUAL(b, FlatFiles::Byte(FlatFileKind::BLOCK, 0, 111));
    cursor.Skip(1000);
    cursor.Read(std::span(&b, 1));
    BOOST_CHECK_EQUAL(b, FlatFiles::Byte(FlatFileKind::BLOCK, 0, 1112));
    BOOST_CHECK_EQUAL(cursor.Pos(), 1113U);

    // Reading past the end of the file throws, like AutoFile.
    FlatFileCursor end(blk, 19990, 4096);
    std::vector<uint8_t> buf(11);
    BOOST_CHECK_THROW(end.Read(buf), std::ios_base::failure);
    FlatFileCursor ok(blk, 19990, 4096);
    buf.resize(10);
    ok.Read(buf);
    CheckBytes(buf, FlatFileKind::BLOCK, 0, 19990);
    FlatFileCursor past(blk, 30000, 4096);
    BOOST_CHECK_THROW(past.Read(std::span(&b, 1)), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(write_file_bypass) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    FlatFiles files;
    files.Write(FlatFileKind::BLOCK, 0, 100);
    files.Write(FlatFileKind::BLOCK, 1, 100);
    files.Write(FlatFileKind::UNDO, 1, 100);
    files.appendable = {1};
    FlatFileReadCache cache(files.Hooks(), 4);

    // The write file is never cached: the host keeps its own path.
    for (int i = 0; i < 3; ++i) {
        BOOST_CHECK(!cache.Acquire(FlatFileKind::BLOCK, 1));
        BOOST_CHECK(!cache.Acquire(FlatFileKind::UNDO, 1));
    }
    BOOST_CHECK(cache.Acquire(FlatFileKind::BLOCK, 0));
    FlatFileCacheStats stats = cache.Stats();
    BOOST_CHECK_EQUAL(stats.bypasses, 6U);
    BOOST_CHECK_EQUAL(stats.open_files, 1U);
    // Every bypass asks again: the answer changes once the node moves on.
    BOOST_CHECK_EQUAL(files.may_append_calls.load(), 7);

    // The node moved on to file 2: file 1 is now cacheable.
    files.appendable = {2};
    BOOST_CHECK(cache.Acquire(FlatFileKind::BLOCK, 1));
    BOOST_CHECK(cache.Acquire(FlatFileKind::UNDO, 1));
    BOOST_CHECK_EQUAL(cache.Stats().open_files, 3U);

    // A file that doesn't exist (yet) isn't cached either.
    BOOST_CHECK(!cache.Acquire(FlatFileKind::BLOCK, 7));
    BOOST_CHECK_EQUAL(cache.Stats().open_failures, 1U);
}

BOOST_AUTO_TEST_CASE(lru_eviction) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    FlatFiles files;
    for (uint32_t n = 0; n < 5; ++n) {
        files.Write(FlatFileKind::BLOCK, n, 50);
    }
    FlatFileReadCache cache(files.Hooks(), 3);
    auto f0 = cache.Acquire(FlatFileKind::BLOCK, 0);
    cache.Acquire(FlatFileKind::BLOCK, 1);
    cache.Acquire(FlatFileKind::BLOCK, 2);
    cache.Acquire(FlatFileKind::BLOCK, 0); // 0 is now the most recent
    cache.Acquire(FlatFileKind::BLOCK, 3); // evicts 1
    FlatFileCacheStats stats = cache.Stats();
    BOOST_CHECK_EQUAL(stats.evictions, 1U);
    BOOST_CHECK_EQUAL(stats.open_files, 3U);
    BOOST_CHECK(cache.Acquire(FlatFileKind::BLOCK, 0) == f0);
    const uint64_t misses = cache.Stats().misses;
    cache.Acquire(FlatFileKind::BLOCK, 1); // miss again
    BOOST_CHECK_EQUAL(cache.Stats().misses, misses + 1);

    // An evicted descriptor stays usable by the reader that holds it.
    FlatFileReadCache tiny(files.Hooks(), 1);
    auto held = tiny.Acquire(FlatFileKind::BLOCK, 4);
    tiny.Acquire(FlatFileKind::BLOCK, 3);
    BOOST_CHECK_EQUAL(tiny.Stats().evictions, 1U);
    CheckBytes(ReadVia(held, 0, 50, 16), FlatFileKind::BLOCK, 4, 0);

    // Zero capacity disables caching.
    FlatFileReadCache off(files.Hooks(), 0);
    BOOST_CHECK(!off.Acquire(FlatFileKind::BLOCK, 0));
}

BOOST_AUTO_TEST_CASE(prune_invalidation) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    FlatFiles files;
    files.Write(FlatFileKind::BLOCK, 0, 100);
    files.Write(FlatFileKind::UNDO, 0, 100);
    files.Write(FlatFileKind::BLOCK, 1, 100);
    FlatFileReadCache cache(files.Hooks(), 8);
    auto blk0 = cache.Acquire(FlatFileKind::BLOCK, 0);
    BOOST_REQUIRE(blk0);
    BOOST_REQUIRE(cache.Acquire(FlatFileKind::UNDO, 0));
    BOOST_REQUIRE(cache.Acquire(FlatFileKind::BLOCK, 1));

    // Prune file 0: the host invalidates before deleting.
    cache.Invalidate(0);
    FlatFileCacheStats stats = cache.Stats();
    BOOST_CHECK_EQUAL(stats.invalidations, 2U);
    BOOST_CHECK_EQUAL(stats.open_files, 1U);
    fs::remove(files.Path(FlatFileKind::BLOCK, 0));
    fs::remove(files.Path(FlatFileKind::UNDO, 0));

    // The pruned files are no longer served from a stale descriptor.
    BOOST_CHECK(!cache.Acquire(FlatFileKind::BLOCK, 0));
    BOOST_CHECK(!cache.Acquire(FlatFileKind::UNDO, 0));
    BOOST_CHECK_EQUAL(cache.Stats().open_failures, 2U);
    // A reader that acquired the file before the prune finishes its read.
    CheckBytes(ReadVia(blk0, 0, 100, 16), FlatFileKind::BLOCK, 0, 0);
    // Other files are untouched.
    BOOST_CHECK(cache.Acquire(FlatFileKind::BLOCK, 1));
    BOOST_CHECK_EQUAL(cache.Stats().misses, 3U);

    // A file recreated under the same number (reindex) is read anew.
    files.Write(FlatFileKind::BLOCK, 0, 100);
    auto again = cache.Acquire(FlatFileKind::BLOCK, 0);
    BOOST_REQUIRE(again);
    BOOST_CHECK(again != blk0);

    cache.Clear();
    BOOST_CHECK_EQUAL(cache.Stats().open_files, 0U);
}

BOOST_AUTO_TEST_CASE(invalidate_during_open) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    FlatFiles files;
    files.Write(FlatFileKind::BLOCK, 0, 100);
    FlatFileReadCache *cache_ptr = nullptr;
    FlatFileReadCache::Hooks hooks = files.Hooks();
    // The prune lands between the may_append check and the open().
    hooks.may_append = [&](FlatFileKind, uint32_t n) {
        cache_ptr->Invalidate(n);
        return false;
    };
    FlatFileReadCache cache(hooks, 8);
    cache_ptr = &cache;
    auto f = cache.Acquire(FlatFileKind::BLOCK, 0);
    BOOST_REQUIRE(f); // usable for this read
    BOOST_CHECK_EQUAL(cache.Stats().open_files, 0U); // but not cached
}

BOOST_AUTO_TEST_CASE(concurrent_readers) {
    if (!FlatFileReadCache::Supported()) {
        return;
    }
    // Readers of a query pool hit, miss, evict and invalidate concurrently;
    // every read must return the right bytes.
    FlatFiles files;
    constexpr uint32_t NUM_FILES = 12;
    constexpr size_t FILE_SIZE = 64 * 1024;
    for (uint32_t n = 0; n < NUM_FILES; ++n) {
        files.Write(FlatFileKind::BLOCK, n, FILE_SIZE);
        files.Write(FlatFileKind::UNDO, n, FILE_SIZE / 4);
    }
    FlatFileReadCache cache(files.Hooks(), 5);
    std::atomic<bool> failed{false};
    std::atomic<uint64_t> reads{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            std::mt19937 rng(t);
            for (int i = 0; i < 3000 && !failed; ++i) {
                const uint32_t n = rng() % NUM_FILES;
                const bool undo = rng() % 3 == 0;
                const FlatFileKind kind =
                    undo ? FlatFileKind::UNDO : FlatFileKind::BLOCK;
                const size_t size = undo ? FILE_SIZE / 4 : FILE_SIZE;
                auto f = cache.Acquire(kind, n);
                if (!f) {
                    failed = true;
                    break;
                }
                const uint64_t pos = rng() % (size - 600);
                const size_t len = 1 + rng() % 500;
                FlatFileCursor cursor(f, pos, 256);
                std::vector<uint8_t> buf(len);
                cursor.Read(buf);
                for (size_t j = 0; j < len; ++j) {
                    if (buf[j] != FlatFiles::Byte(kind, n, pos + j)) {
                        failed = true;
                    }
                }
                ++reads;
                if (t == 0 && i % 100 == 0) {
                    cache.Invalidate(rng() % NUM_FILES);
                }
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }
    BOOST_CHECK(!failed);
    BOOST_CHECK_EQUAL(reads.load(), 8U * 3000U);
    FlatFileCacheStats stats = cache.Stats();
    BOOST_CHECK_LE(stats.open_files, 5U);
    BOOST_CHECK_EQUAL(stats.hits + stats.misses, 8U * 3000U);
    BOOST_CHECK_GT(stats.evictions, 0U);
    BOOST_CHECK_GT(stats.invalidations, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
