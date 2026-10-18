// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <support/allocators/chunked_slab.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(allocator_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(arena_tests) {
    // Fake memory base address for testing
    // without actually using memory.
    void *synth_base = reinterpret_cast<void *>(0x08000000);
    const size_t synth_size = 1024 * 1024;
    Arena b(synth_base, synth_size, 16);
    void *chunk = b.alloc(1000);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(chunk != nullptr);
    // Aligned to 16
    BOOST_CHECK(b.stats().used == 1008);
    // Nothing has disappeared?
    BOOST_CHECK(b.stats().total == synth_size);
    b.free(chunk);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 0);
    BOOST_CHECK(b.stats().free == synth_size);
    try {
        // Test exception on double-free
        b.free(chunk);
        BOOST_CHECK(0);
    } catch (std::runtime_error &) {
    }

    void *a0 = b.alloc(128);
    void *a1 = b.alloc(256);
    void *a2 = b.alloc(512);
    BOOST_CHECK(b.stats().used == 896);
    BOOST_CHECK(b.stats().total == synth_size);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    b.free(a0);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 768);
    b.free(a1);
    BOOST_CHECK(b.stats().used == 512);
    void *a3 = b.alloc(128);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 640);
    b.free(a2);
    BOOST_CHECK(b.stats().used == 128);
    b.free(a3);
    BOOST_CHECK(b.stats().used == 0);
    BOOST_CHECK_EQUAL(b.stats().chunks_used, 0U);
    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);
    BOOST_CHECK_EQUAL(b.stats().chunks_free, 1U);

    std::vector<void *> addr;
    // allocating 0 always returns nullptr
    BOOST_CHECK(b.alloc(0) == nullptr);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    // Sweeping allocate all memory
    addr.reserve(2048);
    for (int x = 0; x < 1024; ++x) {
        addr.push_back(b.alloc(1024));
    }
    BOOST_CHECK(b.stats().free == 0);
    // memory is full, this must return nullptr
    BOOST_CHECK(b.alloc(1024) == nullptr);
    BOOST_CHECK(b.alloc(0) == nullptr);
    for (int x = 0; x < 1024; ++x) {
        b.free(addr[x]);
    }
    addr.clear();
    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);

    // Now in the other direction...
    for (int x = 0; x < 1024; ++x) {
        addr.push_back(b.alloc(1024));
    }
    for (int x = 0; x < 1024; ++x) {
        b.free(addr[1023 - x]);
    }
    addr.clear();

    // Now allocate in smaller unequal chunks, then deallocate haphazardly
    // Not all the chunks will succeed allocating, but freeing nullptr is
    // allowed so that is no problem.
    for (int x = 0; x < 2048; ++x) {
        addr.push_back(b.alloc(x + 1));
    }
    for (int x = 0; x < 2048; ++x) {
        b.free(addr[((x * 23) % 2048) ^ 242]);
    }
    addr.clear();

    // Go entirely wild: free and alloc interleaved, generate targets and sizes
    // using pseudo-randomness.
    for (int x = 0; x < 2048; ++x) {
        addr.push_back(nullptr);
    }
    uint32_t s = 0x12345678;
    for (int x = 0; x < 5000; ++x) {
        int idx = s & (addr.size() - 1);
        if (s & 0x80000000) {
            b.free(addr[idx]);
            addr[idx] = nullptr;
        } else if (!addr[idx]) {
            addr[idx] = b.alloc((s >> 16) & 2047);
        }
        bool lsb = s & 1;
        s >>= 1;
        // LFSR period 0xf7ffffe0
        if (lsb) {
            s ^= 0xf00f00f0;
        }
    }
    for (void *ptr : addr) {
        b.free(ptr);
    }
    addr.clear();

    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);
}

/** Mock LockedPageAllocator for testing */
class TestLockedPageAllocator : public LockedPageAllocator {
public:
    TestLockedPageAllocator(int count_in, int lockedcount_in)
        : count(count_in), lockedcount(lockedcount_in) {}
    void *AllocateLocked(size_t len, bool *lockingSuccess) override {
        *lockingSuccess = false;
        if (count > 0) {
            --count;

            if (lockedcount > 0) {
                --lockedcount;
                *lockingSuccess = true;
            }

            // Fake address, do not actually use this memory
            return reinterpret_cast<void *>(0x08000000 + (count << 24));
        }
        return nullptr;
    }
    void FreeLocked(void *addr, size_t len) override {}
    size_t GetLimit() override { return std::numeric_limits<size_t>::max(); }

private:
    int count;
    int lockedcount;
};

BOOST_AUTO_TEST_CASE(lockedpool_tests_mock) {
    // Test over three virtual arenas, of which one will succeed being locked
    auto x = std::make_unique<TestLockedPageAllocator>(3, 1);
    LockedPool pool(std::move(x));
    BOOST_CHECK(pool.stats().total == 0);
    BOOST_CHECK(pool.stats().locked == 0);

    // Ensure unreasonable requests are refused without allocating anything
    void *invalid_toosmall = pool.alloc(0);
    BOOST_CHECK(invalid_toosmall == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);
    void *invalid_toobig = pool.alloc(LockedPool::ARENA_SIZE + 1);
    BOOST_CHECK(invalid_toobig == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);

    void *a0 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a0);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    void *a1 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a1);
    void *a2 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a2);
    void *a3 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a3);
    void *a4 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a4);
    void *a5 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a5);
    // We've passed a count of three arenas, so this allocation should fail
    void *a6 = pool.alloc(16);
    BOOST_CHECK(!a6);

    pool.free(a0);
    pool.free(a2);
    pool.free(a4);
    pool.free(a1);
    pool.free(a3);
    pool.free(a5);
    BOOST_CHECK(pool.stats().total == 3 * LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().used == 0);
}

// These tests used the live LockedPoolManager object, this is also used by
// other tests so the conditions are somewhat less controllable and thus the
// tests are somewhat more error-prone.
BOOST_AUTO_TEST_CASE(lockedpool_tests_live) {
    LockedPoolManager &pool = LockedPoolManager::Instance();
    LockedPool::Stats initial = pool.stats();

    void *a0 = pool.alloc(16);
    BOOST_CHECK(a0);
    // Test reading and writing the allocated memory
    *((uint32_t *)a0) = 0x1234;
    BOOST_CHECK(*((uint32_t *)a0) == 0x1234);

    pool.free(a0);
    try {
        // Test exception on double-free
        pool.free(a0);
        BOOST_CHECK(0);
    } catch (std::runtime_error &) {
    }
    // If more than one new arena was allocated for the above tests, something
    // is wrong
    BOOST_CHECK(pool.stats().total <= (initial.total + LockedPool::ARENA_SIZE));
    // Usage must be back to where it started
    BOOST_CHECK(pool.stats().used == initial.used);
}

namespace {
// Odd size and a small chunk give this test its own slab pool.
struct SlabTestObject {
    uint64_t words[7];
};
using SlabTestAllocator = GlobalConcurrentSlabAllocator<SlabTestObject, 64>;
} // namespace

BOOST_AUTO_TEST_CASE(global_concurrent_slab_allocator) {
    SlabTestAllocator alloc;
    BOOST_CHECK((alloc == GlobalConcurrentSlabAllocator<int, 64>{}));

    // Worker threads count mismatches instead of using BOOST_CHECK, which is
    // not thread-safe.
    std::atomic<int> mismatches{0};

    // Allocate and free on a worker thread: the thread's magazine is flushed
    // back to the pool when it exits.
    std::thread([&mismatches] {
        SlabTestAllocator a;
        std::vector<SlabTestObject *> objs;
        for (int i = 0; i < 1000; ++i) {
            objs.push_back(a.allocate(1));
            objs.back()->words[0] = uint64_t(i);
        }
        for (int i = 0; i < 1000; ++i) {
            if (objs[i]->words[0] != uint64_t(i)) {
                ++mismatches;
            }
            a.deallocate(objs[i], 1);
        }
    }).join();
    BOOST_CHECK_EQUAL(SlabTestAllocator::OutstandingSlots(), 0U);
    const size_t chunks_after_first = SlabTestAllocator::NumAllocatedChunks();
    BOOST_CHECK_GE(chunks_after_first, 1000U / 64);

    // Cross-thread churn: producers allocate, consumers free. Repeating the
    // same workload must reuse slots rather than carve new chunks.
    auto churn = [&mismatches] {
        constexpr int PAIRS{4};
        constexpr int PER_THREAD{20000};
        constexpr int BATCH{256};
        std::vector<std::thread> threads;
        for (int t = 0; t < PAIRS; ++t) {
            threads.emplace_back([&mismatches] {
                SlabTestAllocator a;
                for (int done = 0; done < PER_THREAD; done += BATCH) {
                    std::vector<SlabTestObject *> batch;
                    for (int i = 0; i < BATCH; ++i) {
                        batch.push_back(a.allocate(1));
                        batch.back()->words[6] = uint64_t(done + i);
                    }
                    // Free on a different thread than the allocating one.
                    std::thread([&batch, &mismatches, done] {
                        SlabTestAllocator b;
                        for (int i = 0; i < BATCH; ++i) {
                            if (batch[i]->words[6] != uint64_t(done + i)) {
                                ++mismatches;
                            }
                            b.deallocate(batch[i], 1);
                        }
                    }).join();
                }
            });
        }
        for (auto &thread : threads) {
            thread.join();
        }
    };
    churn();
    BOOST_CHECK_EQUAL(SlabTestAllocator::OutstandingSlots(), 0U);
    const size_t chunks_after_churn = SlabTestAllocator::NumAllocatedChunks();
    churn();
    BOOST_CHECK_EQUAL(SlabTestAllocator::OutstandingSlots(), 0U);
    BOOST_CHECK_EQUAL(SlabTestAllocator::NumAllocatedChunks(),
                      chunks_after_churn);
    BOOST_CHECK_EQUAL(mismatches.load(), 0);

    // A slot released by a thread_local destructor that runs after the
    // thread's magazine was retired goes straight back to the pool.
    struct LateFree {
        SlabTestObject *obj{nullptr};
        ~LateFree() { SlabTestAllocator{}.deallocate(obj, 1); }
    };
    std::thread([] {
        static thread_local LateFree late;
        late.obj = SlabTestAllocator{}.allocate(1);
    }).join();
    BOOST_CHECK_EQUAL(SlabTestAllocator::OutstandingSlots(), 0U);

    // Multi-object requests bypass the slab.
    SlabTestObject *array = alloc.allocate(3);
    alloc.deallocate(array, 3);
}

BOOST_AUTO_TEST_SUITE_END()
