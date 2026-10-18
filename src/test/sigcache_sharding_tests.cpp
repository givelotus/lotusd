// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <script/sigcache.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <barrier>
#include <cstddef>
#include <memory>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(sigcache_sharding_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(concurrent_shard_and_tls_cache_isolation) {
    SignatureCache cache(2 << 20);
    SignatureCache other_cache(2 << 20);
    std::vector<uint256> entries;
    for (size_t i = 0; i < 1024; ++i) {
        entries.push_back(Hash(strprintf("signature cache shard fixture %u", i)));
        cache.Set(entries.back());
    }
    std::atomic<size_t> failures{0};
    std::vector<std::thread> workers;
    for (size_t worker = 0; worker < 8; ++worker) {
        workers.emplace_back([&, worker] {
            for (size_t round = 0; round < 8; ++round) {
                for (size_t i = worker; i < entries.size(); i += 8) {
                    if (!cache.Get(entries[i], false)) ++failures;
                    // A TLS hit in one cache must never leak into another.
                    if (other_cache.Get(entries[i], false)) ++failures;
                    cache.Set(entries[i]);
                    if (!cache.Get(entries[i], false)) ++failures;
                }
            }
        });
    }
    for (auto &worker : workers) worker.join();
    BOOST_CHECK_EQUAL(failures.load(), 0U);
    // Upstream erase marks cache entries for collection; it does not promise
    // immediate absence. Preserve that behavior while checking lookup success.
    for (const auto &entry : entries) BOOST_CHECK(cache.Get(entry, true));
}

BOOST_AUTO_TEST_CASE(tls_entries_do_not_survive_cache_address_reuse) {
    // Cache entries are opaque API keys: nonce randomness must not be needed
    // for isolation between two distinct cache lifetimes at the same address.
    alignas(SignatureCache) std::array<std::byte, sizeof(SignatureCache)> storage;
    auto *cache = std::construct_at(
        reinterpret_cast<SignatureCache *>(storage.data()), 2 << 20);
    const uint256 entry{0x42};
    cache->Set(entry);
    BOOST_CHECK(cache->Get(entry, false));
    std::barrier phase{2};
    bool old_hit{false}, new_hit{false};
    std::thread reader([&] {
        old_hit = cache->Get(entry, false); // fill another thread's TLS too
        phase.arrive_and_wait();
        phase.arrive_and_wait();
        new_hit = cache->Get(entry, false);
    });
    phase.arrive_and_wait();
    std::destroy_at(cache);
    cache = std::construct_at(
        reinterpret_cast<SignatureCache *>(storage.data()), 2 << 20);
    const bool main_hit = cache->Get(entry, false);
    phase.arrive_and_wait();
    reader.join();
    BOOST_CHECK(old_hit);
    BOOST_CHECK(!main_hit);
    BOOST_CHECK(!new_hit);
    std::destroy_at(cache);
}

BOOST_AUTO_TEST_SUITE_END()
