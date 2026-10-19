// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <array>
#include <atomic>
#include <cassert>
#include <thread>
#include <vector>

// Transactions are created on network threads, serialized again for every
// peer they are relayed to, and often released on another thread. These
// benchmarks use the transactions of block 413567.

namespace {
CBlock LoadBlock() {
    DataStream stream{benchmark::data::block413567};
    CBlock block;
    stream >> block;
    return block;
}

/** The serialization of every transaction of the block. */
std::vector<std::vector<uint8_t>> SerializedTransactions(const CBlock &block) {
    std::vector<std::vector<uint8_t>> txs;
    for (const CTransactionRef &tx : block.vtx) {
        DataStream stream{};
        stream << tx;
        txs.emplace_back(UCharCast(stream.data()),
                         UCharCast(stream.data()) + stream.size());
    }
    return txs;
}
} // namespace

/** Serialize every transaction of the block, as relaying them does. */
static void SerializeBlockTransactions(benchmark::Bench &bench) {
    const CBlock block = LoadBlock();
    DataStream out{};
    bench.unit("block").run([&] {
        for (const CTransactionRef &tx : block.vtx) {
            out.clear();
            out << tx;
        }
        ankerl::nanobench::doNotOptimizeAway(out.size());
    });
}

/** Deserialize each transaction into a reference and release it. */
static void DeserializeTransactionRefs(benchmark::Bench &bench) {
    const auto txs = SerializedTransactions(LoadBlock());
    bench.unit("block").run([&] {
        for (const std::vector<uint8_t> &bytes : txs) {
            SpanReader reader{bytes};
            CTransactionRef tx;
            reader >> tx;
            ankerl::nanobench::doNotOptimizeAway(tx);
        }
    });
}

/**
 * Deserialize each transaction into a reference and hand it to another
 * thread, which releases it, through a lock-free single-producer
 * single-consumer ring, so every release happens on a different thread.
 */
static void
DeserializeTransactionRefsReleasedElsewhere(benchmark::Bench &bench) {
    const auto txs = SerializedTransactions(LoadBlock());

    constexpr size_t RING_SIZE{1024};
    std::array<CTransactionRef, RING_SIZE> ring;
    alignas(64) std::atomic<size_t> head{0};
    alignas(64) std::atomic<size_t> tail{0};
    std::atomic<bool> stop{false};

    std::thread consumer{[&] {
        size_t next = 0;
        while (true) {
            const size_t available = head.load(std::memory_order_acquire);
            if (available == next) {
                if (stop.load(std::memory_order_acquire) &&
                    head.load(std::memory_order_acquire) == next) {
                    return;
                }
                std::this_thread::yield();
                continue;
            }
            for (; next != available; ++next) {
                ring[next % RING_SIZE].reset();
            }
            tail.store(next, std::memory_order_release);
        }
    }};

    size_t produced = 0;
    bench.unit("block").run([&] {
        for (const std::vector<uint8_t> &bytes : txs) {
            SpanReader reader{bytes};
            CTransactionRef tx;
            reader >> tx;
            while (produced - tail.load(std::memory_order_acquire) ==
                   RING_SIZE) {
                std::this_thread::yield();
            }
            ring[produced % RING_SIZE] = std::move(tx);
            head.store(++produced, std::memory_order_release);
        }
    });

    stop.store(true, std::memory_order_release);
    consumer.join();
    assert(tail.load() == produced);
}

BENCHMARK(SerializeBlockTransactions);
BENCHMARK(DeserializeTransactionRefs);
BENCHMARK(DeserializeTransactionRefsReleasedElsewhere);
