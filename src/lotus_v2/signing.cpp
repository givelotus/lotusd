// Copyright (c) 2026 The Lotus developers
#include "signing.h"
#include "batch_randomizers.h"

#include <crypto/sha256.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorr.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>

namespace lotus::v2 {
namespace {
bool VerifyBatchSlice(std::span<const BatchSigItem> slice) {
    if (slice.empty()) return true;
    if (slice.size() == 1) {
        return secp256k1_schnorrsig_verify(
                   secp256k1_context_static, slice[0].sig.data(),
                   slice[0].msg.data(), slice[0].msg.size(),
                   reinterpret_cast<const secp256k1_xonly_pubkey *>(
                       slice[0].parsed_pubkey.data())) == 1;
    }
    const size_t n = slice.size();
    std::vector<const unsigned char *> sigs(n);
    std::vector<const unsigned char *> msgs(n);
    std::vector<const secp256k1_xonly_pubkey *> pubkeys(n);

    for (size_t i = 0; i < n; ++i) {
        sigs[i] = slice[i].sig.data();
        msgs[i] = slice[i].msg.data();
        pubkeys[i] = reinterpret_cast<const secp256k1_xonly_pubkey *>(
            slice[i].parsed_pubkey.data());
    }
    const auto rand32 = GenerateBatchRandomizers(
        n, "Lotus/v2/schnorr-batch-randomizer");

    return secp256k1_schnorrsig_verify_batch(
               secp256k1_context_static, sigs.data(), msgs.data(),
               pubkeys.data(), rand32.data(), n) == 1;
}

bool VerifyLegacyBatchSlice(std::span<const LegacyBatchSigItem> slice) {
    if (slice.empty()) return true;
    if (slice.size() == 1) {
        return secp256k1_schnorr_verify(
                   secp256k1_context_static, slice[0].sig.data(),
                   slice[0].msg.data(),
                   reinterpret_cast<const secp256k1_pubkey *>(
                       slice[0].parsed_pubkey.data())) == 1;
    }
    const size_t n = slice.size();
    std::vector<const unsigned char *> sigs(n);
    std::vector<const unsigned char *> msgs(n);
    std::vector<const secp256k1_pubkey *> pubkeys(n);

    for (size_t i = 0; i < n; ++i) {
        sigs[i] = slice[i].sig.data();
        msgs[i] = slice[i].msg.data();
        pubkeys[i] = reinterpret_cast<const secp256k1_pubkey *>(
            slice[i].parsed_pubkey.data());
    }
    const auto rand32 = GenerateBatchRandomizers(
        n, "Lotus/v2/legacy-schnorr-batch-randomizer");

    return secp256k1_schnorr_verify_batch(
               secp256k1_context_static, sigs.data(), msgs.data(),
               pubkeys.data(), rand32.data(), n) == 1;
}

std::optional<size_t> BisectBatchSlice(std::span<const BatchSigItem> slice,
                                       size_t base_offset) {
    if (slice.empty()) return std::nullopt;
    if (VerifyBatchSlice(slice)) return std::nullopt;
    if (slice.size() == 1) return base_offset;
    const size_t mid = slice.size() / 2;
    if (auto left = BisectBatchSlice(slice.subspan(0, mid), base_offset)) {
        return left;
    }
    return BisectBatchSlice(slice.subspan(mid), base_offset + mid);
}

std::optional<size_t>
BisectLegacyBatchSlice(std::span<const LegacyBatchSigItem> slice,
                       size_t base_offset) {
    if (slice.empty()) return std::nullopt;
    if (VerifyLegacyBatchSlice(slice)) return std::nullopt;
    if (slice.size() == 1) return base_offset;
    const size_t mid = slice.size() / 2;
    if (auto left =
            BisectLegacyBatchSlice(slice.subspan(0, mid), base_offset)) {
        return left;
    }
    return BisectLegacyBatchSlice(slice.subspan(mid), base_offset + mid);
}

class SigningWorkerPool {
public:
    static SigningWorkerPool &Instance() {
        static SigningWorkerPool pool;
        return pool;
    }

    template <typename Fn>
    void Run(size_t num_workers, Fn &&fn) {
        if (num_workers <= 1) {
            fn(0);
            return;
        }
        std::function<void(size_t)> task_fn(std::forward<Fn>(fn));
        std::unique_lock<std::mutex> dispatch_lock(m_dispatch_mutex);
        EnsureWorkers(num_workers - 1);
        const size_t active = std::min(num_workers - 1, m_threads.size());
        if (active == 0) {
            dispatch_lock.unlock();
            task_fn(0);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_task = &task_fn;
            m_active_workers = active;
            m_remaining.store(active, std::memory_order_release);
            ++m_generation;
        }
        m_cv_start.notify_all();
        task_fn(0);
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv_done.wait(lock, [this]() {
                return m_remaining.load(std::memory_order_acquire) == 0;
            });
            m_task = nullptr;
        }
    }

private:
    SigningWorkerPool() = default;
    ~SigningWorkerPool() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
            ++m_generation;
        }
        m_cv_start.notify_all();
        for (auto &t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    void EnsureWorkers(size_t count) {
        while (m_threads.size() < count) {
            const size_t worker_id = m_threads.size() + 1;
            m_threads.emplace_back([this, worker_id]() {
                uint64_t seen_gen = 0;
                while (true) {
                    const std::function<void(size_t)> *fn = nullptr;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv_start.wait(lock, [this, &seen_gen]() {
                            return m_stop || m_generation != seen_gen;
                        });
                        if (m_stop) {
                            return;
                        }
                        seen_gen = m_generation;
                        if (worker_id <= m_active_workers) {
                            fn = m_task;
                        }
                    }
                    if (fn != nullptr) {
                        (*fn)(worker_id);
                        if (m_remaining.fetch_sub(
                                1, std::memory_order_acq_rel) == 1) {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_cv_done.notify_one();
                        }
                    }
                }
            });
        }
    }

    std::mutex m_dispatch_mutex;
    std::mutex m_mutex;
    std::condition_variable m_cv_start;
    std::condition_variable m_cv_done;
    std::vector<std::thread> m_threads;
    const std::function<void(size_t)> *m_task{nullptr};
    size_t m_active_workers{0};
    std::atomic<size_t> m_remaining{0};
    uint64_t m_generation{0};
    bool m_stop{false};
};

size_t EffectiveBatchThreads(size_t total_items, size_t requested_threads) {
    if (total_items < 32) return 1;
    size_t hw = requested_threads;
    if (hw == 0) {
        hw = std::min<size_t>(
            std::max<size_t>(std::thread::hardware_concurrency(), 1), 16);
    }
    return std::min<size_t>(hw, (total_items + 15) / 16);
}
} // namespace

bool BatchSigCollector::Add(std::span<const uint8_t> pubkey,
                            std::span<const uint8_t> sig, const Hash &msg) {
    if (pubkey.size() != 32 || sig.size() < 64) return false;
    secp256k1_xonly_pubkey parsed;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed,
                                      pubkey.data())) {
        return false;
    }
    BatchSigItem item;
    std::memcpy(item.pubkey.data(), pubkey.data(), 32);
    std::memcpy(item.parsed_pubkey.data(), parsed.data, 64);
    std::memcpy(item.sig.data(), sig.data(), 64);
    item.msg = msg;
    items_.push_back(item);
    return true;
}

bool BatchSigCollector::AddLegacySchnorr(std::span<const uint8_t> pubkey,
                                         std::span<const uint8_t> sig64,
                                         const uint8_t *msg32,
                                         const uint8_t *cache_entry32,
                                         bool store_in_cache) {
    if (sig64.size() != 64 || msg32 == nullptr ||
        (pubkey.size() != 33 && pubkey.size() != 65)) {
        return false;
    }
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                   pubkey.data(), pubkey.size())) {
        return false;
    }
    LegacyBatchSigItem item;
    std::memcpy(item.parsed_pubkey.data(), parsed.data, 64);
    std::memcpy(item.sig.data(), sig64.data(), 64);
    std::memcpy(item.msg.data(), msg32, 32);
    if (store_in_cache && cache_entry32 != nullptr) {
        std::memcpy(item.cache_entry.data(), cache_entry32, 32);
        item.store_in_cache = true;
    }
    legacy_items_.push_back(item);
    return true;
}

void BatchSigCollector::Merge(const BatchSigCollector &other) {
    if (!other.items_.empty()) {
        items_.insert(items_.end(), other.items_.begin(), other.items_.end());
    }
    if (!other.legacy_items_.empty()) {
        legacy_items_.insert(legacy_items_.end(), other.legacy_items_.begin(),
                             other.legacy_items_.end());
    }
}

void BatchSigCollector::Merge(BatchSigCollector &&other) {
    if (!other.items_.empty()) {
        if (items_.empty()) {
            items_ = std::move(other.items_);
        } else {
            items_.insert(items_.end(), other.items_.begin(),
                          other.items_.end());
            other.items_.clear();
        }
    }
    if (!other.legacy_items_.empty()) {
        if (legacy_items_.empty()) {
            legacy_items_ = std::move(other.legacy_items_);
        } else {
            legacy_items_.insert(legacy_items_.end(),
                                 other.legacy_items_.begin(),
                                 other.legacy_items_.end());
            other.legacy_items_.clear();
        }
    }
}

bool BatchSigCollector::VerifyAll(size_t num_threads) const {
    if (!items_.empty()) {
        const size_t threads = EffectiveBatchThreads(items_.size(), num_threads);
        const std::span<const BatchSigItem> all(items_.data(), items_.size());
        if (threads <= 1) {
            if (!VerifyBatchSlice(all)) return false;
        } else {
            std::atomic<bool> all_valid{true};
            auto run_chunk = [&](size_t t) {
                const size_t begin = (items_.size() * t) / threads;
                const size_t end = (items_.size() * (t + 1)) / threads;
                if (begin >= end || !all_valid.load(std::memory_order_relaxed))
                    return;
                if (!VerifyBatchSlice(all.subspan(begin, end - begin))) {
                    all_valid.store(false, std::memory_order_relaxed);
                }
            };
            SigningWorkerPool::Instance().Run(threads, run_chunk);
            if (!all_valid.load(std::memory_order_relaxed)) return false;
        }
    }

    if (!legacy_items_.empty()) {
        const size_t threads =
            EffectiveBatchThreads(legacy_items_.size(), num_threads);
        const std::span<const LegacyBatchSigItem> all(legacy_items_.data(),
                                                      legacy_items_.size());
        if (threads <= 1) {
            if (!VerifyLegacyBatchSlice(all)) return false;
        } else {
            std::atomic<bool> all_valid{true};
            auto run_chunk = [&](size_t t) {
                const size_t begin = (legacy_items_.size() * t) / threads;
                const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                if (begin >= end || !all_valid.load(std::memory_order_relaxed))
                    return;
                if (!VerifyLegacyBatchSlice(all.subspan(begin, end - begin))) {
                    all_valid.store(false, std::memory_order_relaxed);
                }
            };
            SigningWorkerPool::Instance().Run(threads, run_chunk);
            if (!all_valid.load(std::memory_order_relaxed)) return false;
        }
    }

    return true;
}

std::optional<size_t>
BatchSigCollector::FirstFailingIndex(size_t num_threads) const {
    if (!items_.empty()) {
        const size_t threads = EffectiveBatchThreads(items_.size(), num_threads);
        const std::span<const BatchSigItem> all(items_.data(), items_.size());
        if (threads <= 1) {
            if (auto fail = BisectBatchSlice(all, 0)) {
                return fail;
            }
        } else {
            std::vector<uint8_t> chunk_ok(threads, 1);
            auto check_chunk = [&](size_t t) {
                const size_t begin = (items_.size() * t) / threads;
                const size_t end = (items_.size() * (t + 1)) / threads;
                if (begin < end &&
                    !VerifyBatchSlice(all.subspan(begin, end - begin))) {
                    chunk_ok[t] = 0;
                }
            };
            SigningWorkerPool::Instance().Run(threads, check_chunk);
            for (size_t t = 0; t < threads; ++t) {
                if (chunk_ok[t] == 0) {
                    const size_t begin = (items_.size() * t) / threads;
                    const size_t end = (items_.size() * (t + 1)) / threads;
                    if (auto fail = BisectBatchSlice(
                            all.subspan(begin, end - begin), begin)) {
                        return fail;
                    }
                }
            }
        }
    }

    if (!legacy_items_.empty()) {
        const size_t base = items_.size();
        const size_t threads =
            EffectiveBatchThreads(legacy_items_.size(), num_threads);
        const std::span<const LegacyBatchSigItem> all(legacy_items_.data(),
                                                      legacy_items_.size());
        if (threads <= 1) {
            if (auto fail = BisectLegacyBatchSlice(all, base)) {
                return fail;
            }
        } else {
            std::vector<uint8_t> chunk_ok(threads, 1);
            auto check_chunk = [&](size_t t) {
                const size_t begin = (legacy_items_.size() * t) / threads;
                const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                if (begin < end &&
                    !VerifyLegacyBatchSlice(all.subspan(begin, end - begin))) {
                    chunk_ok[t] = 0;
                }
            };
            SigningWorkerPool::Instance().Run(threads, check_chunk);
            for (size_t t = 0; t < threads; ++t) {
                if (chunk_ok[t] == 0) {
                    const size_t begin = (legacy_items_.size() * t) / threads;
                    const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                    if (auto fail = BisectLegacyBatchSlice(
                            all.subspan(begin, end - begin), base + begin)) {
                        return fail;
                    }
                }
            }
        }
    }

    return std::nullopt;
}

} // namespace lotus::v2

