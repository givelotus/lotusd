// Copyright (c) 2026 The Lotus developers
#include "chain_index.h"
#include "disk_state.h"
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
namespace lotus::v2 {
namespace {
struct Stop { ChainIndexResult result; };
[[noreturn]] void End(ChainIndexResult result) { throw Stop{result}; }
[[noreturn]] void Corrupt(DiskStateError &error, const char *message) {
    error = {DiskStateErrorCode::Corruption, message}; End(ChainIndexResult::StorageError);
}
template <typename F> ChainIndexResult Run(DiskStateError &error, F &&f) {
    error = {};
    try { f(); return ChainIndexResult::Complete; }
    catch (const Stop &stop) { return stop.result; }
    catch (const std::bad_alloc &) { error = {DiskStateErrorCode::Resource, "index query allocation"}; }
    catch (const std::length_error &) { error = {DiskStateErrorCode::Resource, "index query length"}; }
    return ChainIndexResult::StorageError;
}
std::optional<ActiveChainIndex> Active(const DiskStateStore &store, const Hash &expected, DiskStateError &error) {
    std::optional<ActiveChainIndex> active;
    if (!store.ReadActiveIndex(active, error)) End(ChainIndexResult::StorageError);
    if (!active) End(ChainIndexResult::Missing);
    if (active->tip != expected) End(ChainIndexResult::StaleTip);
    return active;
}
IndexedHeader HeaderFor(const DiskStateStore &store, const Hash &id, DiskStateError &error) {
    std::optional<IndexedHeader> header;
    if (!store.ReadIndexedHeader(id, header, error)) End(ChainIndexResult::StorageError);
    if (!header) Corrupt(error, "missing required indexed header");
    return *header;
}
Hash IdAt(const DiskStateStore &store, uint64_t height, DiskStateError &error) {
    std::optional<Hash> id;
    if (!store.ReadActiveId(height, id, error)) End(ChainIndexResult::StorageError);
    if (!id) Corrupt(error, "missing required active height");
    return *id;
}
class Budget {
    const DiskStateStore &store;
    DiskStateError &error;
    uint64_t remaining;
public:
    Budget(const DiskStateStore &s, DiskStateError &e, uint64_t reads) : store(s), error(e), remaining(reads) {}
    uint64_t Remaining() const { return remaining; }
    template <typename F> auto Read(uint64_t maximum_gets, F &&f) {
        // Authorize the worst-case Gets before entering any storage call.
        // Actual consumption is measured; unused reservation remains available.
        if (maximum_gets > remaining) End(ChainIndexResult::CapacityRefused);
        const auto before = store.LastStats().database_reads;
        auto value = f();
        const auto used = store.LastStats().database_reads - before;
        if (used > maximum_gets) Corrupt(error, "index read budget bound changed");
        remaining -= used; return value;
    }
};
// These include the current-S fence and local parent/active binding checks in
// DiskStateStore. Tests verify actual Get bounds, including refused operations.
constexpr uint64_t ACTIVE_GETS = 7, HEADER_GETS = 3, HEIGHT_GETS = 11;
} // namespace
ChainIndexResult BuildActiveLocator(const DiskStateStore &store, const Hash &expected_tip,
                                    size_t max_ids, std::vector<Hash> &out, DiskStateError &error) {
    return Run(error, [&] {
        if (!max_ids) End(ChainIndexResult::CapacityRefused);
        const auto active = Active(store, expected_tip, error);
        std::vector<Hash> result; uint64_t height = active->height, step = 1;
        while (true) {
            if (result.size() >= max_ids) End(ChainIndexResult::CapacityRefused);
            result.push_back(IdAt(store, height, error));
            if (!height) break;
            if (result.size() > 10)
                step = step > std::numeric_limits<uint64_t>::max() / 2
                           ? std::numeric_limits<uint64_t>::max() : step * 2;
            height = height > step ? height - step : 0;
        }
        (void)Active(store, expected_tip, error); out = std::move(result);
    });
}
ChainIndexResult ReadActiveHeaders(const DiskStateStore &store, const Hash &expected_tip,
    std::span<const Hash> locator, const Hash &stop, size_t max_locator,
    size_t max_headers, std::vector<Header> &out, DiskStateError &error) {
    return Run(error, [&] {
        if (locator.size() > max_locator || !max_headers) End(ChainIndexResult::CapacityRefused);
        const auto active = Active(store, expected_tip, error);
        std::vector<Header> result;
        if (locator.empty()) {
            // Empty locator asks for the explicit stop header only, matching
            // getheaders semantics. It never enumerates an entire chain.
            if (stop != Hash{}) {
                std::optional<IndexedHeader> header;
                if (!store.ReadIndexedHeader(stop, header, error)) End(ChainIndexResult::StorageError);
                if (header && header->header.height <= active->height &&
                    IdAt(store, header->header.height, error) == stop) result.push_back(header->header);
            }
        } else {
            uint64_t common = 0; // Unknown locators fall back to anchored genesis.
            for (const Hash &id : locator) {
                std::optional<IndexedHeader> header;
                if (!store.ReadIndexedHeader(id, header, error)) End(ChainIndexResult::StorageError);
                if (header && header->header.height <= active->height &&
                    IdAt(store, header->header.height, error) == id) {
                    common = header->header.height; break;
                }
            }
            uint64_t height = common;
            while (height < active->height && result.size() < max_headers) {
                ++height;
                const Hash id = IdAt(store, height, error);
                result.push_back(HeaderFor(store, id, error).header);
                if (id == stop) break;
            }
        }
        (void)Active(store, expected_tip, error); out = std::move(result);
    });
}
ChainIndexResult PlanHeaderFork(const DiskStateStore &store, const Hash &expected_tip,
    const Hash &target, const ForkLimits &limits, uint64_t now, uint64_t future_window,
    ForkPlan &out, DiskStateError &error, bool allow_parked_source) {
    return Run(error, [&] {
        Budget budget(store, error, limits.max_reads);
        const auto active = budget.Read(ACTIVE_GETS, [&] { return Active(store, expected_tip, error); });
        std::optional<IndexedHeader> candidate;
        budget.Read(HEADER_GETS, [&] {
            if (!store.ReadIndexedHeader(target, candidate, error)) End(ChainIndexResult::StorageError);
            return 0;
        });
        if (!candidate) End(ChainIndexResult::Missing);
        bool parked_source = false;
        if (store.AvalancheEnabled()) {
            auto policy = [&](const Hash &id) {
                DiskBlockPolicy p;
                const auto cap = budget.Remaining();
                if (!budget.Read(cap, [&] { return store.ReadBlockPolicy(id, cap, p, error); })) {
                    if (error.code == DiskStateErrorCode::Resource) End(ChainIndexResult::CapacityRefused);
                    End(ChainIndexResult::StorageError);
                }
                return p;
            };
            const auto target_policy = policy(target);
            if (target_policy.parked || target_policy.conflicting_finalized) End(ChainIndexResult::Excluded);
            if (allow_parked_source) parked_source = policy(expected_tip).parked;
        }
        if (CompareChainWork(candidate->chain_work, active->chain_work) <= 0 && !parked_source)
            End(ChainIndexResult::NotHeavier);
        if (candidate->max_ancestor_time > now && candidate->max_ancestor_time - now > future_window)
            End(ChainIndexResult::Deferred);
        IndexedHeader left = budget.Read(HEADER_GETS, [&] { return HeaderFor(store, expected_tip, error); });
        IndexedHeader right = *candidate;
        if ((left.header.height > right.header.height && left.header.height - right.header.height > limits.max_disconnect) ||
            (right.header.height > left.header.height && right.header.height - left.header.height > limits.max_connect))
            End(ChainIndexResult::CapacityRefused);
        ForkPlan plan; plan.source = expected_tip; plan.target = target;
        Hash left_id = expected_tip, right_id = target;
        while (left_id != right_id) {
            if (left.header.height >= right.header.height) {
                if (!left.header.height) Corrupt(error, "header forks have different genesis");
                if (plan.disconnect.size() >= limits.max_disconnect) End(ChainIndexResult::CapacityRefused);
                const Hash mapped = budget.Read(HEIGHT_GETS, [&] { return IdAt(store, left.header.height, error); });
                if (mapped != left_id) Corrupt(error, "fork source is not active");
                plan.disconnect.push_back(left_id); left_id = left.header.prev_id;
                left = budget.Read(HEADER_GETS, [&] { return HeaderFor(store, left_id, error); });
            } else {
                if (!right.header.height) Corrupt(error, "header forks have different genesis");
                if (plan.connect.size() >= limits.max_connect) End(ChainIndexResult::CapacityRefused);
                plan.connect.push_back(right_id); right_id = right.header.prev_id;
                right = budget.Read(HEADER_GETS, [&] { return HeaderFor(store, right_id, error); });
            }
        }
        const Hash mapped = budget.Read(HEIGHT_GETS, [&] { return IdAt(store, left.header.height, error); });
        if (mapped != left_id) Corrupt(error, "fork point is not active");
        plan.fork = left_id; std::reverse(plan.connect.begin(), plan.connect.end());
        if (CompareChainWork(candidate->chain_work, active->chain_work) <= 0 &&
            (plan.fork != target || plan.disconnect.empty())) End(ChainIndexResult::NotHeavier);
        (void)budget.Read(ACTIVE_GETS, [&] { return Active(store, expected_tip, error); });
        out = std::move(plan);
    });
}
} // namespace lotus::v2
