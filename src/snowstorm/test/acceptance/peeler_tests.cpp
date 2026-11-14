// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../oracle/schedule.h"
#include <snowstorm/peeler.h>
#include <map>
#include <bit>
#include <limits>
using namespace snowstorm_test;
namespace {
using RawCells = std::map<snowstorm::SymbolIndex, snowstorm_oracle::Cell>;
RawCells immutable_raw_cells(std::span<const snowstorm::IndexedCell> supplied,
                             const IdSet &initial_reference) {
    snowstorm::SymbolIndex end = 0;
    for (const auto &entry : supplied) end = std::max(end, entry.index + 1);
    const auto encoded = snowstorm_oracle::encode(initial_reference, 0, end);
    RawCells raw;
    for (const auto &entry : supplied) {
        auto negative_reference = encoded[entry.index];
        negative_reference.count = -negative_reference.count;
        // supplied residual + initial reference, exclusively oracle arithmetic.
        BOOST_REQUIRE(raw.emplace(entry.index, snowstorm_oracle::subtract(
            to_oracle(entry.cell), negative_reference)).second);
    }
    return raw;
}
void verify_audits(std::span<const snowstorm::DecodeAudit> audits,
                   std::span<const snowstorm::SignedItem> output,
                   const RawCells &original_raw, IdSet &reference) {
    std::size_t flattened = 0;
    for (const auto &audit : audits) {
        const auto original = original_raw.find(audit.index);
        BOOST_REQUIRE(original != original_raw.end());
        const auto encoded = snowstorm_oracle::encode(reference, audit.index, audit.index + 1)[0];
        const auto source = snowstorm_oracle::subtract(original->second, encoded);
        require_cell_equal(audit.source_before, source);
        BOOST_REQUIRE(audit.decoded.kind == snowstorm::DecodeKind::one ||
                      audit.decoded.kind == snowstorm::DecodeKind::two);
        BOOST_REQUIRE_EQUAL(audit.decoded.size,
            audit.decoded.kind == snowstorm::DecodeKind::one ? 1U : 2U);
        const auto decoded = to_oracle(audit.decoded);
        BOOST_REQUIRE(snowstorm_oracle::verifies_decode(source, audit.index, decoded, reference));
        // Both members of Two are checked against the independently reconstructed
        // original common source and membership before either member is applied.
        for (std::size_t i = 0; i < decoded.size(); ++i)
            BOOST_REQUIRE_EQUAL(audit.in_reference_before[i], reference.contains(decoded[i].item));
        for (const auto &item : decoded) {
            BOOST_REQUIRE_LT(flattened, output.size());
            BOOST_REQUIRE_EQUAL(output[flattened].item, item.item);
            BOOST_REQUIRE_EQUAL(static_cast<int>(output[flattened].sign), item.sign);
            ++flattened;
            if (item.sign > 0) reference.insert(item.item); else reference.erase(item.item);
        }
    }
    BOOST_REQUIRE_EQUAL(flattened, output.size());
}
void verify_residuals(const snowstorm::Peeler &peeler, const IdSet &reference,
                      const RawCells &original_raw) {
    BOOST_REQUIRE_EQUAL(peeler.symbol_count(), original_raw.size());
    std::vector<snowstorm::ResidualObservation> observations(original_raw.size());
    std::size_t written = 0;
    BOOST_REQUIRE(peeler.observations(observations, written) == snowstorm::Error::ok);
    BOOST_REQUIRE_EQUAL(written, observations.size());
    const auto end = original_raw.empty() ? 0 : original_raw.rbegin()->first + 1;
    const auto reference_cells = snowstorm_oracle::encode(reference, 0, end);
    auto original = original_raw.begin();
    for (const auto &entry : observations) {
        BOOST_REQUIRE_EQUAL(entry.index, original->first);
        require_cell_equal(entry.raw, original->second);
        require_cell_equal(entry.residual, snowstorm_oracle::subtract(
            original->second, reference_cells[entry.index]));
        ++original;
    }
}
void verify_run(const snowstorm::Peeler &peeler, const snowstorm::PeelResult &result,
                std::span<const snowstorm::SignedItem> output,
                std::span<const snowstorm::DecodeAudit> audits,
                const RawCells &original_raw, IdSet &reference) {
    BOOST_REQUIRE_LE(result.item_count, output.size());
    BOOST_REQUIRE_LE(result.audit_count, audits.size());
    verify_audits(audits.first(result.audit_count), output.first(result.item_count),
                  original_raw, reference);
    verify_residuals(peeler, reference, original_raw);
}
void reconcile(std::size_t difference, Rng &rng) {
    IdSet local, remote;
    for (unsigned i = 0; i < 16; ++i) local.insert(rng.nonzero());
    remote = local;
    std::map<std::uint64_t, int> expected;
    for (std::size_t i = 0; i < difference; ++i) {
        auto id = rng.nonzero();
        while (local.contains(id) || remote.contains(id)) id = rng.nonzero();
        const int sign = i % 2 ? -1 : 1;
        if (sign > 0) remote.insert(id); else local.insert(id);
        expected.emplace(id, sign);
    }
    const auto symbols = std::max<std::size_t>(64, 16 * (difference + 1));
    snowstorm::Peeler peeler({local.size() + difference + 4, symbols, 2 * difference + 8, symbols - 1});
    BOOST_REQUIRE(peeler.reset(sorted_ids(local)) == snowstorm::Error::ok);
    const auto a = snowstorm_oracle::encode(remote, 0, symbols);
    const auto b = snowstorm_oracle::encode(local, 0, symbols);
    std::vector<snowstorm::IndexedCell> residuals;
    for (std::size_t i = 0; i < symbols; ++i)
        residuals.push_back({i, to_core(snowstorm_oracle::subtract(a[i], b[i]))});
    const auto original_raw = immutable_raw_cells(residuals, local);
    BOOST_REQUIRE(peeler.append(residuals) == snowstorm::Error::ok);
    std::vector<snowstorm::SignedItem> output(2 * difference + 8);
    std::vector<snowstorm::DecodeAudit> audit(output.size());
    const auto result = peeler.run(output, audit);
    BOOST_REQUIRE(result.error == snowstorm::Error::ok);
    BOOST_REQUIRE(result.done);
    BOOST_REQUIRE_EQUAL(result.item_count, difference);
    BOOST_REQUIRE_LE(result.decode_steps, 64 * (difference + 1) * symbols);
    verify_run(peeler, result, output, audit, original_raw, local);
    std::map<std::uint64_t, int> actual;
    for (std::size_t i = 0; i < result.item_count; ++i)
        BOOST_REQUIRE(actual.emplace(output[i].item, static_cast<int>(output[i].sign)).second);
    BOOST_REQUIRE(actual == expected);
    BOOST_REQUIRE(local == remote);
}
void check_random_residual(Rng &rng, bool full_count_domain) {
    snowstorm::Peeler peeler({128, 32, 64, 255});
    IdSet reference;
    BOOST_REQUIRE(peeler.reset({}) == snowstorm::Error::ok);
    std::vector<snowstorm::IndexedCell> input;
    bool invalid_count = false;
    for (std::uint64_t index = 0; index < 32; ++index) {
        // The low32 projection is uniform; bit_cast preserves all signed bit
        // patterns, including INT_MIN, without implementation-defined conversion.
        const auto count = full_count_domain
            ? std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rng.next()))
            : static_cast<std::int32_t>(rng.bounded(11)) - 5;
        invalid_count |= count == std::numeric_limits<std::int32_t>::min();
        input.push_back({index, {count, rng.next(), rng.next(), rng.next()}});
    }
    const auto original_raw = invalid_count ? RawCells{} : immutable_raw_cells(input, reference);
    const auto append_result = peeler.append(input);
    if (invalid_count) {
        // INT_MIN is outside the normative cell domain. Check bounded rejection
        // rather than resampling a different distribution or peeling bad input.
        BOOST_REQUIRE(append_result == snowstorm::Error::overflow);
        BOOST_REQUIRE_EQUAL(peeler.symbol_count(), 0U);
        BOOST_REQUIRE_EQUAL(peeler.decode_steps(), 0U);
        return;
    }
    BOOST_REQUIRE(append_result == snowstorm::Error::ok);
    std::array<snowstorm::SignedItem, 64> output;
    std::array<snowstorm::DecodeAudit, 64> audits;
    const auto result = peeler.run(output, audits);
    BOOST_REQUIRE(result.error == snowstorm::Error::ok ||
                  result.error == snowstorm::Error::inconsistent_symbols);
    BOOST_REQUIRE_LE(result.decode_steps, 64 * (result.item_count + 1) * input.size());
    verify_run(peeler, result, output, audits, original_raw, reference);
}
}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T5_exact_signed_differences) {
    Rng rng(0x7435000000000001ULL);
    for (auto size : {0U, 1U, 2U, 3U, 10U, 100U, 1000U, 2000U}) reconcile(size, rng);
}
BOOST_AUTO_TEST_CASE(T5_ten_thousand_uniform_full_domain_residuals) {
    Rng rng(0x7435000000000003ULL);
    for (unsigned trial = 0; trial < 10000; ++trial)
        check_random_residual(rng, true);
}
BOOST_AUTO_TEST_CASE(T5_ten_thousand_focused_small_count_residuals) {
    Rng rng(0x7435000000000002ULL);
    for (unsigned trial = 0; trial < 10000; ++trial)
        check_random_residual(rng, false);
}
BOOST_AUTO_TEST_CASE(T5_invalid_count_rejects_entire_append_batch_atomically) {
    snowstorm::Peeler peeler({8, 4, 8, 255});
    const std::array<snowstorm::ShortId, 1> initial_reference{7};
    BOOST_REQUIRE(peeler.reset(initial_reference) == snowstorm::Error::ok);
    const std::array<snowstorm::IndexedCell, 1> initial{{{0, {}}}};
    const auto original_raw = immutable_raw_cells(initial, {7});
    BOOST_REQUIRE(peeler.append(initial) == snowstorm::Error::ok);
    std::array<snowstorm::ResidualObservation, 4> before;
    std::size_t before_count = 0;
    BOOST_REQUIRE(peeler.observations(before, before_count) == snowstorm::Error::ok);
    const auto symbols_before = peeler.symbol_count();
    const auto steps_before = peeler.decode_steps();
    // The first entry would otherwise add a new index: discovering the second
    // invalid entry must not leave that valid prefix installed.
    const std::array<snowstorm::IndexedCell, 2> batch{{
        {1, {}}, {2, {std::numeric_limits<std::int32_t>::min(), 1, 2, 3}}}};
    BOOST_REQUIRE(peeler.append(batch) == snowstorm::Error::overflow);
    BOOST_REQUIRE_EQUAL(peeler.symbol_count(), symbols_before);
    BOOST_REQUIRE_EQUAL(peeler.decode_steps(), steps_before);
    BOOST_REQUIRE(peeler.contains(7));
    BOOST_REQUIRE(!peeler.contains(1));
    BOOST_REQUIRE(!peeler.contains(2));
    std::array<snowstorm::ResidualObservation, 4> after;
    std::size_t after_count = 0;
    BOOST_REQUIRE(peeler.observations(after, after_count) == snowstorm::Error::ok);
    BOOST_REQUIRE_EQUAL(after_count, before_count);
    for (std::size_t i = 0; i < before_count; ++i) {
        BOOST_REQUIRE_EQUAL(after[i].index, before[i].index);
        require_cell_equal(after[i].raw, to_oracle(before[i].raw));
        require_cell_equal(after[i].residual, to_oracle(before[i].residual));
    }
    std::array<snowstorm::SignedItem, 8> output;
    std::array<snowstorm::DecodeAudit, 8> audit;
    const auto result = peeler.run(output, audit);
    BOOST_REQUIRE(result.error == snowstorm::Error::ok);
    BOOST_REQUIRE(result.done);
    BOOST_REQUIRE_EQUAL(result.item_count, 0U);
    BOOST_REQUIRE_EQUAL(result.audit_count, 0U);
    IdSet reference{7};
    verify_run(peeler, result, output, audit, original_raw, reference);
}
BOOST_AUTO_TEST_CASE(T5_contradictory_singleton_zero_has_no_cycle) {
    constexpr std::uint64_t id = 7;
    const auto schedule = snowstorm_oracle::schedule(id, 255);
    BOOST_REQUIRE_GE(schedule.size(), 2U);
    snowstorm_oracle::Cell single;
    BOOST_REQUIRE(snowstorm_oracle::add(single, id, 1));
    snowstorm::Peeler peeler({8, 2, 8, 255});
    BOOST_REQUIRE(peeler.reset({}) == snowstorm::Error::ok);
    const std::array<snowstorm::IndexedCell, 2> input{{{0, to_core(single)}, {schedule[1], {}}}};
    const auto original_raw = immutable_raw_cells(input, {});
    BOOST_REQUIRE(peeler.append(input) == snowstorm::Error::ok);
    std::array<snowstorm::SignedItem, 8> output;
    std::array<snowstorm::DecodeAudit, 8> audits;
    const auto result = peeler.run(output, audits);
    BOOST_REQUIRE(result.error == snowstorm::Error::inconsistent_symbols);
    BOOST_REQUIRE(!result.done);
    BOOST_REQUIRE_LE(result.decode_steps, 256U);
    IdSet reference;
    verify_run(peeler, result, output, audits, original_raw, reference);
}
BOOST_AUTO_TEST_CASE(T5_singleton_before_pair_rechecks_stale_pair_source) {
    const IdSet remote{7, 11};
    std::uint64_t singleton_index = 0;
    constexpr std::uint64_t pair_index = 0;
    for (std::uint64_t i = 1; i < 4096; ++i) {
        const bool a = snowstorm_oracle::includes(7, i);
        const bool b = snowstorm_oracle::includes(11, i);
        if (a != b) { singleton_index = i; break; }
    }
    BOOST_REQUIRE_NE(singleton_index, 0U);
    snowstorm::Peeler peeler({8, 2, 8, 4095});
    BOOST_REQUIRE(peeler.reset({}) == snowstorm::Error::ok);
    const std::array<snowstorm::IndexedCell, 2> input{{
        {singleton_index, to_core(snowstorm_oracle::encode(remote, singleton_index, singleton_index + 1)[0])},
        {pair_index, to_core(snowstorm_oracle::encode(remote, pair_index, pair_index + 1)[0])}}};
    const auto original_raw = immutable_raw_cells(input, {});
    BOOST_REQUIRE(peeler.append(input) == snowstorm::Error::ok);
    std::array<snowstorm::SignedItem, 8> output;
    std::array<snowstorm::DecodeAudit, 8> audits;
    const auto result = peeler.run(output, audits);
    BOOST_REQUIRE(result.error == snowstorm::Error::ok);
    BOOST_REQUIRE(result.done);
    BOOST_REQUIRE_EQUAL(result.item_count, 2U);
    BOOST_REQUIRE_EQUAL(result.audit_count, 2U);
    BOOST_REQUIRE(audits[0].decoded.kind == snowstorm::DecodeKind::one);
    BOOST_REQUIRE(audits[1].decoded.kind == snowstorm::DecodeKind::one);
    IdSet reference;
    verify_run(peeler, result, output, audits, original_raw, reference);
    BOOST_REQUIRE(reference == remote);
}
BOOST_AUTO_TEST_SUITE_END()
