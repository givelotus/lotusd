// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/peeler.h>
#include "cell_soa.h"
namespace snowstorm::detail {
/** Shared engine for the fully reserved public Peeler and proportionally reserved
 * Node sessions. Only reserve_storage may allocate after construction.
 */
class PeelerEngine {
    struct Staged { SymbolIndex index; Cell raw; Cell residual; };
    struct Candidate { std::size_t pos; std::uint64_t version; Cell cell; };
    struct Change { std::size_t pos; Cell cell; std::int64_t count; };
    PeelerCapacity limits_, storage_{};
    std::vector<ItemPowers> reference_;
    std::vector<ShortId> claims_;
    std::vector<SymbolIndex> indices_;
    CellSoA raw_, residual_;
    std::vector<std::uint64_t> versions_;
    std::vector<std::uint8_t> queued_;
    std::vector<std::size_t> work_;
    std::vector<Candidate> snapshot_, pairs_;
    std::vector<Staged> staged_;
    std::vector<Change> changes_;
    std::vector<std::uint64_t> cubes_, inverses_, inverse_scratch_;
    std::uint64_t steps_{}, pass_{1};
    std::size_t lower(SymbolIndex index) const noexcept;
    ReferenceView reference_view() const noexcept;
    void mark(std::size_t pos) noexcept;
    void mark_all() noexcept;
    Error stage_append(std::span<const IndexedCell> input) noexcept;
    Error reconstruct_raw() noexcept;
    Error stage_delta(const DecodeResult &decoded) noexcept;
    Error stage_item(const SignedItem &item) noexcept;
    void apply_delta(const DecodeResult &decoded) noexcept;
    Error commit(std::size_t pos, const DecodeResult &decoded, DecodePolicy policy,
                 std::span<SignedItem> output, std::span<DecodeAudit> audit,
                 PeelResult &result) noexcept;
    bool current(const Candidate &candidate) const noexcept;
    Error singles(DecodePolicy policy, std::span<SignedItem> output,
                  std::span<DecodeAudit> audit, PeelResult &result) noexcept;
    Error pairs(DecodePolicy policy, std::span<SignedItem> output,
                std::span<DecodeAudit> audit, PeelResult &result) noexcept;
public:
    PeelerEngine(PeelerCapacity limits, PeelerCapacity storage);
    void reserve_storage(PeelerCapacity storage);
    Error reset(std::span<const ShortId> reference) noexcept;
    Error append(std::span<const IndexedCell> input) noexcept;
    Error reference_change(ShortId item, Sign sign) noexcept;
    PeelResult run(std::span<SignedItem> output, std::span<DecodeAudit> audit,
                   DecodePolicy policy) noexcept;
    bool contains(ShortId item) const noexcept;
    std::size_t symbol_count() const noexcept { return indices_.size(); }
    std::uint64_t decode_steps() const noexcept { return steps_; }
    Error observations(std::span<ResidualObservation> output, std::size_t &written) const noexcept;
    /** Actual retained buffers, excluding the engine object itself. */
    std::size_t allocated_bytes() const noexcept;
};
} // namespace snowstorm::detail
