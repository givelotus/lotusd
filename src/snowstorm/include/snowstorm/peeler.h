// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
/** @defgroup snowstorm_peeler_contract Snowstorm peeler public contract
 * §§4.4,6.2,6.4,10: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §§4.4,10: incoming residual associated with its actual symbol index. */
struct IndexedCell {
    SymbolIndex index{};
    Cell cell{};
};
/** §§4.4,10: raw/residual pair for independent invariant checks. */
struct ResidualObservation {
    SymbolIndex index{};
    Cell raw{};
    Cell residual{};
};
/** §§4.4,10: grouped atomic source proof, including original membership bits. */
struct DecodeAudit {
    SymbolIndex index{};
    Cell source_before{};
    DecodeResult decoded{};
    std::array<bool, 2> in_reference_before{};
    std::uint64_t pass{};
};
/** §§4.4,6.4: preallocation capacities, not an iteration budget. */
struct PeelerCapacity {
    std::size_t max_reference_items{};
    std::size_t max_symbols{};
    std::size_t max_claims{};
    SymbolIndex max_symbol_index{};
};
/** §§4.4,6.2: optional core-owned precommit policy; no allocations/calls to host.
 * A non-ok return prevents that entire One/Two from mutating the reference and
 * ends run() with the returned error. Previously committed events remain audited.
 */
struct DecodePolicy {
    void *context{};
    Error (*accept)(void *, const DecodeResult &) noexcept{};
};
/** §§4.4,10: output spans contain exactly the reported prefix lengths. */
struct PeelResult {
    Error error{Error::ok};
    bool done{};
    std::size_t item_count{};
    std::size_t audit_count{};
    std::uint64_t decode_steps{};
    std::uint64_t stuck{};
};
/** §4.4: reserved-workspace peeler; append/run/reference_change never allocate. */
class Peeler {
public:
    /** §§4.4,6.4: reserve all storage, throwing only for invalid local capacities. */
    explicit Peeler(PeelerCapacity capacity);
    /** §4.4: release preallocated storage. */
    ~Peeler();
    /** §4.4: transfer ownership without allocation. */
    Peeler(Peeler &&) noexcept;
    /** §4.4: transfer ownership without allocation. */
    Peeler &operator=(Peeler &&) noexcept;
    /** §4.4: peeler state is not copyable. */
    Peeler(const Peeler &) = delete;
    /** §4.4: peeler state is not copyable. */
    Peeler &operator=(const Peeler &) = delete;
    /** §4.4: new pass/snapshot, sorted distinct nonzero reference IDs. */
    Error reset(std::span<const ShortId> reference) noexcept;
    /** §§4.4,6.4: append residuals, deriving raw cells using current reference.
     * Validate the entire batch before mutation. Prohibited INT32_MIN counts or
     * raw reconstruction overflow return overflow; out-of-range indices return
     * invalid_range; conflicting duplicate indices within the batch or against
     * stored raw cells return inconsistent_symbols; insufficient capacity returns
     * capacity. Each error leaves all peeler state unchanged. Identical duplicate
     * raw cells are no-ops.
     */
    Error append(std::span<const IndexedCell> residuals) noexcept;
    /** §§4.4,6.2: external reference delta, atomic, starts a new claim-ledger pass. */
    Error reference_change(ShortId item, Sign sign) noexcept;
    /** §4.4: outputs need max_claims and max_claims audit slots respectively;
     * capacity failure is checked before mutation. Worklist has no step cap.
     */
    PeelResult run(std::span<SignedItem> output, std::span<DecodeAudit> audit,
                   DecodePolicy policy = {}) noexcept;
    /** §§4.4,10: current reference membership, not remote ground truth. */
    bool contains(ShortId item) const noexcept;
    /** §10: number of stored distinct symbol indices. */
    std::size_t symbol_count() const noexcept;
    /** §10: cumulative actual decode attempts since reset. */
    std::uint64_t decode_steps() const noexcept;
    /** §10: copy sorted raw/residual observations without allocation. */
    Error observations(std::span<ResidualObservation> output,
                       std::size_t &written) const noexcept;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace snowstorm
/** @} */
