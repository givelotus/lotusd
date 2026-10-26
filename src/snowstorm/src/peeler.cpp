// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/peeler.h>
#include "peeler_engine.h"
namespace snowstorm {
class Peeler::Impl : public detail::PeelerEngine {
public:
    explicit Impl(PeelerCapacity capacity) : PeelerEngine(capacity, capacity) {}
};
Peeler::Peeler(PeelerCapacity capacity) : impl_(std::make_unique<Impl>(capacity)) {}
Peeler::~Peeler() = default;
Peeler::Peeler(Peeler &&) noexcept = default;
Peeler &Peeler::operator=(Peeler &&) noexcept = default;
Error Peeler::reset(std::span<const ShortId> reference) noexcept { return impl_->reset(reference); }
Error Peeler::append(std::span<const IndexedCell> residuals) noexcept { return impl_->append(residuals); }
Error Peeler::reference_change(ShortId item, Sign sign) noexcept { return impl_->reference_change(item, sign); }
PeelResult Peeler::run(std::span<SignedItem> output, std::span<DecodeAudit> audit, DecodePolicy policy) noexcept {
    return impl_->run(output, audit, policy);
}
bool Peeler::contains(ShortId item) const noexcept { return impl_->contains(item); }
std::size_t Peeler::symbol_count() const noexcept { return impl_->symbol_count(); }
std::uint64_t Peeler::decode_steps() const noexcept { return impl_->decode_steps(); }
Error Peeler::observations(std::span<ResidualObservation> output, std::size_t &written) const noexcept {
    return impl_->observations(output, written);
}
} // namespace snowstorm
