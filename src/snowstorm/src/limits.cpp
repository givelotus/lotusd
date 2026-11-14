// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "limits.h"
#include <algorithm>
#include <limits>
namespace snowstorm {
Error derive_limits(std::uint64_t m, std::uint64_t peers, Limits &out) noexcept {
    if (m == 0 || m > detail::MAX_SET_SIZE || peers > params::MAX_PEERS) return Error::invalid_argument;
    Limits result{};
    result.max_set_size = m; result.max_peers = peers;
    result.max_ranges = params::MAX_RANGES;
    result.max_cells = std::min(params::MAX_MESSAGE_CELLS, detail::cell_limit(m));
    result.max_message_bytes = params::MESSAGE_BYTES;
    result.max_exclusions = m; result.max_change_log = detail::log_limit(m);
    result.max_symbol_index = std::min(detail::MAX_SYMBOL_INDEX, detail::symbol_index_limit(m));
    result.max_pending = detail::pending_limit(m);
    result.max_fetch_records = result.max_pending; result.max_pending_fetch_union = result.max_pending;
    result.max_probation = detail::failure_limit(m); result.max_rejected = result.max_probation;
    result.max_local_rejected = result.max_probation; result.max_unavailable = result.max_probation;
    result.max_donors_per_id = std::min(peers, params::MAX_DONORS);
    result.max_donor_records = detail::donor_limit(m);
    result.max_plus = detail::membership_limit(m); result.max_minus = result.max_plus;
    result.reference_bound = m + result.max_plus;
    result.peer_floor_bytes = params::PEER_FLOOR_BYTES; result.node_floor_bytes = params::NODE_FLOOR_BYTES;
    out = result;
    return Error::ok;
}
Error session_symbol_limit(std::uint64_t snapshot_size, std::uint64_t declared_bound,
                           std::uint64_t &out) noexcept {
    constexpr std::uint64_t SYMBOL_FACTOR = 3;
    constexpr std::uint64_t SYMBOL_FIXED = 32;
    const auto result = SYMBOL_FACTOR * (static_cast<unsigned __int128>(snapshot_size) + declared_bound) + SYMBOL_FIXED;
    if (result > std::numeric_limits<std::uint64_t>::max()) return Error::overflow;
    out = static_cast<std::uint64_t>(result);
    return Error::ok;
}
} // namespace snowstorm
