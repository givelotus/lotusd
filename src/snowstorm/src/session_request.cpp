// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "session_request.h"
#include "params.h"
#include "range_validation.h"
#include <algorithm>
#include <limits>
namespace snowstorm::detail {
SessionRequest::SessionRequest(Time rtt) noexcept : rtt_(std::max(params::MIN_RTT, rtt)) {}
Error SessionRequest::next_deadline(Time now, Time &deadline) const noexcept {
    constexpr auto maximum = std::numeric_limits<Time>::max();
    if (rtt_ > (maximum - now) / params::RETRANSMIT_FACTOR) return Error::overflow;
    deadline = now + params::RETRANSMIT_FACTOR * rtt_;
    return Error::ok;
}
Error SessionRequest::begin(SessionId session, RequestId request, PollId poll,
                            std::span<const Range> ranges, Time now, const Limits &limits) {
    if (request_ != 0 || session == 0 || request == 0 || now < 0) return Error::invalid_argument;
    std::uint64_t count = 0;
    const auto error = detail::check_ranges(ranges, limits, count);
    if (error != Error::ok) return error;
    Time deadline = 0;
    const auto timing = next_deadline(now, deadline);
    if (timing != Error::ok) return timing;
    std::vector<Range> prepared(ranges.begin(), ranges.end());
    ranges_.swap(prepared);
    session_ = session;
    request_ = request;
    poll_ = poll;
    original_ = latest_ = now;
    repeated_ = false;
    deadline_ = deadline;
    return Error::ok;
}
Error SessionRequest::resend(PollId poll, Time now) noexcept {
    if (request_ == 0) return Error::not_found;
    if (now < latest_) return Error::nonmonotonic_time;
    Time deadline = 0;
    const auto timing = next_deadline(now, deadline);
    if (timing != Error::ok) return timing;
    latest_ = now;
    poll_ = poll;
    repeated_ = true;
    deadline_ = deadline;
    return Error::ok;
}
bool SessionRequest::due(Time now) const noexcept {
    return request_ != 0 && deadline_ && now >= *deadline_;
}
bool SessionRequest::matches(const ReconSymbols &response) const noexcept {
    return request_ != 0 && response.session_id == session_ && response.request_id == request_;
}
Error SessionRequest::check_ranges(const ReconSymbols &response) const noexcept {
    if (!matches(response)) return Error::not_found;
    if (response.status != SymbolsStatus::normal) return Error::ok;
    if (!std::equal(ranges_.begin(), ranges_.end(), response.ranges.begin(), response.ranges.end(),
                    [](Range a, Range b) { return a.begin == b.begin && a.end == b.end; }))
        return Error::invalid_range;
    std::uint64_t count = 0;
    for (const auto &range : ranges_) count += range.end - range.begin;
    return count == response.cells.size() ? Error::ok : Error::malformed_message;
}
Error SessionRequest::complete(Time now) noexcept {
    if (request_ == 0) return Error::not_found;
    if (now < latest_) return Error::nonmonotonic_time;
    const auto elapsed = std::max(params::MIN_RTT, now - original_);
    rtt_ = repeated_ ? std::max(rtt_, elapsed) : elapsed;
    cancel();
    return Error::ok;
}
void SessionRequest::cancel() noexcept {
    session_ = request_ = poll_ = 0;
    deadline_.reset();
    std::vector<Range>().swap(ranges_);
    repeated_ = false;
}
} // namespace snowstorm::detail
