// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/messages.h>
namespace snowstorm::detail {
/** Single logical request. Poll reissues preserve its immutable data identity.
 * The owner validates immutable response metadata before calling complete().
 */
class SessionRequest {
    SessionId session_{};
    RequestId request_{};
    PollId poll_{};
    Time original_{}, latest_{}, rtt_{1};
    std::optional<Time> deadline_;
    std::vector<Range> ranges_;
    bool repeated_{};
    Error next_deadline(Time now, Time &deadline) const noexcept;
public:
    explicit SessionRequest(Time rtt) noexcept;
    Error begin(SessionId session, RequestId request, PollId poll,
                std::span<const Range> ranges, Time now, const Limits &limits);
    Error resend(PollId poll, Time now) noexcept;
    bool due(Time now) const noexcept;
    bool matches(const ReconSymbols &response) const noexcept;
    Error check_ranges(const ReconSymbols &response) const noexcept;
    Error complete(Time now) noexcept;
    void cancel() noexcept;
    SessionId session() const noexcept { return session_; }
    RequestId request() const noexcept { return request_; }
    PollId poll() const noexcept { return poll_; }
    Time rtt() const noexcept { return rtt_; }
    Time original_sent() const noexcept { return original_; }
    Time latest_sent() const noexcept { return latest_; }
    std::optional<Time> deadline() const noexcept { return deadline_; }
    std::span<const Range> ranges() const noexcept { return ranges_; }
    std::size_t ranges_capacity() const noexcept { return ranges_.capacity(); }
};
} // namespace snowstorm::detail
