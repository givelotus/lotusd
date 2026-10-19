// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_PAUSE_H
#define CHRONIK_NATIVE_PAUSE_H

#include <chronik/native/host.h>

#include <functional>
#include <memory>
#include <string_view>
#include <utility>

/**
 * Port of chronik-indexer pause.rs (-chronikallowpause, /pause, /resume).
 *
 * Rust uses a tokio watch channel holding the latest PauseMsg (initially
 * Resume). Pause::BlockIfPaused blocks the calling (event) thread while the
 * latest value is Pause; it returns once the value becomes Resume or the
 * PauseNotify is destroyed (Rust treats the closed channel as "resume").
 * Like a watch channel, only the latest value counts: a Pause/Resume/Pause
 * sequence that happens before the blocked thread wakes keeps it blocked.
 */
namespace chronik::native {

namespace detail {
struct PauseState;
}

/** "403: Pause is not allowed on this node; enable with -chronikallowpause" */
inline constexpr std::string_view PAUSE_NOT_ALLOWED_MSG =
    "403: Pause is not allowed on this node; enable with -chronikallowpause";
/** PauseNotifyError::NotifyFailed (declared in Rust, never returned). */
inline constexpr std::string_view PAUSE_NOTIFY_FAILED_MSG =
    "500: Failed notifying pause";
/**
 * What Rust actually reports when the Pause side is gone: the tokio watch
 * SendError, propagated through `?` (Display "channel closed").
 */
inline constexpr std::string_view PAUSE_CHANNEL_CLOSED_MSG = "channel closed";
/** Logged (log!, Info) when blocking. */
inline constexpr std::string_view PAUSE_BLOCKING_LOG_MSG =
    "Chronik is paused, resume by calling /resume. To disallow pausing on "
    "this node, remove the -chronikallowpause arg.\n";

using PauseLogFn = std::function<void(LogLevel, std::string_view)>;

class PauseNotify;

/** Allows blocking the thread until resumed by PauseNotify. */
class Pause {
public:
    /** Pause::new_pair */
    static std::pair<Pause, PauseNotify> NewPair(bool is_pause_allowed);

    Pause(Pause &&) noexcept;
    Pause &operator=(Pause &&) noexcept;
    Pause(const Pause &) = delete;
    Pause &operator=(const Pause &) = delete;
    ~Pause();

    /**
     * If we are paused, block until resumed by our corresponding PauseNotify
     * (or until it is destroyed). Otherwise, do nothing.
     */
    void BlockIfPaused(const PauseLogFn &log = {}) const;

    /** Whether the latest value is Pause (diagnostics/tests). */
    bool IsPaused() const;

private:
    explicit Pause(std::shared_ptr<detail::PauseState> state);
    void Release() noexcept;
    std::shared_ptr<detail::PauseState> m_state;
};

/**
 * Handle to pause/resume indexing any updates from the node. This fills up
 * the validation interface queue, so use with caution. Thread-safe (shared
 * by the HTTP handlers; Rust: Arc<PauseNotify>).
 */
class PauseNotify {
public:
    PauseNotify(PauseNotify &&) noexcept;
    PauseNotify &operator=(PauseNotify &&) noexcept;
    PauseNotify(const PauseNotify &) = delete;
    PauseNotify &operator=(const PauseNotify &) = delete;
    ~PauseNotify();

    /**
     * Pause the corresponding Pause, such that the next BlockIfPaused blocks.
     * No-op if already paused. Throws ChronikError(PAUSE_NOT_ALLOWED_MSG) if
     * pausing is not allowed, ChronikError(PAUSE_CHANNEL_CLOSED_MSG) if the
     * Pause was destroyed.
     */
    void DoPause() const;
    /** Resume; any pending BlockIfPaused returns immediately. */
    void Resume() const;

    bool IsPauseAllowed() const { return m_is_pause_allowed; }

private:
    friend class Pause;
    PauseNotify(std::shared_ptr<detail::PauseState> state, bool allowed);
    void Send(bool pause) const;
    void Release() noexcept;
    std::shared_ptr<detail::PauseState> m_state;
    bool m_is_pause_allowed;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_PAUSE_H
