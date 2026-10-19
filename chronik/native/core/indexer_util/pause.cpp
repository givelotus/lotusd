// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer pause.rs.

#include <chronik/native/pause.h>

#include <chronik/native/error.h>

#include <condition_variable>
#include <mutex>
#include <string>

namespace chronik::native {

namespace detail {
/** tokio watch::channel(PauseMsg::Resume) */
struct PauseState {
    std::mutex mu;
    std::condition_variable cv;
    bool paused = false;
    bool sender_alive = true;
    bool receiver_alive = true;
};
} // namespace detail

std::pair<Pause, PauseNotify> Pause::NewPair(bool is_pause_allowed) {
    auto state = std::make_shared<detail::PauseState>();
    return {Pause(state), PauseNotify(state, is_pause_allowed)};
}

Pause::Pause(std::shared_ptr<detail::PauseState> state)
    : m_state(std::move(state)) {}
Pause::Pause(Pause &&) noexcept = default;
Pause &Pause::operator=(Pause &&other) noexcept {
    if (this != &other) {
        Release();
        m_state = std::move(other.m_state);
    }
    return *this;
}
Pause::~Pause() { Release(); }
void Pause::Release() noexcept {
    if (m_state) {
        std::lock_guard lock(m_state->mu);
        m_state->receiver_alive = false;
    }
    m_state.reset();
}

bool Pause::IsPaused() const {
    if (!m_state) {
        return false;
    }
    std::lock_guard lock(m_state->mu);
    return m_state->paused;
}

void Pause::BlockIfPaused(const PauseLogFn &log) const {
    if (!m_state) {
        return;
    }
    std::unique_lock lock(m_state->mu);
    if (!m_state->paused) {
        return;
    }
    if (log) {
        lock.unlock();
        log(LogLevel::Info, PAUSE_BLOCKING_LOG_MSG);
        lock.lock();
    }
    // Closed channel (PauseNotify dropped) is treated as a "resume".
    m_state->cv.wait(lock,
                     [&] { return !m_state->paused || !m_state->sender_alive; });
}

PauseNotify::PauseNotify(std::shared_ptr<detail::PauseState> state,
                         bool allowed)
    : m_state(std::move(state)), m_is_pause_allowed(allowed) {}
PauseNotify::PauseNotify(PauseNotify &&) noexcept = default;
PauseNotify &PauseNotify::operator=(PauseNotify &&other) noexcept {
    if (this != &other) {
        Release();
        m_state = std::move(other.m_state);
        m_is_pause_allowed = other.m_is_pause_allowed;
    }
    return *this;
}
PauseNotify::~PauseNotify() { Release(); }
void PauseNotify::Release() noexcept {
    if (m_state) {
        {
            std::lock_guard lock(m_state->mu);
            m_state->sender_alive = false;
        }
        m_state->cv.notify_all();
    }
    m_state.reset();
}

void PauseNotify::DoPause() const { Send(true); }
void PauseNotify::Resume() const { Send(false); }

void PauseNotify::Send(bool pause) const {
    if (!m_is_pause_allowed) {
        throw ChronikError(std::string(PAUSE_NOT_ALLOWED_MSG));
    }
    if (!m_state) {
        throw ChronikError(std::string(PAUSE_CHANNEL_CLOSED_MSG));
    }
    {
        std::lock_guard lock(m_state->mu);
        // watch::Sender::send fails (value not stored) without receivers
        if (!m_state->receiver_alive) {
            throw ChronikError(std::string(PAUSE_CHANNEL_CLOSED_MSG));
        }
        m_state->paused = pause;
    }
    m_state->cv.notify_all();
}

} // namespace chronik::native
