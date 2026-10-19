// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_JOURNAL_H
#define BITCOIN_LOGGING_JOURNAL_H

#include <string>
#include <string_view>

namespace BCLog {
/** Native journald transport, used only by the logger thread. No libsystemd. */
class JournalSink {
    int m_fd{-1};
    std::string m_path;
    bool SendOnce(std::string_view entry);

public:
    JournalSink() = default;
    ~JournalSink();
    JournalSink(const JournalSink &) = delete;
    JournalSink &operator=(const JournalSink &) = delete;
    bool Open(std::string_view path = "/run/systemd/journal/socket");
    void Close();
    /** One entry, using a sealed memfd if too large for a datagram. */
    bool Send(std::string_view entry);
};
} // namespace BCLog
#endif // BITCOIN_LOGGING_JOURNAL_H
