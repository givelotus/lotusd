// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_tls.h>

#include <logging.h>

#include <openssl/err.h>

#include <cerrno>
#include <climits>

TlsByteLayer::TlsByteLayer(tls::SslPtr ssl) : m_ssl{std::move(ssl)} {}

ssize_t TlsByteLayer::Translate(int ret, Sock::Event *wait) {
    if (ret > 0) {
        return ret;
    }
    const int err{SSL_get_error(m_ssl.get(), ret)};
    switch (err) {
        case SSL_ERROR_WANT_READ:
            if (wait) {
                *wait = Sock::RECV;
            }
            errno = EAGAIN;
            return -1;
        case SSL_ERROR_WANT_WRITE:
            if (wait) {
                *wait = Sock::SEND;
            }
            errno = EAGAIN;
            return -1;
        case SSL_ERROR_ZERO_RETURN:
            // Orderly TLS close_notify.
            return 0;
        case SSL_ERROR_SYSCALL:
            if (errno == 0) {
                errno = ECONNRESET;
            }
            return -1;
        default:
            LogDebug(BCLog::NET, "WebSocket TLS error: %s\n",
                     tls::ErrorString());
            errno = ECONNRESET;
            return -1;
    }
}

ssize_t TlsByteLayer::Read(SOCKET fd, uint8_t *buf, size_t len) {
    ERR_clear_error();
    const int n{SSL_read(m_ssl.get(), buf, int(std::min<size_t>(len, INT_MAX)))};
    return Translate(n, nullptr);
}

ssize_t TlsByteLayer::Write(SOCKET fd, const uint8_t *buf, size_t len) {
    // OpenSSL requires a retried write to repeat the same length.
    len = m_retry_len != 0 ? std::min(len, m_retry_len)
                           : std::min<size_t>(len, INT_MAX);
    ERR_clear_error();
    const int n{SSL_write(m_ssl.get(), buf, int(len))};
    Sock::Event wait{Sock::SEND};
    const ssize_t r{Translate(n, &wait)};
    const bool again{r < 0 && errno == EAGAIN};
    m_retry_len = again ? len : 0;
    // A write can need to read first (e.g. a TLS 1.3 KeyUpdate exchange).
    m_write_waits_for = again ? wait : Sock::SEND;
    return r;
}

bool TlsByteLayer::HasBuffered() const {
    return SSL_pending(m_ssl.get()) > 0;
}

void TlsByteLayer::Shutdown(SOCKET fd) {
    if (!m_shutdown) {
        m_shutdown = true;
        ERR_clear_error();
        // One non-blocking attempt to send close_notify.
        (void)SSL_shutdown(m_ssl.get());
    }
}
