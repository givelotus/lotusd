// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_TLS_H
#define BITCOIN_NET_WEBSOCKET_TLS_H

#include <net_websocket_sock.h>
#include <tls_util.h>

/**
 * TLS beneath WebSocketSock: an OpenSSL session bound to the socket itself
 * (SSL_set_fd), driven non-blocking. With kernel TLS available (Linux,
 * SSL_OP_ENABLE_KTLS), OpenSSL offloads record encryption to the kernel
 * behind the same calls.
 *
 * OpenSSL's socket BIO writes with write(), not send(MSG_NOSIGNAL): a write
 * after the peer closed raises SIGPIPE on Linux, which the node ignores
 * (AppInitBasicSetup). A custom BIO would avoid that but lose kernel TLS.
 *
 * The handshake has completed before the layer is constructed.
 */
class TlsByteLayer final : public WebSocketByteLayer {
public:
    explicit TlsByteLayer(tls::SslPtr ssl);

    ssize_t Read(SOCKET fd, uint8_t *buf, size_t len) override;
    ssize_t Write(SOCKET fd, const uint8_t *buf, size_t len) override;
    bool HasBuffered() const override;
    Sock::Event WriteWaitsFor() const override { return m_write_waits_for; }
    Sock::Event ReadWaitsFor() const override { return m_read_waits_for; }
    void Shutdown(SOCKET fd) override;
    bool IsTLS() const override { return true; }

    SSL *Native() const { return m_ssl.get(); }

private:
    //! Map an OpenSSL result to the recv/send convention; `wait` receives
    //! the OS event a WANT_READ/WANT_WRITE needs.
    ssize_t Translate(int ret, Sock::Event *wait);

    const tls::SslPtr m_ssl;
    Sock::Event m_write_waits_for{Sock::SEND};
    Sock::Event m_read_waits_for{Sock::RECV};
    //! Length of a write OpenSSL must see again (0: none pending). The
    //! caller's buffer only grows at the end, so the bytes are unchanged.
    size_t m_retry_len{0};
    bool m_shutdown{false};
};

#endif // BITCOIN_NET_WEBSOCKET_TLS_H
