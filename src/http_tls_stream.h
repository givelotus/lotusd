// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTP_TLS_STREAM_H
#define BITCOIN_HTTP_TLS_STREAM_H

#include <tls_util.h>

#include <boost/asio/async_result.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core/buffers_range.hpp>
#include <boost/beast/core/role.hpp>
#include <boost/beast/core/tcp_stream.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <boost/asio/buffer.hpp>

#include <climits>
#include <vector>
#include <utility>

/**
 * An asio AsyncStream (for Beast HTTP and WebSocket) over an OpenSSL session
 * bound directly to the TCP socket with SSL_set_fd, instead of asio's
 * ssl::stream (which keeps TLS state in its own memory BIOs). Owning the
 * SSL* this way lets the HTTP server hand an upgraded /p2p/ws connection,
 * TLS session and all, to CConnman (see ReleaseSsl()).
 *
 * SSL_ERROR_WANT_READ/WANT_WRITE wait for socket readiness with
 * async_wait. Operations that complete immediately are re-posted, never
 * completed inline.
 */
class OsslStream {
public:
    using next_layer_type = boost::beast::tcp_stream;
    using executor_type = next_layer_type::executor_type;

    OsslStream(next_layer_type &next, tls::SslPtr ssl)
        : m_next{next}, m_ssl{std::move(ssl)} {}

    executor_type get_executor() { return m_next.get_executor(); }
    next_layer_type &next_layer() { return m_next; }
    const next_layer_type &next_layer() const { return m_next; }
    SSL *native_handle() const { return m_ssl.get(); }

    /** Give up the session (with the stream no longer used) */
    tls::SslPtr ReleaseSsl() { return std::move(m_ssl); }

    template <typename MutableBuffers, typename Token>
    auto async_read_some(const MutableBuffers &buffers, Token &&token) {
        // Reading into no buffer space succeeds with 0 bytes.
        const bool empty{boost::asio::buffer_size(buffers) == 0};
        return Run<std::size_t>(
            [this, buffers]() {
                for (const auto &b : boost::beast::buffers_range_ref(buffers)) {
                    if (b.size() > 0) {
                        return SSL_read(m_ssl.get(), b.data(),
                                        int(std::min<std::size_t>(b.size(),
                                                                  INT_MAX)));
                    }
                }
                return 0;
            },
            std::forward<Token>(token), /*zero_is_eof=*/true, empty);
    }

    template <typename ConstBuffers, typename Token>
    auto async_write_some(const ConstBuffers &buffers, Token &&token) {
        const bool empty{boost::asio::buffer_size(buffers) == 0};
        return Run<std::size_t>(
            [this, buffers]() { return WriteGathered(buffers); },
            std::forward<Token>(token), /*zero_is_eof=*/false, empty);
    }

    /**
     * Non-blocking synchronous write (Beast SyncWriteStream): what fits now,
     * or error::would_block. Lets callers skip the scheduler when the socket
     * has room, as on plain TCP.
     */
    template <typename ConstBuffers>
    std::size_t write_some(const ConstBuffers &buffers) {
        boost::system::error_code ec;
        const std::size_t n{write_some(buffers, ec)};
        if (ec) {
            throw boost::system::system_error{ec};
        }
        return n;
    }

    template <typename ConstBuffers>
    std::size_t write_some(const ConstBuffers &buffers,
                           boost::system::error_code &ec) {
        ec = {};
        if (boost::asio::buffer_size(buffers) == 0) {
            return 0;
        }
        ERR_clear_error();
        const int n{WriteGathered(buffers)};
        if (n > 0) {
            return std::size_t(n);
        }
        const int err{SSL_get_error(m_ssl.get(), n)};
        ec = err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE
                 ? make_error_code(boost::asio::error::would_block)
                 : make_error_code(boost::asio::error::connection_reset);
        return 0;
    }

    /** Server-side TLS handshake */
    template <typename Token> auto async_handshake(Token &&token) {
        SSL_set_accept_state(m_ssl.get());
        return Run<int>([this]() { return SSL_do_handshake(m_ssl.get()); },
                        std::forward<Token>(token), /*zero_is_eof=*/false);
    }

    /** Send close_notify once (not waiting for the peer's) */
    void shutdown(boost::system::error_code &ec) {
        ec = {};
        if (m_ssl) {
            ERR_clear_error();
            (void)SSL_shutdown(m_ssl.get());
        }
    }

private:
    //! Largest write coalesced into one TLS record batch
    static constexpr std::size_t MAX_GATHER = 64 * 1024;

    /**
     * SSL_write the start of `buffers`, coalescing a multi-buffer sequence
     * (e.g. HTTP header + body) so it becomes one TLS record and syscall.
     * A write OpenSSL asked to retry is retried with exactly the same length.
     */
    template <typename ConstBuffers>
    int WriteGathered(const ConstBuffers &buffers) {
        const std::size_t total{boost::asio::buffer_size(buffers)};
        std::size_t len{std::min<std::size_t>(total, INT_MAX)};
        const auto first{*boost::asio::buffer_sequence_begin(buffers)};
        const void *data{first.data()};
        if (first.size() < len) {
            // More than one buffer: gather (bounded) into one write.
            len = std::min(len, MAX_GATHER);
            if (m_retry_len != 0) {
                len = m_retry_len;
            }
            m_gather.resize(len);
            boost::asio::buffer_copy(boost::asio::buffer(m_gather), buffers);
            data = m_gather.data();
        } else if (m_retry_len != 0) {
            len = m_retry_len;
        }
        const int n{SSL_write(m_ssl.get(), data, int(len))};
        if (n > 0) {
            m_retry_len = 0;
        } else {
            const int err{SSL_get_error(m_ssl.get(), n)};
            m_retry_len = (err == SSL_ERROR_WANT_READ ||
                           err == SSL_ERROR_WANT_WRITE)
                              ? len
                              : 0;
        }
        return n;
    }

    /**
     * Run `attempt` (an OpenSSL call returning >0 on success) until it
     * succeeds or fails, waiting for socket readiness as OpenSSL asks.
     * Completion signature: void(error_code, Result).
     */
    template <typename Result, typename Attempt, typename Token>
    auto Run(Attempt attempt, Token &&token, bool zero_is_eof,
             bool empty = false) {
        enum class State { START, WAITED, DONE };
        return boost::asio::async_compose<Token, void(boost::system::error_code,
                                                      Result)>(
            [this, attempt, zero_is_eof, empty, state = State::START,
             result_ec = boost::system::error_code{}, result = Result{}](
                auto &self, boost::system::error_code ec = {}) mutable {
                if (state == State::DONE) {
                    return self.complete(result_ec, result);
                }
                if (state == State::WAITED && ec) {
                    return self.complete(ec, Result{});
                }
                const bool initiating{state == State::START};
                if (!m_ssl) {
                    result_ec = boost::asio::error::bad_descriptor;
                    state = State::DONE;
                    boost::asio::post(m_next.get_executor(), std::move(self));
                    return;
                }
                ERR_clear_error();
                const int n{empty ? 0 : attempt()};
                if (empty) {
                    result = Result{};
                } else if (n > 0) {
                    result = Result(n);
                } else {
                    const int err{SSL_get_error(m_ssl.get(), n)};
                    if (err == SSL_ERROR_WANT_READ ||
                        err == SSL_ERROR_WANT_WRITE) {
                        state = State::WAITED;
                        m_next.socket().async_wait(
                            err == SSL_ERROR_WANT_READ
                                ? boost::asio::socket_base::wait_read
                                : boost::asio::socket_base::wait_write,
                            std::move(self));
                        return;
                    }
                    if (err == SSL_ERROR_ZERO_RETURN ||
                        (zero_is_eof && err == SSL_ERROR_SYSCALL && n == 0)) {
                        result_ec = boost::asio::error::eof;
                    } else {
                        result_ec = boost::asio::error::connection_reset;
                    }
                }
                if (!initiating) {
                    // Resumed by async_wait: already on a fresh stack.
                    return self.complete(result_ec, result);
                }
                // Never complete inline from the initiating call.
                state = State::DONE;
                boost::asio::post(m_next.get_executor(), std::move(self));
            },
            token, m_next);
    }

    next_layer_type &m_next;
    tls::SslPtr m_ssl;
    std::vector<unsigned char> m_gather;
    //! Length of a write OpenSSL must see again (0: none pending)
    std::size_t m_retry_len{0};
};

/** Beast WebSocket teardown for OsslStream: close_notify, then TCP */
inline void teardown(boost::beast::role_type, OsslStream &stream,
                     boost::system::error_code &ec) {
    stream.shutdown(ec);
    stream.next_layer().socket().shutdown(
        boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = {};
}

template <typename TeardownHandler>
void async_teardown(boost::beast::role_type role, OsslStream &stream,
                    TeardownHandler &&handler) {
    boost::system::error_code ec;
    teardown(role, stream, ec);
    boost::asio::post(stream.get_executor(),
                      [h = std::forward<TeardownHandler>(handler),
                       ec]() mutable { h(ec); });
}

#endif // BITCOIN_HTTP_TLS_STREAM_H
