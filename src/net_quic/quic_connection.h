// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_CONNECTION_H
#define BITCOIN_NET_QUIC_QUIC_CONNECTION_H

// Internal to the QUIC engine (net_quic/*.cpp): includes ngtcp2 and OpenSSL.
// Everything here runs on the engine thread only.

#include <net_quic/udp_socket.h>
#include <netaddress.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <openssl/ssl.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

class QuicConnection;

/** Monotonic nanoseconds, the clock ngtcp2 timestamps use */
uint64_t QuicNow();
/** Wall-clock nanoseconds (address validation tokens) */
uint64_t QuicSystemNow();

/** Bytes queued on a stream we write ourselves; kept until acknowledged
 * because ngtcp2 does not copy stream data */
struct QuicTxChunk {
    std::vector<uint8_t> data;
    size_t sent{0};
    size_t acked{0};
};

struct QuicStream {
    enum class Kind {
        //! A peer stream whose first bytes have not been classified yet
        PENDING,
        //! Written by a library (nghttp3): data, acks and blocking are
        //! reported to the application
        LIBRARY,
        //! Written from `txq` by the connection itself
        OWN,
        //! Ignored (refused/closed by us); data is discarded
        IGNORED,
    };
    int64_t id{-1};
    Kind kind{Kind::PENDING};
    //! Send priority among OWN streams (lower first)
    int priority{0};
    bool blocked{false};
    bool fin_queued{false};
    bool fin_sent{false};
    bool shut_wr{false};
    std::deque<QuicTxChunk> txq;
    //! Bytes in txq not yet handed to ngtcp2
    uint64_t unsent{0};
    //! Bytes received before the stream's kind was known
    std::vector<uint8_t> pending;
    //! Opaque per-stream value for the application
    uint64_t app_tag{0};

    bool WantsWrite() const {
        return !blocked && !shut_wr &&
               (unsent > 0 || (fin_queued && !fin_sent));
    }
};

/**
 * What runs on top of a QUIC connection (HTTP/3 + WebTransport, or the
 * test echo). Callbacks return 0, or an ngtcp2 error code to fail the
 * connection.
 */
class QuicApp {
public:
    virtual ~QuicApp() = default;
    //! The TLS handshake completed (called before any 1-RTT stream data)
    virtual int OnHandshakeCompleted(QuicConnection &conn) { return 0; }
    //! Data on a peer or local stream; `stream.kind` may be PENDING
    virtual int OnStreamData(QuicConnection &conn, QuicStream &stream,
                             uint32_t flags, const uint8_t *data,
                             size_t len) = 0;
    virtual void OnStreamClose(QuicConnection &conn, int64_t stream_id,
                               bool app_error_set, uint64_t app_error) {}
    virtual void OnStreamReset(QuicConnection &conn, int64_t stream_id,
                               uint64_t app_error) {}
    virtual void OnStreamStopSending(QuicConnection &conn, int64_t stream_id,
                                     uint64_t app_error) {}
    //! LIBRARY streams: acknowledged / unblocked
    virtual int OnLibraryAcked(QuicConnection &conn, int64_t stream_id,
                               uint64_t datalen) {
        return 0;
    }
    virtual void OnLibraryUnblocked(QuicConnection &conn, int64_t stream_id) {}
    virtual void OnMaxRemoteStreamsBidi(QuicConnection &conn, uint64_t max) {}
    virtual void OnDatagram(QuicConnection &conn, const uint8_t *data,
                            size_t len) {}
    /**
     * Data a library wants written: fills `vec`, sets `stream_id` (-1 if
     * none) and `fin`. Returns the vector count or a negative error.
     */
    virtual ngtcp2_ssize WritevLibrary(QuicConnection &conn,
                                       int64_t &stream_id, int &fin,
                                       ngtcp2_vec *vec, size_t veccnt) {
        stream_id = -1;
        fin = 0;
        return 0;
    }
    virtual int OnLibraryWritten(QuicConnection &conn, int64_t stream_id,
                                 size_t datalen) {
        return 0;
    }
    virtual void OnLibraryBlocked(QuicConnection &conn, int64_t stream_id) {}
    virtual void OnLibraryShutWr(QuicConnection &conn, int64_t stream_id) {}
    //! Before each write pass: move queued data onto streams
    virtual void BeforeWrite(QuicConnection &conn) {}
    //! Application timer (UINT64_MAX: none) and its handler
    virtual uint64_t NextTimer() const { return UINT64_MAX; }
    virtual void OnTimer(QuicConnection &conn, uint64_t now) {}
    //! The connection is closing or closed (called once)
    virtual void OnClosed(QuicConnection &conn) {}
};

class QuicEngineCore;

/** One QUIC connection (server or client role) */
class QuicConnection {
public:
    enum class State { HANDSHAKING, ESTABLISHED, CLOSING, DRAINING, DEAD };

    QuicConnection(QuicEngineCore &engine, bool server, UdpSocket &sock,
                   const sockaddr_storage &local, socklen_t local_len,
                   const sockaddr_storage &remote, socklen_t remote_len);
    ~QuicConnection();
    QuicConnection(const QuicConnection &) = delete;
    QuicConnection &operator=(const QuicConnection &) = delete;

    bool IsServer() const { return m_server; }
    State GetState() const { return m_state; }
    bool HandshakeDone() const { return m_handshake_done; }
    bool IsOpen() const {
        return m_state == State::HANDSHAKING || m_state == State::ESTABLISHED;
    }
    ngtcp2_conn *Conn() const { return m_conn; }
    SSL *Ssl() const { return m_ssl; }
    const CService &Remote() const { return m_remote_service; }
    const CService &Local() const { return m_local_service; }
    QuicEngineCore &Engine() { return m_engine; }

    void SetApp(std::unique_ptr<QuicApp> app) { m_app = std::move(app); }
    QuicApp *App() { return m_app.get(); }

    /** Create the ngtcp2 connection and TLS session (see quic_engine.cpp) */
    bool InitServer(const ngtcp2_pkt_hd &hd, const ngtcp2_cid *ocid,
                    ngtcp2_token_type token_type);
    bool InitClient(const std::string &sni);

    //! Feed a received datagram
    void Read(const UdpDatagram &dgram, uint64_t now);
    //! Write as many packets as congestion control and pacing allow
    void Write(uint64_t now);
    //! Handle an expired ngtcp2 or application timer
    void HandleExpiry(uint64_t now);
    //! The earliest time Write()/HandleExpiry() has work
    uint64_t NextExpiry() const;

    /** Close with an application error (CONNECTION_CLOSE, closing period) */
    void CloseApp(uint64_t app_error, const std::string &reason = "");
    /** Close with a transport/library error */
    void CloseLib(int liberr);
    //! Drop without sending anything
    void Kill();
    //! Time after which a closing/draining connection is forgotten
    uint64_t CloseDeadline() const { return m_close_deadline; }

    QuicStream &Stream(int64_t id);
    QuicStream *FindStream(int64_t id);
    std::map<int64_t, QuicStream> &Streams() { return m_streams; }

    /** Open a local bidirectional/unidirectional stream (-1 if none
     * allowed now) */
    int64_t OpenStream(bool bidi, QuicStream::Kind kind, int priority = 0);
    /** Queue bytes (and optionally FIN) on an OWN stream */
    void QueueStreamData(QuicStream &stream, std::vector<uint8_t> &&data,
                         bool fin = false);
    /** Queue an HTTP/3 datagram payload (sent before stream data; dropped
     * if datagrams were not negotiated or it is too large) */
    void QueueDatagram(std::vector<uint8_t> &&payload);
    /** Let the peer send `n` more bytes on the stream (and connection) */
    void ExtendCredit(int64_t stream_id, uint64_t n);
    /** Stop reading and writing a stream with an application error */
    void ShutdownStream(int64_t stream_id, uint64_t app_error);

    //! Registered connection IDs (the engine's routing keys)
    std::vector<std::string> &Cids() { return m_cids; }
    //! Time of the first handshake packet
    uint64_t Created() const { return m_created; }
    //! Set by another thread to make the engine drop the connection
    std::shared_ptr<std::atomic<bool>> &CancelFlag() { return m_cancel; }

    void OnHandshakeCompletedInternal();
    void OnAckedOwn(QuicStream &stream, uint64_t datalen);

private:
    bool InitTls(bool server, const std::string &sni);
    void SendPacket(const uint8_t *data, size_t len);
    void StartClosing(const ngtcp2_ccerr &err);
    void EnterDraining(uint64_t now);
    QuicStream *PickOwnStream();
    void AccountWritten(QuicStream &stream, size_t datalen, bool fin);
    uint64_t Clamp(uint64_t now);

    QuicEngineCore &m_engine;
    const bool m_server;
    UdpSocket &m_sock;
    sockaddr_storage m_local{};
    socklen_t m_local_len{0};
    sockaddr_storage m_remote{};
    socklen_t m_remote_len{0};
    CService m_local_service;
    CService m_remote_service;

    ngtcp2_conn *m_conn{nullptr};
    ngtcp2_crypto_ossl_ctx *m_ossl{nullptr};
    SSL *m_ssl{nullptr};
    ngtcp2_crypto_conn_ref m_ref{};
    std::unique_ptr<QuicApp> m_app;

    State m_state{State::HANDSHAKING};
    bool m_app_closed{false};
    bool m_handshake_done{false};
    uint64_t m_close_deadline{0};
    std::vector<uint8_t> m_close_pkt;
    std::map<int64_t, QuicStream> m_streams;
    //! Round-robin among OWN streams of equal priority
    int64_t m_rr_last{-1};
    std::vector<std::string> m_cids;
    uint64_t m_created{0};
    uint64_t m_last_ts{0};
    std::vector<uint8_t> m_txbuf;
    std::deque<std::vector<uint8_t>> m_datagrams;
    uint64_t m_next_datagram_id{1};
    std::shared_ptr<std::atomic<bool>> m_cancel;
};

/**
 * What a connection needs from its engine (implemented in quic_engine.cpp).
 */
class QuicEngineCore {
public:
    virtual ~QuicEngineCore() = default;
    virtual void RegisterCid(QuicConnection &conn, const ngtcp2_cid &cid) = 0;
    virtual void UnregisterCid(QuicConnection &conn, const ngtcp2_cid &cid) = 0;
    //! Secret for stateless reset tokens (never rotated: a reset must be
    //! recognisable for the lifetime of every connection ID issued)
    virtual const uint8_t *Secret() const = 0;
    virtual size_t SecretLen() const = 0;
    //! Secret for address validation tokens (current generation)
    virtual const uint8_t *TokenSecret() const = 0;
    virtual SSL_CTX *ServerContext() = 0;
    virtual SSL_CTX *ClientContext() = 0;
    virtual void FillSettings(ngtcp2_settings &settings,
                              ngtcp2_transport_params &params, bool server,
                              uint64_t now) = 0;
    virtual void OnPacketSent(size_t bytes) = 0;
    virtual void OnHandshakeDone(QuicConnection &conn) = 0;
    virtual void OnIdleClose(QuicConnection &conn) = 0;
};

#endif // BITCOIN_NET_QUIC_QUIC_CONNECTION_H
