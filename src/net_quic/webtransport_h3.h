// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_WEBTRANSPORT_H3_H
#define BITCOIN_NET_QUIC_WEBTRANSPORT_H3_H

// Internal to the QUIC engine: HTTP/3 (nghttp3) and the WebTransport
// session on top of one QUIC connection. Engine thread only.

#include <net_quic/quic_connection.h>
#include <net_webtransport.h>

#include <nghttp3/nghttp3.h>

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class H3Session;

/** The extended CONNECT as the server saw it */
struct WtRequest {
    std::string method;
    std::string protocol;
    std::string scheme;
    std::string authority;
    std::string path;
    std::string origin;
    std::string available_protocols;
    bool draft02_header{false};
    std::string status;
    std::string wt_protocol;
};

/**
 * Receives what happens to the WebTransport session of one connection (the
 * P2P bridge, or tests). Engine thread.
 */
class WtSessionHandler {
public:
    virtual ~WtSessionHandler() = default;
    //! The TLS handshake completed: check the peer (pins); false closes
    virtual bool OnHandshake(H3Session &session, QuicConnection &conn) {
        return true;
    }
    //! Server: the request passed the path/token/origin checks; return the
    //! status to answer (200 accepts, 503 when nobody takes sessions)
    virtual int OnConnect(H3Session &session, const WtRequest &request) {
        return 200;
    }
    //! The CONNECT was answered (client: the status received)
    virtual void OnConnectResponse(H3Session &session, int status) {}
    //! All five class streams exist (server: seen; client: opened)
    virtual void OnSessionReady(H3Session &session) = 0;
    //! Bytes on a class stream. The handler extends the stream's flow
    //! control credit (H3Session::ExtendCredit) as it consumes them.
    virtual void OnClassData(H3Session &session, StreamClass cls,
                             const uint8_t *data, size_t len, bool fin) = 0;
    //! The session ended (close capsule, CONNECT stream end, connection
    //! end); called once
    virtual void OnSessionClosed(H3Session &session, uint32_t code,
                                 const std::string &reason) = 0;
    //! Before each write pass
    virtual void BeforeWrite(H3Session &session) {}
};

struct H3Options {
    bool server{false};
    //! Server: the accepted request path. Client: the request path.
    std::string path{P2P_WEBTRANSPORT_PATH};
    //! Server: accepted Origin values (empty: any)
    std::vector<std::string> origins;
    //! Server: required access token (?t=); client: token to send
    std::string token;
    //! Client: :authority, Origin (empty: none, as a node) and :protocol
    std::string authority;
    std::string origin;
    std::string protocol_token{"webtransport-h3"};
    //! Client: wt-available-protocols to offer (empty: no header)
    std::vector<std::string> offer{P2P_WT_PROTOCOL_V1};
    //! Server: application protocols supported, in preference order
    std::vector<std::string> supported{P2P_WT_PROTOCOL_V1};
    //! Server (tests, browser interop): echo WebTransport streams and
    //! datagrams instead of running the P2P class-stream protocol
    bool echo{false};
    //! Client: how long to wait for the server's SETTINGS
    uint64_t settings_timeout_ns{500 * NGTCP2_MILLISECONDS};
};

/** HTTP/3 + WebTransport on one QUIC connection */
class H3Session final : public QuicApp {
public:
    H3Session(const H3Options &options,
              std::unique_ptr<WtSessionHandler> handler);
    ~H3Session() override;

    // QuicApp
    int OnHandshakeCompleted(QuicConnection &conn) override;
    int OnStreamData(QuicConnection &conn, QuicStream &stream, uint32_t flags,
                     const uint8_t *data, size_t len) override;
    void OnStreamClose(QuicConnection &conn, int64_t stream_id,
                       bool app_error_set, uint64_t app_error) override;
    void OnStreamReset(QuicConnection &conn, int64_t stream_id,
                       uint64_t app_error) override;
    void OnStreamStopSending(QuicConnection &conn, int64_t stream_id,
                             uint64_t app_error) override;
    int OnLibraryAcked(QuicConnection &conn, int64_t stream_id,
                       uint64_t datalen) override;
    void OnLibraryUnblocked(QuicConnection &conn, int64_t stream_id) override;
    void OnMaxRemoteStreamsBidi(QuicConnection &conn, uint64_t max) override;
    void OnDatagram(QuicConnection &conn, const uint8_t *data,
                    size_t len) override;
    ngtcp2_ssize WritevLibrary(QuicConnection &conn, int64_t &stream_id,
                               int &fin, ngtcp2_vec *vec,
                               size_t veccnt) override;
    int OnLibraryWritten(QuicConnection &conn, int64_t stream_id,
                         size_t datalen) override;
    void OnLibraryBlocked(QuicConnection &conn, int64_t stream_id) override;
    void OnLibraryShutWr(QuicConnection &conn, int64_t stream_id) override;
    void BeforeWrite(QuicConnection &conn) override;
    uint64_t NextTimer() const override;
    void OnTimer(QuicConnection &conn, uint64_t now) override;
    void OnClosed(QuicConnection &conn) override;

    QuicConnection *Conn() { return m_conn; }
    WtSessionHandler *Handler() { return m_handler.get(); }
    const H3Options &Options() const { return m_opts; }

    /** Queue bytes on a class stream (after OnSessionReady) */
    void QueueClassData(StreamClass cls, std::vector<uint8_t> &&data);
    /** Unsent bytes on a class stream */
    uint64_t ClassUnsent(StreamClass cls) const;
    /** Allow the peer `n` more bytes on a class stream */
    void ExtendCredit(StreamClass cls, uint64_t n);
    /** End the session: WT_CLOSE_SESSION + FIN, then the connection */
    void CloseSession(uint32_t code, const std::string &reason);

    bool Ready() const { return m_ready; }
    bool Closed() const { return m_session_closed; }
    //! The CONNECT stream (session id), -1 before the request
    int64_t SessionId() const { return m_session_id; }
    //! Rank of the newest WebTransport draft the peer announced (see
    //! wt::DraftRank) and its SETTINGS identifier
    int PeerDraftRank() const { return m_peer_draft_rank; }
    uint64_t PeerDraftSetting() const { return m_peer_draft_setting; }
    //! The negotiated wt-protocol ("" if none)
    const std::string &Protocol() const { return m_protocol; }
    const WtRequest &Request() const { return m_request; }
    //! Datagrams received and dropped (no P2P use)
    uint64_t DatagramsDropped() const { return m_datagrams_dropped; }
    //! Tests: a second CONNECT on the same connection; its status is given
    //! to the handler's OnConnectResponse
    void SubmitExtraConnectForTest();

    // nghttp3 callbacks (static trampolines in the .cpp)
    int OnBeginHeaders(int64_t stream_id);
    int OnHeader(int64_t stream_id, std::string_view name,
                 std::string_view value);
    int OnEndHeaders(int64_t stream_id, int fin);
    int OnRecvData(int64_t stream_id, const uint8_t *data, size_t len);
    int OnEndStream(int64_t stream_id);
    void OnPeerSettings(const nghttp3_proto_settings &settings);
    void OnExtraSetting(uint64_t id, uint64_t value);
    nghttp3_ssize ReadConnectBody(int64_t stream_id, nghttp3_vec *vec,
                                  size_t veccnt, uint32_t *flags);
    int OnConnectBodyAcked(int64_t stream_id, uint64_t datalen);

private:
    bool InitH3(QuicConnection &conn);
    int FeedH3(QuicConnection &conn, int64_t stream_id, const uint8_t *data,
               size_t len, bool fin);
    int HandleWtStream(QuicConnection &conn, QuicStream &stream, bool fin);
    void HandleClassBytes(QuicConnection &conn, QuicStream &stream,
                          const uint8_t *data, size_t len, bool fin);
    void ServerHandleRequest(int64_t stream_id, bool fin);
    void ClientHandleResponse(int64_t stream_id);
    void SubmitConnect();
    void Respond(int64_t stream_id, int status,
                 const std::vector<std::pair<std::string, std::string>>
                     &extra = {});
    void OpenClassStreams();
    void ParseCapsules();
    void SessionEnded(uint32_t code, const std::string &reason);
    void QueueConnectBody(std::vector<uint8_t> &&data, bool fin);
    void RejectStream(int64_t stream_id);

    const H3Options m_opts;
    std::unique_ptr<WtSessionHandler> m_handler;
    QuicConnection *m_conn{nullptr};
    nghttp3_conn *m_h3{nullptr};

    std::map<int64_t, WtRequest> m_requests;
    WtRequest m_request;
    bool m_peer_settings{false};
    bool m_peer_connect_protocol{false};
    int m_peer_draft_rank{0};
    uint64_t m_peer_draft_setting{0};
    uint64_t m_settings_deadline{UINT64_MAX};

    int64_t m_session_id{-1};
    bool m_connect_sent{false};
    bool m_accepted{false};
    bool m_ready{false};
    bool m_session_closed{false};
    std::string m_protocol;
    std::array<int64_t, NUM_STREAM_CLASSES> m_class_streams;
    //! Echo mode: our unidirectional stream for uni echoes
    int64_t m_echo_uni{-1};

    //! Capsule bytes received on the CONNECT stream, not yet parsed
    std::vector<uint8_t> m_capsule_rx;
    //! CONNECT stream body we send (capsules); kept until acknowledged
    struct BodyChunk {
        std::vector<uint8_t> data;
        bool given{false};
    };
    std::deque<BodyChunk> m_connect_tx;
    bool m_connect_fin{false};
    bool m_connect_fin_given{false};
    //! After our close capsule: close the connection by then
    uint64_t m_close_deadline{UINT64_MAX};
    uint64_t m_datagrams_dropped{0};
};

#endif // BITCOIN_NET_QUIC_WEBTRANSPORT_H3_H
