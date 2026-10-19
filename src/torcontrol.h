// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include <netaddress.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/signals2/signal.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

extern const std::string DEFAULT_TOR_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

void StartTorControl(CService onion_service_target);
void InterruptTorControl();
void StopTorControl();

CService DefaultOnionServiceTarget();

/**
 * Parse a Tor control port address: a numeric IPv4 or IPv6 address with an
 * optional port, written as "1.2.3.4", "1.2.3.4:9051", "[::1]", "[::1]:9051"
 * or "::1". Host names are rejected. A missing port gives port 0; a given port
 * must be in 1-65535. These are the forms libevent's
 * evutil_parse_sockaddr_port accepts.
 */
std::optional<CService> ParseTorControlAddress(const std::string &address);

/**
 * Split reply line in the form 'AUTH METHODS=...' into a type 'AUTH' and
 * arguments 'METHODS=...'.
 */
std::pair<std::string, std::string> SplitTorReplyLine(const std::string &s);

/**
 * Parse reply arguments in the form 'METHODS=COOKIE,SAFECOOKIE
 * COOKIEFILE=".../control_auth_cookie"'. Returns a map of keys to values, or
 * an empty map if there was an error.
 */
std::map<std::string, std::string> ParseTorReplyMapping(const std::string &s);

/** Reply from Tor, can be single or multi-line */
class TorControlReply {
public:
    TorControlReply() { Clear(); }

    int code;
    std::vector<std::string> lines;

    void Clear() {
        code = 0;
        lines.clear();
    }
};

/**
 * Low-level handling for Tor control connection.
 * Speaks the SMTP-like protocol as defined in torspec/control-spec.txt
 *
 * All methods and callbacks run on the thread that runs the io_context.
 */
class TorControlConnection {
public:
    typedef std::function<void(TorControlConnection &)> ConnectionCB;
    typedef std::function<void(TorControlConnection &, const TorControlReply &)>
        ReplyHandlerCB;

    /** Create a new TorControlConnection. */
    explicit TorControlConnection(boost::asio::io_context &io);
    ~TorControlConnection();

    /**
     * Connect to a Tor control port.
     * tor_control_center is address of the form host:port.
     * connected is the handler that is called when connection is successfully
     * established.
     * disconnected is a handler that is called when the connection is broken.
     * Return true on success.
     */
    bool Connect(const std::string &tor_control_center,
                 const ConnectionCB &connected,
                 const ConnectionCB &disconnected);

    /**
     * Disconnect from Tor control port.
     */
    void Disconnect();

    /**
     * Send a command, register a handler for the reply.
     * A trailing CRLF is automatically added.
     * Return true on success.
     */
    bool Command(const std::string &cmd, const ReplyHandlerCB &reply_handler);

    /** Response handlers for async replies */
    boost::signals2::signal<void(TorControlConnection &,
                                 const TorControlReply &)>
        async_handler;

private:
    void OnConnect(uint64_t gen, const boost::system::error_code &ec);
    void StartRead();
    void OnRead(uint64_t gen, const boost::system::error_code &ec,
                size_t bytes);
    void StartWrite();
    void OnWrite(uint64_t gen, const boost::system::error_code &ec);
    /** Handle a broken connection: log, disconnect, notify. */
    void Lost(const boost::system::error_code &ec);

    boost::asio::io_context &m_io;
    /** Callback when ready for use */
    std::function<void(TorControlConnection &)> connected;
    /** Callback when connection lost */
    std::function<void(TorControlConnection &)> disconnected;
    /** Connection to control socket */
    std::optional<boost::asio::ip::tcp::socket> m_socket;
    /** Whether the connection attempt has completed */
    bool m_connected{false};
    /** Received bytes not yet forming a complete line */
    std::string m_rbuf;
    /** Socket read buffer */
    std::vector<char> m_read_chunk;
    /** Commands waiting to be written */
    std::deque<std::string> m_wqueue;
    /** Whether a write is in progress */
    bool m_writing{false};
    /**
     * Incremented by Disconnect(), so completions of operations on an older
     * socket are ignored.
     */
    uint64_t m_gen{0};
    /** Message being received */
    TorControlReply message;
    /** Response handlers */
    std::deque<ReplyHandlerCB> reply_handlers;
};

#endif // BITCOIN_TORCONTROL_H
