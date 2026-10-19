// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <torcontrol.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <compat/compat.h>
#include <crypto/hmac_sha256.h>
#include <logging.h>
#include <net.h>
#include <netaddress.h>
#include <netbase.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/thread.h>
#include <util/time.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/signals2/signal.hpp>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <vector>

using util::ReplaceAll;
using util::SplitString;

/** Default control port */
const std::string DEFAULT_TOR_CONTROL = "127.0.0.1:9051";
/** Tor cookie size (from control-spec.txt) */
static const int TOR_COOKIE_SIZE = 32;
/** Size of client/server nonce for SAFECOOKIE */
static const int TOR_NONCE_SIZE = 32;
/** For computing serverHash in SAFECOOKIE */
static const std::string TOR_SAFE_SERVERKEY =
    "Tor safe cookie authentication server-to-controller hash";
/** For computing clientHash in SAFECOOKIE */
static const std::string TOR_SAFE_CLIENTKEY =
    "Tor safe cookie authentication controller-to-server hash";
/** Exponential backoff configuration - initial timeout in seconds */
static const float RECONNECT_TIMEOUT_START = 1.0;
/** Exponential backoff configuration - growth factor */
static const float RECONNECT_TIMEOUT_EXP = 1.5;
/**
 * Maximum length for lines received on TorControlConnection.
 * tor-control-spec.txt mentions that there is explicitly no limit defined to
 * line length, this is belt-and-suspenders sanity limit to prevent memory
 * exhaustion.
 */
static const int MAX_LINE_LENGTH = 100000;

/****** Low-level TorControlConnection ********/

namespace {
/** Size of each socket read. */
constexpr size_t TOR_READ_CHUNK_SIZE = 64 * 1024;
} // namespace

TorControlConnection::TorControlConnection(boost::asio::io_context &io)
    : m_io(io), m_read_chunk(TOR_READ_CHUNK_SIZE) {}

TorControlConnection::~TorControlConnection() {
    Disconnect();
}

void TorControlConnection::Lost(const boost::system::error_code &ec) {
    if (ec == boost::asio::error::eof) {
        LogDebug(BCLog::TOR, "tor: End of stream\n");
    } else {
        LogDebug(BCLog::TOR, "tor: Error connecting to Tor control socket\n");
    }
    Disconnect();
    disconnected(*this);
}

void TorControlConnection::OnConnect(uint64_t gen,
                                     const boost::system::error_code &ec) {
    if (gen != m_gen || ec == boost::asio::error::operation_aborted) {
        return;
    }
    if (ec) {
        LogDebug(BCLog::TOR, "tor: Error connecting to Tor control socket\n");
        Disconnect();
        disconnected(*this);
        return;
    }
    m_connected = true;
    LogDebug(BCLog::TOR, "tor: Successfully connected!\n");
    connected(*this);
    if (gen != m_gen) {
        // The callback disconnected.
        return;
    }
    StartWrite();
    StartRead();
}

void TorControlConnection::StartRead() {
    const uint64_t gen = m_gen;
    m_socket->async_read_some(
        boost::asio::buffer(m_read_chunk),
        [this, gen](const boost::system::error_code &ec, size_t bytes) {
            OnRead(gen, ec, bytes);
        });
}

void TorControlConnection::OnRead(uint64_t gen,
                                  const boost::system::error_code &ec,
                                  size_t bytes) {
    if (gen != m_gen || ec == boost::asio::error::operation_aborted) {
        return;
    }
    if (ec) {
        Lost(ec);
        return;
    }
    m_rbuf.append(m_read_chunk.data(), bytes);

    // Take every complete line. A line ends with LF, optionally preceded by
    // CR, which is removed.
    size_t begin = 0;
    size_t end;
    while ((end = m_rbuf.find('\n', begin)) != std::string::npos) {
        std::string s = m_rbuf.substr(begin, end - begin);
        begin = end + 1;
        if (!s.empty() && s.back() == '\r') {
            s.pop_back();
        }
        // Short line
        if (s.size() < 4) {
            continue;
        }
        // <status>(-|+| )<data><CRLF>
        message.code = LocaleIndependentAtoi<int>(s.substr(0, 3));
        message.lines.push_back(s.substr(4));
        // '-','+' or ' '
        char ch = s[3];
        if (ch == ' ') {
            // Final line, dispatch reply and clean up
            if (message.code >= 600) {
                // Dispatch async notifications to async handler.
                // Synchronous and asynchronous messages are never interleaved
                async_handler(*this, message);
            } else {
                if (!reply_handlers.empty()) {
                    // Invoke reply handler with message
                    reply_handlers.front()(*this, message);
                    reply_handlers.pop_front();
                } else {
                    LogDebug(BCLog::TOR,
                             "tor: Received unexpected sync reply %i\n",
                             message.code);
                }
            }
            message.Clear();
            if (gen != m_gen) {
                // A handler disconnected; the rest of the input is dropped.
                return;
            }
        }
    }
    m_rbuf.erase(0, begin);

    // Check for size of buffer - protect against memory exhaustion with very
    // long lines. Do this after reading the lines to make sure all full lines
    // have been removed from the buffer. Everything left is an incomplete line.
    if (m_rbuf.size() > size_t(MAX_LINE_LENGTH)) {
        LogPrintf("tor: Disconnecting because MAX_LINE_LENGTH exceeded\n");
        Disconnect();
        return;
    }
    StartRead();
}

void TorControlConnection::StartWrite() {
    if (!m_socket || !m_connected || m_writing || m_wqueue.empty()) {
        return;
    }
    // Write everything queued so far in one operation. The data is owned by
    // the completion handler, so it outlives a Disconnect() in between.
    auto data = std::make_shared<std::string>();
    for (const std::string &cmd : m_wqueue) {
        data->append(cmd);
    }
    m_wqueue.clear();
    m_writing = true;
    const uint64_t gen = m_gen;
    boost::asio::async_write(
        *m_socket, boost::asio::buffer(*data),
        [this, gen, data](const boost::system::error_code &ec, size_t) {
            OnWrite(gen, ec);
        });
}

void TorControlConnection::OnWrite(uint64_t gen,
                                   const boost::system::error_code &ec) {
    if (gen != m_gen || ec == boost::asio::error::operation_aborted) {
        return;
    }
    m_writing = false;
    if (ec) {
        Lost(ec);
        return;
    }
    StartWrite();
}

bool TorControlConnection::Connect(const std::string &tor_control_center,
                                   const ConnectionCB &_connected,
                                   const ConnectionCB &_disconnected) {
    if (m_socket) {
        Disconnect();
    }
    // Parse tor_control_center address:port
    const std::optional<CService> addr =
        ParseTorControlAddress(tor_control_center);
    struct sockaddr_storage connect_to_addr;
    socklen_t connect_to_addrlen = sizeof(connect_to_addr);
    if (!addr || !addr->GetSockAddr(
                     reinterpret_cast<struct sockaddr *>(&connect_to_addr),
                     &connect_to_addrlen)) {
        LogPrintf("tor: Error parsing socket address %s\n", tor_control_center);
        return false;
    }
    boost::asio::ip::tcp::endpoint endpoint;
    std::memcpy(endpoint.data(), &connect_to_addr, connect_to_addrlen);
    endpoint.resize(connect_to_addrlen);

    // Create a new socket
    boost::system::error_code ec;
    m_socket.emplace(m_io);
    m_socket->open(endpoint.protocol(), ec);
    if (ec) {
        m_socket.reset();
        LogPrintf("tor: Error connecting to address %s\n", tor_control_center);
        return false;
    }
    this->connected = _connected;
    this->disconnected = _disconnected;

    // Finally, connect to tor_control_center
    const uint64_t gen = m_gen;
    m_socket->async_connect(
        endpoint,
        [this, gen](const boost::system::error_code &e) { OnConnect(gen, e); });
    return true;
}

void TorControlConnection::Disconnect() {
    ++m_gen;
    if (m_socket) {
        boost::system::error_code ignored;
        m_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                           ignored);
        m_socket->close(ignored);
        m_socket.reset();
    }
    m_connected = false;
    m_writing = false;
    m_rbuf.clear();
    m_wqueue.clear();
}

bool TorControlConnection::Command(const std::string &cmd,
                                   const ReplyHandlerCB &reply_handler) {
    if (!m_socket) {
        return false;
    }
    m_wqueue.push_back(cmd + "\r\n");
    reply_handlers.push_back(reply_handler);
    StartWrite();
    return true;
}

/****** General parsing utilities ********/

std::optional<CService> ParseTorControlAddress(const std::string &address) {
    std::string addr_part;
    std::optional<std::string> port_part;
    bool is_ipv6;
    const size_t colon = address.find(':');
    if (!address.empty() && address[0] == '[') {
        const size_t close = address.find(']');
        if (close == std::string::npos) {
            return std::nullopt;
        }
        addr_part = address.substr(1, close - 1);
        if (close + 1 < address.size() && address[close + 1] == ':') {
            port_part = address.substr(close + 2);
        }
        is_ipv6 = true;
    } else if (colon != std::string::npos &&
               address.find(':', colon + 1) != std::string::npos) {
        // More than one ':' and no brackets: a bare IPv6 address, no port.
        addr_part = address;
        is_ipv6 = true;
    } else if (colon != std::string::npos) {
        addr_part = address.substr(0, colon);
        port_part = address.substr(colon + 1);
        is_ipv6 = false;
    } else {
        addr_part = address;
        is_ipv6 = false;
    }

    uint16_t port = 0;
    if (port_part) {
        // atoi() semantics: leading white space and sign, trailing garbage
        // ignored.
        const int64_t value = LocaleIndependentAtoi<int64_t>(*port_part);
        if (value <= 0 || value > 65535) {
            return std::nullopt;
        }
        port = static_cast<uint16_t>(value);
    }
    if (addr_part.find('\0') != std::string::npos) {
        return std::nullopt;
    }

    if (is_ipv6) {
        struct sockaddr_in6 sin6 {};
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(port);
        std::string ip = addr_part;
        const size_t percent = ip.find('%');
        if (percent != std::string::npos) {
            // Scoped address: interface name or numeric index.
            const std::string scope = ip.substr(percent + 1);
            ip = ip.substr(0, percent);
#ifndef WIN32
            unsigned int index = if_nametoindex(scope.c_str());
#else
            unsigned int index = 0;
#endif
            if (index == 0) {
                char *end = nullptr;
                const unsigned long numeric =
                    std::strtoul(scope.c_str(), &end, 10);
                if (scope.empty() || *end != '\0' ||
                    numeric > std::numeric_limits<uint32_t>::max()) {
                    return std::nullopt;
                }
                index = static_cast<unsigned int>(numeric);
            }
            sin6.sin6_scope_id = index;
        }
        if (inet_pton(AF_INET6, ip.c_str(), &sin6.sin6_addr) != 1) {
            return std::nullopt;
        }
        return CService(sin6);
    }
    struct sockaddr_in sin {};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, addr_part.c_str(), &sin.sin_addr) != 1) {
        return std::nullopt;
    }
    return CService(sin);
}

/* Split reply line in the form 'AUTH METHODS=...' into a type
 * 'AUTH' and arguments 'METHODS=...'.
 * Grammar is implicitly defined in https://spec.torproject.org/control-spec by
 * the server reply formats for PROTOCOLINFO (S3.21) and AUTHCHALLENGE (S3.24).
 */
std::pair<std::string, std::string> SplitTorReplyLine(const std::string &s) {
    size_t ptr = 0;
    std::string type;
    while (ptr < s.size() && s[ptr] != ' ') {
        type.push_back(s[ptr]);
        ++ptr;
    }
    if (ptr < s.size()) {
        // skip ' '
        ++ptr;
    }
    return make_pair(type, s.substr(ptr));
}

/**
 * Parse reply arguments in the form 'METHODS=COOKIE,SAFECOOKIE
 * COOKIEFILE=".../control_auth_cookie"'.
 * Returns a map of keys to values, or an empty map if there was an error.
 * Grammar is implicitly defined in https://spec.torproject.org/control-spec by
 * the server reply formats for PROTOCOLINFO (S3.21), AUTHCHALLENGE (S3.24),
 * and ADD_ONION (S3.27). See also sections 2.1 and 2.3.
 */
std::map<std::string, std::string> ParseTorReplyMapping(const std::string &s) {
    std::map<std::string, std::string> mapping;
    size_t ptr = 0;
    while (ptr < s.size()) {
        std::string key, value;
        while (ptr < s.size() && s[ptr] != '=' && s[ptr] != ' ') {
            key.push_back(s[ptr]);
            ++ptr;
        }
        // unexpected end of line
        if (ptr == s.size()) {
            return std::map<std::string, std::string>();
        }
        // The remaining string is an OptArguments
        if (s[ptr] == ' ') {
            break;
        }
        // skip '='
        ++ptr;
        // Quoted string
        if (ptr < s.size() && s[ptr] == '"') {
            // skip opening '"'
            ++ptr;
            bool escape_next = false;
            while (ptr < s.size() && (escape_next || s[ptr] != '"')) {
                // Repeated backslashes must be interpreted as pairs
                escape_next = (s[ptr] == '\\' && !escape_next);
                value.push_back(s[ptr]);
                ++ptr;
            }
            // unexpected end of line
            if (ptr == s.size()) {
                return std::map<std::string, std::string>();
            }
            // skip closing '"'
            ++ptr;
            /**
             * Unescape value. Per https://spec.torproject.org/control-spec
             * section 2.1.1:
             *
             * For future-proofing, controller implementors MAY use the
             * following rules to be compatible with buggy Tor implementations
             * and with future ones that implement the spec as intended:
             *
             * Read \n \t \r and \0 ... \377 as C escapes.
             * Treat a backslash followed by any other character as that
             * character.
             */
            std::string escaped_value;
            for (size_t i = 0; i < value.size(); ++i) {
                if (value[i] == '\\') {
                    // This will always be valid, because if the QuotedString
                    // ended in an odd number of backslashes, then the parser
                    // would already have returned above, due to a missing
                    // terminating double-quote.
                    ++i;
                    if (value[i] == 'n') {
                        escaped_value.push_back('\n');
                    } else if (value[i] == 't') {
                        escaped_value.push_back('\t');
                    } else if (value[i] == 'r') {
                        escaped_value.push_back('\r');
                    } else if ('0' <= value[i] && value[i] <= '7') {
                        size_t j;
                        // Octal escape sequences have a limit of three octal
                        // digits, but terminate at the first character that is
                        // not a valid octal digit if encountered sooner.
                        for (j = 1; j < 3 && (i + j) < value.size() &&
                                    '0' <= value[i + j] && value[i + j] <= '7';
                             ++j) {
                        }
                        // Tor restricts first digit to 0-3 for three-digit
                        // octals. A leading digit of 4-7 would therefore be
                        // interpreted as a two-digit octal.
                        if (j == 3 && value[i] > '3') {
                            j--;
                        }
                        escaped_value.push_back(
                            strtol(value.substr(i, j).c_str(), nullptr, 8));
                        // Account for automatic incrementing at loop end
                        i += j - 1;
                    } else {
                        escaped_value.push_back(value[i]);
                    }
                } else {
                    escaped_value.push_back(value[i]);
                }
            }
            value = escaped_value;
        } else {
            // Unquoted value. Note that values can contain '=' at will, just no
            // spaces
            while (ptr < s.size() && s[ptr] != ' ') {
                value.push_back(s[ptr]);
                ++ptr;
            }
        }
        if (ptr < s.size() && s[ptr] == ' ') {
            // skip ' ' after key=value
            ++ptr;
        }
        mapping[key] = value;
    }
    return mapping;
}

/****** Bitcoin specific TorController implementation ********/

/**
 * Controller that connects to Tor control socket, authenticate, then create
 * and maintain an ephemeral onion service.
 */
class TorController {
public:
    TorController(boost::asio::io_context &io,
                  const std::string &tor_control_center,
                  const CService &target);
    ~TorController();

    /** Get name fo file to store private key in */
    fs::path GetPrivateKeyFile();

    /** Reconnect, after getting disconnected */
    void Reconnect();

private:
    const std::string m_tor_control_center;
    TorControlConnection conn;
    std::string private_key;
    std::string service_id;
    bool reconnect{true};
    boost::asio::steady_timer m_reconnect_timer;
    float reconnect_timeout{RECONNECT_TIMEOUT_START};
    CService service;
    const CService m_target;
    /** Cookie for SAFECOOKIE auth */
    std::vector<uint8_t> cookie;
    /** ClientNonce for SAFECOOKIE auth */
    std::vector<uint8_t> clientNonce;

    /** Callback for ADD_ONION result */
    void add_onion_cb(TorControlConnection &conn, const TorControlReply &reply);
    /** Callback for AUTHENTICATE result */
    void auth_cb(TorControlConnection &conn, const TorControlReply &reply);
    /** Callback for AUTHCHALLENGE result */
    void authchallenge_cb(TorControlConnection &conn,
                          const TorControlReply &reply);
    /** Callback for PROTOCOLINFO result */
    void protocolinfo_cb(TorControlConnection &conn,
                         const TorControlReply &reply);
    /** Callback after successful connection */
    void connected_cb(TorControlConnection &conn);
    /** Callback after connection lost or failed connection attempt */
    void disconnected_cb(TorControlConnection &conn);
};

TorController::TorController(boost::asio::io_context &io,
                             const std::string &tor_control_center,
                             const CService &target)
    : m_tor_control_center(tor_control_center), conn(io), m_reconnect_timer(io),
      m_target(target) {
    // Start connection attempts immediately
    if (!conn.Connect(m_tor_control_center,
                      std::bind(&TorController::connected_cb, this,
                                std::placeholders::_1),
                      std::bind(&TorController::disconnected_cb, this,
                                std::placeholders::_1))) {
        LogPrintf("tor: Initiating connection to Tor control port %s failed\n",
                  m_tor_control_center);
    }
    // Read service private key if cached
    std::pair<bool, std::string> pkf = ReadBinaryFile(GetPrivateKeyFile());
    if (pkf.first) {
        LogDebug(BCLog::TOR, "tor: Reading cached private key from %s\n",
                 fs::PathToString(GetPrivateKeyFile()));
        private_key = pkf.second;
    }
}

TorController::~TorController() {
    if (service.IsValid()) {
        RemoveLocal(service);
    }
}

void TorController::add_onion_cb(TorControlConnection &_conn,
                                 const TorControlReply &reply) {
    if (reply.code == 250) {
        LogDebug(BCLog::TOR, "tor: ADD_ONION successful\n");
        for (const std::string &s : reply.lines) {
            std::map<std::string, std::string> m = ParseTorReplyMapping(s);
            std::map<std::string, std::string>::iterator i;
            if ((i = m.find("ServiceID")) != m.end()) {
                service_id = i->second;
            }
            if ((i = m.find("PrivateKey")) != m.end()) {
                private_key = i->second;
            }
        }
        if (service_id.empty()) {
            LogPrintf("tor: Error parsing ADD_ONION parameters:\n");
            for (const std::string &s : reply.lines) {
                LogPrintf("    %s\n", SanitizeString(s));
            }
            return;
        }
        service = LookupNumeric(std::string(service_id + ".onion"),
                                Params().GetDefaultPort());
        LogInfo("Got tor service ID %s, advertising service %s\n", service_id,
                service.ToStringAddrPort());
        if (WriteBinaryFile(GetPrivateKeyFile(), private_key)) {
            LogDebug(BCLog::TOR, "tor: Cached service private key to %s\n",
                     fs::PathToString(GetPrivateKeyFile()));
        } else {
            LogPrintf("tor: Error writing service private key to %s\n",
                      fs::PathToString(GetPrivateKeyFile()));
        }
        AddLocal(service, LOCAL_MANUAL);
        // ... onion requested - keep connection open
    } else if (reply.code == 510) { // 510 Unrecognized command
        LogPrintf("tor: Add onion failed with unrecognized command (You "
                  "probably need to upgrade Tor)\n");
    } else {
        LogPrintf("tor: Add onion failed; error code %d\n", reply.code);
    }
}

void TorController::auth_cb(TorControlConnection &_conn,
                            const TorControlReply &reply) {
    if (reply.code == 250) {
        LogDebug(BCLog::TOR, "tor: Authentication successful\n");

        // Now that we know Tor is running setup the proxy for onion addresses
        // if -onion isn't set to something else.
        if (gArgs.GetArg("-onion", "") == "") {
            CService resolved(LookupNumeric("127.0.0.1", 9050));
            Proxy addrOnion = Proxy(resolved, true);
            SetProxy(NET_ONION, addrOnion);

            const auto onlynets = gArgs.GetArgs("-onlynet");

            const bool onion_allowed_by_onlynet{
                !gArgs.IsArgSet("-onlynet") ||
                std::any_of(onlynets.begin(), onlynets.end(),
                            [](const auto &n) {
                                return ParseNetwork(n) == NET_ONION;
                            })};

            if (onion_allowed_by_onlynet) {
                // If NET_ONION is reachable, then the below is a noop.
                //
                // If NET_ONION is not reachable, then none of -proxy or -onion
                // was given. Since we are here, then -torcontrol and
                // -torpassword were given.
                SetReachable(NET_ONION, true);
            }
        }

        // Finally - now create the service
        // No private key, generate one
        if (private_key.empty()) {
            // Explicitly request key type - see issue #9214
            private_key = "NEW:ED25519-V3";
        }
        // Request onion service, redirect port.
        // Note that the 'virtual' port doesn't have to be the same as our
        // internal port, but this is just a convenient choice. TODO; refactor
        // the shutdown sequence some day.
        _conn.Command(strprintf("ADD_ONION %s Port=%i,%s", private_key,
                                Params().GetDefaultPort(),
                                m_target.ToStringAddrPort()),
                      std::bind(&TorController::add_onion_cb, this,
                                std::placeholders::_1, std::placeholders::_2));
    } else {
        LogPrintf("tor: Authentication failed\n");
    }
}

/** Compute Tor SAFECOOKIE response.
 *
 *    ServerHash is computed as:
 *      HMAC-SHA256("Tor safe cookie authentication server-to-controller hash",
 *                  CookieString | ClientNonce | ServerNonce)
 *    (with the HMAC key as its first argument)
 *
 *    After a controller sends a successful AUTHCHALLENGE command, the
 *    next command sent on the connection must be an AUTHENTICATE command,
 *    and the only authentication string which that AUTHENTICATE command
 *    will accept is:
 *
 *      HMAC-SHA256("Tor safe cookie authentication controller-to-server hash",
 *                  CookieString | ClientNonce | ServerNonce)
 *
 */
static std::vector<uint8_t>
ComputeResponse(const std::string &key, const std::vector<uint8_t> &cookie,
                const std::vector<uint8_t> &clientNonce,
                const std::vector<uint8_t> &serverNonce) {
    CHMAC_SHA256 computeHash((const uint8_t *)key.data(), key.size());
    std::vector<uint8_t> computedHash(CHMAC_SHA256::OUTPUT_SIZE, 0);
    computeHash.Write(cookie.data(), cookie.size());
    computeHash.Write(clientNonce.data(), clientNonce.size());
    computeHash.Write(serverNonce.data(), serverNonce.size());
    computeHash.Finalize(computedHash.data());
    return computedHash;
}

void TorController::authchallenge_cb(TorControlConnection &_conn,
                                     const TorControlReply &reply) {
    if (reply.code == 250) {
        LogDebug(BCLog::TOR,
                 "tor: SAFECOOKIE authentication challenge successful\n");
        std::pair<std::string, std::string> l =
            SplitTorReplyLine(reply.lines[0]);
        if (l.first == "AUTHCHALLENGE") {
            std::map<std::string, std::string> m =
                ParseTorReplyMapping(l.second);
            if (m.empty()) {
                LogPrintf("tor: Error parsing AUTHCHALLENGE parameters: %s\n",
                          SanitizeString(l.second));
                return;
            }
            std::vector<uint8_t> serverHash = ParseHex(m["SERVERHASH"]);
            std::vector<uint8_t> serverNonce = ParseHex(m["SERVERNONCE"]);
            LogDebug(BCLog::TOR,
                     "tor: AUTHCHALLENGE ServerHash %s ServerNonce %s\n",
                     HexStr(serverHash), HexStr(serverNonce));
            if (serverNonce.size() != 32) {
                LogPrintf(
                    "tor: ServerNonce is not 32 bytes, as required by spec\n");
                return;
            }

            std::vector<uint8_t> computedServerHash = ComputeResponse(
                TOR_SAFE_SERVERKEY, cookie, clientNonce, serverNonce);
            if (computedServerHash != serverHash) {
                LogPrintf("tor: ServerHash %s does not match expected "
                          "ServerHash %s\n",
                          HexStr(serverHash), HexStr(computedServerHash));
                return;
            }

            std::vector<uint8_t> computedClientHash = ComputeResponse(
                TOR_SAFE_CLIENTKEY, cookie, clientNonce, serverNonce);
            _conn.Command("AUTHENTICATE " + HexStr(computedClientHash),
                          std::bind(&TorController::auth_cb, this,
                                    std::placeholders::_1,
                                    std::placeholders::_2));
        } else {
            LogPrintf("tor: Invalid reply to AUTHCHALLENGE\n");
        }
    } else {
        LogPrintf("tor: SAFECOOKIE authentication challenge failed\n");
    }
}

void TorController::protocolinfo_cb(TorControlConnection &_conn,
                                    const TorControlReply &reply) {
    if (reply.code == 250) {
        std::set<std::string> methods;
        std::string cookiefile;
        /*
         * 250-AUTH METHODS=COOKIE,SAFECOOKIE
         * COOKIEFILE="/home/x/.tor/control_auth_cookie"
         * 250-AUTH METHODS=NULL
         * 250-AUTH METHODS=HASHEDPASSWORD
         */
        for (const std::string &s : reply.lines) {
            std::pair<std::string, std::string> l = SplitTorReplyLine(s);
            if (l.first == "AUTH") {
                std::map<std::string, std::string> m =
                    ParseTorReplyMapping(l.second);
                std::map<std::string, std::string>::iterator i;
                if ((i = m.find("METHODS")) != m.end()) {
                    std::vector<std::string> m_vec =
                        SplitString(i->second, ',');
                    methods = std::set<std::string>(m_vec.begin(), m_vec.end());
                }
                if ((i = m.find("COOKIEFILE")) != m.end()) {
                    cookiefile = i->second;
                }
            } else if (l.first == "VERSION") {
                std::map<std::string, std::string> m =
                    ParseTorReplyMapping(l.second);
                std::map<std::string, std::string>::iterator i;
                if ((i = m.find("Tor")) != m.end()) {
                    LogDebug(BCLog::TOR, "tor: Connected to Tor version %s\n",
                             i->second);
                }
            }
        }
        for (const std::string &s : methods) {
            LogDebug(BCLog::TOR, "tor: Supported authentication method: %s\n",
                     s);
        }
        // Prefer NULL, otherwise SAFECOOKIE. If a password is provided, use
        // HASHEDPASSWORD
        /* Authentication:
         *   cookie:   hex-encoded ~/.tor/control_auth_cookie
         *   password: "password"
         */
        std::string torpassword = gArgs.GetArg("-torpassword", "");
        if (!torpassword.empty()) {
            if (methods.count("HASHEDPASSWORD")) {
                LogDebug(BCLog::TOR,
                         "tor: Using HASHEDPASSWORD authentication\n");
                ReplaceAll(torpassword, "\"", "\\\"");
                _conn.Command("AUTHENTICATE \"" + torpassword + "\"",
                              std::bind(&TorController::auth_cb, this,
                                        std::placeholders::_1,
                                        std::placeholders::_2));
            } else {
                LogPrintf("tor: Password provided with -torpassword, but "
                          "HASHEDPASSWORD authentication is not available\n");
            }
        } else if (methods.count("NULL")) {
            LogDebug(BCLog::TOR, "tor: Using NULL authentication\n");
            _conn.Command("AUTHENTICATE", std::bind(&TorController::auth_cb,
                                                    this, std::placeholders::_1,
                                                    std::placeholders::_2));
        } else if (methods.count("SAFECOOKIE")) {
            // Cookie: hexdump -e '32/1 "%02x""\n"'  ~/.tor/control_auth_cookie
            LogDebug(BCLog::TOR,
                     "tor: Using SAFECOOKIE authentication, "
                     "reading cookie authentication from %s\n",
                     cookiefile);
            std::pair<bool, std::string> status_cookie =
                ReadBinaryFile(fs::PathFromString(cookiefile), TOR_COOKIE_SIZE);
            if (status_cookie.first &&
                status_cookie.second.size() == TOR_COOKIE_SIZE) {
                // _conn.Command("AUTHENTICATE " + HexStr(status_cookie.second),
                // std::bind(&TorController::auth_cb, this,
                // std::placeholders::_1, std::placeholders::_2));
                cookie = std::vector<uint8_t>(status_cookie.second.begin(),
                                              status_cookie.second.end());
                clientNonce = std::vector<uint8_t>(TOR_NONCE_SIZE, 0);
                GetRandBytes(clientNonce);
                _conn.Command("AUTHCHALLENGE SAFECOOKIE " + HexStr(clientNonce),
                              std::bind(&TorController::authchallenge_cb, this,
                                        std::placeholders::_1,
                                        std::placeholders::_2));
            } else {
                if (status_cookie.first) {
                    LogPrintf("tor: Authentication cookie %s is not exactly %i "
                              "bytes, as is required by the spec\n",
                              cookiefile, TOR_COOKIE_SIZE);
                } else {
                    LogPrintf("tor: Authentication cookie %s could not be "
                              "opened (check permissions)\n",
                              cookiefile);
                }
            }
        } else if (methods.count("HASHEDPASSWORD")) {
            LogPrintf("tor: The only supported authentication mechanism left "
                      "is password, but no password provided with "
                      "-torpassword\n");
        } else {
            LogPrintf("tor: No supported authentication method\n");
        }
    } else {
        LogPrintf("tor: Requesting protocol info failed\n");
    }
}

void TorController::connected_cb(TorControlConnection &_conn) {
    reconnect_timeout = RECONNECT_TIMEOUT_START;
    // First send a PROTOCOLINFO command to figure out what authentication is
    // expected
    if (!_conn.Command("PROTOCOLINFO 1",
                       std::bind(&TorController::protocolinfo_cb, this,
                                 std::placeholders::_1,
                                 std::placeholders::_2))) {
        LogPrintf("tor: Error sending initial protocolinfo command\n");
    }
}

void TorController::disconnected_cb(TorControlConnection &_conn) {
    // Stop advertising service when disconnected
    if (service.IsValid()) {
        RemoveLocal(service);
    }
    service = CService();
    if (!reconnect) {
        return;
    }

    LogDebug(BCLog::TOR,
             "tor: Not connected to Tor control port %s, trying to reconnect\n",
             m_tor_control_center);

    // Single-shot timer for reconnect. Use exponential backoff.
    m_reconnect_timer.expires_after(
        std::chrono::milliseconds(int64_t(reconnect_timeout * 1000.0)));
    m_reconnect_timer.async_wait([this](const boost::system::error_code &ec) {
        if (!ec) {
            Reconnect();
        }
    });
    reconnect_timeout *= RECONNECT_TIMEOUT_EXP;
}

void TorController::Reconnect() {
    /* Try to reconnect and reestablish if we get booted - for example, Tor may
     * be restarting.
     */
    if (!conn.Connect(m_tor_control_center,
                      std::bind(&TorController::connected_cb, this,
                                std::placeholders::_1),
                      std::bind(&TorController::disconnected_cb, this,
                                std::placeholders::_1))) {
        LogPrintf(
            "tor: Re-initiating connection to Tor control port %s failed\n",
            m_tor_control_center);
    }
}

fs::path TorController::GetPrivateKeyFile() {
    return gArgs.GetDataDirNet() / "onion_v3_private_key";
}

/****** Thread ********/
static std::unique_ptr<boost::asio::io_context> g_tor_io;
static std::thread torControlThread;

static void TorControlThread(CService onion_service_target) {
    auto work = boost::asio::make_work_guard(*g_tor_io);
    TorController ctrl(*g_tor_io,
                       gArgs.GetArg("-torcontrol", DEFAULT_TOR_CONTROL),
                       onion_service_target);

    g_tor_io->run();
}

void StartTorControl(CService onion_service_target) {
    assert(!g_tor_io);
    g_tor_io = std::make_unique<boost::asio::io_context>(1);

    torControlThread =
        std::thread(&util::TraceThread, "torcontrol", [onion_service_target] {
            TorControlThread(onion_service_target);
        });
}

void InterruptTorControl() {
    if (g_tor_io) {
        LogPrintf("tor: Thread interrupt\n");
        // Thread-safe; if the loop has not started yet, run() returns at once.
        g_tor_io->stop();
    }
}

void StopTorControl() {
    if (g_tor_io) {
        torControlThread.join();
        g_tor_io.reset();
    }
}

CService DefaultOnionServiceTarget() {
    struct in_addr onion_service_target;
    onion_service_target.s_addr = htonl(INADDR_LOOPBACK);
    return {onion_service_target, BaseParams().OnionServiceTargetPort()};
}
