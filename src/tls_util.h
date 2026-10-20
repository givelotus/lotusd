// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TLS_UTIL_H
#define BITCOIN_TLS_UTIL_H

#include <util/fs.h>

#include <openssl/ssl.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/** OpenSSL helpers shared by the HTTP server and P2P WebSocket transport */
namespace tls {

struct SslCtxDeleter {
    void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
};
struct SslDeleter {
    void operator()(SSL *p) const { SSL_free(p); }
};
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

/**
 * A new TLS 1.2+ context for non-blocking use on sockets owned by the
 * caller: partial writes and moving write buffers are allowed (as
 * WebSocketSock requires), and kernel TLS is enabled where OpenSSL and the
 * kernel support it. Servers select ALPN http/1.1 when offered; clients
 * offer it (after h2 with `offer_h2`, as browsers do), with cipher suites,
 * groups and signature algorithms ordered like a mainstream browser. Only
 * offer h2 when the connection can then be spoken as HTTP/2.
 */
SslCtxPtr NewContext(bool server, bool offer_h2 = false);

/**
 * Let a server session select ALPN h2 (HTTP/2), preferred over http/1.1,
 * when the client offers it. Off by default: only call this for a
 * connection that will be served with HTTP/2 if it is selected.
 */
void AllowServerAlpnH2(SSL *ssl);

/** Load a PEM certificate chain and private key into `ctx` */
bool UseCertificatePem(SSL_CTX *ctx, const std::string &cert_chain_pem,
                       const std::string &key_pem);

/** Load PEM files (certificate chain and key) into `ctx` */
bool UseCertificateFiles(SSL_CTX *ctx, const fs::path &cert_chain,
                         const fs::path &key);

/**
 * Client TLS contexts are immutable after publication. Check file mtimes on
 * new handshakes (at most once a second), just like the inbound listener.
 * A failed replacement retains the last valid context; existing SSL objects
 * retain their own OpenSSL reference to that context.
 */
class ReloadingClientContext {
    std::mutex m_mutex;
    std::shared_ptr<SSL_CTX> m_context;
    std::optional<fs::path> m_cert, m_key;
    fs::file_time_type m_cert_mtime{}, m_key_mtime{};
    bool m_loaded{false};
    const bool m_offer_h2;
    std::chrono::steady_clock::time_point m_next_check{};

public:
    ReloadingClientContext(const std::optional<fs::path> &cert,
                           const std::optional<fs::path> &key,
                           bool offer_h2 = false);
    std::shared_ptr<SSL_CTX> Get();
};

struct SelfSigned {
    std::string cert_pem;
    std::string key_pem;
};

/**
 * Generate a self-signed certificate (CA:FALSE) with the given subject CN,
 * DNS and IP subject alternative names and validity, for a new EC P-256 key
 * or, if `key_pem` is set, for that existing key (renewals keep the public
 * key, and with it any SPKI pins).
 */
std::optional<SelfSigned>
GenerateSelfSigned(const std::string &common_name,
                   const std::vector<std::string> &dns_names,
                   const std::vector<std::string> &ip_addresses,
                   std::chrono::seconds validity,
                   const std::string &key_pem = {});

/** Write a key (mode 0600) and certificate as PEM files */
bool WritePemFiles(const SelfSigned &pem, const fs::path &cert_path,
                   const fs::path &key_path);

/** Replace a file's contents atomically (write a sibling, then rename) */
bool ReplaceFile(const fs::path &path, const std::string &contents);

/** Read a whole (small) file, or std::nullopt */
std::optional<std::string> ReadFile(const fs::path &path);

struct CertificateInfo {
    std::string common_name;
    //! Seconds until notAfter (negative once expired)
    int64_t seconds_left{0};
};

/** Subject CN and expiry of the first certificate in a PEM file */
std::optional<CertificateInfo> ReadCertificateInfo(const fs::path &path);

/** SHA-256 of a certificate's DER SubjectPublicKeyInfo (empty on error) */
std::vector<unsigned char> SpkiSha256(X509 *cert);

/** SHA-256 of the whole DER certificate, hex (empty if no certificate) */
std::string CertSha256Hex(X509 *cert);

/** The peer's certificate, or nullptr (caller frees with X509_free) */
X509 *PeerCertificate(const SSL *ssl);

/** The ALPN protocol agreed on the session ("" if none) */
std::string NegotiatedAlpn(const SSL *ssl);

/** OpenSSL's queued error strings, for logging */
std::string ErrorString();

/**
 * Whether the TLS client offers the X25519MLKEM768 post-quantum hybrid key
 * exchange (OpenSSL >= 3.5; older versions fall back to X25519)
 */
bool HasHybridKeyExchange();

/** The OpenSSL in use, the one built against, and the client's key exchange */
std::string LibraryDescription();

} // namespace tls

#endif // BITCOIN_TLS_UTIL_H
