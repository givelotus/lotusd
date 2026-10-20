// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_CERTIFICATE_H
#define BITCOIN_NET_QUIC_QUIC_CERTIFICATE_H

#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/** Owned certificate state shared by the engine and public-info provider.
 * Browser hash mode uses the existing node TLS key, never replaces it, and
 * keeps two overlapping ten-day certificates. Normal CA mode is read-only.
 * Refresh is lazy on discovery or new TLS handshakes; existing TLS sessions
 * retain their OpenSSL context. No system clock or global trust is modified. */
class QuicCertificate {
public:
    struct Info {
        std::vector<std::string> hashes;
        std::string spki;
        uint64_t generation{0};
    };
    QuicCertificate(fs::path certificate, fs::path key, bool browser,
                    std::function<int64_t()> clock = {});
    bool Refresh(std::string &error);
    Info Snapshot() const;
    const fs::path &CertificatePath() const { return m_certificate; }

private:
    struct Certificate {
        std::string pem, hash, spki;
        int64_t begin{0}, end{0};
        bool x509v3{false};
    };
    static std::optional<Certificate> Read(const std::string &pem,
                                           const std::string &key);
    static std::optional<Certificate> Generate(const std::string &key,
                                               int64_t begin);
    const fs::path m_certificate, m_key, m_next_path;
    const bool m_browser;
    const std::function<int64_t()> m_clock;
    mutable std::mutex m_mutex;
    std::optional<Certificate> m_current, m_next;
    std::string m_key_pem;
    uint64_t m_generation{0};
    std::optional<int64_t> m_last_refresh;
};

#endif // BITCOIN_NET_QUIC_QUIC_CERTIFICATE_H
