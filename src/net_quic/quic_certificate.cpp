// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/quic_certificate.h>

#include <net_websocket.h>
#include <tls_util.h>
#include <util/time.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ctime>
#include <memory>
#include <string_view>
#include <utility>

namespace {
constexpr int64_t DAY{86400};
using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

KeyPtr ReadKey(const std::string &pem) {
    BioPtr bio{BIO_new_mem_buf(pem.data(), int(pem.size())), BIO_free};
    return {bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
                : nullptr,
            EVP_PKEY_free};
}
bool IsP256(EVP_PKEY *key) {
    if (!key || !EVP_PKEY_is_a(key, "EC")) return false;
    char group[80];
    size_t size{0};
    return EVP_PKEY_get_group_name(key, group, sizeof(group), &size) == 1 &&
           std::string_view{group, size} == "prime256v1";
}
std::optional<int64_t> Seconds(const ASN1_TIME *value) {
    std::tm tm{};
    if (ASN1_TIME_to_tm(value, &tm) != 1) return std::nullopt;
    return timegm(&tm);
}
} // namespace

QuicCertificate::QuicCertificate(fs::path certificate, fs::path key,
                                 bool browser, std::function<int64_t()> clock)
    : m_certificate{std::move(certificate)}, m_key{std::move(key)},
      m_next_path{m_certificate.parent_path() / "node_wt_cert_next.pem"},
      m_browser{browser}, m_clock{std::move(clock)} {}

std::optional<QuicCertificate::Certificate>
QuicCertificate::Read(const std::string &pem, const std::string &key_pem) {
    BioPtr bio{BIO_new_mem_buf(pem.data(), int(pem.size())), BIO_free};
    CertificatePtr cert{
        bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr,
        X509_free};
    auto key{ReadKey(key_pem)};
    if (!cert || !key || X509_check_private_key(cert.get(), key.get()) != 1)
        return std::nullopt;
    const auto begin{Seconds(X509_get0_notBefore(cert.get()))};
    const auto end{Seconds(X509_get0_notAfter(cert.get()))};
    if (!begin || !end) return std::nullopt;
    Certificate result{pem,
                       tls::CertSha256Hex(cert.get()),
                       EncodeSpkiPin(tls::SpkiSha256(cert.get())),
                       *begin,
                       *end,
                       X509_get_version(cert.get()) == 2};
    if (result.hash.size() != 64 || result.spki.empty()) return std::nullopt;
    return result;
}

std::optional<QuicCertificate::Certificate>
QuicCertificate::Generate(const std::string &key, int64_t begin) {
    const auto pem{tls::GenerateSelfSigned(
        "localhost", {"localhost"}, {"127.0.0.1", "::1"},
        std::chrono::seconds{10 * DAY}, key, begin)};
    return pem ? Read(pem->cert_pem, key) : std::nullopt;
}

bool QuicCertificate::Refresh(std::string &error) {
    std::lock_guard lock{m_mutex};
    const int64_t now{m_clock ? m_clock()
                              : GetTime<std::chrono::seconds>().count()};
    // Public discovery requests share this state. Parse key/certificate files
    // at most once per wall-clock second, while mocktime changes remain
    // visible.
    if (m_last_refresh && *m_last_refresh == now) return true;
    const auto key_pem{tls::ReadFile(m_key)};
    if (!key_pem) {
        error = "unable to read WebTransport TLS key";
        return false;
    }
    if (!m_browser) {
        const auto pem{tls::ReadFile(m_certificate)};
        auto certificate{pem ? Read(*pem, *key_pem) : std::nullopt};
        if (!certificate) {
            error = "unable to read matching WebTransport certificate and key";
            return false;
        }
        if (!m_current || certificate->hash != m_current->hash) ++m_generation;
        m_current = std::move(certificate);
        m_last_refresh = now;
        return true;
    }
    const auto key{ReadKey(*key_pem)};
    if (!IsP256(key.get())) {
        error = "-p2pwebtransportbrowsercert requires the existing TLS key to "
                "be EC P-256; the key is not replaced automatically";
        return false;
    }
    auto current{m_current}, next{m_next};
    if (!current || m_key_pem != *key_pem) {
        const auto pem{tls::ReadFile(m_certificate)};
        const auto next_pem{tls::ReadFile(m_next_path)};
        current = pem ? Read(*pem, *key_pem) : std::nullopt;
        next = next_pem ? Read(*next_pem, *key_pem) : std::nullopt;
    }
    const auto usable = [now](const std::optional<Certificate> &c) {
        return c && c->x509v3 && c->end > c->begin &&
               c->end - c->begin <= 14 * DAY && c->begin <= now && now < c->end;
    };
    if (!usable(current)) {
        current = usable(next) ? next : Generate(*key_pem, now - 3600);
        next.reset();
    } else if (current->end - now <= 4 * DAY) {
        current = usable(next) ? next : Generate(*key_pem, now - 3600);
        next.reset();
    }
    if (!current) {
        error = "unable to generate browser WebTransport certificate";
        return false;
    }
    if (!next || !next->x509v3 || next->begin != current->end - 4 * DAY ||
        next->end - next->begin != 10 * DAY || next->spki != current->spki) {
        next = Generate(*key_pem, current->end - 4 * DAY);
    }
    if (!next || next->hash == current->hash) {
        error = "unable to generate next browser WebTransport certificate";
        return false;
    }
    // Publish the previous next certificate as current before replacing next.
    // A crash between the two atomic replacements then retains a current hash
    // already advertised to clients. Never rewrite the shared TLS private key.
    if ((!m_current || m_current->hash != current->hash) &&
        !tls::ReplaceFile(m_certificate, current->pem)) {
        error = "unable to write browser WebTransport certificate";
        return false;
    }
    if (!m_current || m_current->hash != current->hash) ++m_generation;
    m_current = std::move(current);
    m_key_pem = *key_pem;
    if (m_next && m_next->hash == m_current->hash) m_next.reset();
    if ((!m_next || m_next->hash != next->hash) &&
        !tls::ReplaceFile(m_next_path, next->pem)) {
        // Current was published: snapshots must describe the actual leaf even
        // if writing its successor fails. A later refresh retries the
        // successor.
        error = "unable to write next browser WebTransport certificate";
        return false;
    }
    m_next = std::move(next);
    m_last_refresh = now;
    return true;
}

QuicCertificate::Info QuicCertificate::Snapshot() const {
    std::lock_guard lock{m_mutex};
    Info info;
    if (m_current) {
        info.hashes.push_back(m_current->hash);
        info.spki = m_current->spki;
    }
    if (m_next) info.hashes.push_back(m_next->hash);
    info.generation = m_generation;
    return info;
}
