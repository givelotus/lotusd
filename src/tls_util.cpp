// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tls_util.h>

#include <logging.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace tls {
namespace {
struct EVPPKeyDeleter {
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
struct EVPPKeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};
struct X509Deleter {
    void operator()(X509 *p) const { X509_free(p); }
};
struct BNDeleter {
    void operator()(BIGNUM *p) const { BN_free(p); }
};
struct BIODeleter {
    void operator()(BIO *p) const { BIO_free(p); }
};

bool AddX509Extension(X509 *cert, int nid, const std::string &value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid,
                                              const_cast<char *>(value.c_str()));
    if (!ext) {
        return false;
    }
    const bool ok{X509_add_ext(cert, ext, -1) == 1};
    X509_EXTENSION_free(ext);
    return ok;
}

std::string BioToString(BIO *bio) {
    char *data{nullptr};
    const long len{BIO_get_mem_data(bio, &data)};
    return len > 0 ? std::string(data, len) : std::string{};
}
} // namespace

namespace {
//! ALPN protocol list (length-prefixed): HTTP/1.1, which WebSocket uses
constexpr unsigned char ALPN_HTTP11[]{8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

int SelectAlpn(SSL *, const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen, void *) {
    unsigned char *selected{nullptr};
    if (SSL_select_next_proto(&selected, outlen, ALPN_HTTP11,
                              sizeof(ALPN_HTTP11), in,
                              inlen) != OPENSSL_NPN_NEGOTIATED) {
        // No http/1.1 offered (e.g. h2 only): continue without ALPN, as
        // HTTP/1.1-only web servers do.
        return SSL_TLSEXT_ERR_NOACK;
    }
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}

/**
 * Order the client's offer like a mainstream browser (Chrome) as far as
 * OpenSSL allows. Remaining fingerprint differences (no GREASE values,
 * fixed extension order, no h2 in ALPN, no ECH) are documented in
 * doc/p2p-websocket.md.
 */
void ApplyClientProfile(SSL_CTX *ctx) {
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:"
                                  "TLS_AES_256_GCM_SHA384:"
                                  "TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(
        ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
             "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
             "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
             "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
             "AES256-GCM-SHA384:AES128-SHA:AES256-SHA");
    // The post-quantum hybrid group needs OpenSSL >= 3.5.
    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256:P-384") !=
        1) {
        ERR_clear_error();
        SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
    }
    SSL_CTX_set1_sigalgs_list(
        ctx, "ECDSA+SHA256:rsa_pss_rsae_sha256:RSA+SHA256:ECDSA+SHA384:"
             "rsa_pss_rsae_sha384:RSA+SHA384:rsa_pss_rsae_sha512:RSA+SHA512");
    SSL_CTX_set_alpn_protos(ctx, ALPN_HTTP11, sizeof(ALPN_HTTP11));
}
} // namespace

std::string NegotiatedAlpn(const SSL *ssl) {
    const unsigned char *data{nullptr};
    unsigned int len{0};
    SSL_get0_alpn_selected(ssl, &data, &len);
    return data ? std::string(reinterpret_cast<const char *>(data), len)
                : std::string{};
}

SslCtxPtr NewContext(bool server) {
    SslCtxPtr ctx{
        SSL_CTX_new(server ? TLS_server_method() : TLS_client_method())};
    if (!ctx) {
        return ctx;
    }
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_mode(ctx.get(), SSL_MODE_ENABLE_PARTIAL_WRITE |
                                    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    uint64_t options{SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION};
#ifdef SSL_OP_ENABLE_KTLS
    options |= SSL_OP_ENABLE_KTLS;
#endif
    SSL_CTX_set_options(ctx.get(), options);
    if (server) {
        SSL_CTX_set_alpn_select_cb(ctx.get(), SelectAlpn, nullptr);
    } else {
        ApplyClientProfile(ctx.get());
    }
    return ctx;
}

bool UseCertificatePem(SSL_CTX *ctx, const std::string &cert_chain_pem,
                       const std::string &key_pem) {
    std::unique_ptr<BIO, BIODeleter> cert_bio{
        BIO_new_mem_buf(cert_chain_pem.data(), int(cert_chain_pem.size()))};
    std::unique_ptr<BIO, BIODeleter> key_bio{
        BIO_new_mem_buf(key_pem.data(), int(key_pem.size()))};
    if (!cert_bio || !key_bio) {
        return false;
    }
    std::unique_ptr<X509, X509Deleter> cert{
        PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)};
    std::unique_ptr<EVP_PKEY, EVPPKeyDeleter> key{
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr)};
    if (!cert || !key || SSL_CTX_use_certificate(ctx, cert.get()) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, key.get()) != 1) {
        return false;
    }
    // Remaining certificates in the chain.
    while (X509 *extra =
               PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)) {
        if (SSL_CTX_add0_chain_cert(ctx, extra) != 1) {
            X509_free(extra);
            return false;
        }
    }
    ERR_clear_error(); // End of the PEM chain.
    return SSL_CTX_check_private_key(ctx) == 1;
}

bool UseCertificateFiles(SSL_CTX *ctx, const fs::path &cert_chain,
                         const fs::path &key) {
    return SSL_CTX_use_certificate_chain_file(
               ctx, fs::PathToString(cert_chain).c_str()) == 1 &&
           SSL_CTX_use_PrivateKey_file(ctx, fs::PathToString(key).c_str(),
                                       SSL_FILETYPE_PEM) == 1 &&
           SSL_CTX_check_private_key(ctx) == 1;
}

ReloadingClientContext::ReloadingClientContext(
    const std::optional<fs::path> &cert, const std::optional<fs::path> &key)
    : m_cert{cert}, m_key{key} {
    auto ctx{NewContext(/*server=*/false)};
    if (ctx) {
        // Self-signed peers are allowed; explicit SPKI pins authenticate
        // peers in the dialer, as before certificate reloading.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        m_context = std::shared_ptr<SSL_CTX>{ctx.release(), SslCtxDeleter{}};
    }
}

std::shared_ptr<SSL_CTX> ReloadingClientContext::Get() {
    std::lock_guard<std::mutex> lock{m_mutex};
    const auto now{std::chrono::steady_clock::now()};
    if (!m_context || !m_cert || !m_key || now < m_next_check) {
        return m_context;
    }
    m_next_check = now + std::chrono::seconds{1};
    std::error_code cert_error, key_error;
    const auto cert_mtime{fs::last_write_time(*m_cert, cert_error)};
    const auto key_mtime{fs::last_write_time(*m_key, key_error)};
    if (m_loaded && !cert_error && !key_error && cert_mtime == m_cert_mtime &&
        key_mtime == m_key_mtime) {
        return m_context;
    }
    auto ctx{NewContext(/*server=*/false)};
    if (!ctx || !UseCertificateFiles(ctx.get(), *m_cert, *m_key)) {
        LogPrintf("Not reloading TLS client certificate %s: %s\n",
                  fs::PathToString(*m_cert), ErrorString());
        return m_context;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    m_context = std::shared_ptr<SSL_CTX>{ctx.release(), SslCtxDeleter{}};
    m_loaded = true;
    m_cert_mtime = cert_mtime;
    m_key_mtime = key_mtime;
    LogPrintf("Loaded TLS client certificate %s\n", fs::PathToString(*m_cert));
    return m_context;
}

namespace {
EVP_PKEY *NewP256Key() {
    std::unique_ptr<EVP_PKEY_CTX, EVPPKeyCtxDeleter> pctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    EVP_PKEY *key{nullptr};
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(),
                                               NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_CTX_set_ec_param_enc(pctx.get(), OPENSSL_EC_NAMED_CURVE) !=
            1 ||
        EVP_PKEY_keygen(pctx.get(), &key) != 1) {
        return nullptr;
    }
    return key;
}

EVP_PKEY *ReadPrivateKey(const std::string &pem) {
    std::unique_ptr<BIO, BIODeleter> bio{
        BIO_new_mem_buf(pem.data(), int(pem.size()))};
    return bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
               : nullptr;
}
} // namespace

std::optional<SelfSigned>
GenerateSelfSigned(const std::string &common_name,
                   const std::vector<std::string> &dns_names,
                   const std::vector<std::string> &ip_addresses,
                   std::chrono::seconds validity,
                   const std::string &key_pem) {
    std::unique_ptr<EVP_PKEY, EVPPKeyDeleter> key{
        key_pem.empty() ? NewP256Key() : ReadPrivateKey(key_pem)};
    if (!key) {
        return std::nullopt;
    }

    std::unique_ptr<X509, X509Deleter> cert{X509_new()};
    std::unique_ptr<BIGNUM, BNDeleter> serial{BN_new()};
    if (!cert || !serial || X509_set_version(cert.get(), 2) != 1 ||
        BN_rand(serial.get(), 127, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1 ||
        !BN_to_ASN1_INTEGER(serial.get(),
                            X509_get_serialNumber(cert.get())) ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()),
                         static_cast<long>(validity.count())) ||
        X509_set_pubkey(cert.get(), key.get()) != 1) {
        return std::nullopt;
    }
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name{
        X509_NAME_new(), &X509_NAME_free};
    std::vector<std::string> sans;
    for (const auto &dns : dns_names) {
        sans.push_back("DNS:" + dns);
    }
    for (const auto &ip : ip_addresses) {
        sans.push_back("IP:" + ip);
    }
    if (!name ||
        X509_NAME_add_entry_by_txt(
            name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(common_name.c_str()), -1,
            -1, 0) != 1 ||
        X509_set_subject_name(cert.get(), name.get()) != 1 ||
        X509_set_issuer_name(cert.get(), name.get()) != 1 ||
        !AddX509Extension(cert.get(), NID_basic_constraints,
                          "critical,CA:FALSE") ||
        (!sans.empty() &&
         !AddX509Extension(cert.get(), NID_subject_alt_name,
                           util::Join(sans, ","))) ||
        X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        return std::nullopt;
    }

    std::unique_ptr<BIO, BIODeleter> key_bio{BIO_new(BIO_s_mem())};
    std::unique_ptr<BIO, BIODeleter> cert_bio{BIO_new(BIO_s_mem())};
    if (!key_bio || !cert_bio ||
        PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1 ||
        PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
        return std::nullopt;
    }
    return SelfSigned{BioToString(cert_bio.get()), BioToString(key_bio.get())};
}

bool WritePemFiles(const SelfSigned &pem, const fs::path &cert_path,
                   const fs::path &key_path) {
    FILE *key_file = fsbridge::fopen(key_path, "wb");
    if (!key_file) {
        return false;
    }
#ifndef WIN32
    fchmod(fileno(key_file), S_IRUSR | S_IWUSR);
#endif
    const bool key_ok{fwrite(pem.key_pem.data(), 1, pem.key_pem.size(),
                             key_file) == pem.key_pem.size()};
    const bool key_closed{fclose(key_file) == 0};
    if (!key_ok || !key_closed) {
        return false;
    }
    FILE *cert_file = fsbridge::fopen(cert_path, "wb");
    if (!cert_file) {
        return false;
    }
    const bool cert_ok{fwrite(pem.cert_pem.data(), 1, pem.cert_pem.size(),
                              cert_file) == pem.cert_pem.size()};
    const bool cert_closed{fclose(cert_file) == 0};
    return cert_ok && cert_closed;
}

bool ReplaceFile(const fs::path &path, const std::string &contents) {
    fs::path tmp{path};
    tmp += ".new";
    FILE *file{fsbridge::fopen(tmp, "wb")};
    if (!file) {
        return false;
    }
    const bool ok{fwrite(contents.data(), 1, contents.size(), file) ==
                  contents.size()};
    if (fclose(file) != 0 || !ok) {
        return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

std::optional<std::string> ReadFile(const fs::path &path) {
    FILE *file{fsbridge::fopen(path, "rb")};
    if (!file) {
        return std::nullopt;
    }
    std::string out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        out.append(buf, n);
    }
    const bool ok{ferror(file) == 0};
    fclose(file);
    return ok ? std::optional{out} : std::nullopt;
}

std::optional<CertificateInfo> ReadCertificateInfo(const fs::path &path) {
    const auto pem{ReadFile(path)};
    if (!pem) {
        return std::nullopt;
    }
    std::unique_ptr<BIO, BIODeleter> bio{
        BIO_new_mem_buf(pem->data(), int(pem->size()))};
    std::unique_ptr<X509, X509Deleter> cert{
        bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)
            : nullptr};
    if (!cert) {
        return std::nullopt;
    }
    CertificateInfo info;
    char cn[256];
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert.get()),
                                  NID_commonName, cn, sizeof(cn)) > 0) {
        info.common_name = cn;
    }
    int days{0}, seconds{0};
    if (ASN1_TIME_diff(&days, &seconds, /*from=now*/ nullptr,
                       X509_get0_notAfter(cert.get())) != 1) {
        return std::nullopt;
    }
    info.seconds_left = int64_t{days} * 86400 + seconds;
    return info;
}

std::vector<unsigned char> SpkiSha256(X509 *cert) {
    if (!cert) {
        return {};
    }
    unsigned char *der{nullptr};
    const int len{i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der)};
    if (len <= 0) {
        return {};
    }
    std::vector<unsigned char> md(EVP_MAX_MD_SIZE);
    unsigned int md_len{0};
    const bool ok{EVP_Digest(der, len, md.data(), &md_len, EVP_sha256(),
                             nullptr) == 1};
    OPENSSL_free(der);
    if (!ok) {
        return {};
    }
    md.resize(md_len);
    return md;
}

std::string CertSha256Hex(X509 *cert) {
    if (!cert) {
        return {};
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len{0};
    if (X509_digest(cert, EVP_sha256(), md, &len) != 1) {
        return {};
    }
    return HexStr(Span<const unsigned char>{md, len});
}

X509 *PeerCertificate(const SSL *ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return SSL_get1_peer_certificate(ssl);
#else
    return SSL_get_peer_certificate(ssl);
#endif
}

std::string ErrorString() {
    std::string out;
    unsigned long err;
    char buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!out.empty()) {
            out += "; ";
        }
        out += buf;
    }
    return out;
}

} // namespace tls
