// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Compiled only with -DENABLE_WEBTRANSPORT=ON: fail the build early, with a
// clear message, when the QUIC/HTTP/3 libraries found are too old or not the
// patched nghttp3 from depends.

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <openssl/opensslv.h>

#include <cstdint>

static_assert(NGTCP2_VERSION_NUM >= 0x011900,
              "P2P over WebTransport needs ngtcp2 >= 1.25.0");
static_assert(NGHTTP3_VERSION_NUM >= 0x011200,
              "P2P over WebTransport needs nghttp3 >= 1.18.0");
static_assert(OPENSSL_VERSION_NUMBER >= 0x30500000L,
              "ngtcp2's OpenSSL backend needs OpenSSL >= 3.5 (QUIC TLS API)");
// Provided only by depends/patches/nghttp3/0001-extra-settings.patch.
static_assert(sizeof(nghttp3_extra_setting) == 2 * sizeof(uint64_t),
              "nghttp3 lacks the WebTransport SETTINGS patch from depends");
