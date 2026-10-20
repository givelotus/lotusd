package=ngtcp2
$(package)_version=1.25.0
$(package)_download_path=https://github.com/ngtcp2/ngtcp2/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb
# libngtcp2_crypto_ossl needs OpenSSL's QUIC TLS callbacks
# (SSL_set_quic_tls_cbs), i.e. OpenSSL >= 3.5: depends' openssl.mk must be the
# 3.5 LTS package. With 1.1.1 configure silently skips the backend and the
# node's CMake (FindNgtcp2, component crypto_ossl) fails.
$(package)_dependencies=openssl

# QUIC transport plus the OpenSSL crypto backend only (P2P over WebTransport,
# -DENABLE_WEBTRANSPORT). nghttp3 is only needed for ngtcp2's examples.
define $(package)_set_vars
$(package)_config_opts=--enable-lib-only --disable-shared --enable-static
$(package)_config_opts+=--with-openssl --without-libnghttp3 --without-jemalloc
$(package)_config_opts+=--without-gnutls --without-boringssl --without-picotls --without-wolfssl
$(package)_config_opts+=--disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

# Fail here, not in the node's CMake, when the OpenSSL backend was skipped
# (configure only warns when SSL_set_quic_tls_cbs is missing).
define $(package)_build_cmds
  $(MAKE) -j$(JOBS) -C lib && \
  $(MAKE) -j$(JOBS) -C crypto && \
  test -f crypto/ossl/.libs/libngtcp2_crypto_ossl.a || \
  { echo "ngtcp2: libngtcp2_crypto_ossl was not built; OpenSSL >= 3.5 is required" >&2; exit 1; }
endef

define $(package)_stage_cmds
  $(MAKE) -C lib DESTDIR=$($(package)_staging_dir) install && \
  $(MAKE) -C crypto DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
