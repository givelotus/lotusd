package=nghttp2
# 1.70.0 includes every library fix in the nghttp2 security advisories,
# among them HTTP/2 Rapid Reset (CVE-2023-44487, fixed in 1.57.0), the
# CONTINUATION flood (CVE-2024-28182, 1.61.0) and the missing state check
# after an internal session termination (CVE-2026-27135, 1.68.1). See
# doc/http2.md before changing the version.
$(package)_version=1.70.0
$(package)_download_path=https://github.com/nghttp2/nghttp2/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=aa317e2cf9dca6afa0aed68f8fad6ff303ec6982e25a78c75c0b65e2b9b3ded5

# Only libnghttp2 (HTTP/2 framing and HPACK): no applications, examples,
# HPACK tools, HTTP/3 or Python, and no optional dependencies, so nothing is
# picked up from the build host.
define $(package)_set_vars
  $(package)_config_opts=--enable-lib-only --disable-shared --enable-static
  $(package)_config_opts+=--disable-dependency-tracking --disable-werror
  $(package)_config_opts+=--disable-debug --disable-failmalloc --disable-http3
  $(package)_config_opts+=--without-libxml2 --without-jansson --without-zlib
  $(package)_config_opts+=--without-libevent-openssl --without-libcares
  $(package)_config_opts+=--without-wolfssl --without-openssl --without-libev
  $(package)_config_opts+=--without-jemalloc --without-systemd --without-mruby
  $(package)_config_opts+=--without-neverbleed --without-libngtcp2
  $(package)_config_opts+=--without-libnghttp3 --without-libbpf
  $(package)_config_opts+=--without-libbrotlienc --without-libbrotlidec
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -C lib -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) -C lib DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf bin share lib/*.la
endef
