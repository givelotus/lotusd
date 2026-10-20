package=nghttp3
$(package)_version=1.18.0
$(package)_download_path=https://github.com/ngtcp2/nghttp3/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=aad782c23d3f01bd4bb52c8bac7a553b631ef8115fd1612703df6183449fef19
# Adds nghttp3_conn_set_extra_settings() and an unknown-SETTINGS callback so
# the node can advertise and read the WebTransport SETTINGS codepoints (see
# doc/p2p-webtransport.md). Drop it once nghttp3 ships WebTransport support.
$(package)_patches=0001-extra-settings.patch

# HTTP/3 framing and QPACK only (P2P over WebTransport, -DENABLE_WEBTRANSPORT).
define $(package)_set_vars
$(package)_config_opts=--enable-lib-only --disable-shared --enable-static
$(package)_config_opts+=--disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/0001-extra-settings.patch && \
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS) -C lib
endef

define $(package)_stage_cmds
  $(MAKE) -C lib DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
