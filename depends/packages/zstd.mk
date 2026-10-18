package=zstd
$(package)_version=1.5.7
$(package)_download_path=https://github.com/facebook/zstd/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3

define $(package)_set_vars
$(package)_build_env=CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)"
$(package)_build_env+=CFLAGS="$($(package)_cflags) $($(package)_cppflags)"
$(package)_build_opts=ZSTD_LEGACY_SUPPORT=0 ZSTD_NO_ASM=1 HAVE_PTHREAD=1
endef

define $(package)_build_cmds
  $($(package)_build_env) $(MAKE) -C lib -j$(JOBS) $($(package)_build_opts) libzstd.a
endef

define $(package)_stage_cmds
  $(MAKE) -C lib $($(package)_build_opts) DESTDIR=$($(package)_staging_dir) PREFIX=$(host_prefix) install-static install-includes
endef
