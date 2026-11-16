package=nng
$(package)_version=2.1.0
$(package)_download_path=https://github.com/nanomsg/nng/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=e2fdcdf126b530e331b4727812b710629cdb5d90d230ce8f080e2eb520299d8d
$(package)_patches=remove_deps.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/remove_deps.patch
endef

define $(package)_config_cmds
  cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$($(package)_staging_dir)/$(host_prefix) \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CROSSCOMPILING=on \
    -DNNG_ENABLE_NNGCAT=off \
    -DNNG_TESTS=off \
    -DNNG_TOOLS=off \
    -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN_FILE) \
    -DBASEPREFIX=$(BASEPREFIX)
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  ninja install
endef
