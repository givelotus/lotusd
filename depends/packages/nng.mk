package=nng
$(package)_version=1.5.2
$(package)_download_path=https://github.com/nanomsg/nng/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=f8b25ab86738864b1f2e3128e8badab581510fa8085ff5ca9bb980d317334c46
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
    -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN_FILE) \
    -DBASEPREFIX=$(BASEPREFIX)
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  ninja install
endef
