package=Flatbuffers
$(package)_version=$(native_$(package)_version)
$(package)_download_path=$(native_$(package)_download_path)
$(package)_file_name=$(native_$(package)_file_name)
$(package)_sha256_hash=$(native_$(package)_sha256_hash)
$(package)_dependencies=native_$(package)

define $(package)_set_vars
  $(package)_cxxflags=-std=c++11
endef

define $(package)_config_cmds
  cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$($(package)_staging_dir)/$(host_prefix) \
    -DCMAKE_BUILD_TYPE=Release \
    -DFLATBUFFERS_BUILD_TESTS=off \
    -DFLATBUFFERS_BUILD_FLATC=off \
    -DFLATBUFFERS_BUILD_FLATHASH=off \
    -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN_FILE) \
    -DBASEPREFIX=$(BASEPREFIX)
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  ninja install
endef

define $(package)_postprocess_cmds
  rm -rf bin lib
endef
