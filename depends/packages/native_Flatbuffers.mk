package=native_Flatbuffers
$(package)_version=2.0.0
$(package)_download_path=https://github.com/google/flatbuffers/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=9ddb9031798f4f8754d00fca2f1a68ecf9d0f83dfac7239af1311e4fd9a565c4

define $(package)_set_vars
  $(package)_cxxflags=-std=c++11
endef

define $(package)_config_cmds
  cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$(build_prefix) \
    -DCMAKE_BUILD_TYPE=Release \
    -DFLATBUFFERS_BUILD_TESTS=off \
    -DFLATBUFFERS_BUILD_FLATHASH=off
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) ninja install
endef

define $(package)_postprocess_cmds
  rm -rf include 
endef
