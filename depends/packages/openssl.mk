package=openssl
$(package)_version=3.5.9
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

# Static libcrypto and libssl only: no programs, docs, tests, engines or
# loadable modules (providers are built in), and no algorithms or protocols
# the node does not use. The QUIC TLS API that QUIC stacks such as ngtcp2 use
# is built even with no-quic; no-quic only drops OpenSSL's own QUIC stack.
# ML-KEM must stay enabled: the TLS client offers X25519MLKEM768.
define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)"
$(package)_config_opts=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl --libdir=lib
$(package)_config_opts+=no-shared
$(package)_config_opts+=no-apps
$(package)_config_opts+=no-docs
$(package)_config_opts+=no-tests
$(package)_config_opts+=no-unit-test
$(package)_config_opts+=no-module
$(package)_config_opts+=no-legacy
$(package)_config_opts+=no-dso
$(package)_config_opts+=no-engine
$(package)_config_opts+=no-capieng
$(package)_config_opts+=no-winstore
$(package)_config_opts+=no-autoload-config
$(package)_config_opts+=no-aria
$(package)_config_opts+=no-camellia
$(package)_config_opts+=no-cast
$(package)_config_opts+=no-cmp
$(package)_config_opts+=no-cms
$(package)_config_opts+=no-comp
$(package)_config_opts+=no-ct
$(package)_config_opts+=no-dtls
$(package)_config_opts+=no-ec_nistp_64_gcc_128
$(package)_config_opts+=no-gost
$(package)_config_opts+=no-idea
$(package)_config_opts+=no-md2
$(package)_config_opts+=no-mdc2
$(package)_config_opts+=no-ocsp
$(package)_config_opts+=no-quic
$(package)_config_opts+=no-rc2
$(package)_config_opts+=no-rc4
$(package)_config_opts+=no-rc5
$(package)_config_opts+=no-rdrand
$(package)_config_opts+=no-rfc3779
$(package)_config_opts+=no-sctp
$(package)_config_opts+=no-seed
$(package)_config_opts+=no-sm2
$(package)_config_opts+=no-sm3
$(package)_config_opts+=no-sm4
$(package)_config_opts+=no-srp
$(package)_config_opts+=no-srtp
$(package)_config_opts+=no-ssl-trace
$(package)_config_opts+=no-ssl3
$(package)_config_opts+=no-ts
$(package)_config_opts+=no-weak-ssl-ciphers
$(package)_config_opts+=no-whirlpool
$(package)_config_opts+=no-zlib
$(package)_config_opts+=no-zlib-dynamic
$(package)_config_opts+=$($(package)_cflags) $($(package)_cppflags)
$(package)_config_opts_linux=-fPIC -Wa,--noexecstack
$(package)_config_opts_x86_64_linux=linux-x86_64
$(package)_config_opts_i686_linux=linux-generic32
$(package)_config_opts_arm_linux=linux-generic32
$(package)_config_opts_aarch64_linux=linux-generic64
$(package)_config_opts_aarch64_darwin=darwin64-arm64-cc
$(package)_config_opts_mipsel_linux=linux-generic32
$(package)_config_opts_mips_linux=linux-generic32
$(package)_config_opts_powerpc_linux=linux-generic32
$(package)_config_opts_x86_64_darwin=darwin64-x86_64-cc
$(package)_config_opts_x86_64_darwin+=$(darwin_LDFLAGS)
$(package)_config_opts_x86_64_mingw32=mingw64
$(package)_config_opts_i686_mingw32=mingw
endef

define $(package)_preprocess_cmds
  sed -i.old "s/define DATE .*/define DATE \"\"/g" util/mkbuildinf.pl
endef

define $(package)_config_cmds
  WINDRES=$($(host_os)_WINDRES) ./Configure $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS) build_libs
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install_sw
endef

define $(package)_postprocess_cmds
  rm -rf share bin etc lib/cmake lib/engines-3 lib/ossl-modules
endef
