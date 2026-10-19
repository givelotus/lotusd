packages:=boost zstd

protobuf_native_packages = native_protobuf
protobuf_packages = protobuf

openssl_packages = openssl

# P2P over WebTransport (HTTP/3 / QUIC); ngtcp2 needs openssl >= 3.5
webtransport_packages = nghttp3 ngtcp2

sqlite_packages=sqlite


http2_packages = nghttp2

jemalloc_packages = jemalloc

ifeq ($(host_os),linux)
cpython_native_packages = native_cpython
cpython_packages = cpython
endif
