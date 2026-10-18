packages:=boost zstd

protobuf_native_packages = native_protobuf
protobuf_packages = protobuf

openssl_packages = openssl

# P2P over WebTransport (HTTP/3 / QUIC); ngtcp2 needs openssl >= 3.5
webtransport_packages = nghttp3 ngtcp2

qrencode_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm

qt_darwin_packages=qt
qt_mingw32_packages=qt

sqlite_packages=sqlite

zmq_packages=zeromq

http2_packages = nghttp2

jemalloc_packages = jemalloc

ifeq ($(host_os),linux)
cpython_native_packages = native_cpython
cpython_packages = cpython
endif
