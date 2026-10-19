Dependencies
============

These are the dependencies currently used by Bitcoin ABC. You can find instructions for installing them in the [`build-*.md`](../INSTALL.md) file for your platform.

| Dependency | Version used | Minimum required | CVEs | Shared |
| --- | --- | --- | --- | --- |
| Berkeley DB | [5.3.28](http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index.html) | 5.3 | No |  |
| Boost | [1.81.0](https://www.boost.org/users/download/) | 1.64.0 | No |  |
| Clang |  | [10](https://releases.llvm.org/download.html) (C++20 support) |  |  |
| CMake |  | [3.25](https://cmake.org/download/) |  |  |
| GCC |  | [12](https://gcc.gnu.org/) |  |  |
| glibc | | [2.31](https://www.gnu.org/software/libc/) |  |  |
| jemalloc | [5.2.1](https://github.com/jemalloc/jemalloc/releases) | 3.6.0 |  |  |
| nghttp2 | [1.70.0](https://github.com/nghttp2/nghttp2/releases) | 1.68.1 | No |  |
| Ninja |  | [1.5.1](https://github.com/ninja-build/ninja/releases) |  |  |
| OpenSSL | [3.5.9](https://openssl-library.org/source/) | 3.0 | No |  |
| protobuf | [21.12](https://github.com/protocolbuffers/protobuf/releases/tag/v21.12) |  | No |  |
| Python (tests) |  | [3.10](https://www.python.org/downloads) |  |  |
| SQLite | [3.32.1](https://sqlite.org/download.html) | 3.7.17 |  |  |
| systemtap ([tracing](tracing.md))| | | | |

Controlling dependencies
------------------------
Some dependencies are not needed in all configurations. The following are some
factors that affect the dependency list.

#### Options passed to `cmake`
* Berkeley DB and SQLite are not needed with `-DBUILD_WALLET=OFF`.
* OpenSSL is always needed: the node terminates TLS itself (RPC, `-publicbind`
  and WebSocket P2P listeners, and `wss://` dialing).
* systemtap is not needed with `-DENABLE_TRACING=OFF`.
* nghttp2 is only needed with `-DENABLE_HTTP2=ON` (default OFF).
