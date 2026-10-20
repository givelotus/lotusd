HTTP/2
======

The node's HTTP server (RPC, REST, Chronik, health checks and the P2P
WebSocket endpoint) can speak HTTP/2 on its TLS listeners. HTTP/2 framing and
HPACK header compression come from [nghttp2](https://nghttp2.org/), a C
library without I/O or TLS of its own; the node drives it from its existing
Boost.Asio connections and keeps Boost.Beast's request and response types for
everything above the framing.

HTTP/2 is optional and **off by default** at build time.

Building
--------

Configure with `-DENABLE_HTTP2=ON`. CMake then requires nghttp2 **1.68.1 or
newer** (see [Security](#security) for why) and fails otherwise:

```sh
cmake -GNinja .. -DENABLE_HTTP2=ON
```

- Native developer builds use the system library (`libnghttp2-dev` on
  Debian/Ubuntu, `libnghttp2` on Homebrew, `nghttp2` on Fedora). Distribution
  packages older than 1.68.1 (for example Debian 12 and Ubuntu 24.04) are
  refused; use the depends build instead.
- The [depends](../depends/README.md) system builds a static libnghttp2
  (library only: no applications, examples, HPACK tools, HTTP/3 or Python
  bindings, and none of their optional dependencies). It is built by default;
  pass `NO_HTTP2=1` to skip it, like `NO_ZMQ=1`.

Security
--------

The pinned release is **nghttp2 1.70.0** (released 2026-07-29), downloaded from
the official GitHub release with SHA-256
`aa317e2cf9dca6afa0aed68f8fad6ff303ec6982e25a78c75c0b65e2b9b3ded5` (checked
against the digest GitHub publishes for the release asset). It contains the
fixes for every library vulnerability in the
[nghttp2 security advisories](https://github.com/nghttp2/nghttp2/security/advisories)
and the NVD:

| CVE | Fixed in | Issue |
| --- | --- | --- |
| CVE-2026-27135 | 1.68.1 | Assertion failure (DoS): reading continued after the library terminated a session internally. |
| CVE-2024-28182 | 1.61.0 | CONTINUATION flood: an unbounded number of CONTINUATION frames used excessive CPU. Bounded by `nghttp2_option_set_max_continuations` (default 8). |
| CVE-2023-44487 | 1.57.0 | HTTP/2 Rapid Reset: streams opened and immediately reset. Bounded by a RST_STREAM rate limit. |
| CVE-2023-35945 | 1.55.1 | Memory leak of header structures on certain RST_STREAM/GOAWAY sequences. |
| CVE-2020-11080 | 1.41.0 | Overly large SETTINGS frames used excessive CPU. |
| CVE-2019-9511, CVE-2019-9513 | 1.39.2 | "Data dribble" (window/priority manipulation) and "resource loop" (priority churn). |
| CVE-2018-1000168 | 1.31.1 | NULL dereference on a malformed ALTSVC frame. |
| CVE-2016-1544 | 1.7.1 | Memory exhaustion via HPACK header fields. |
| CVE-2015-8659 | 1.6.0 | Use after free in idle stream handling. |

RFC 7540 priorities, whose handling was the subject of several of these, are
no longer processed by current nghttp2 at all.

CVE-2026-58055 (nghttpx forwarding an HTTP/1.1 Upgrade request with a body) is
in the `nghttpx` proxy application, which is not built.

Advisories against *other* HTTP/2 implementations that use nghttp2 (Node.js,
Envoy, dnsdist) describe bugs in those programs, not in the library.

When updating nghttp2, check the release notes and advisories for every
release since the pinned one, update the SHA-256 from the release asset (and
verify it locally), and keep the CMake minimum at the oldest release that has
every library fix.
