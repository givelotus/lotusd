# P2P over WebTransport

This is an experimental, default-off eCash-tier transport. Its committed
foundation covers dependencies, message classification, the QUIC engine and
HTTP/3 WebTransport sessions. The P2P socket integration is under focused
validation. Discovery/fallback policy, complete DoS metrics, production browser
certificate lifecycle, Linux batching and the release measurement gate remain
unfinished. Do not use prototype/browser echo results as P2P acceptance evidence.

Configure with `-DENABLE_WEBTRANSPORT=ON`; this requires OpenSSL >= 3.5,
ngtcp2 1.25.0 with `crypto_ossl`, and nghttp3 1.18.0 with the small SETTINGS
extension in `depends/patches/nghttp3`. Both the CMake and runtime feature
defaults remain off. `-p2pwebtransport=1` enables the engine when compiled.
Raw ABC/eCash P2P framing and stock TCP connections remain available.

## Wire framing

The engine uses UDP, QUIC v1, TLS 1.3, ALPN `h3`, HTTP/3 Extended CONNECT
and one WebTransport session per connection. The default path is `/p2p/wt`.
Public WebTransport draft SETTINGS and `:protocol` names are negotiated for
browser interoperability. The current application protocol is solely
`p2p-v1`, selected by standard `wt-available-protocols` / `wt-protocol`
headers. A node offering that protocol rejects a missing, malformed or
unoffered selection. No private older/newer protocol fallback is inferred.
A browser omitting the optional application protocol offer receives no
application protocol selection; its stream bytes must still use this endpoint's
current framing.

The client opens five bidirectional streams. Each starts with the standard
WebTransport bidirectional signal (`0x41` as a QUIC varint), CONNECT session
stream ID (varint), then one application class byte:

| Tag | Class | Messages |
| --- | --- | --- |
| 1 | CONTROL | handshake, ping and unknown message names |
| 2 | AVALANCHE | votes, polls, proofs and related inventory |
| 3 | TX_ANNOUNCE | transaction inventory and relay announcements |
| 4 | TX_BODY | transaction bodies and requests |
| 5 | BLOCK | block requests, block bodies and block inventory |

CONTROL and AVALANCHE share the highest send priority, then TX_ANNOUNCE,
TX_BODY and BLOCK. Mixed `inv`, `getdata` and `notfound` vectors split into
one message per class, preserving entry order inside each class. Their inner
payload length and checksum are recomputed. This changes per-message counts
while preserving inventory meaning. Unknown message names use CONTROL.

Each application message is `u32 little-endian length`, one flags byte,
and body. Length counts flags plus body. Flags 0 carries raw bytes; 1 carries
zstd with one independent streaming context per class and direction; 2 carries
an independent zstd frame. Both compressed forms use the existing P2P
dictionary. Reserved flags, invalid lengths and excessive decompressed sizes
close the peer. Inside the body is the current eCash 24-byte message header
and payload. Messages below 64 bytes remain raw; messages from 64 KiB use
independent compression. Datagram P2P is not implemented.

The socket bridge gives CNode complete messages. Before peer verack,
non-CONTROL frames wait so messages arriving on another stream cannot race
the handshake. Incoming complete frames notify a local socketpair; QUIC and
HTTP/3 state stays on one `quic` thread. Compression and decompression run on
the net caller, outside the QUIC engine.

## Listener and identity behavior

`-listen=0` suppresses the UDP listener, including explicit
`-p2pwebtransportbind`; outbound dialing remains available. Otherwise an explicit
WebTransport bind list overrides automatic binds. Automatic UDP binds mirror
ordinary `-bind`, `-whitebind` and `-publicbind` addresses, or the normal P2P
port on IPv4/IPv6 when no explicit P2P binds are supplied. Onion-only bind
addresses have no UDP counterpart. A failed optional UDP bind is logged;
the existing TCP listener continues.

QUIC always encrypts its traffic. Neighboring raw/WebSocket listen options
control those TCP transports separately. `-p2prequiretls` cannot weaken QUIC
TLS. No SOCKS transport exists for QUIC: name/network proxy and onion dials
fail closed. `-onlynet` still restricts the destination's address network.

The engine loads `-tlscert` / `-tlskey`, or the node's datadir TLS files,
and checks server certificate replacement once per minute. A bad replacement
retains the previous identity. Existing sessions retain their original
certificate. The `wt://host:port/path#spki=<base64url>` URL pins the SHA-256
of SubjectPublicKeyInfo; `#cert=<hex>` pins the DER certificate SHA-256.
The existing per-host P2P key pins and known-client-key permissions are reused.
Matching whitebind address/port permissions apply to inbound sessions.

Browser-specific short-lived certificate rotation and its public information
endpoint are unfinished. The generic default certificate is not claimed to
meet browser `serverCertificateHashes` validity constraints.

## Recovery findings and verification limits

The recovered W1 depends build found that OpenSSL's `no-quic` configure
option did not disable ngtcp2's external `crypto_ossl` TLS APIs. Homebrew
headers can otherwise shadow the patched dependency prefix, so dependency
include directories precede system paths.

ngtcp2 1.25.0 lacks RESET_STREAM_AT. The public draft union supports the
historically tested browsers, but strict draft-16 clients requiring that
transport parameter remain unsupported. Safari is unverified. Public draft
negotiation is distinct from obsolete private application version support.

The eCash tier has no V2 compress-once cache. Independent frames use one-shot
dictionary compression. Nucleation sends `sendinvshort` after verack and it
must share TX_ANNOUNCE ordering with `invshort`; the final merged message table
still needs its W11 audit.

Recovered records report Chrome 155/Firefox 158 echo-mode interoperability,
plus W1–W5 builds/focused tests. Resumed verification covers CMake configuration, source diff/Python syntax,
exact W1–W6 mailbox replay, Chronik-enabled daemon/unit builds, 26 selected
unit cases and the basic/TLS functional tests. The new fuzz target has not
built/run. Full runtime suites,
Linux loss/CPU measurements, Guix reproducibility and a 24-hour soak have not
run. Both defaults stay OFF until the complete measurement gate passes.

## Fingerprint and proxy acceptance extension

Client/server fingerprint and load-balancer interoperability are now explicit
acceptance work alongside the original W1–W12 gate. See
[`contrib/bench/webtransport/README.md`](../contrib/bench/webtransport/README.md)
for capture, JA4 derivation, raw ordered-field comparisons and controlled
browser/engine recipes. The observer is test-only and opt-in; it exports no
session secrets or production CLI mode. Actual node, Chrome and Firefox captures/JA4 comparisons are recorded in
[`MEASURED.md`](../contrib/bench/webtransport/MEASURED.md); their differences
remain explicit. Reverse-proxy profiles and merged
HTTP/2/WT proxy behavior remain pending.

Compare ALPN and Extended CONNECT support separately for HTTP/2 RFC 8441 and
HTTP/3 WebTransport, including flow control, idle/request timeouts and graceful
shutdown. The current HTTP/3 engine serves WT P2P sessions only, with no generic
H3 RPC claim. Keep TLS 1.3 and actual peer identity authentication through
supported proxy paths. The installed OpenSSL API can set cipher/group/signature
lists; it does not provide Chromium extension permutation. No named browser
profile or indistinguishability claim has been applied.
