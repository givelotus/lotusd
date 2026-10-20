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

## Automatic discovery and fallback (W7)

`NODE_WEBTRANSPORT` (`1 << 26`) says the advertised host and port also accept
P2P WebTransport on UDP. It is optional and does not change the services
required for ordinary peers. The node advertises it only after actual binds
succeed, using the default `/p2p/wt` path without a required URL token. The
ordinary P2P port and each configured public/domain port must have a matching
UDP listener; custom paths/tokens and outbound-only engines remain usable
through explicit URLs without advertising this bit.

With the engine enabled, `-p2pwebtransportdial=prefer` attempts WT for such
addresses, then uses the address's normal TCP transport if UDP fails: `NET_WSS`
addresses use `wss://`, while IPv4/IPv6 addresses retain stock raw P2P TCP.
An IP address's service bit does not imply an HTTP listener on its TCP port.
`off` disables these automatic attempts; `only` disables their TCP fallback.
Explicit `wt://` URLs remain WT-only and keep their explicit pins and path.
No service bit or policy enrolls the node in rendezvous or hole punching.

Automatic attempts use `-p2pwebtransporttimeout=3000` milliseconds. A failed
QUIC/WT attempt enters an exact-address, maximum4096-entry LRU cache for
`-p2pwebtransportretryafter=3600` seconds. Lookups do not extend its monotonic
expiry; zero disables caching. Interruptions and proxy/cache skips do not
create failures. `getwebtransportinfo` exposes current cache size and failure
counts; with metrics enabled, `fullnode_p2p_wt_fallback_total{reason=...}` exports
timeout/refused/unsupported/handshake counters. The fuller browser/info endpoint
and DoS metrics remain W8/W9 work.

Automatic UDP is disabled when a name or target-network proxy applies, and
obeys `-onlynet`. Explicit WT URLs never fall back. Proxy-configured discovery uses its
normal proxied TCP path instead. A pin supplied with `-p2pwebsocketpin` also
applies to WT dials of that host. Automatic discovery does not invent a pin;
use explicit configured pins when peer identity authentication is required.

Focused W7 validation passes: daemon/unit builds, 10 selected cases (319
assertions), the WT discovery/fallback test and both existing WebSocket
discovery/address-version tests. No broad sweep or benchmark was run.

## Admission, buffering and metrics (W8)

The engine checks banned/discouraged sources before allocating inbound TLS
state. `-p2pwebtransportmaxperip=16` counts handshaking, established and retained
closing connections by IPv4 /32 or IPv6 /64. TLS handshake state is limited
by `-p2pwebtransportmaxhandshaking=256`. A separate finite inbound engine cap
uses CConnman's effective inbound budget, including TLS connections that have
not opened a WT session. Accepted P2P sessions also enter the existing combined
TCP/WebSocket/WT connection accounting and eviction path.

`-p2pwebtransportretry=auto` asks for standard QUIC address validation above
64 pending inbound handshakes or 8 token-less Initials from an IP group within
10 seconds. `always` validates every new source; `off` retains QUIC's normal
anti-amplification protection without Retry. The source/rate table is bounded
at 4096 entries, preserves active counts and cannot replace recent source-rate
history with an unvalidated source. Global exhaustion uses Retry or rejection,
not unbounded allocations. Stateless resets retain their 10-per-second limit.
These mechanisms do not perform rendezvous introductions or hole punching.

Complete-frame receive credit follows `-maxreceivebuffer`. A large valid
message needs room to finish before the net thread can consume it, so the
aggregate encoded-byte bound also includes one maximum wire frame and the
32MiB receive window already granted by QUIC. At most 4096 complete frames
may wait per peer, including early CONTROL frames. A peer exceeding these
bounds loses its session. Large completed reassembly buffers are transferred
or released, instead of retained independently by all five stream classes.
These are encoded-byte/queue bounds; allocator capacity, decoded messages and
QUIC/TLS state add memory beyond that accounting.

With `-metrics`, `/metrics` reports WT connection gauges by direction/state,
TLS handshake results, Retry/reset counts, admission/session rejection reasons,
class-stream bytes and flow-control stalls, declared packet losses, smoothed
RTT samples, inventory splits and fallback reasons. Class-stream bytes include
framing: outbound bytes are counted when queued, inbound bytes when consumed.
RTT is sampled at most once per second per established connection. Labels use
fixed sets without peer addresses or URL tokens. Existing peer/connection
metrics now identify WebTransport separately from raw TCP and WebSocket.

Focused W8 checks pass: daemon and unit builds, 25 selected QUIC/peer-socket
cases (13,286 assertions), the six-node admission/Retry/ban/reconnect/block
test, and the existing HTTP metrics functional test. The opt-in capture-server
case remained inactive; no new browser cohort or broad benchmark ran. Linux,
Guix, cross-lane admission integration and the remaining W9–W12 gates are
separate from these focused results.

## Browser certificates and discovery (W9)

For normal Web PKI, provide `-tlscert` and `-tlskey` with a certificate
trusted by the browser for the node's hostname. The H3 listener uses the same
certificate as HTTP/WebSocket unless browser hash mode is enabled. H3 serves
WebTransport P2P sessions only; it does not serve generic RPC or wallet HTTP
resources. No blanket `Alt-Svc: h3` is emitted for those resources.

`-p2pwebtransportbrowsercert=1` creates `node_wt_cert.pem` and
`node_wt_cert_next.pem` in the network datadir. Each leaf is valid for ten
days. The next begins four days before current expiry; at that point it is
promoted and another successor is prepared. Both hashes survive restart.
Refresh happens on discovery requests or new TLS handshakes, using the node's
clock, and changed generations reload before the new handshake. Existing TLS
sessions keep their original context. Each certificate uses the existing
`node_tls_key.pem` (or explicit `-tlskey`), preserving its SPKI. HTTP/WSS
certificates and the shared private key are not rewritten. Browser hash mode
fails clearly for a key other than EC P-256; it does not silently rotate keys.
On storage failure, discovery retains the hash of the actual published leaf
and logs the failure; publishing its successor is retried on a later refresh.

Browser hash authentication requires a full leaf DER SHA-256, not an SPKI
hash. The [WebTransport specification](https://www.w3.org/TR/webtransport/)
requires a currently valid X.509v3 leaf lasting at most two weeks, includes
P-256 as an interoperable key type, and excludes RSA in this mode. Normal CA
authentication has its normal certificate rules. Certificate hashes must
arrive over a trusted channel, such as the application's authenticated
configuration. Fetching a hash from an unauthenticated endpoint cannot
authenticate that same endpoint, and knowing a hash does not grant client
permissions.

`getwebtransportinfo` reports binds, path, `p2p-v1`, current/next certificate
hashes, SPKI, allowed Origins, public WT standards SETTINGS identifiers and
private connection/fallback/cache counts. `GET` or `HEAD /p2p/wt/info` exposes
only discovery metadata on public listeners and on allowed RPC listeners.
It contains no URL token or connection/cache/fallback counters, permits
noncredentialed cross-origin reads, and uses `Cache-Control: no-store`.
Other methods return 405. WT Origin enforcement remains independent of this
public metadata endpoint.

```js
// Supplied by the application's authenticated configuration, not TOFU fetch.
const info = trustedApplicationConfig.webtransport;
const transport = new WebTransport(`https://node.example${info.path}`, {
  protocols: ["p2p-v1"],
  serverCertificateHashes: info.cert_sha256.map(hex => ({
    algorithm: "sha-256",
    value: Uint8Array.from(hex.match(/../g), pair => parseInt(pair, 16)),
  })),
});
await transport.ready;
// P2P class streams and framing follow the protocol above.
```

Allow the advertised UDP port through the firewall. The QUIC listener does
not accept PROXY protocol or infer UDP peer identity from `-trustedproxy`.
UDP passthrough preserves the node's TLS identity; a terminating proxy must
itself support WebTransport extended CONNECT, WT/H3 SETTINGS, stream and
connection flow control, sufficient handshake/idle timeouts and orderly
session shutdown. Ordinary HTTP/2 support or RFC 8441 WebSocket support alone
does not establish HTTP/3 WebTransport support. Native H2/TCP fallback and
cross-lane proxy integration require their own interoperability checks.

The bounded actual-node browser gate creates its own regtest datadir and
fresh profile, then checks authentication, `p2p-v1`, readiness and clean close:

```sh
contrib/devtools/webtransport-browser-test/run.sh \
  --node build/src/bitcoind --kind chrome \
  --browser '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  --out /tmp/wt-browser-gate-fresh
```

It prints PASS/FAIL JSON and records commands, binary hashes, browser version,
timing and summed process-group RSS. It does not use a default profile or
modify global trust. Supply `--ca-cert` and `--ca-key` for the CA path, omitting
hash overrides; the browser must genuinely trust that leaf. Firefox can
import a local root using `--ca-root` and an NSS `--certutil` into only the
fresh profile. For current Chrome, the test root can instead be stored in the
fresh profile's `ServerCertificate` database, constrained to `localhost`,
using the schema observed in the isolated Chrome 155 baseline and documented
by Chromium's certificate database sources. This is test tooling, not a
system/user keychain change or a certificate-error bypass. Run the same leaf
without `--ca-root`, with `--expect-reject`, as the paired untrusted-root
control. A negative result alone does not distinguish authentication failure
from a reachability failure; the paired trusted run checks that distinction.
No browser/CA result is claimed until those actual gates pass.

Chrome's stock WebTransport CA path additionally requires a *known* root,
not merely a locally trusted one. Chromium documents this in its
[WebTransport switch](https://chromium.googlesource.com/chromium/src/+/refs/tags/140.0.7339.19/components/network_session_configurator/common/network_switch_list.h)
and [proof-verifier selection](https://chromium.googlesource.com/chromium/src/+/d50147ff3e3622ef1a527c07d1442504a21a7c91/net/quic/dedicated_web_transport_http3_client.cc).
For an explicit isolated local-CA development test only,
`--local-ca-development` adds the documented browser developer switch.
Certificate-chain and hostname verification still run; use the paired
untrusted-root negative control in that mode too. Such a result is a
development-CA result, not stock public-CA or browser-fingerprint equivalence.
The node's TLS policy and browser defaults are unchanged.

Focused W9 validation passes daemon/unit builds, 37 selected cases (13,630
assertions), browser-certificate rotation/public-info/live-leaf checks, and
unchanged fallback/HTTP metrics tests. Chrome 155 on an actual isolated node
passes hash authentication, p2p-v1 and clean close. Stock local-CA attempts
reject with and without the profile root. With explicit local-CA development
mode, the untrusted control rejects and the profile-trusted control passes.
This does not establish stock publicly trusted CA or reverse-proxy acceptance.
Raw development NetLogs have unfinished JSON envelopes after browser SIGTERM;
complete event records and the browser's final result are preserved separately.

## Linux UDP batching (W10)

Linux uses nonblocking `recvmmsg`/`sendmmsg` batches of at most 64 datagrams.
One receive-buffer set is reused by the engine thread across its sockets.
Other platforms retain individual `recvmsg`/`sendmsg` calls; unavailable Linux
batch syscalls fall back to those calls too. Destination-address ancillary
data is kept so wildcard listeners reply from the address the peer used.
Outgoing packets use ngtcp2's generated path, including path-validation
traffic and standard NAT port rebinding, rather than the original tuple.
This does not perform rendezvous discovery or coordinated hole punching.

`-p2pwebtransportgso=0` disables UDP segmentation offload. When requested,
Linux probes `UDP_SEGMENT`; ngtcp2 may aggregate up to ten naturally full
packets with a final shorter packet, within its send quantum. No forced or
random padding is added. Unsupported offload falls back to the original
individual datagram boundaries and disables offload on that socket. UDP GRO
is not enabled: each receive result remains one wire datagram. A nonblocking
send's unsent suffix uses normal QUIC loss recovery, as the earlier sendmsg
path did. Existing engine packet/byte counters count constructed send attempts,
not an acknowledgement or a capture of successful wire transmission.

The portable tests check segmentation fallback, one-megabyte on/off stream
transfers and a same-IP port rebinding. A separate Linux-only test checks a
one-megabyte UDP transfer and logs the runtime offload capability before/after;
fallback success is not evidence that GSO executed. Linux/Guix runtime/build,
CPU measurements and wire packetization comparisons remain separate gates.
Cross-IP migration also needs shared admission/permission transfer review;
peer permissions currently refer to the address accepted at session setup.

Focused macOS W10 checks pass: combined daemon/unit build, 31 selected cases
(13,366 assertions), existing basic and limits functionals. Payloads match
with the GSO option on/off on this host's portable fallback; the Linux-only
case is not compiled here. These results do not validate Linux batching,
actual GSO execution, Guix or the CPU gate.

## Bulk preference and current transaction relay (W11)

`-p2pwebtransportbulk=1` retains the default automatic preference for all
advertised WT peers. With `0`, an address advertising chain service
(`NODE_NETWORK` or `NODE_NETWORK_LIMITED`) without `NODE_AVALANCHE` uses its
existing TCP/WebSocket path directly. It creates no failed-UDP cache entry or
fallback failure metric. Peers without chain-service flags and Avalanche
service hints retain WT preference. Explicit `wt://` URLs and `dial=only`
override this bulk preference; proxy and `-onlynet` restrictions still apply.
No CPU gate has been measured, so this does not recommend changing the default.

Current Nucleation names `sendinvshort` and `invshort` share TX_ANNOUNCE with
continuous Merklix summaries/buckets. `getshorttx`/`shorttx` remain TX_BODY.
Capability messages travel on the same stream as the feature they gate;
unknown message names remain CONTROL. The coverage inventory compares the
current relay owner's message table with this branch and pins its two added
names, without adding wire-version negotiation or claiming the whole relay
runtime is already merged. The existing Merklix classifier implementation
is retained.

Focused W11 macOS checks: daemon/unit builds pass (39/171 actions); eleven
URL/cache/service/classifier cases pass 330 assertions and the stock raw
fallback policy case passes 18 assertions. Bulk routing (3.33 s) and existing
fallback (6.09 s) functionals pass. The first bulk fixture's false Avalanche
hint correctly selected WT but then failed the existing Avalanche-only
service check; the corrected routing fixture uses full-relay connections.
These tests do not validate a merged relay runtime or Avalanche proof/quorum
behavior. The Linux CPU gate remains unmeasured.

## Measurement gate and defaults (W12)

`contrib/devtools/wt-loss-experiment/run.py --plan` prints the original
interleaved loss matrix without starting jobs. Its explicit single-case mode
uses two fresh copies of a stopped artificial regtest fixture, a real next
block, fresh ping samples and matched valid Avalanche response RTT debug
events. The fixture and valid staked quorum identities must be supplied; tiny
smokes cannot substitute for the 32 MB real-transaction workload. The bounded
prototype-derived UDP relay is WT-only. A userspace TCP byte dropper cannot
model packet loss: the WSS comparison requires audited identical packet-level
impairment on a controlled Linux VM, with a receipt and before/after counters.
See the tool README for exact artifacts and the limits of receipt validation.

Current measured gate status is **not passed**. This macOS work has not run the
24-case Linux loss matrix, 1 GiB/16-peer CPU ceiling, two-builder Guix equality,
24-hour/50-peer churn soak or test-VM firewall test. Stock/public-known-root CA
browser acceptance and common reverse-proxy/merged H2 acceptance remain open.
No speedup, CPU ratio, poll p99 or Linux/GSO performance number is claimed.
Historical prototype numbers do not establish the real implementation's gate.
`ENABLE_WEBTRANSPORT` remains OFF and `-p2pwebtransport` remains 0. Bulk preference
remains 1 because its conditional CPU failure gate has not been measured.

Future rendezvous-assisted QUIC hole punching is a separate, explicitly
opt-in feature with default OFF: ordinary outbound synchronization must not
enroll in discovery, advertise reachability or authorize coordinated punching.
It is not implemented here and is distinct from normal QUIC address validation
and migration.

Focused W12 checks on macOS: combined daemon/Avalanche-unit build passes
23 actions; the added RTT observation assertions rebuild in 7 actions and
four selected cases pass 383 assertions. Twelve deterministic Python checks
and Ruff pass. Fresh two-node WT/WSS tool smokes each deliver an artificial
181-byte height-1 block and clean up in under one second; a 768-byte bounded
UDP echo also passes. Both node cases explicitly report incomplete latency
and `gate_pass=false`: neither has Avalanche samples, and the tiny WSS
interval finishes before a fresh ping completes. These are tooling checks,
not a transport comparison. The initial smoke failure is preserved: its
connection settings reserved all inbound capacity and its connection wait
ignored the requested work budget. Corrected fixture settings and shared
budget/socket/encoding negative controls address those harness errors.
