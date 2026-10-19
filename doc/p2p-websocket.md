# P2P over WebSocket

A node can carry P2P connections over WebSocket (`ws://`) or WebSocket over
TLS (`wss://`): on its P2P port, beside raw P2P, on `-publicbind` listeners
and on its RPC port. On the network, a `wss://` peer connection looks like a browser
talking to a web site: TCP to port 443 (or whichever you choose), a TLS
handshake with ALPN `h2` or `http/1.1`, a WebSocket opened by an HTTP/1.1
upgrade or an HTTP/2 extended CONNECT, then encrypted traffic.

This is useful to:

- reach peers from networks that only allow web traffic;
- run a node behind a TLS-terminating reverse proxy or CDN;
- make a node harder to find and block (see
  [Privacy and censorship](#privacy-and-censorship)).

Raw P2P ("raw" means plain P2P, the ordinary non-WebSocket protocol) is
unchanged in the shared eCash engine, and the two can be used together or separately.
Lotus v2 uses only WebSocket; its differences are listed below.

## Listening: which transports, on which port

`-listen` stays the master switch for inbound peers, with its usual default
(1 unless `-proxy` or `-connect`) and interactions. Two switches select what
it accepts:

| `-listen` | `-p2prawlisten` | `-p2pwslisten` | Accepted inbound | P2P port |
|---|---|---|---|---|
| 0 | any | any | nothing, on any transport | not bound |
| 1 | 1 (default) | 1 (default) | raw P2P and WebSocket | bound |
| 1 | 0 | 1 | WebSocket only | bound (raw P2P closed) |
| 1 | 1 | 0 | raw P2P only, like stock Bitcoin ABC | bound |
| 1 | 0 | 0 | nothing (a warning says so) | not bound |

With `-listen=0`, `/p2p/ws` answers 503 and accepts no peer.

### One port for raw P2P, `ws://` and `wss://`

With the defaults, the P2P port (`-port`, `-bind`, `-whitebind`) accepts
WebSocket peers as well as raw ones. Each connection is classified from
its first bytes, which are only peeked at:

- `0x16 0x03` (a TLS ClientHello) is `wss://`;
- `GET ` (an HTTP request line) is `ws://`;
- anything else is raw P2P. Stock peers start with the network magic,
  whose first byte can start neither, so they are recognized at once and
  proceed exactly as with stock Bitcoin ABC.

Over HTTP or TLS, the P2P port serves **only** the P2P WebSocket endpoint
(`-p2pwebsocketpath`, with `-p2pwebsockettoken` rules). Everything else gets
404, or the `-publicfallback` site when it is set: never JSON-RPC, REST,
wallet, Chronik or health checks. A plain-text request other than `GET` is
not HTTP to the P2P port at all: raw P2P rejects it. TLS uses the same
certificates as `-publicbind` (`-tlscert`/`-tlskey` or `-tlsephemeral`,
reloaded live). `-whitebind` permissions apply to WebSocket peers on that
listener too. WebSocket needs the HTTP server (`-server`, on by default for
ecashd); without it the P2P port is raw P2P only.

With the defaults, the public P2P port therefore accepts WebSocket peers as
well as stock raw peers. With `-p2pwslisten=0` it speaks raw P2P only, like
stock Bitcoin ABC.

Limits:

- With raw P2P on, every connection is an ordinary inbound peer until it
  shows HTTP or TLS (same slots, bans, eviction and timeouts; a silent
  client stays a raw peer). It is then handed over without anything being
  read; such a peer uses a second node id.
- With raw P2P off, bans, discouragement and a full node are checked first,
  then the HTTP server classifies the connection and closes raw P2P.
- A connection has `-p2pporthandshaketimeout` seconds (debug option,
  default 10) to classify and, for WebSocket, to complete its upgrade.
  At most 64 connections (8 per address) may be between classification and
  upgrade; others are closed.
- Trusted PROXY protocol headers are read on `-publicbind` and the RPC
  port. On the shared P2P port they work only with `-p2prawlisten=0`:
  with raw P2P enabled, the classifier treats the PROXY signature as raw
  P2P before it can reach the HTTP server. Use `-publicbind` for a load
  balancer that must work with either raw-listen setting.

Advertisement does not change: raw P2P addresses are advertised when raw P2P
is accepted, `NET_WSS` addresses only with `-externaldomain`. A peer that
knows only a node's IP address could reach its WebSocket endpoint at
`wss://<ip>:<port>/p2p/ws` on the same port, but nodes do not try this by
themselves; use it with `-addnode`/`-connect`.

### `-p2prawlisten=0`

- Raw P2P connections on the P2P port are closed. The port stays bound
  while `-p2pwslisten=1`.
- No raw P2P address is learned or advertised: not `-externalip` (refused),
  interface discovery, NAT-PMP mappings, nor the address peers see us at.
  Only `-externaldomain` (`NET_WSS`) is advertised.
- `-listenonion=1`, onion binds (`-bind=...=onion`) and
  `-i2pacceptincoming=1` serve raw P2P over Tor or I2P, so they are
  refused; by default they are turned off. A Tor hidden service would
  forward to the onion bind, a raw P2P listener.
- Outbound connections are not affected: use `-onlynet=wss`.

### `-p2prequiretls`

With `-p2prequiretls=1`, WebSocket peers must use TLS wherever WebSocket is
accepted (P2P port, `-publicbind`, RPC port). A `ws://` upgrade gets the
same answer as any unserved request (404, or `-publicfallback`), so probes
cannot tell the endpoint exists. Raw P2P is controlled by `-p2prawlisten`.

Behind a TLS-terminating proxy, a connection from a `-trustedproxy` address
counts as TLS when the proxy says the client used it: `X-Forwarded-Proto:
https` as set by the nearest proxy (the last value), or the SSL TLV of a
PROXY v2 header. Headers from untrusted addresses are never believed.
Behind a layer-4 balancer sending PROXY v2, only its TLV counts, since the
HTTP then comes from the client itself.

### Lotus v2: WebSocket only

Lotus v2 nodes have no raw TCP P2P. The P2P port (`-port`, `-bind`,
`-whitebind`, onion binds) is an HTTP/WebSocket listener with TLS detected per
connection, serving `/p2p/ws` (and the other public endpoints) to anyone:

- Peers known by address are dialed as `wss://<address>:<port>/p2p/ws`, or
  `ws://` for onion and private addresses (Tor encrypts already; a private
  network is the operator's). DNS seeds, address gossip and `-addnode` /
  `-connect` addresses keep their usual form.
- `/p2p/ws` is public on every listener, the RPC port included. If `-rpcbind`
  and `-bind` name the same address and port, one listener serves both: P2P
  to anyone, RPC to `-rpcallowip` clients. That is one port for P2P, RPC,
  Chronik behind a load balancer. Health checks are not served on the P2P port.
- A listening node without `-server` still runs the HTTP server, with no RPC
  listeners. `-p2pwslisten=0` requires `-listen=0`; `-p2prawlisten` defaults to 0 and cannot be enabled.
- `-p2pwebsocketrequirecert` applies to every inbound peer, since all are
  WebSocket peers; peers on `ws://` (onion, private addresses) present no
  certificate and are dropped.
- I2P is not supported.

## Serving

The table describes the shared eCash engine. Lotus v2 keeps raw P2P disabled,
serves public P2P and Chronik on its listeners, and starts HTTP for listening
even without `-server`, as described above.

| Option | Effect |
|---|---|
| `-p2pwslisten` (default on) | Accept P2P upgrades at `/p2p/ws`, on the P2P port, `-publicbind` and the RPC port. Needs `-listen` and `-server`. |
| `-p2prawlisten` (default on) | Accept raw P2P on the P2P port. See [above](#-p2prawlisten0). |
| `-p2prequiretls` (default off) | Accept WebSocket peers only over TLS. See [above](#-p2prequiretls). |
| P2P port | Serves P2P WebSocket to anyone, beside raw P2P, and nothing else over HTTP. |
| `-publicbind=<addr>:<port>` | An extra listener for anyone, serving **only** P2P WebSocket and Chronik (`/chronik`). JSON-RPC, wallet and REST are refused there whatever the client address. Expose this port, never the RPC port. Not advertised. |
| RPC port | Also serves P2P WebSocket, but only to `-rpcallowip` clients. |
| `-tlscert`, `-tlskey` | Certificate chain and key for TLS. New inbound handshakes and outbound `wss://` dials pick up replaced files (e.g. an ACME renewal) without a restart, checking mtimes at most once a second. The certificate/key pair must load and match before replacing the context. Failed replacements keep the previous identity; established connections are unaffected. |
| `-tlsephemeral` (default on) | Without `-tlscert`, use a self-signed certificate in the datadir. It is issued for the first `-externaldomain` (else a random host name), valid for 90 days, and renewed with the same key when fewer than 30 days remain. |
| `-externaldomain=<domain>[:port]` | Advertise `wss://<domain>:<port><path>` (default port 443; the path is `-p2pwebsocketpath`, else `/p2p/ws`) to peers that support ADDRv2 (BIP155), so they can find and dial it. |
| `-p2pwebsocketpath=<path>` | Serve the upgrade at another path. |
| `-p2pwebsockettoken=<token>` | Require a token (repeatable). Without it, the endpoint answers like any unknown path. |
| `-publicfallback=<host>:<port>` | Hand everything else on `-publicbind` and the P2P port (pages, probes, upgrades without the token or, with `-p2prequiretls`, without TLS) to a plain-HTTP web server, which then answers that connection byte for byte. |
| `-p2pwebsocketpeer=[permissions@]<pin>` | Recognize inbound peers by their TLS client key and grant them permissions, as `-whitelist` does. Turns on `-tlsmutual`. |
| `-p2pwebsocketrequirecert` | Only accept WebSocket peers whose client key is listed with `-p2pwebsocketpeer`. Raw P2P peers are not affected. |
| `-trustedproxy=<ip\|subnet>` | Load balancers and reverse proxies whose client addresses are believed: a PROXY protocol v1/v2 header at the start of a connection (layer-4 balancers such as AWS NLB, HAProxy), and `X-Forwarded-For` on each request (HTTP proxies such as AWS ALB, nginx), walked from the right while hops are trusted. The address found is used for `-rpcallowip`, P2P peers (bans, eviction, addrman) and logs. Repeatable. |
| `-p2pwebsockettrustforwardedfor` | Shorthand for trusting a proxy on this host (`127.0.0.0/8`, `::1`). |
| `-httphealth` | `/livez` (the server runs), `/readyz` and `/healthz` (out of initial block download, with peers; else 503 and the reason), for health checks (not on the P2P port). On by default, off with `-p2pwebsockettoken` or `-publicfallback`, where they would reveal the node to probes. |

TLS is detected on each connection, so one port serves `ws://`, `wss://`,
HTTP and HTTPS.

`-externaldomain` cannot be combined with `-p2pwebsockettoken`: tokens are
never advertised, so peers learning the address could not connect. An
advertised `-p2pwebsocketpath` is limited to `/` followed by
`A-Z a-z 0-9 - . _ ~ /`.

## Connecting

Use a URL as a peer address with `-addnode`, `-connect` or the `addnode`
RPC:

```
wss://host[:port][/path][?token=<token>][#spki=<pin>]
ws://host[:port][/path]
```

- The default port is 443 for `wss://` and 80 for `ws://`; the default path
  is `/p2p/ws`.
- `?token=` is removed from the request and sent as
  `Authorization: Bearer <token>`. Logs show it as `token=***`.
- `#spki=<pin>` pins the server's public key: the connection is refused
  unless its key matches. A pin is the base64url SHA-256 of the DER
  SubjectPublicKeyInfo, as `getpeerinfo` shows in `websocket.peer_spki`. It
  names the key, not the certificate, so it survives certificate renewals.
  Pins require `wss://`.
- `-p2pwebsocketpin=<host>=<pin>` (repeatable) pins every dial of a host,
  including addresses learned from peers. A pin in the URL takes precedence.

Without a pin, TLS protects against passive observers but does not
authenticate the peer (the same as plain TCP P2P).

When `-proxy` is set, WebSocket dials go through it, and the host *name* is
passed to the proxy, so there is no local DNS lookup. `.onion` hosts use
`-onion`. A dial never falls back to a direct connection when the proxy
fails. `-onlynet` without `wss` refuses WebSocket dials. `wss` means
WebSocket over TLS: with `-onlynet=wss` alone, unencrypted `ws://` dials
(except to `.onion`) are refused, and so are manual raw P2P connections
(`-addnode`, `-connect`), local and private addresses included.

`getpeerinfo` reports `transport` (`tcp`, `ws` or `wss`) and, for WebSocket
peers, a `websocket` object with the compression in use, payload and wire
byte counts, the TLS certificate fingerprint and key pin, the agreed ALPN,
and whether the key was pinned or listed.

### Compression

Peers negotiate a subprotocol. `p2p-zstd-v1` (the default) compresses the
message stream with zstd and a built-in dictionary of common P2P messages,
so even small messages shrink; `p2p-zstd` does the same without the
dictionary; `none` sends plain messages. Both zstd subprotocols also carry
independent block frames, below.

### Independent block frames (compress once, serve many)

A zstd stream's compressed bytes depend on everything sent before on that
connection, so a block sent to many WebSocket peers would be compressed
again for each of them. An independent frame is compressed with the
built-in dictionary only, so the node compresses a block once and sends the
same bytes to every zstd peer.

**Format.** An independent frame is one unfragmented binary WebSocket
message (FIN=1, opcode 2) with RSV2 (`0x20`) set and no other RSV bit. Its
payload is `[format byte = 1][dictionary version, LE32 = 1][one zstd
frame]`. Dictionary version 1 is the `p2p-zstd-v1` dictionary
(`P2P_ZSTD_DICT_V1`), also on `p2p-zstd` connections. The zstd frame
records its content size and is compressed with that dictionary and no
other history. It decompresses to whole P2P messages (24-byte header
included), which continue the connection's P2P byte stream at that point.
Independent frames neither use nor change either direction's zstd stream:
the next stream message continues from the previous one.

Either end of a `p2p-zstd-v1` or `p2p-zstd` connection may send independent
frames, and must accept them. Plain (`none`) and permessage-deflate
connections use no RSV bits; a frame with any RSV bit ends them. The HTTP
server's debug bridge (`-p2pwebsocketbridge`) does not support independent
frames: a peer sending one through it is disconnected.

A receiver rejects, and disconnects for: RSV2 on a fragmented, continuation,
text or control frame; RSV1 or RSV3; an unknown format byte or dictionary
version; a payload that is not exactly one zstd frame (skippable frames,
concatenated frames, trailing or truncated data); a missing content size or
one above the message size limit (the configured or adaptive block size
limit plus the P2P header, as for stream and plain messages); and a declared
zstd window above 1 MiB, checked before any output is allocated.

**Sending.** Nodes send `block` messages of at least
`-p2pcompressoncethreshold` bytes (default 65536, P2P header included) as
independent frames; `0` keeps every message in the stream (incoming frames
are still accepted), which is the control for comparisons. Smaller blocks
and other messages stay in the stream, where the connection's history
compresses them better and nothing is shared between peers. Encoded blocks
are kept in an LRU cache shared by all peers, bounded by the allocated
bytes of the frames (`-p2pcompressoncecache`, MiB, default 128) and by 64
blocks. Its key includes the block hash, a full double-SHA256 digest of the
payload, the exact 24-byte P2P header and the dictionary version. The
short P2P checksum alone is insufficient to identify supplied payloads. Peers asking for a
block while it is being compressed wait for that compression rather than
repeating it.

`getpeerinfo` counts independent frames sent and received per peer
(`websocket.independent_frames_sent`, `_recv`). With `-metrics`:
`fullnode_p2p_websocket_independent_frames_total{direction}` and
`fullnode_p2p_compress_once_{cache_hits,cache_misses,cache_evictions,encodes}_total`,
`fullnode_p2p_compress_once_cache_{bytes,entries}`.

The frame format comes from the V2 tier (its patch 095).

## Over HTTP/2

In builds with HTTP/2 (`-DENABLE_HTTP2=ON`, see [HTTP/2](http2.md)) and with
`-http2` on (the default there):

- The TLS listeners (`-publicbind` and the RPC port) prefer ALPN `h2`, and
  accept WebSockets over HTTP/2 (RFC 8441: `CONNECT` with
  `:protocol websocket`, advertised with `SETTINGS_ENABLE_CONNECT_PROTOCOL`)
  for `/p2p/ws` (or `-p2pwebsocketpath`) and Chronik's `/chronik/ws`, under
  the same rules as the HTTP/1.1 upgrade: `-rpcallowip` on the RPC port,
  tokens, `-trustedproxy`, the compression subprotocols. `permessage-deflate`
  is not offered over HTTP/2. A browser or HTTP client that negotiated `h2`
  can therefore still open the P2P WebSocket, next to other requests on the
  same connection.
- The dialer offers `h2, http/1.1`, like a browser. If the server selects
  `h2` and allows extended CONNECT, the WebSocket is opened over HTTP/2;
  if it selects `http/1.1`, the HTTP/1.1 upgrade is used as before. A
  server that selects `h2` without extended CONNECT is not dialed over
  that connection (logged).
- `getpeerinfo` shows `websocket.alpn` `h2` for such peers. Message framing,
  compression, pins and permissions are the same.

Without HTTP/2 built, or with `-http2=0`, nothing changes: `h2` is neither
offered nor selected. Plain `ws://` is always HTTP/1.1.

An inbound P2P peer over HTTP/2 shares its HTTP/2 connection with other
streams, so its traffic passes through the HTTP server's I/O threads (an
HTTP/1.1 WebSocket peer's connection is handed to the P2P layer instead),
and it is disconnected when the HTTP server stops. Platforms without Unix
socket pairs (Windows) answer such upgrades with 501.

## Discovery

- Only `-externaldomain` is ever advertised, as a NET_WSS address (BIP155
  network id `0x10`), and only to ADDRv2 peers. Nodes that support it dial
  such addresses automatically.
- The address payload starts with a format version. Version 1 is the
  domain name followed by the path when it is not `/p2p/ws`; the port is
  the address's own. Nodes store and relay NET_WSS addresses of versions
  they do not know, unchanged, but never dial them. A later format can
  therefore spread through older nodes. `getnodeaddresses` shows
  `wss_version` and, for version 1, `wss_path`.
- `-publicbind` and the RPC port are never advertised.
- A node never advertises its IP address with a WebSocket port.

So unless you set `-externaldomain`, peers learn about a WebSocket endpoint
only from you.

## Privacy and censorship

> **Legal and personal risk.** Running a node, or using circumvention
> tools, may be illegal or dangerous where you live. The features below
> reduce what network observers can learn about your node. They do not make
> you anonymous or undetectable, and they have not been independently
> audited. Transactions are public; who broadcast one first can often be
> inferred from timing.

### Threat model

| Adversary | What helps | What does not |
|---|---|---|
| Passive observer (ISP, DPI) | `wss://`: P2P messages are inside TLS 1.2/1.3 with SNI, ALPN `h2, http/1.1` (`http/1.1` without HTTP/2) and a browser-ordered cipher offer; neutral 90-day certificates name no software. | Traffic patterns (sizes, timing) are not shaped. The TLS ClientHello is not identical to a browser's (see below). `ws://` and plain TCP are readable. |
| Active prober (connects to suspected servers) | Secret path and token, plus `-publicfallback`: probes get an ordinary web site; the node's endpoint answers like a missing page. | A prober who learns the URL and token can connect. Malformed TLS or HTTP is answered by the node, not the fallback. |
| Blocking by address or name | Bridges run by people you trust, reached through Xray or Tor (below). | A bridge that is blocked must be replaced. |
| Malicious peers (Sybil/eclipse, logging IPs) | `-connect` only to bridges you trust, with key pins; `-p2pwebsocketrequirecert` on bridges. | Any peer you connect to sees the transactions you relay. |
| Your own node revealing you | `-proxy` with remote DNS and no direct fallback; no self-advertisement; `-listen=0 -discover=0 -dnsseed=0 -fixedseeds=0`. | Anything outside the node: other software, DNS on the machine, time zone. |

### TLS fingerprint

lotusd uses OpenSSL. Its client offers ALPN `h2, http/1.1` as Chrome does
(only `http/1.1` in builds without HTTP/2 or with `-http2=0`), sends SNI for
host names, and orders its TLS 1.3 suites, TLS 1.2 ciphers, groups
(`X25519MLKEM768` where OpenSSL is 3.5 or newer) and signature algorithms
like Chrome. OpenSSL cannot send GREASE values, randomize extension order,
or do ECH, so JA3/JA4 fingerprints still differ from a browser's. After the
handshake, the HTTP/2 connection's first frames (SETTINGS values, window
sizes, header order) differ from a browser's too. Dialing `wss://<IP address>`
sends no SNI, which is unusual for web traffic, so the node logs a warning.
Where fingerprinting matters, put a tool built for it (Xray REALITY, Tor
pluggable transports) between the node and the network.

## Recipes

Each recipe is exercised by `test/functional/feature_p2p_privacy_recipes.py`,
with a local SOCKS5 proxy standing in for Xray or Tor.

### A node that does not reveal itself

Connects out only, does not listen, look up seeds or discover its address:

```
listen=0
discover=0
dnsseed=0
fixedseeds=0
connect=<peer or bridge URL>
proxy=127.0.0.1:<socks port>   # Xray or Tor, see contrib/censorship
```

### WebSocket-only node

Accepts and makes WebSocket connections only, while keeping its usual P2P
port (shared by `ws://` and `wss://`):

```
p2prawlisten=0      # close raw P2P on the P2P port; advertise no raw address
onlynet=wss         # dial WebSocket over TLS only: no raw P2P, no ws://
externaldomain=node.example.org   # optional: let peers find wss://node.example.org
```

- `-p2prawlisten=0` stops raw P2P inbound. The P2P port stays bound for
  WebSocket, and `-publicbind` and the RPC port keep their WebSocket
  handling.
- `-onlynet=wss` stops raw P2P and unencrypted WebSocket outbound.
  `-p2prawlisten` alone does not change who the node dials.
- Peers reach it with `wss://<host>:<P2P port>/p2p/ws` (or
  `-externaldomain`). Stock nodes, which speak raw P2P only, cannot.

### TLS-only node

Every P2P connection, in and out, is encrypted:

```
p2prawlisten=0      # no raw P2P inbound
p2prequiretls=1     # no ws:// inbound: 404 (or -publicfallback) instead
onlynet=wss         # outbound wss:// only
```

Behind a TLS-terminating proxy or CDN, also list it with `-trustedproxy`:
the proxy-to-node hop may then be plain `ws://`, and the node accepts it
because the proxy says (`X-Forwarded-Proto: https`, or a PROXY v2 SSL TLV)
that the client used TLS. That hop itself is not encrypted: keep it on the
same host or a private network, and trust only proxies that set or
overwrite the header. A proxy that passes a client's own
`X-Forwarded-Proto` through makes the requirement meaningless.

### Client of a private bridge

```
connect=wss://bridge.example.com/assets/v2/stream?token=<token>#spki=<pin>
proxy=127.0.0.1:10808
onlynet=wss
listen=0
discover=0
dnsseed=0
fixedseeds=0
```

The pin comes from the bridge operator (`getpeerinfo`'s `peer_spki` on any
connection to the bridge, or computed from its certificate). Several
`connect=` lines give several bridges.

### Bridge server

```
publicbind=0.0.0.0:443
p2pwebsocketpath=/assets/v2/stream
p2pwebsockettoken=<random token, e.g. from: openssl rand -base64 24 | tr '+/' '-_' | tr -d =>
publicfallback=127.0.0.1:8080  # an ordinary web site
tlscert=/etc/letsencrypt/live/bridge.example.com/fullchain.pem
tlskey=/etc/letsencrypt/live/bridge.example.com/privkey.pem
```

Do not set `-externaldomain`. Give each user the URL, token and pin over a
channel you trust. Optionally, list users' client keys with
`-p2pwebsocketpeer=<pin>` and set `-p2pwebsocketrequirecert`.

### Public node behind a TLS proxy or CDN

```
publicbind=127.0.0.1:8443
externaldomain=node.example.org
trustedproxy=127.0.0.1
```

Point the proxy's `https://node.example.org/p2p/ws` (WebSocket enabled) at
`127.0.0.1:8443`. Other nodes learn `node.example.org` over ADDRv2 and dial
it.

### Nodes behind load balancers on a private network

For example AWS (an NLB, then an ALB) in a VPC, or OVH servers on a vRack:

```
publicbind=0.0.0.0:443             # the port the balancers forward to
trustedproxy=10.0.0.0/8            # every balancer layer's private range
externaldomain=p2p.example.com     # the public name peers should dial
discover=0                         # never advertise private addresses
rpcallowip=10.20.0.0/16            # RPC only via your permissioned balancer
```

- Each layer adds its hop: a layer-4 balancer with PROXY protocol v2
  enabled, an HTTP balancer with `X-Forwarded-For`. The node walks back
  through trusted hops to the first untrusted address, the client. Whatever
  a client writes into `X-Forwarded-For` itself is ignored, because the walk
  stops at the client.
- Point target-group health checks at `/readyz`, so syncing nodes or nodes
  without peers get no traffic.
- Several nodes behind one public name look like one address to the
  network. That is harmless: each node recognizes connections to itself.

### Through Xray (VLESS + REALITY) or Tor

See [`contrib/censorship/`](../contrib/censorship/). Both provide a local
SOCKS5 proxy for `-proxy`.
