# P2P over WebSocket

Besides the normal P2P port, a node can carry P2P connections over WebSocket
(`ws://`) or WebSocket over TLS (`wss://`), on the same port as its HTTP
server. On the network, a `wss://` peer connection looks like a browser
talking to a web site: TCP to port 443 (or whichever you choose), a TLS
handshake with ALPN `http/1.1`, an HTTP upgrade, then encrypted traffic.

This is useful to:

- reach peers from networks that only allow web traffic;
- run a node behind a TLS-terminating reverse proxy or CDN;
- make a node harder to find and block (see
  [Privacy and censorship](#privacy-and-censorship)).

Plain TCP P2P is unchanged, and the two can be used together.

## Serving

| Option | Effect |
|---|---|
| `-p2pwebsocket` (default on) | Accept P2P upgrades at `/p2p/ws`. Needs `-listen` and `-server`. |
| `-publicbind=<addr>:<port>` | An extra listener for anyone, serving **only** P2P WebSocket and Chronik (`/chronik`). JSON-RPC, wallet and REST are refused there whatever the client address. Expose this port, never the RPC port. Not advertised. |
| RPC port | Also serves P2P WebSocket, but only to `-rpcallowip` clients. |
| `-tlscert`, `-tlskey` | Certificate chain and key for TLS. New inbound handshakes and outbound `wss://` dials pick up replaced files (e.g. an ACME renewal) without a restart, checking mtimes at most once a second. The certificate/key pair must load and match before replacing the context. Failed replacements keep the previous identity; established connections are unaffected. |
| `-tlsephemeral` (default on) | Without `-tlscert`, use a self-signed certificate in the datadir. It is issued for the first `-externaldomain` (else a random host name), valid for 90 days, and renewed with the same key when fewer than 30 days remain. |
| `-externaldomain=<domain>[:port]` | Advertise `wss://<domain>:<port><path>` (default port 443; the path is `-p2pwebsocketpath`, else `/p2p/ws`) to peers that support ADDRv2 (BIP155), so they can find and dial it. |
| `-p2pwebsocketpath=<path>` | Serve the upgrade at another path. |
| `-p2pwebsockettoken=<token>` | Require a token (repeatable). Without it, the endpoint answers like any unknown path. |
| `-publicfallback=<host>:<port>` | Hand everything else on `-publicbind` (pages, probes, upgrades without the token) to a plain-HTTP web server, which then answers that connection byte for byte. |
| `-p2pwebsocketpeer=[permissions@]<pin>` | Recognize inbound peers by their TLS client key and grant them permissions, as `-whitelist` does. Turns on `-tlsmutual`. |
| `-p2pwebsocketrequirecert` | Only accept WebSocket peers whose client key is listed with `-p2pwebsocketpeer`. Plain TCP peers are not affected. |
| `-trustedproxy=<ip\|subnet>` | Load balancers and reverse proxies whose client addresses are believed: a PROXY protocol v1/v2 header at the start of a connection (layer-4 balancers such as AWS NLB, HAProxy), and `X-Forwarded-For` on each request (HTTP proxies such as AWS ALB, nginx), walked from the right while hops are trusted. The address found is used for `-rpcallowip`, P2P peers (bans, eviction, addrman) and logs. Repeatable. |
| `-p2pwebsockettrustforwardedfor` | Shorthand for trusting a proxy on this host (`127.0.0.0/8`, `::1`). |
| `-httphealth` | `/livez` (the server runs), `/readyz` and `/healthz` (out of initial block download, with peers; else 503 and the reason), for health checks. On by default, off with `-p2pwebsockettoken` or `-publicfallback`, where they would reveal the node to probes. |

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
fails. `-onlynet` without `wss` refuses WebSocket dials.

`getpeerinfo` reports `transport` (`tcp`, `ws` or `wss`) and, for WebSocket
peers, a `websocket` object with the compression in use, payload and wire
byte counts, the TLS certificate fingerprint and key pin, the agreed ALPN,
and whether the key was pinned or listed.

### Compression

Peers negotiate a subprotocol. `p2p-zstd-v1` (the default) compresses the
message stream with zstd and a built-in dictionary of common P2P messages,
so even small messages shrink; `p2p-zstd` does the same without the
dictionary; `none` sends plain messages.

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
| Passive observer (ISP, DPI) | `wss://`: P2P messages are inside TLS 1.2/1.3 with SNI, ALPN `http/1.1` and a browser-ordered cipher offer; neutral 90-day certificates name no software. | Traffic patterns (sizes, timing) are not shaped. The TLS ClientHello is not identical to a browser's (see below). `ws://` and plain TCP are readable. |
| Active prober (connects to suspected servers) | Secret path and token, plus `-publicfallback`: probes get an ordinary web site; the node's endpoint answers like a missing page. | A prober who learns the URL and token can connect. Malformed TLS or HTTP is answered by the node, not the fallback. |
| Blocking by address or name | Bridges run by people you trust, reached through Xray or Tor (below). | A bridge that is blocked must be replaced. |
| Malicious peers (Sybil/eclipse, logging IPs) | `-connect` only to bridges you trust, with key pins; `-p2pwebsocketrequirecert` on bridges. | Any peer you connect to sees the transactions you relay. |
| Your own node revealing you | `-proxy` with remote DNS and no direct fallback; no self-advertisement; `-listen=0 -discover=0 -dnsseed=0 -fixedseeds=0`. | Anything outside the node: other software, DNS on the machine, time zone. |

### TLS fingerprint

lotusd uses OpenSSL. Its client offers ALPN `http/1.1`, sends SNI for host
names, and orders its TLS 1.3 suites, TLS 1.2 ciphers, groups
(`X25519MLKEM768` where OpenSSL is 3.5 or newer) and signature algorithms
like Chrome. OpenSSL cannot send GREASE values, randomize extension order,
advertise `h2` (WebSocket needs HTTP/1.1), or do ECH, so JA3/JA4
fingerprints still differ from a browser's. Dialing `wss://<IP address>`
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
