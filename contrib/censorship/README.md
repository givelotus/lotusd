# Reaching the network through Xray or Tor

These are starting points for running lotusd where the network blocks or
inspects traffic. Both tools give lotusd a local SOCKS5 proxy (`-proxy`).
lotusd then sends every peer connection through it, passes host names to the
proxy (no local DNS), and never falls back to a direct connection. See
[doc/p2p-websocket.md](../../doc/p2p-websocket.md) for the threat model and
the node-side recipes, which `test/functional/feature_p2p_privacy_recipes.py`
exercises.

Using circumvention tools may be illegal or dangerous where you live. These
configurations are examples, not audited advice; check each tool's current
documentation, because blocking methods and the tools change often.

## Xray: VLESS + REALITY

REALITY makes the tunnel look like a TLS connection to a real, popular site
(`www.example.com` above: choose a site reachable from the client's network
that supports TLS 1.3 and HTTP/2). Active probes of the server reach that site.

1. On a server outside the censored network, install Xray and generate:
   - a client id: `xray uuid`
   - a key pair: `xray x25519` (the private key goes in the server config,
     the public key in the client config)
   - a short id: `openssl rand -hex 8`
2. Fill these into [`xray-server.json`](xray-server.json) and
   [`xray-client.json`](xray-client.json). Newer Xray releases also accept
   `target` for `dest`.
3. Run `xray run -c xray-client.json` next to lotusd, and start lotusd with
   `-proxy=127.0.0.1:10808`, plus the client recipe from the guide: plain
   `-connect=<peer>` or a private bridge URL.

The `xtls-rprx-vision` flow is designed to avoid the double-TLS pattern when
the traffic inside the tunnel is itself TLS (as `wss://` is). Plain TCP peers
work through the tunnel too.

## Tor

[`torrc.example`](torrc.example) runs Tor as a SOCKS5 proxy, with bridges for
networks that block Tor. Start lotusd with `-proxy=127.0.0.1:9050`. For onion
peers, also see [doc/tor.md](../../doc/tor.md). Where Tor is heavily blocked,
which bridge transports work changes over time; Snowflake and WebTunnel are
the current options to try.
