# The wallet UI in the browser

The node serves a wallet app (a progressive web app, "PWA") at `/wallet/` on
its RPC port. The app is a set of static files that talk only to the node's
ordinary wallet and node RPCs, so the keys stay in the node's wallet. Its
source is `wallets/node-pwa/` in the Lotus monorepo; it is not part of this
source tree.

## Opening it

- `bitcoind -gui` opens the wallet in the default browser once the node is up,
  logged in with a one-time link. It implies `-server`. On a terminal, the
  link is also printed (`Wallet: http://127.0.0.1:<rpcport>/wallet/#/login/…`);
  it is never written to `debug.log`.
- For a node that runs as a service, run `bitcoin-cli getwalletpwaurl` and
  open the link it returns. It is valid once, for 120 seconds, and logs the
  browser in as the RPC user that asked for it.
- Or open `http://127.0.0.1:<rpcport>/wallet/` and log in with the RPC user
  and password, an `-rpcauth` user, or the contents of the `.cookie` file
  (`__cookie__:<hex>`, pasted as one line).

Until the node is ready, the app shows the RPC warm-up message.

## Where the files come from

- Release builds embed a prebuilt bundle, pinned by its sha256:

  ```sh
  cmake -B build -DWALLET_PWA_BUNDLE=/path/to/node-pwa-X.Y.Z.tar.gz \
        -DWALLET_PWA_BUNDLE_SHA256=<sha256>
  ```

  Configure fails if the hash does not match. The bundle (format
  `node-pwa-bundle/1`) is checked file by file by
  `contrib/devtools/embed_wallet_pwa.py` and compiled in; nothing is read
  from disk at run time. Bundles are published as GitHub release assets of
  the monorepo.
- A build without a bundle (the default) answers `/wallet/` with a short
  page saying so. `-gui` is then an error, unless `-walletpwadir` is given.
- `-walletpwadir=<dir>` serves the app from a directory instead, read on
  every request (for development: point it at `wallets/node-pwa/src`).

Embedded files are sent with an `ETag`, `Cache-Control: no-cache` and, when
the browser accepts it, their pre-compressed gzip form. Files from
`-walletpwadir` are sent with `Cache-Control: no-store`. Every response under
`/wallet/` carries a strict `Content-Security-Policy` (no inline script, no
remote origins) and related headers.

## Options

| Option | Default | Meaning |
|---|---|---|
| `-walletpwa` | `1` | Serve `/wallet/` and `/auth/*`. With `0`, they answer 404 and browser sessions are refused. |
| `-walletpwadir=<dir>` | unset | Serve the app from this directory. |
| `-walletpwaorigin=<origin>` | none | Repeatable. Also accept browser logins from this origin, `scheme://host[:port]` (a DNS name or a reverse proxy). |
| `-gui` | `0` | Open the app in the default browser at startup. |

## Browser sessions

A login (one-time link or password) creates a session: an `HttpOnly`,
`SameSite=Strict` cookie named `nodewallet_<rpcport>` (so several nodes on one
host do not collide), and a CSRF token that the app keeps in memory only.
With the cookie, JSON-RPC requests to `/` and `/wallet/<name>` are authorized
only when they also carry the CSRF token in `X-CSRF-Token`, an `Origin` that
is exactly the node's own, an allowed `Host`, and `Content-Type:
application/json`.

- Sessions live in memory: restarting the node logs every browser out. They
  expire after 7 days unused, and 30 days after login in any case. The app's
  "Log out" ends one.
- `Host` must be a loopback address (`127.0.0.0/8`, `[::1]`) or `localhost`
  with any port (so `ssh -L` forwards work), or the host of a
  `-walletpwaorigin`. This defeats DNS rebinding.
- Another web page in the same browser cannot use the session: it cannot read
  the CSRF token, its `Origin` differs (a page on another port of
  `127.0.0.1` included), and no CORS headers are sent to it.
- Sessions are only created over HTTPS or from a loopback client.

Clients that send `Authorization: Basic` (bitcoin-cli, scripts) work exactly
as before and need no CSRF token. `-rpccorsdomain` still only applies to such
Basic-auth requests; a browser session cannot be used from that origin.

### What a session may do

A session may call exactly what its RPC user may call: `-rpcwhitelist`
applies to it as usual. The app's console needs every RPC, as bitcoin-qt's
did. To give a browser less, create an `-rpcauth` user with a
`-rpcwhitelist` and log in as that user.

Note that RPCs taking file names (`backupwallet`, `dumpwallet`,
`importwallet`, `loadwallet`, …) refer to the node's file system, not the
browser's.

## Remote access

Prefer an SSH tunnel: `ssh -L 8000:127.0.0.1:<rpcport> node`, then open
`http://127.0.0.1:8000/wallet/`.

Otherwise, use HTTPS with a certificate the browser trusts (from an ACME
service or an internal CA): with a self-signed certificate, RPC clients work
but browsers will not run the app's service worker. Either:

- give the node the certificate (`-tlscert`, `-tlskey`; TLS is detected on
  the RPC port), and set `-rpcbind`, `-rpcallowip` and
  `-walletpwaorigin=https://node.example.org:<rpcport>`; or
- put a TLS-terminating reverse proxy in front, with `-trustedproxy` set to
  its address and `-walletpwaorigin=https://node.example.org`. The node
  believes `X-Forwarded-Proto` only from a trusted proxy, and marks the
  cookie `Secure` when the browser's side is HTTPS. For nginx:

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:<rpcport>;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
  }
  ```

Plain-HTTP logins from non-loopback clients are refused. `/wallet/` and
`/auth/*` are never served on `-publicbind` listeners, and `-rpcallowip`
applies to them as to RPC.

## Logs

Logins, failed logins and logouts are logged with the RPC user and client
address. Tokens, session ids, cookies and CSRF tokens are never logged.
Refused requests are logged, without values, in the `http` debug category.
