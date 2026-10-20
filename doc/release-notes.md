# Bitcoin ABC 0.34.1 Release Notes

Bitcoin ABC version 0.34.1 is now available from:

  <https://download.bitcoinabc.org/0.34.1/>

This release includes the following features and fixes:
- On zstd P2P WebSocket connections (`p2p-zstd-v1`, `p2p-zstd`), large
  blocks are sent as independent zstd frames, compressed once and shared by
  every such peer instead of once per peer. See
  `-p2pcompressoncethreshold`, `-p2pcompressoncecache` and
  doc/p2p-websocket.md.
- Wallets receive chain notifications (blocks, mempool transactions and chain
  state flushes) on a per-wallet worker thread instead of the validation
  scheduler thread, in the same order as before. A wallet that is busy, for
  example during a long rescan, no longer delays notifications to the rest of
  the node until its bounded queue fills. RPCs that wait for wallet
  notifications (`sendrawtransaction`, `submitpackage` and wallet RPCs that
  sync to the chain) also wait for this worker.
- `unloadwallet` now waits until the wallet has processed the notifications
  already queued for it.
- An error while a wallet processes a chain notification now shuts the node
  down cleanly instead of aborting it. The wallet rescans from its last flushed
  best block on restart.
- Add new format string placeholders for `walletnotify`:
  - `%b` - the hash of the block containting the transaction (`unconfirmed` if a mempool transaction)
  - `%h` - the height of the block containing the transaction (`-1` if a mempool transaction)
- Add a `shutdownnotify` option to specify a command to execute synchronously
  before Bitcoin ABC has begun its shutdown sequence.
- On non-Windows systems, an authenticated RPC caller allowed to create wallets
  could execute arbitrary commands as the node process account when
  `-walletnotify` was configured, by crafting a wallet name with regex
  replacement characters. Wallet notification placeholder replacement now
  treats wallet names literally.
- Add new endpoints to the REST API: `blockfilter` and `blockfilterheaders`. See
  doc/REST-interface.md for details.
- The `/headers/` endpoint of the REST API has been updated to use a query parameter
  instead of path parameter to specify the result count. The count parameter is
  now optional, and defaults to 5. Use
  `GET /rest/headers/<BLOCK-HASH>.<bin|hex|json>?count=<COUNT=5>`
  instead of
  `GET /rest/headers/<COUNT>/<BLOCK-HASH>.<bin|hex|json>` (deprecated)
- New Chronik options `-chroniksubsmaxscriptsize` and `-chroniksubsmaxpluginsize`
  limit the size of scripts and plugin groups that can be registered on
  WebSocket subscriptions (defaults: 201 and 100 bytes). Oversized payloads are
  still indexed and remain available via HTTP and txid lookup.
- The Chronik Electrum peer discovery feature is now disabled by default. To
  enable it, set the desired peer check interval with the
  `-chronikelectrumpeersvalidationinterval` node option.
- libevent is no longer a dependency. The RPC command line client now uses
  Boost.Beast and the Tor controller Boost.Asio, like the HTTP server. The
  `libevent` logging category is still accepted by `-debug`, `-debugexclude`
  and the `logging` RPC but has no effect; it is deprecated. A host name given
  to the command line client's `-rpcconnect` is now tried on each of its
  addresses, and `-rpcclienttimeout=0` now means no timeout at all.
- P2P over WebSocket is accepted on the P2P port, beside raw P2P:
  connections starting with a TLS ClientHello or an HTTP `GET` go to the
  WebSocket endpoint, everything else is raw P2P, so stock peers connect
  as with Bitcoin ABC. The P2P port serves nothing else over HTTP (404, or
  `-publicfallback`).
- New `-p2prawlisten` (default 1) and `-p2pwslisten` (default 1) select
  which transports `-listen` accepts. With
  `-p2prawlisten=0` the node closes raw P2P connections, advertises no raw
  P2P address and refuses `-externalip`, `-listenonion`, onion binds and
  `-i2pacceptincoming`. See doc/p2p-websocket.md for a WebSocket-only node.
- New `-p2prequiretls` (default 0) refuses WebSocket peers that did not use
  TLS, or that a `-trustedproxy` does not vouch for (`X-Forwarded-Proto`,
  PROXY v2 SSL TLV).
- `-onlynet=wss` (WebSocket over TLS) applies to manual connections
  (`-addnode`, `-connect`) too, and allows no unencrypted `ws://` dials.
