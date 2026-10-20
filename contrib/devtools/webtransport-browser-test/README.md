# WebTransport browser interop check

`run.sh <bitcoind> [--firefox] [--portbase N] [--keep]` starts a regtest node
built with `-DENABLE_WEBTRANSPORT=ON`, loads `wt_test.html` in headless Chrome
(and Firefox with `--firefox`) and prints one JSON line per browser; it exits 0
only if all pass. Ports `N`, `N+1`, `N+2` are used (default 46400).

The page connects with `serverCertificateHashes` (a 10-day ECDSA P-256
certificate made with `openssl`) and checks a bidirectional stream echo, a
unidirectional stream echo and a datagram echo. The node runs with
`-p2pwebtransportecho=1` (a test-only switch: echo instead of P2P sessions).

Browsers: `CHROME=/path/to/chrome` and `FIREFOX=/path/to/firefox` override the
macOS defaults. Safari needs Remote Automation and is not driven by this script.
