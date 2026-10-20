# WebTransport handshake fingerprints

These tools capture controlled UDP payloads without privilege and compare
reassembled ClientHello profiles. They are acceptance tooling, not a claim
that OpenSSL/ngtcp2 is browser-indistinguishable. The W1–W12 gate now also
requires captured client and server directions against version-pinned browser
and common reverse-proxy references, including QUIC and HTTP/3 behavior.

Installed browser metadata read on 2026-10-19: Chrome 155.0.8059.85,
Firefox 158.0 (build 15826.10.7), Safari 26.6 (build 21624.4.5.11.5).
No nginx, Caddy, Envoy, tshark or dumpcap executable was found locally.
Those are inventory findings, not captured reference profiles. Obtain controlled
reverse-proxy reference binaries/captures as part of subsequent acceptance;
no system package installation is required by these tools.

## How to reproduce

Use isolated regtest nodes and directories, never existing node data. The
following records one controlled client through a relay; the node binary is
an argument, not an embedded workspace path. Substitute an unused port block
approved for your test environment (these avoid 20000–34999).

```sh
NODE=/absolute/path/to/bitcoind
WORK=/absolute/path/to/new-isolated-capture-directory
mkdir -p "$WORK/node"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 10 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem"
"$NODE" -regtest -datadir="$WORK/node" -server=1 -dnsseed=0 -fixedseeds=0 \
  -bind=127.0.0.1:41001 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=41002 \
  -p2pwebtransport=1 -p2pwebtransportbind=127.0.0.1:41001 \
  -tlscert="$WORK/cert.pem" -tlskey="$WORK/key.pem"
# Run the following in another terminal; it stops after 30 seconds.
python3 contrib/bench/webtransport/capture_udp.py \
  --listen 127.0.0.1:41000 --server 127.0.0.1:41001 \
  --pcap "$WORK/chrome.pcap" --metadata "$WORK/chrome.jsonl" --seconds 30
```

Serve the handshake-only page using the existing page server:

```sh
python3 contrib/devtools/webtransport-browser-test/serve.py \
  --port 41003 --result "$WORK/chrome-result.json"
```

Calculate the DER SHA-256 of `cert.pem`; open this URL in Chrome with an
isolated user data directory, then repeat with a separate Firefox profile,
new relay output filenames, and a distinct result file:

```text
http://127.0.0.1:41003/handshake.html?url=https%3A%2F%2Flocalhost%3A41000%2Fp2p%2Fwt&hash=<DER-SHA256-hex>
```

The page verifies the exact certificate hash and reports handshake success or
failure to the result file. For CA mode omit `hash` and use a certificate
trusted by that isolated browser; never disable certificate verification.
Use `localhost` for a controlled SNI baseline and `127.0.0.1` as a separately
labeled IP/no-SNI case. Do not supply an unrelated third-party SNI. Stop only
the exact node/page-server/browser PIDs started for this experiment.

Repeat with a node client using an explicit
`wt://localhost:41000/p2p/wt#cert=<DER-SHA256-hex>` addnode. Save binary hashes,
OpenSSL/ngtcp2/nghttp3 versions, browser version/profile flags, cert metadata,
command lines, result JSON, direction and capture SHA-256 with each run.
Run several fresh handshakes: Chromium's extension ordering varies, so one
sample does not describe the distribution.

The relay writes DLT_RAW PCAP with synthesized IPv4/UDP headers, normalized
client/server endpoints, exact received datagram payloads and receive times.
It preserves QUIC UDP packetization at its userspace observation point; it
does not measure NIC offloads or original IP headers. JSONL includes lengths,
directions, endpoints, times and payload hashes. It forwards up to sixteen
separate UDP source flows by default and records any flow-cap drops.

Analyze/decrypt Initial packets and reassemble CRYPTO using a separately
available analyzer (for example Wireshark). Export the **complete ClientHello
handshake bytes** (type + 24-bit length + body), without TLS record headers.
Never concatenate encrypted packet fragments and call that a ClientHello.
Then normalize and compare actual captures:

```sh
python3 contrib/bench/webtransport/clienthello.py \
  --clienthello "$WORK/chrome-clienthello.bin" > "$WORK/chrome-profile.json"
python3 contrib/bench/webtransport/clienthello.py \
  --clienthello "$WORK/node-clienthello.bin" \
  --reference "$WORK/chrome-profile.json" > "$WORK/node-vs-chrome.json"
python3 contrib/bench/webtransport/test_fingerprint.py
```

The normalizer emits JA4 (`q` for QUIC), its unhashed inputs, ordered cipher,
extension, signature, version/group and ALPN fields, plus ordered QUIC
transport parameters. JA4 sorts cipher and extension IDs after GREASE removal;
signature algorithm order remains significant. Cipher-order-only changes do
not establish JA4 equality. Ordered raw fields still expose differences that
JA4 intentionally collapses. The small checks use the published FoxIO vector,
permutation/GREASE invariants, truncation rejection and payload preservation.
They are not real browser capture results.

## Remaining acceptance work and backend limits

Actual node, Chrome and Firefox captures now exist; see [MEASURED.md](MEASURED.md).
The local analyzer/decryptor is not installed. Reverse-proxy
reference captures, node UDP packet-shape and encrypted HTTP/3 SETTINGS
comparison remain open. Focused product builds/unit/relay/TLS checks pass.
For encrypted handshake/1-RTT analysis, an explicitly instrumented controlled
endpoint must export test session secrets; do not add automatic production
key logging. Retain TLS 1.3 and pinned/CA peer authentication in every profile.

OpenSSL exposes cipher, supported-group and signature-algorithm lists, but no
public ClientHello extension-permutation API was found in the installed
3.6.5 headers. Library extension availability, key-share behavior and ngtcp2
QUIC transport parameter serialization/packetization remain separate profile
surfaces. Current WT contexts otherwise use OpenSSL defaults. The explicit
16MiB/4MiB/1MiB flow windows, 8/8 streams, CID limit 7, datagram limit 65535
and public WT draft SETTINGS union must be compared with actual references.
No unsupported extension is advertised to imitate a browser and no backend
rewrite or named browser-equivalence profile has been applied.

The GFW reachability study describes observations during its measurement
period, not permanent/NAT-stable guarantees. Keep HTTP/2/TCP fallback and
explicitly measure QUIC timeout/fallback on controlled test networks. Do not
force privileged source port 443, fake unrelated SNI, or malformed padding.
Standard-compliant Initial fragmentation/padding needs its own wire review.

Primary references: [FoxIO JA4 algorithm](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md),
[BoringSSL extension permutation](https://boringssl.googlesource.com/boringssl.git/+/e9c5d72c09e01a0f71f30f7c3454e5e7f8711476%5E!/),
[2025 QUIC reachability study](https://gfw.report/publications/usenixsecurity25/en/).

## Observation-only engine harness

The opt-in C++ `QuicEngineOptions::handshake_observer` uses OpenSSL's public
message callback only when supplied by a test. It copies ClientHello,
ServerHello, certificate and EncryptedExtensions messages; it never exports
session secrets. A single engine caps copies at 64 KiB/message, 256 messages
and 8 MiB total. Consumers own their captures until `Stop()` joins the engine.
Normal node startup supplies no observer and installs no callback.

Once the current test binary is built, the following node-to-node fixture
produces actual emitted/received handshake binaries and verifies the existing
correct-pin/mismatched-pin behavior and TLS 1.3 ServerHello:

```sh
TEST=/absolute/path/to/build/src/test/test_bitcoin
WT_HANDSHAKE_ARTIFACT_DIR="$WORK/node-handshakes" "$TEST" \
  --run_test=net_quic_tests/webtransport_handshake_observer --log_level=message
```

An alternative controlled server for browser captures is the opt-in unit
harness below. Use it instead of the daemon in the earlier recipe, run one
isolated browser per invocation, and read its generated `server.json` for the
certificate hash. The output directory must not exist. It listens 30 seconds
and requires at least one observed ClientHello. It is inert in ordinary unit
runs and is a handshake capture, not a P2P relay test:

```sh
WT_BROWSER_CAPTURE_DIR="$WORK/chrome-engine" WT_BROWSER_CAPTURE_PORT=41001 \
  "$TEST" --run_test=net_quic_tests/webtransport_browser_capture_server \
  --log_level=message
```

The normalizer can read `*-in-type1.bin` directly from this controlled server,
without a QUIC decryptor. The parallel UDP relay still captures packet sizes,
order and timing. Handshake-only browser results also report graceful session
close. Preserve fresh output paths and executable SHA-256 for each invocation.
The C++ observer, Chrome and Firefox controlled-server paths have built and
run. Chrome passed two isolated samples; Firefox passed one corrected isolated
run. Its initial driver cutoff remains preserved separately. See MEASURED.md
for actual fingerprints, raw differences, versions and bounded-run limitations.

## Load balancer and reverse-proxy acceptance

Interoperability with common infrastructure is the primary reason for profile
comparison. Equal JA4 alone does not establish this compatibility. Record the
exact proxy/version/configuration and both direct and proxied results:

| Path | Required checks | Current evidence |
| --- | --- | --- |
| UDP passthrough load balancer | QUIC handshake, real endpoint identity/pin, exact UDP payload forwarding, idle timeout and graceful WT close | Capture relay tools; real run pending |
| HTTP/3 terminating, WebTransport-aware proxy | ALPN h3, Extended CONNECT `:protocol`, permitted Origin/path, selected application protocol, bidi class streams, flow control/backpressure and close capsule | No proxy binary/capture present |
| HTTP/2 terminating proxy | ALPN h2, RFC 8441 SETTINGS_ENABLE_CONNECT_PROTOCOL and Extended CONNECT support, framing, per-stream/connection flow control, request/idle timeouts, graceful shutdown | Separate HTTP/2 lane; merged validation pending |
| Ordinary HTTP/3 request proxy | Record actual refusal/unsupported Extended CONNECT response and correct bounded fallback; never assume generic H3 implies WT support | Not run |

The current engine handles HTTP/3 **WebTransport P2P sessions only**. It does
not implement a generic HTTP/3 RPC server. Ordinary request forwarding,
WebTransport tunneling and RFC 8441 over HTTP/2 are distinct proxy capabilities.
The endpoint's public identity, authentication and permissions must remain
valid through any supported topology. A synthetic userspace relay capture
cannot establish a terminating proxy's server TLS/QUIC fingerprint.

For explicit isolated browser launch (with page/relay/server already running):

```sh
CHROME=/absolute/path/to/chrome
FIREFOX=/absolute/path/to/firefox
URL='http://127.0.0.1:41003/handshake.html?url=https%3A%2F%2Flocalhost%3A41000%2Fp2p%2Fwt&hash=<DER-SHA256-hex>'
"$CHROME" --headless=new --no-first-run --no-default-browser-check \
  --host-resolver-rules='MAP localhost 127.0.0.1' \
  --user-data-dir="$WORK/fresh-chrome-profile" "$URL"
# In a separate capture invocation, after the Chrome process is stopped:
mkdir "$WORK/fresh-firefox-profile"
printf '%s\n' 'user_pref("network.dns.disableIPv6", true);' \
  > "$WORK/fresh-firefox-profile/user.js"
"$FIREFOX" --headless --no-remote --profile "$WORK/fresh-firefox-profile" "$URL"
```

The IPv4-only relay intentionally requires controlled IPv4 resolution;
record these resolver/profile flags in the capture manifest. They do not
substitute unrelated SNI or turn off identity verification. Do not open these
commands with a user's normal profile path.

Public server handshake artifacts can be normalized separately:

```sh
python3 contrib/bench/webtransport/server_handshake.py \
  --handshake "$WORK/node-handshakes/<server-out-type2.bin>"
python3 contrib/bench/webtransport/server_handshake.py \
  --handshake "$WORK/node-handshakes/<server-out-type8.bin>"
python3 contrib/bench/webtransport/server_handshake.py \
  --handshake "$WORK/node-handshakes/<server-out-type11.bin>"
```

This reports ServerHello cipher/version/key-share shape, EncryptedExtensions
ALPN/raw QUIC parameters, and certificate chain lengths/hashes. It is not a
JA4S implementation. Certificate hashes and random CID/token fields naturally
vary; preserve their raw evidence and compare stable shape separately. The
normalizer checks pass against synthetic structural fixtures; real peer and
proxy artifacts still require the explicit capture runs.

## Bounded capture driver

The driver creates only new output/profile directories and cleans only its
owned process groups, recording RSS/load, commands and executable/tool hashes.
It preserves the controlled server's buffered observations even after a page
failure. One default sample has 25s to cover the page's 15s+3s timers, within
the 30s controlled server. Two samples require an explicitly shorter deadline
and may be inconclusive under startup/load delays.

```sh
python3 contrib/bench/webtransport/capture_browser.py \
  --test-binary "$TEST" --browser "$FIREFOX" --kind firefox \
  --out "$WORK/new-firefox-capture" --reference "$WORK/node-domain-profile.json" \
  --portbase 41000 --samples 1 --sample-timeout 25
```
