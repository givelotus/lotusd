# Controlled handshake evidence (2026-10-19 local)

These are actual handshake observations on the shared macOS arm64 machine,
not browser-equivalence or release-gate results. TLS policy was not changed.
The node test uses the actual WT Dial path with localhost SNI, TLS1.3 and a
correct DER certificate pin; a mismatched pin is refused. Chrome uses a fresh
profile and the exact short-lived P-256 certificate hash, then closes cleanly.

| Sample | JA4 | Result |
| --- | --- | --- |
| Node, IP/no SNI | `q13i0311h3_55b375c5d22e_c68ce4ba94e2` | Captured; authenticated unit fixture |
| Node, localhost SNI | `q13d0312h3_55b375c5d22e_c68ce4ba94e2` | Captured; 75 observer assertions pass |
| Chrome155.0.8059.85 sample1 | `q13d0310h3_55b375c5d22e_d19a137375ab` | Authenticated WT/clean close PASS |
| Chrome155.0.8059.85 sample2 | same as sample1 | Authenticated WT/clean close PASS |
| Firefox158.0 initial attempt | not derived | Inconclusive harness cutoff, preserved |
| Firefox158.0 corrected single run | `q13d0315h3_55b375c5d22e_dc5437974b47` | Authenticated WT/clean close PASS |

The node/domain ClientHello is 1521 bytes; Chrome's samples are 1487 and 1489.
All have three TLS1.3 cipher IDs. Their set hash matches, while the node order
is `1302,1303,1301` and Chrome uses `1301,1302,1303`. The node advertises
12 TLS extensions and 20 signature algorithms; Chrome advertises 10 and 9.
Chrome's two raw extension orders differ while its JA4 stays equal, as the
sorted algorithm predicts. Supported group counts are 8 versus 4. Both offer
1216-byte X25519MLKEM768 and 32-byte X25519 key shares. No algorithm or
unsupported extension was added to chase a fingerprint hash.

QUIC parameters also differ: node connection/stream windows are 16MiB/4MiB,
Chrome's are 15MiB/6MiB; bidi/uni stream counts are 8/8 versus 100/103.
The observed initial source CID lengths are 18 versus 0 bytes. Datagram
limits, parameter order, randomized parameters and version information differ.
These are further reasons not to infer equivalence from cipher ordering.

Chrome peak summed RSS of owned process groups was 1,070,160KiB (not PSS);
load averages changed from 13.03/12.84/14.77 to 11.67/12.55/14.59. No latency
or speedup comparison is claimed. Both samples used the same controlled
server implementation, with distinct fresh browser profiles/UDP captures.

Firefox's driver stopped waiting at 12s, before the page's 15s handshake plus
3s close timers. UDP packets were exchanged, but no page result arrived by
that cutoff. Its summed owned-group RSS reached 1,911,568KiB. The failure's
PCAP/logs and original capture-tool sources are preserved. The driver also
terminated the server before buffered observations flushed, so no Firefox JA4
is claimed. The corrected source allows a 25s single sample, finishes the
bounded server interval on failure and forwards bounded separate UDP flows;
the one granted retry passed authenticated WT with `p2p-v1` and clean close.
The 30.48s cohort peaked at 982,816KiB summed RSS. One fresh browser profile
produced two observed ClientHellos, each 1891 bytes with 15 extensions, 11
signature algorithms and 5 groups; their raw extension order differed but
JA4 matched. Cipher order is `1301,1303,1302`; key shares additionally include
65-byte P-256. Firefox connection credit is 24MiB and bidi/uni counts are
100/100. Both raw handshakes and server public-message profiles are retained.
These observations establish this controlled handshake, not browser-equivalent
node traffic or a reverse-proxy deployment.

Raw handshake bytes, synthetic-header PCAPs, normalized profiles/diffs,
executable/tool SHA256, command lines, load/RSS and browser results are in the
lane delivery evidence under `resumed-claude/webtransport/`: node-handshakes-r1,
node-handshakes-domain-r2, chrome-capture-r1, firefox-capture-r1 and
capture-tools-r1; the corrected run is firefox-capture-r2. The raw data is public handshake material, with no session
secret export. The installed libraries are ngtcp2 1.25.0, patched nghttp3
1.18.0 and linked OpenSSL3.6.5.

Outstanding: CA-mode captures, common reverse-proxy
reference captures, encrypted H3 SETTINGS and node UDP packet-shape comparison,
RFC8441/WT proxy behavior, Safari, Linux/Guix/Windows/sanitizers, loss/CPU gate
and soak. The H3 engine serves WT P2P only, with no generic H3 RPC support.
