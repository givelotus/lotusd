#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Browser interop check for P2P over WebTransport. Starts a regtest node
# with -p2pwebtransport=1 -p2pwebtransportecho=1 and a 10-day ECDSA P-256
# certificate, serves wt_test.html, opens it in headless Chrome (and
# Firefox with --firefox) using serverCertificateHashes, and prints one
# JSON result per browser. Exits 0 only if every browser run passes.
#
# Usage: run.sh <bitcoind> [--firefox] [--portbase N] [--keep]
#   <bitcoind>   path to the node binary (built with -DENABLE_WEBTRANSPORT=ON)
#   --portbase   first of the 3 ports used (default 46400; avoid 20000-34999)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
node=${1:?usage: run.sh <bitcoind> [--firefox] [--portbase N] [--keep]}
shift
firefox=0 portbase=46400 keep=0
while [ $# -gt 0 ]; do
  case "$1" in
    --firefox) firefox=1 ;;
    --portbase) portbase=$2; shift ;;
    --keep) keep=1 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
chrome=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
firefox_bin=${FIREFOX:-"/Applications/Firefox.app/Contents/MacOS/firefox"}
command -v "$chrome" >/dev/null 2>&1 || [ -x "$chrome" ] || chrome=$(command -v google-chrome || command -v chromium || true)
p2p=$portbase rpc=$((portbase + 1)) web=$((portbase + 2))

work=$(mktemp -d "${TMPDIR:-/tmp}/wt-browser.XXXXXX")
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ "$keep" = 1 ] && echo "kept $work" >&2 || rm -rf "$work"
}
trap cleanup EXIT

# A certificate browsers accept by hash: ECDSA P-256, valid < 14 days.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 10 -subj /CN=localhost -addext subjectAltName=IP:127.0.0.1,DNS:localhost \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
hash=$(openssl x509 -in "$work/cert.pem" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')

mkdir -p "$work/node"
"$node" -regtest -datadir="$work/node" -listen=1 -port=$p2p -bind=127.0.0.1 \
  -rpcport=$rpc -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -server=1 -dnsseed=0 -fixedseeds=0 \
  -tlscert="$work/cert.pem" -tlskey="$work/key.pem" \
  -p2pwebtransport=1 -p2pwebtransportbind=127.0.0.1:$p2p -p2pwebtransportecho=1 \
  -debug=webtransport -printtoconsole=0 > "$work/node.out" 2>&1 &
pids+=($!)
for _ in $(seq 100); do
  grep -q "WebTransport listening" "$work/node/regtest/debug.log" 2>/dev/null && break
  sleep 0.1
done

python3 "$here/serve.py" --port $web --result "$work/result.json" &
pids+=($!)
sleep 0.5
url="http://127.0.0.1:$web/wt_test.html?port=$p2p&hash=$hash"

status=0
run_browser() { # name cmd...
  local name=$1; shift
  rm -f "$work/result.json"
  "$@" > "$work/$name.out" 2>&1 &
  local bp=$!
  for _ in $(seq 300); do [ -s "$work/result.json" ] && break; sleep 0.1; done
  kill $bp 2>/dev/null || true; wait $bp 2>/dev/null || true
  if [ -s "$work/result.json" ]; then
    python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); r["browser"]=sys.argv[2]; print(json.dumps(r)); sys.exit(0 if r.get("ok") else 1)' "$work/result.json" "$name" || status=1
  else
    echo "{\"browser\": \"$name\", \"ok\": false, \"error\": \"no result within 30 s\"}"
    status=1
  fi
}

run_browser chrome "$chrome" --headless=new --no-first-run --no-default-browser-check \
  --user-data-dir="$work/chrome-profile" "$url"
if [ "$firefox" = 1 ]; then
  mkdir -p "$work/ff-profile"
  run_browser firefox "$firefox_bin" --headless --no-remote --profile "$work/ff-profile" "$url"
fi
grep -E "WebTransport session from" "$work/node/regtest/debug.log" | sed 's/^/# node: /' >&2 || true
exit $status
