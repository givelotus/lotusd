#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded actual-node WebTransport browser gate, with isolated owned profiles."""

import argparse
import base64
import hashlib
import json
import os
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--kind", choices=("chrome", "firefox"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--portbase", type=int, default=41000)
    parser.add_argument(
        "--ca-cert", type=Path, help="CA-signed leaf covering localhost"
    )
    parser.add_argument("--ca-key", type=Path)
    parser.add_argument(
        "--ca-root",
        type=Path,
        help="Trust a test root only in this run's fresh browser profile",
    )
    parser.add_argument(
        "--certutil",
        type=Path,
        help="NSS certutil binary, required for Firefox --ca-root",
    )
    parser.add_argument(
        "--expect-reject",
        action="store_true",
        help="Negative CA control: require opening-handshake rejection without root import",
    )
    parser.add_argument(
        "--local-ca-development",
        action="store_true",
        help="Chrome only: relax known-root policy for an isolated CA test; still verify certificate chain/hostname",
    )
    args = parser.parse_args()
    if bool(args.ca_cert) != bool(args.ca_key):
        parser.error("--ca-cert and --ca-key must be supplied together")
    if args.ca_root and (
        not args.ca_cert or (args.kind == "firefox" and not args.certutil)
    ):
        parser.error(
            "--ca-root requires a CA-signed leaf/key and, for Firefox, NSS --certutil"
        )
    if args.expect_reject and (not args.ca_cert or args.ca_root):
        parser.error(
            "--expect-reject requires a CA leaf/key without importing its root"
        )
    if args.local_ca_development and (args.kind != "chrome" or not args.ca_cert):
        parser.error("--local-ca-development requires Chrome and a CA leaf/key")
    if not 35000 <= args.portbase <= 49995:
        parser.error("port block must be within the coordinated 35000..49999 range")
    args.out = args.out.resolve()
    if args.out.exists():
        parser.error("--out must not exist; preserve earlier runs")
    args.out.mkdir(parents=True)
    data, profile = args.out / "node", args.out / "profile"
    data.mkdir()
    profile.mkdir()
    processes, logs, commands = [], [], []
    peak_rss, results, failure = 0, {}, None
    load_start = os.getloadavg()
    started = time.time_ns()

    def launch(command, name):
        log = (args.out / (name + ".log")).open("xb")
        logs.append(log)
        process = subprocess.Popen(
            [str(x) for x in command], stdout=log, stderr=log, start_new_session=True
        )
        processes.append(process)
        commands.append(
            {"name": name, "pid": process.pid, "argv": [str(x) for x in command]}
        )
        return process

    def memory():
        nonlocal peak_rss
        groups = {p.pid for p in processes if p.poll() is None}
        output = subprocess.check_output(
            ["ps", "-axo", "pgid=,rss="], text=True, timeout=2
        )
        peak_rss = max(
            peak_rss,
            sum(
                int(parts[1])
                for line in output.splitlines()
                if len(parts := line.split()) == 2 and int(parts[0]) in groups
            ),
        )

    def rpc(method):
        cookie = (data / "regtest/.cookie").read_text().strip()
        request = urllib.request.Request(
            f"http://127.0.0.1:{args.portbase + 1}/",
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": []}
            ).encode(),
            {"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            value = json.load(response)
        if value.get("error"):
            raise RuntimeError(str(value["error"]))
        return value["result"]

    try:
        command = [
            args.node.resolve(),
            "-regtest",
            f"-datadir={data}",
            "-server=1",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-connect=0",
            "-discover=0",
            "-listenonion=0",
            "-chronik=0",
            "-p2pwebsocket=0",
            "-p2pwebtransport=1",
            f"-bind=127.0.0.1:{args.portbase}",
            f"-port={args.portbase}",
            f"-rpcport={args.portbase + 1}",
            f"-rpcbind=127.0.0.1:{args.portbase + 1}",
            "-rpcallowip=127.0.0.1",
        ]
        if args.ca_cert:
            command += [
                f"-tlscert={args.ca_cert.resolve()}",
                f"-tlskey={args.ca_key.resolve()}",
            ]
        else:
            command.append("-p2pwebtransportbrowsercert=1")
        node = launch(command, "node")
        deadline = time.monotonic() + 10
        while True:
            memory()
            try:
                results["node_info"] = rpc("getwebtransportinfo")
                break
            except (OSError, ValueError, RuntimeError):
                if node.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("owned test node failed to become ready")
                time.sleep(0.1)
        if args.ca_root and args.kind == "firefox":
            for command in (
                [args.certutil, "-N", "--empty-password", "-d", f"sql:{profile}"],
                [
                    args.certutil,
                    "-A",
                    "-n",
                    "WT isolated local root",
                    "-t",
                    "C,,",
                    "-i",
                    args.ca_root.resolve(),
                    "-d",
                    f"sql:{profile}",
                ],
            ):
                subprocess.run(
                    [str(x) for x in command],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
            results["isolated_trust"] = {
                "store": "fresh-profile NSS",
                "root_sha256": sha256(args.ca_root),
            }
        elif args.ca_root:
            # Chromium's per-profile ServerCertificate store, schema 1, as
            # observed read-only in our isolated Chrome 155 baseline. No
            # migration, existing profile or system/user keychain is touched.
            # CertificateMetadata: trust=TRUSTED, DNS constraint=localhost.
            # https://chromium.googlesource.com/chromium/src/+/refs/tags/143.0.7491.0/components/server_certificate_database/server_certificate_database.cc
            # https://chromium.googlesource.com/chromium/src/+/refs/tags/135.0.7044.0/components/server_certificate_database/server_certificate_database.proto
            store = profile / "Default/ServerCertificate"
            store.parent.mkdir()
            der = ssl.PEM_cert_to_DER_cert(args.ca_root.read_text())
            with sqlite3.connect(store) as database:
                database.execute(
                    "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)"
                )
                database.executemany(
                    "INSERT INTO meta VALUES(?,?)",
                    [
                        ("mmap_status", "-1"),
                        ("version", "1"),
                        ("last_compatible_version", "1"),
                    ],
                )
                database.execute(
                    "CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY,der_cert BLOB NOT NULL,trust_settings BLOB NOT NULL)"
                )
                database.execute(
                    "INSERT INTO certificates VALUES(?,?,?)",
                    (
                        hashlib.sha256(der).hexdigest().upper(),
                        der,
                        b"\x0a\x02\x08\x03\x12\x0b\x0a\x09localhost",
                    ),
                )
            results["isolated_trust"] = {
                "store": "fresh-profile Chromium ServerCertificate",
                "schema": 1,
                "dns_constraint": "localhost",
                "root_der_sha256": hashlib.sha256(der).hexdigest(),
                "database_sha256_before_browser": sha256(store),
            }
        response = args.out / "result.json"
        page = launch(
            [
                sys.executable,
                Path(__file__).with_name("serve.py"),
                "--port",
                args.portbase + 3,
                "--result",
                response,
            ],
            "page",
        )
        time.sleep(0.2)
        query = {"url": f"https://localhost:{args.portbase}/p2p/wt"}
        if not args.ca_cert:
            query["hash"] = results["node_info"]["cert_sha256"][0]
        url = (
            f"http://127.0.0.1:{args.portbase + 3}/handshake.html?"
            + urllib.parse.urlencode(query)
        )
        if args.kind == "chrome":
            command = [
                args.browser.resolve(),
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--host-resolver-rules=MAP localhost 127.0.0.1",
                f"--user-data-dir={profile}",
                f"--log-net-log={args.out / 'netlog.json'}",
            ]
            if args.local_ca_development:
                command.append("--webtransport-developer-mode")
            command.append(url)
        else:
            (profile / "user.js").write_text(
                'user_pref("network.dns.disableIPv6", true);\n'
            )
            command = [
                args.browser.resolve(),
                "--headless",
                "--no-remote",
                "--profile",
                profile,
                url,
            ]
        browser = launch(command, "browser")
        deadline = time.monotonic() + 25
        while not response.exists():
            memory()
            if (
                browser.poll() is not None
                or page.poll() is not None
                or time.monotonic() >= deadline
            ):
                raise RuntimeError("browser did not report a bounded handshake result")
            time.sleep(0.1)
        results["browser"] = json.loads(response.read_text())
        if args.expect_reject:
            if results["browser"].get("ok") or not results["browser"].get("error"):
                raise RuntimeError(
                    "negative control did not reject the opening handshake"
                )
            results["expected_rejection_observed"] = True
        elif not (
            results["browser"].get("ok")
            and results["browser"].get("closed_cleanly")
            and results["browser"].get("protocol") == "p2p-v1"
        ):
            raise RuntimeError("browser handshake/protocol/close failed")
    except Exception as error:
        failure = str(error)
    finally:
        # Stop only process groups created by this run. Never touch a user's
        # default browser, node, global keychain or trust configuration.
        for process in reversed(processes):
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        for log in logs:
            log.close()
        try:
            version = subprocess.run(
                [str(args.browser), "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except Exception as error:
            version = "unavailable: " + str(error)
        manifest = {
            "ok": failure is None,
            "failure": failure,
            "results": results,
            "mode": "ca" if args.ca_cert else "certificate-hash",
            "expected_rejection": args.expect_reject,
            "local_ca_development": args.local_ca_development,
            "browser_sha256": sha256(args.browser),
            "node_sha256": sha256(args.node),
            "browser_version": version,
            "commands": commands,
            "start_ns": started,
            "end_ns": time.time_ns(),
            "load_start": load_start,
            "load_end": os.getloadavg(),
            "peak_owned_process_group_rss_kib": peak_rss,
            "rss_is_sum_not_pss": True,
        }
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"ok": failure is None, "failure": failure, "out": str(args.out)}))
    return int(failure is not None)


if __name__ == "__main__":
    sys.exit(main())
