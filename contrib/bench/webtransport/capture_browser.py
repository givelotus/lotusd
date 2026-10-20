#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Controlled handshake capture: explicit test/browser binaries, fresh profiles."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

from clienthello import parse_clienthello


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--kind", choices=("chrome", "firefox"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--portbase", type=int, default=41000)
    parser.add_argument("--samples", type=int, default=1, choices=(1, 2))
    parser.add_argument(
        "--sample-timeout",
        type=float,
        default=25,
        help="one sample needs up to 15s handshake + 3s close",
    )
    args = parser.parse_args()
    if args.sample_timeout < 1 or args.samples * args.sample_timeout > 26:
        parser.error("samples * sample-timeout must fit the 30s controlled server")
    args.out = args.out.resolve()
    if args.out.exists():
        parser.error("--out must not exist (preserve earlier captures)")
    if not (35000 <= args.portbase <= 49995):
        parser.error("use a coordinated port block in 35000..49999")
    args.out.mkdir(parents=True)
    root = Path(__file__).resolve().parents[3]
    processes, files, commands = [], [], []
    tool_paths = [
        Path(__file__),
        Path(__file__).with_name("capture_udp.py"),
        Path(__file__).with_name("clienthello.py"),
        root / "contrib/devtools/webtransport-browser-test/handshake.html",
        root / "contrib/devtools/webtransport-browser-test/serve.py",
    ]
    tool_hashes = {str(p.relative_to(root)): digest(p) for p in tool_paths}
    load_start = os.getloadavg()
    start_ns = time.time_ns()
    peak_rss_kib = 0

    def launch(command, label, env=None):
        log = (args.out / (label + ".log")).open("xb")
        files.append(log)
        process = subprocess.Popen(
            [str(x) for x in command],
            stdout=log,
            stderr=log,
            env=env,
            start_new_session=True,
        )
        processes.append(process)
        commands.append(
            {"label": label, "pid": process.pid, "argv": [str(x) for x in command]}
        )
        return process

    def sample_memory():
        nonlocal peak_rss_kib
        groups = {p.pid for p in processes if p.poll() is None}
        output = subprocess.check_output(["ps", "-axo", "pgid=,rss="], text=True)
        total = sum(
            int(parts[1])
            for line in output.splitlines()
            if len(parts := line.split()) == 2 and int(parts[0]) in groups
        )
        peak_rss_kib = max(peak_rss_kib, total)

    def stop(process):
        # Every group here was created by this driver, never a user's browser.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)

    success, failure = False, None
    results = []
    server = None
    try:
        environment = os.environ.copy()
        environment["WT_BROWSER_CAPTURE_DIR"] = str(args.out / "engine")
        environment["WT_BROWSER_CAPTURE_PORT"] = str(args.portbase + 1)
        server = launch(
            [
                args.test_binary,
                "--run_test=net_quic_tests/webtransport_browser_capture_server",
                "--log_level=message",
                "--report_level=short",
            ],
            "engine",
            environment,
        )
        readiness = args.out / "engine/server.json"
        deadline = time.monotonic() + 10
        while not readiness.exists():
            if server.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("controlled server failed to become ready")
            time.sleep(0.05)
        info = json.loads(readiness.read_text())
        relay = launch(
            [
                sys.executable,
                Path(__file__).with_name("capture_udp.py"),
                "--listen",
                f"127.0.0.1:{args.portbase}",
                "--server",
                f"127.0.0.1:{args.portbase + 1}",
                "--pcap",
                args.out / "wire-0.pcap",
                "--metadata",
                args.out / "wire-0.jsonl",
                "--seconds",
                "32",
            ],
            "relay",
        )
        page = launch(
            [
                sys.executable,
                root / "contrib/devtools/webtransport-browser-test/serve.py",
                "--port",
                str(args.portbase + 3),
                "--result",
                args.out / "current-result.json",
            ],
            "page",
        )
        time.sleep(0.3)
        url = (
            f"http://127.0.0.1:{args.portbase + 3}/handshake.html?"
            + urllib.parse.urlencode(
                {
                    "url": f"https://localhost:{args.portbase}/p2p/wt",
                    "hash": info["cert_sha256"],
                }
            )
        )
        for index in range(args.samples):
            if index:
                # Each fresh browser uses a new source endpoint. Keep each
                # single-client capture separate instead of mixing tuples.
                stop(relay)
                relay = launch(
                    [
                        sys.executable,
                        Path(__file__).with_name("capture_udp.py"),
                        "--listen",
                        f"127.0.0.1:{args.portbase}",
                        "--server",
                        f"127.0.0.1:{args.portbase + 1}",
                        "--pcap",
                        args.out / f"wire-{index}.pcap",
                        "--metadata",
                        args.out / f"wire-{index}.jsonl",
                        "--seconds",
                        "32",
                    ],
                    f"relay-{index}",
                )
                time.sleep(0.2)
            profile = args.out / f"profile-{index}"
            profile.mkdir()
            if args.kind == "chrome":
                command = [
                    args.browser,
                    "--headless=new",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--host-resolver-rules=MAP localhost 127.0.0.1",
                    f"--user-data-dir={profile}",
                    url,
                ]
            else:
                (profile / "user.js").write_text(
                    'user_pref("network.dns.disableIPv6", true);\n'
                )
                command = [
                    args.browser,
                    "--headless",
                    "--no-remote",
                    "--profile",
                    profile,
                    url,
                ]
            browser = launch(command, f"browser-{index}")
            response = args.out / "current-result.json"
            deadline = time.monotonic() + args.sample_timeout
            while not response.exists():
                sample_memory()
                if browser.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"browser sample {index} did not report a result"
                    )
                time.sleep(0.1)
            result = json.loads(response.read_text())
            response.rename(args.out / f"result-{index}.json")
            results.append(result)
            stop(browser)
            if not result.get("ok"):
                raise RuntimeError(
                    f"browser sample {index} handshake/close failed: {result}"
                )
        while server.poll() is None:
            sample_memory()
            time.sleep(0.1)
        if server.returncode:
            raise RuntimeError(f"controlled server exited {server.returncode}")
        stop(relay)
        stop(page)
        reference = json.loads(args.reference.read_text())
        reference = reference.get("profile", reference)
        captures = sorted((args.out / "engine").glob("*-in-type1.bin"))
        if len(captures) < args.samples:
            raise RuntimeError("missing captured ClientHello messages")
        for index, path in enumerate(captures):
            actual = parse_clienthello(path.read_bytes())
            differences = {
                key: {"actual": actual.get(key), "reference": reference.get(key)}
                for key in sorted(actual.keys() | reference.keys())
                if actual.get(key) != reference.get(key)
            }
            (args.out / f"clienthello-{index}.json").write_text(
                json.dumps({"profile": actual, "differences": differences}, indent=2)
                + "\n"
            )
        success = True
    except Exception as error:
        failure = str(error)
    finally:
        if server is not None and server.poll() is None:
            deadline = time.monotonic() + 32
            while server.poll() is None and time.monotonic() < deadline:
                sample_memory()
                time.sleep(0.1)
        for process in reversed(processes):
            stop(process)
        for file in files:
            file.close()
        try:
            version = subprocess.run(
                [str(args.browser), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        except Exception as error:
            version = "unavailable: " + str(error)
        if not success:
            for index, path in enumerate(
                sorted((args.out / "engine").glob("*-in-type1.bin"))
            ):
                try:
                    normalized = {
                        "profile": parse_clienthello(path.read_bytes()),
                        "handshake_result": "failed or inconclusive; see manifest",
                    }
                    (args.out / f"clienthello-{index}.json").write_text(
                        json.dumps(normalized, indent=2) + "\n"
                    )
                except ValueError as error:
                    failure = (failure or "") + "; parse: " + str(error)
        capture_files = [
            *args.out.glob("wire-*"),
            *args.out.glob("result-*.json"),
            *args.out.glob("clienthello-*.json"),
            *(args.out / "engine").glob("*.bin"),
        ]
        manifest = {
            "ok": success,
            "failure": failure,
            "kind": args.kind,
            "browser_version": version,
            "load_start": load_start,
            "load_end": os.getloadavg(),
            "start_ns": start_ns,
            "end_ns": time.time_ns(),
            "platform": list(os.uname()),
            "artifact_sha256": {
                str(p.relative_to(args.out)): digest(p) for p in capture_files
            },
            "tool_sha256": tool_hashes,
            "browser_sha256": digest(args.browser),
            "test_binary_sha256": digest(args.test_binary),
            "reference_sha256": digest(args.reference),
            "peak_owned_process_group_rss_kib": peak_rss_kib,
            "rss_is_sum_not_pss": True,
            "synthetic_pcap_headers": True,
            "commands": commands,
            "results": results,
        }
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if not success:
        raise SystemExit(failure)
    print(json.dumps({"ok": True, "out": str(args.out), "peak_rss_kib": peak_rss_kib}))


if __name__ == "__main__":
    main()
