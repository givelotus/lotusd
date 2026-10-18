#!/usr/bin/env python3
"""Exercise inherited stream flag restoration against an actual wallet client.

Usage: python3 test_fd_flags.py /path/to/lotus-v2-wallet-client /path/to/manifest.json
The manifest must describe a valid development profile. No node is launched.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile


def check_run(binary, manifest, home, command, payload, flags, *,
              timeout=False, output_failure=False, argument_failure=False):
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    secret_read, secret_write = os.pipe()
    local, remote = socket.socketpair()
    try:
        # macOS exposes a sticky kernel "has written" bit via F_GETFL.
        # Set it before the snapshot so the comparison isolates client edits.
        os.write(output_write, b"\n")
        os.read(output_read, 1)
        for fd in (input_read, output_write):
            original = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, original | flags)
        before = {fd: fcntl.fcntl(fd, fcntl.F_GETFL)
                  for fd in (input_read, output_write)}
        if payload:
            os.write(input_write, payload)
        if not timeout:
            os.close(input_write)
            input_write = -1
        os.write(secret_write, b"test passphrase\n")
        os.close(secret_write)
        secret_write = -1
        if output_failure:
            os.close(output_read)
            output_read = -1
        argv = [binary, manifest, str(home), command,
                f"--node-fd={local.fileno()}", "--timeout-ms=1000"]
        if command == "create":
            argv.append(f"--passphrase-fd={secret_read}")
        if timeout:
            argv[-1] = "--timeout-ms=100"
        if argument_failure:
            argv.append("--invalid-option")
        child = subprocess.run(argv, stdin=input_read, stdout=output_write,
                               stderr=subprocess.PIPE,
                               pass_fds=(local.fileno(), secret_read), timeout=10)
        after = {fd: fcntl.fcntl(fd, fcntl.F_GETFL) for fd in before}
        assert after == before, (command, flags, before, after, child.stderr)
        if output_failure or timeout:
            assert child.returncode != 0
        else:
            response = json.loads(os.read(output_read, 65536))
            if argument_failure or payload != b"{}":
                assert child.returncode != 0 and response["result"] == "setup_error", response
            else:
                assert child.returncode == 0 and response["result"] == "success", response
    finally:
        local.close()
        remote.close()
        for fd in (input_read, input_write, output_read, output_write,
                   secret_read, secret_write):
            if fd >= 0:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("manifest", type=lambda value: str(Path(value).resolve()))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lotus-v2-client-flags-") as directory:
        for i, flags in enumerate((os.O_APPEND, os.O_APPEND | os.O_NONBLOCK)):
            home = Path(directory) / str(i)
            check_run(args.binary, args.manifest, home, "create", b"{}", flags)
            check_run(args.binary, args.manifest, home, "info", b"{}", flags)
            check_run(args.binary, args.manifest, home, "info", b"invalid", flags)
            check_run(args.binary, args.manifest, home, "info", b"{}", flags,
                      argument_failure=True)
            check_run(args.binary, args.manifest, home, "info", b"", flags,
                      timeout=True)
            check_run(args.binary, args.manifest, home, "info", b"{}", flags,
                      output_failure=True)
    print("wallet client inherited FD flags: 12 cases passed")


if __name__ == "__main__":
    main()
