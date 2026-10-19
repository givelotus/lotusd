#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for embed_wallet_pwa.py."""

import gzip
import hashlib
import io
import json
import os
import random
import subprocess
import sys
import tarfile
import tempfile
import unittest

from embed_wallet_pwa import BundleError, embed, load_bundle

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "embed_wallet_pwa.py")

FILES = {
    "index.html": b"<!doctype html><title>w</title>",
    "app.js": b"console.log('hi');\n",
    "mining/hash.wgsl": b"@compute @workgroup_size(1) fn main() {}",
    "icons/icon.png": b"\x89PNG\r\n\x1a\n",
    "manifest.webmanifest": b'{"name":"w"}',
}


def gz(data):
    return gzip.compress(data, mtime=0)


def manifest(files, **override):
    m = {
        "format": 1,
        "name": "node-pwa",
        "version": "0.1.0",
        "source_commit": "a" * 40,
        "files": {
            rel: {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d)}
            for rel, d in files.items()
        },
    }
    m.update(override)
    return json.dumps(m).encode()


def members(files=FILES, **override):
    out = {"BUNDLE.json": manifest(files, **override)}
    for rel, data in files.items():
        out[rel] = data
        if rel.endswith((".html", ".js", ".webmanifest")):
            out[rel + ".gz"] = gz(data)
    return out


def tarball(entries, shuffle=None, mtime=0, extra=()):
    """entries: {relpath: bytes}; extra: prepared TarInfo, data pairs."""
    buf = io.BytesIO()
    names = sorted(entries)
    if shuffle is not None:
        random.Random(shuffle).shuffle(names)
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for rel in names:
            info = tarfile.TarInfo("node-pwa/" + rel)
            info.size = len(entries[rel])
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(entries[rel]))
        for info, data in extra:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


class EmbedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data, name="b.tar.gz"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as f:
            f.write(data)
        return path, hashlib.sha256(data).hexdigest()

    def test_valid_bundle(self):
        version, assets = load_bundle(tarball(members()))
        self.assertEqual(version, "0.1.0")
        paths = [a[0] for a in assets]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(
            set(paths), set(FILES) | {"BUNDLE.json"}, "no .gz members as files"
        )
        by_path = {a[0]: a for a in assets}
        self.assertEqual(by_path["app.js"][1], "text/javascript; charset=utf-8")
        self.assertEqual(by_path["mining/hash.wgsl"][1], "text/plain; charset=utf-8")
        self.assertEqual(by_path["mining/hash.wgsl"][3], FILES["mining/hash.wgsl"])
        self.assertEqual(by_path["app.js"][4], gz(FILES["app.js"]))
        self.assertEqual(by_path["icons/icon.png"][4], b"")
        source = embed(*self.write(tarball(members())))
        self.assertIn('"0.1.0"', source)
        digest = hashlib.sha256(FILES["app.js"]).hexdigest()
        self.assertIn('"\\042' + digest[:32] + '\\042"', source)

    def test_deterministic(self):
        a = embed(*self.write(tarball(members()), "a.tar.gz"))
        b = embed(*self.write(tarball(members(), shuffle=7, mtime=12345), "b.tar.gz"))
        c = embed(*self.write(tarball(members(), shuffle=8, mtime=99), "c.tar.gz"))
        self.assertEqual(a, b)
        self.assertEqual(a, c)
        self.assertNotIn(self.tmp.name, a)

    def assertRejected(self, data, fragment):
        with self.assertRaises(BundleError) as ctx:
            load_bundle(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_rejects_links_and_specials(self):
        for kind in (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.DIRTYPE,
            tarfile.FIFOTYPE,
        ):
            info = tarfile.TarInfo("node-pwa/x.js")
            info.type = kind
            info.linkname = "index.html"
            self.assertRejected(
                tarball(members(), extra=[(info, None)]), "not a regular file"
            )

    def test_rejects_bad_paths(self):
        for name in (
            "node-pwa/../x.js",
            "node-pwa/a/../../x.js",
            "node-pwa//x.js",
            "node-pwa/.hidden.js",
            "/node-pwa/x.js",
            "other/x.js",
            "node-pwa/a\\b.js",
        ):
            info = tarfile.TarInfo(name)
            info.size = 1
            with self.assertRaises(BundleError, msg=name):
                load_bundle(tarball(members(), extra=[(info, b"x")]))

    def test_rejects_unlisted_and_missing(self):
        m = members()
        m["extra.js"] = b"x"
        self.assertRejected(tarball(m), "unlisted members: extra.js")
        m = members()
        m["BUNDLE.json.gz"] = gz(m["BUNDLE.json"])
        self.assertRejected(tarball(m), "unlisted")
        m = members()
        del m["app.js"]
        del m["app.js.gz"]
        self.assertRejected(tarball(m), "missing")
        m = members()
        del m["app.js.gz"]
        self.assertRejected(tarball(m), "missing 'app.js.gz'")
        m = members()
        del m["BUNDLE.json"]
        self.assertRejected(tarball(m), "missing node-pwa/BUNDLE.json")
        files = dict(FILES, **{"run.exe": b"MZ"})
        self.assertRejected(tarball(members(files)), "type the node does not serve")

    def test_rejects_hash_and_size_mismatch(self):
        m = members()
        m["index.html"] = b"<!doctype html><title>x</title>"
        m["index.html.gz"] = gz(m["index.html"])
        self.assertRejected(tarball(m), "does not match its sha256 or size")
        path, digest = self.write(tarball(members()))
        with self.assertRaises(BundleError):
            embed(path, "0" * 64)
        with self.assertRaises(BundleError):
            embed(path, digest.upper())

    def test_rejects_bad_gzip(self):
        m = members()
        m["app.js.gz"] = gz(b"something else")
        self.assertRejected(tarball(m), "does not decompress")
        m = members()
        m["app.js.gz"] = b"not gzip"
        self.assertRejected(tarball(m), "not valid gzip")

    def test_rejects_bad_manifest(self):
        self.assertRejected(tarball(members(format=2)), "format 1")
        self.assertRejected(tarball(members(version="1.0")), "bad version")
        self.assertRejected(tarball(members(source_commit="x")), "source_commit")
        m = members()
        m["BUNDLE.json"] = b"{"
        self.assertRejected(tarball(m), "bad BUNDLE.json")
        self.assertRejected(b"not a tarball", "not a valid .tar.gz")

    def test_empty_bundle(self):
        source = embed("", "")
        self.assertIn("return {};", source)
        self.assertIn('return "";', source)
        out = os.path.join(self.tmp.name, "out.cpp")
        subprocess.run(
            [sys.executable, SCRIPT, "--bundle", "", "--sha256", "", "--out", out],
            check=True,
        )
        with open(out, encoding="utf8") as f:
            self.assertEqual(f.read(), source)

    def test_command_line_errors(self):
        path, _ = self.write(tarball(members()))
        out = os.path.join(self.tmp.name, "out.cpp")
        result = subprocess.run(
            [
                sys.executable,
                SCRIPT,
                "--bundle",
                path,
                "--sha256",
                "0" * 64,
                "--out",
                out,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match", result.stderr)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
