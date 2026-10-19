#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Turn a prebuilt wallet PWA bundle into C++ for the daemon to embed.

The bundle is a node-pwa-<version>.tar.gz in the node-pwa-bundle/1 format
(made by wallets/node-pwa/tools/pack.mjs in the monorepo):

- every member is a regular file under node-pwa/;
- node-pwa/BUNDLE.json lists every other file with its sha256 and size;
- each listed .html .js .mjs .css .json .webmanifest .svg .txt file has a
  deterministic <file>.gz beside it, which is not listed;
- nothing else.

The tarball is read in memory and never extracted. The output depends only on
the bundle's bytes (members are sorted; no timestamps or paths are written),
so builds stay reproducible. With --bundle "", the output is an empty table.

    embed_wallet_pwa.py --bundle node-pwa-0.1.0.tar.gz --sha256 <hex> --out x.cpp
"""

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile

PREFIX = "node-pwa/"
MANIFEST = "BUNDLE.json"
MAX_TOTAL_SIZE = 32 * 1024 * 1024
COMPRESSIBLE = (".html", ".js", ".mjs", ".css", ".json", ".webmanifest", ".svg", ".txt")
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".wasm": "application/wasm",
    ".wgsl": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}


class BundleError(Exception):
    pass


def mime_type(path):
    dot = path.rfind(".")
    if dot < 0 or "/" in path[dot:]:
        return None
    return MIME.get(path[dot:].lower())


def check_relpath(rel):
    if not rel or len(rel) > 256 or rel.startswith("/"):
        raise BundleError(f"bad member path {rel!r}")
    if "\\" in rel or "\0" in rel or "%" in rel:
        raise BundleError(f"bad member path {rel!r}")
    for segment in rel.split("/"):
        if not segment or segment.startswith("."):
            raise BundleError(f"bad member path {rel!r}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_members(data):
    """{relative path: bytes} of a node-pwa-bundle/1 tarball, checked."""
    members = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for info in tar:
                if not info.isreg():
                    raise BundleError(f"{info.name!r} is not a regular file")
                if not info.name.startswith(PREFIX):
                    raise BundleError(f"{info.name!r} is not under {PREFIX}")
                rel = info.name[len(PREFIX) :]
                check_relpath(rel)
                if rel in members:
                    raise BundleError(f"duplicate member {rel!r}")
                total += info.size
                if total > MAX_TOTAL_SIZE:
                    raise BundleError("bundle is larger than 32 MiB")
                f = tar.extractfile(info)
                members[rel] = f.read()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BundleError(f"not a valid .tar.gz: {e}") from e
    return members


def parse_manifest(members):
    if MANIFEST not in members:
        raise BundleError(f"missing {PREFIX}{MANIFEST}")
    try:
        manifest = json.loads(members[MANIFEST])
    except (ValueError, UnicodeDecodeError) as e:
        raise BundleError(f"bad {MANIFEST}: {e}") from e
    if not isinstance(manifest, dict):
        raise BundleError(f"bad {MANIFEST}")
    if manifest.get("format") != 1 or manifest.get("name") != "node-pwa":
        raise BundleError(f"{MANIFEST} is not format 1 of node-pwa")
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BundleError(f"bad version in {MANIFEST}")
    commit = manifest.get("source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BundleError(f"bad source_commit in {MANIFEST}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise BundleError(f"bad files in {MANIFEST}")
    return version, files


def load_bundle(data):
    """Return (version, [(path, content_type, sha256 hex, body, gzip body)])."""
    members = read_members(data)
    version, files = parse_manifest(members)
    expected = {MANIFEST}
    assets = []
    for rel, meta in files.items():
        check_relpath(rel)
        if rel == MANIFEST or rel.endswith(".gz"):
            raise BundleError(f"{rel!r} must not be listed")
        if not isinstance(meta, dict):
            raise BundleError(f"bad entry for {rel!r}")
        content_type = mime_type(rel)
        if content_type is None:
            raise BundleError(f"{rel!r} has a type the node does not serve")
        if rel not in members:
            raise BundleError(f"listed file {rel!r} is missing")
        body = members[rel]
        digest = hashlib.sha256(body).hexdigest()
        if meta.get("sha256") != digest or meta.get("size") != len(body):
            raise BundleError(f"{rel!r} does not match its sha256 or size")
        expected.add(rel)
        gz = b""
        if rel.endswith(COMPRESSIBLE):
            gz_name = rel + ".gz"
            if gz_name not in members:
                raise BundleError(f"missing {gz_name!r}")
            gz = members[gz_name]
            try:
                if gzip.decompress(gz) != body:
                    raise BundleError(f"{gz_name!r} does not decompress to {rel!r}")
            except (OSError, EOFError) as e:
                raise BundleError(f"{gz_name!r} is not valid gzip: {e}") from e
            expected.add(gz_name)
        assets.append((rel, content_type, digest, body, gz))
    unlisted = sorted(set(members) - expected)
    if unlisted:
        raise BundleError(f"unlisted members: {', '.join(unlisted)}")
    # The manifest is served too: the service worker reads its file list.
    manifest = members[MANIFEST]
    assets.append(
        (
            MANIFEST,
            MIME[".json"],
            hashlib.sha256(manifest).hexdigest(),
            manifest,
            b"",
        )
    )
    assets.sort(key=lambda a: a[0].encode())
    return version, assets


def cxx_string(s):
    out = []
    for ch in s.encode():
        if ch in (0x22, 0x5C) or ch < 0x20 or ch > 0x7E:
            out.append(f"\\{ch:03o}")
        else:
            out.append(chr(ch))
    return '"' + "".join(out) + '"'


def cxx_array(name, data):
    lines = [f"alignas(8) static constexpr unsigned char {name}[] = {{"]
    for i in range(0, len(data), 16):
        lines.append("    " + ",".join(f"0x{b:02x}" for b in data[i : i + 16]) + ",")
    if not data:
        lines.append("    0")
    lines.append("};")
    return lines


def generate(version, assets):
    out = [
        "// Generated by contrib/devtools/embed_wallet_pwa.py. Do not edit.",
        "",
        "#include <walletpwa/assets.h>",
        "",
        "#include <array>",
        "",
        "namespace walletpwa {",
        "",
        "namespace {",
    ]
    for i, (_path, _type, _digest, body, gz) in enumerate(assets):
        out += cxx_array(f"BODY_{i}", body)
        if gz:
            out += cxx_array(f"GZIP_{i}", gz)
    out.append("} // namespace")
    out.append("")

    def view(name, size):
        return (
            f"std::string_view{{reinterpret_cast<const char *>({name}), {size}}}"
            if size
            else "std::string_view{}"
        )

    out.append("std::span<const EmbeddedAsset> EmbeddedBundle() {")
    if assets:
        out.append(
            f"    static const std::array<EmbeddedAsset, {len(assets)}> ASSETS{{{{"
        )
        for i, (path, content_type, digest, body, gz) in enumerate(assets):
            etag = '"' + digest[:32] + '"'
            out.append("        {")
            out.append(f"            {cxx_string(path)},")
            out.append(f"            {cxx_string(content_type)},")
            out.append(f"            {cxx_string(etag)},")
            out.append(f"            {view(f'BODY_{i}', len(body))},")
            out.append(f"            {view(f'GZIP_{i}', len(gz))},")
            out.append("        },")
        out.append("    }};")
        out.append("    return ASSETS;")
    else:
        out.append("    return {};")
    out.append("}")
    out.append("")
    out.append("std::string_view EmbeddedBundleVersion() {")
    out.append(f"    return {cxx_string(version)};")
    out.append("}")
    out.append("")
    out.append("} // namespace walletpwa")
    out.append("")
    return "\n".join(out)


def embed(bundle_path, expected_sha256):
    if not bundle_path:
        return generate("", [])
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise BundleError("--sha256 must be 64 lowercase hex characters")
    actual = sha256_file(bundle_path)
    if actual != expected_sha256:
        raise BundleError(
            f"{bundle_path}: sha256 {actual} does not match {expected_sha256}"
        )
    with open(bundle_path, "rb") as f:
        data = f.read()
    version, assets = load_bundle(data)
    return generate(version, assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", default="", help="node-pwa-*.tar.gz, or ''")
    parser.add_argument("--sha256", default="", help="required sha256 of --bundle")
    parser.add_argument("--out", required=True, help="C++ file to write")
    args = parser.parse_args()
    try:
        source = embed(args.bundle, args.sha256)
    except (BundleError, OSError) as e:
        print(f"embed_wallet_pwa.py: error: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf8", newline="\n") as f:
        f.write(source)
    return 0


if __name__ == "__main__":
    sys.exit(main())
