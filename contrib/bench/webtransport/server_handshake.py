#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Normalize public TLS 1.3 server handshake fields; this does not claim JA4S."""

import argparse
import hashlib
import json
from pathlib import Path

from clienthello import Reader, u16s, vector_exact


def extensions(data):
    reader = Reader(data)
    result = []
    seen = set()
    while reader.remaining():
        kind, value = reader.number(2), reader.vector(2)
        if kind in seen:
            raise ValueError("duplicate TLS extension")
        seen.add(kind)
        result.append((kind, value))
    return result


def profile(data):
    reader = Reader(data)
    kind = reader.number(1)
    body = Reader(reader.take(reader.number(3)))
    if reader.remaining():
        raise ValueError("trailing handshake data")
    result = {"message_type": kind, "handshake_bytes": len(data)}
    if kind == 2:
        result["legacy_version"] = body.number(2)
        random = body.take(32)
        result["hello_retry_request"] = random.hex() == (
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        )
        body.vector(1)  # random session ID is not a stable profile field
        result["cipher"] = body.number(2)
        result["compression"] = body.number(1)
        fields = extensions(body.vector(2))
        result["extensions_ordered"] = [key for key, _ in fields]
        for key, value in fields:
            if key == 43:
                versions = u16s(value)
                if len(versions) != 1:
                    raise ValueError("invalid server supported_versions")
                result["selected_version"] = versions[0]
            elif key == 51:
                share = Reader(value)
                result["key_share_group"] = share.number(2)
                if not result["hello_retry_request"]:
                    result["key_share_bytes"] = len(share.vector(2))
                if share.remaining():
                    raise ValueError("trailing server key share data")
    elif kind == 8:
        fields = extensions(body.vector(2))
        result["extensions_ordered"] = [key for key, _ in fields]
        for key, value in fields:
            if key == 16:
                names = Reader(vector_exact(value, 2))
                alpn = []
                while names.remaining():
                    alpn.append(names.vector(1).hex())
                result["alpn_hex"] = alpn
            elif key == 57:
                # Preserve actual raw QUIC server parameter bytes for later
                # analyzer comparison; connection IDs/tokens are variable.
                result["quic_transport_parameters_hex"] = value.hex()
    elif kind == 11:
        body.vector(1)  # certificate request context
        certificates = Reader(body.vector(3))
        chain = []
        while certificates.remaining():
            der = certificates.vector(3)
            fields = extensions(certificates.vector(2))
            chain.append(
                {
                    "der_bytes": len(der),
                    "der_sha256": hashlib.sha256(der).hexdigest(),
                    "extensions_ordered": [key for key, _ in fields],
                }
            )
        result["certificates"] = chain
    else:
        raise ValueError("expected TLS 1.3 ServerHello/EncryptedExtensions/Certificate")
    if body.remaining():
        raise ValueError("trailing handshake body")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handshake", required=True, type=Path)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    actual = profile(args.handshake.read_bytes())
    output = {"profile": actual}
    if args.reference:
        reference = json.loads(args.reference.read_text())
        reference = reference.get("profile", reference)
        output["differences"] = {
            key: {"actual": actual.get(key), "reference": reference.get(key)}
            for key in sorted(actual.keys() | reference.keys())
            if actual.get(key) != reference.get(key)
        }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
