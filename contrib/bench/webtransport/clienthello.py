#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Normalize a reassembled TLS ClientHello; derive QUIC/TLS JA4 and raw diffs.

Input is the TLS handshake message (type + uint24 length + ClientHello),
not a TLS record or encrypted QUIC packet. QUIC Initial decryption and CRYPTO
reassembly belong to the capture analyzer (e.g. Wireshark), not this tool.
Algorithm: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
"""

import argparse
import hashlib
import json
from pathlib import Path


def grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 255


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated TLS field")
        result = self.data[self.pos : self.pos + count]
        self.pos += count
        return result

    def number(self, size):
        return int.from_bytes(self.take(size), "big")

    def vector(self, size):
        return self.take(self.number(size))

    def remaining(self):
        return len(self.data) - self.pos


def vector_exact(data, size):
    reader = Reader(data)
    value = reader.vector(size)
    if reader.remaining():
        raise ValueError("trailing TLS vector data")
    return value


def u16s(data):
    if len(data) % 2:
        raise ValueError("odd uint16 list")
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def varint(reader):
    first = reader.number(1)
    size = 1 << (first >> 6)
    value = first & 63
    for byte in reader.take(size - 1):
        value = (value << 8) | byte
    return value


def hexes(values):
    return ",".join(f"{value:04x}" for value in values)


def short_hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()[:12]


def derive_ja4(ciphers, extensions, signatures, versions, alpn, transport="q"):
    if transport not in ("q", "t", "d"):
        raise ValueError("unknown transport")
    cipher_list = [v for v in ciphers if not grease(v)]
    extension_list = [v for v in extensions if not grease(v)]
    signatures = [v for v in signatures if not grease(v)]
    versions = [v for v in versions if not grease(v)]
    version = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }.get(max(versions, default=0), "00")
    first = alpn[0] if alpn else b""
    if not first:
        alpn_code = "00"
    elif all(
        48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 for c in (first[0], first[-1])
    ):
        alpn_code = chr(first[0]) + chr(first[-1])
    else:
        alpn_code = first.hex()[0] + first.hex()[-1]
    a = (
        transport
        + version
        + ("d" if 0 in extension_list else "i")
        + f"{min(99, len(cipher_list)):02}{min(99, len(extension_list)):02}"
        + alpn_code
    )
    b_input = hexes(sorted(cipher_list))
    hashed_extensions = sorted(v for v in extension_list if v not in (0, 16))
    c_input = hexes(hashed_extensions)
    if signatures:
        c_input += "_" + hexes(signatures)
    b = short_hash(b_input) if cipher_list else "000000000000"
    c = short_hash(c_input) if hashed_extensions else "000000000000"
    return {
        "ja4": f"{a}_{b}_{c}",
        "ja4_a": a,
        "ja4_b_input": b_input,
        "ja4_c_input": c_input,
    }


def parse_clienthello(data, transport="q"):
    r = Reader(data)
    if r.number(1) != 1:
        raise ValueError("input is not a ClientHello handshake")
    body = Reader(r.take(r.number(3)))
    if r.remaining():
        raise ValueError("trailing handshake data")
    legacy_version = body.number(2)
    body.take(32)  # random: excluded from the normalized profile
    body.vector(1)  # session ID: also excluded
    ciphers = u16s(body.vector(2))
    compression = body.vector(1)
    extension_bytes = body.vector(2) if body.remaining() else b""
    if body.remaining():
        raise ValueError("trailing ClientHello body")
    ext = Reader(extension_bytes)
    extension_ids, extension_data = [], {}
    while ext.remaining():
        kind, value = ext.number(2), ext.vector(2)
        if kind in extension_data:
            raise ValueError("duplicate TLS extension")
        extension_ids.append(kind)
        extension_data[kind] = value
    signatures = (
        u16s(vector_exact(extension_data[13], 2)) if 13 in extension_data else []
    )
    versions = (
        u16s(vector_exact(extension_data[43], 1))
        if 43 in extension_data
        else [legacy_version]
    )
    groups = u16s(vector_exact(extension_data[10], 2)) if 10 in extension_data else []
    alpn = []
    if 16 in extension_data:
        names = Reader(vector_exact(extension_data[16], 2))
        while names.remaining():
            alpn.append(names.vector(1))
    key_shares = []
    if 51 in extension_data:
        shares = Reader(vector_exact(extension_data[51], 2))
        while shares.remaining():
            group, exchange = shares.number(2), shares.vector(2)
            key_shares.append({"group": group, "exchange_bytes": len(exchange)})
    params = []
    if 57 in extension_data:
        values = Reader(extension_data[57])
        while values.remaining():
            kind = varint(values)
            value = values.take(varint(values))
            item = {"id": kind, "value_bytes": len(value)}
            if kind in (0, 2, 15, 16):
                # Random connection IDs/reset tokens are not stable profile
                # values; the PCAP remains the raw evidence.
                item["opaque"] = True
            elif kind in (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32):
                number = Reader(value)
                item["integer"] = varint(number)
                if number.remaining():
                    raise ValueError("trailing integer transport parameter data")
            else:
                item["value_hex"] = value.hex()
            params.append(item)
    result = derive_ja4(ciphers, extension_ids, signatures, versions, alpn, transport)
    result.update(
        {
            "transport": transport,
            "ciphers_ordered": ciphers,
            "extensions_ordered": extension_ids,
            "signature_algorithms_ordered": signatures,
            "supported_versions_ordered": versions,
            "supported_groups_ordered": groups,
            "key_shares_ordered": key_shares,
            "alpn_hex_ordered": [x.hex() for x in alpn],
            "quic_transport_parameters_ordered": params,
            "compression_methods_hex": compression.hex(),
            "clienthello_bytes": len(data),
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clienthello",
        required=True,
        type=Path,
        help="reassembled binary handshake (not QUIC ciphertext)",
    )
    parser.add_argument("--transport", choices=("q", "t", "d"), default="q")
    parser.add_argument(
        "--reference", type=Path, help="normalized JSON from a captured reference"
    )
    args = parser.parse_args()
    profile = parse_clienthello(args.clienthello.read_bytes(), args.transport)
    output = {"profile": profile}
    if args.reference:
        reference = json.loads(args.reference.read_text())
        reference = reference.get("profile", reference)
        output["differences"] = {
            key: {"actual": profile.get(key), "reference": reference.get(key)}
            for key in sorted(profile.keys() | reference.keys())
            if profile.get(key) != reference.get(key)
        }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
