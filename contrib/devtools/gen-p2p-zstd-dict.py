#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate src/net_zstd_dict.h: the prebaked p2p-zstd-v1 dictionary.

The dictionary is a zstd "raw content" dictionary: the compressor may copy
from it as if it preceded the first message of a connection. It holds byte
patterns that recur in P2P traffic: message headers, inventory entries and
transaction/script templates. zstd prefers recent history, so the most
common patterns are placed last.

The output is deterministic. NEVER change the bytes of an existing version:
both peers must use identical dictionaries. Add a new version (and a new
Sec-WebSocket-Protocol token) instead.

Usage: contrib/devtools/gen-p2p-zstd-dict.py > src/net_zstd_dict_data.h
"""

import hashlib
import struct

MAGICS = [
    bytes.fromhex("e3e1f3e8"),  # mainnet
    bytes.fromhex("f4e5f3f4"),  # testnet
    bytes.fromhex("dab5bffa"),  # regtest
]

# Least frequent first; zstd favours the end of the dictionary.
COMMANDS_RARE = [
    "getaddr", "mempool", "merkleblock", "filterload", "filteradd",
    "filterclear", "getcfilters", "cfilter", "getcfheaders", "cfheaders",
    "getcfcheckpt", "cfcheckpt", "getblocks", "avahello", "getavaaddr",
    "getavaproofs", "avaproofs", "avaproofsreq", "addr", "addrv2",
    "sendaddrv2", "sendheaders", "sendcmpct", "feefilter", "verack",
    "version", "notfound", "block", "getheaders", "headers",
]
COMMANDS_COMMON = [
    "avaproof", "blocktxn", "getblocktxn", "cmpctblock", "avaresponse",
    "avapoll", "pong", "ping", "getdata", "tx", "inv",
]


def cmd12(name):
    raw = name.encode()
    assert len(raw) <= 12
    return raw + b"\x00" * (12 - len(raw))


def header(magic, name, length=0):
    return magic + cmd12(name) + struct.pack("<I", length)


def compact(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


# Script templates (scriptPubKey bodies; hashes/keys zeroed).
P2PKH = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
P2SH = b"\xa9\x14" + b"\x00" * 20 + b"\x87"
OP_RETURN = b"\x6a\x04\x00\x00\x00\x00"
# CashToken-prefixed P2PKH (PREFIX_TOKEN 0xef + category + bitfield)
CASHTOKEN_P2PKH = b"\xef" + b"\x00" * 32 + b"\x10" + P2PKH
# Lotus V2 Taproot (OP_SCRIPTTYPE OP_1 <32/33-byte key>) and template script
# opcode runs.
TAPROOT = b"\x62\x51\x21\x02" + b"\x00" * 32
TAPROOT_STATE = TAPROOT + b"\x20" + b"\x00" * 32
TAPROOT_PUSH = b"\x22\x51\x20" + b"\x00" * 32
TMPL_OPS = bytes([0x50, 0x62, 0x6D, 0xEB, 0xEC, 0xED, 0xDF, 0xDE, 0xBD, 0xAC])

# scriptSig templates: Schnorr (65-byte sig) and DER ECDSA (71/72-byte sig)
SCHNORR_SCRIPTSIG = b"\x64\x41" + b"\x00" * 64 + b"\x41" + b"\x21\x02" + b"\x00" * 32
ECDSA_SCRIPTSIG = (
    b"\x6b\x48\x30\x45\x02\x21\x00" + b"\x00" * 32 + b"\x02\x20" + b"\x00" * 32
    + b"\x41\x21\x03" + b"\x00" * 32
)

VERSIONS = [b"\x01\x00\x00\x00", b"\x02\x00\x00\x00"]
SEQ_FINAL = b"\xff\xff\xff\xff"
SEQ_RBF = b"\xfe\xff\xff\xff"
LOCKTIME0 = b"\x00\x00\x00\x00"

INV_TYPES = [
    struct.pack("<I", 0x1F000002),  # MSG_AVA_STAKE_CONTENDER
    struct.pack("<I", 0x1F000001),  # MSG_AVA_PROOF
    b"\x04\x00\x00\x00",  # MSG_CMPCT_BLOCK
    b"\x02\x00\x00\x00",  # MSG_BLOCK
    b"\x01\x00\x00\x00",  # MSG_TX
]


def txout(value, script):
    return struct.pack("<q", value) + compact(len(script)) + script


def txin(script_sig, sequence, vout=0):
    return b"\x00" * 32 + struct.pack("<I", vout) + compact(len(script_sig)) + script_sig + sequence


def sample_tx(version, ins, outs, locktime=LOCKTIME0):
    out = version + compact(len(ins)) + b"".join(ins)
    out += compact(len(outs)) + b"".join(outs) + locktime
    return out


def build():
    d = bytearray()

    # 1. Rare message headers for every network.
    for magic in MAGICS:
        for name in COMMANDS_RARE:
            d += header(magic, name)

    # 2. version message body skeleton and user agents
    for ua in (b"/Bitcoin ABC:0.34.1(EB32.0)/", b"/Bitcoin ABC:0.34.1/",
               b"/Lotus:11.6.1/", b"/lotusd:12.0.0/"):
        body = struct.pack("<iQq", 70016, 0x425, 0)
        body += struct.pack("<Q", 0x425) + b"\x00" * 10 + b"\xff\xff" + b"\x7f\x00\x00\x01" + b"\x20\x8d"
        body += struct.pack("<Q", 0x425) + b"\x00" * 16 + b"\x00\x00"
        body += b"\x00" * 8 + compact(len(ua)) + ua + struct.pack("<i", 0) + b"\x01"
        d += body

    # 3. Script templates, alone and in outputs
    for script in (TMPL_OPS * 4, TAPROOT_PUSH, TAPROOT_STATE, TAPROOT,
                   CASHTOKEN_P2PKH, OP_RETURN, P2SH, P2PKH):
        d += txout(546, script)
        d += txout(100000000, script)

    # 4. headers message: 80-byte headers followed by a zero tx count
    for magic in MAGICS:
        d += header(magic, "headers") + b"\x02"
        for _ in range(2):
            d += VERSIONS[0] + b"\x00" * 32 + b"\x00" * 32 + LOCKTIME0 + b"\xff\xff\x7f\x20" + LOCKTIME0 + b"\x00"

    # 5. Transaction skeletons (in block order: back-to-back txs)
    for version in VERSIONS:
        for sig, seq in ((ECDSA_SCRIPTSIG, SEQ_FINAL), (SCHNORR_SCRIPTSIG, SEQ_RBF),
                         (SCHNORR_SCRIPTSIG, SEQ_FINAL)):
            d += sample_tx(version, [txin(sig, seq, 1)],
                           [txout(1000000, P2PKH), txout(98990000, P2PKH)])
            d += sample_tx(version, [txin(sig, seq, 0), txin(sig, seq, 1)],
                           [txout(50000, P2SH), txout(4949000, P2PKH)])

    # 6. Inventory entries and common message headers, most common last
    for magic in MAGICS:
        for name in COMMANDS_COMMON:
            d += header(magic, name)
        for inv_type in INV_TYPES:
            d += header(magic, "inv", 37) + b"\x01" + inv_type + b"\x00" * 32
            d += header(magic, "getdata", 37) + b"\x01" + inv_type + b"\x00" * 32
    # Common boundaries between consecutive outputs / transactions
    d += (b"\x88\xac" + LOCKTIME0 + VERSIONS[1] + b"\x01") * 4
    d += (b"\x87" + LOCKTIME0 + VERSIONS[0] + b"\x01") * 2
    d += (SEQ_FINAL + b"\x02") * 4 + (SEQ_RBF + b"\x02") * 2
    mainnet = MAGICS[0]
    for name in ("ping", "pong", "getdata", "tx", "inv"):
        d += header(mainnet, name)
    return bytes(d)


def main():
    data = build()
    digest = hashlib.sha256(data).hexdigest()
    print("// Generated by contrib/devtools/gen-p2p-zstd-dict.py. Do not edit.")
    print(f"// Size: {len(data)} bytes, SHA256: {digest}")
    print("// NEVER change these bytes: peers negotiating p2p-zstd-v1 must use")
    print("// identical dictionaries. Add a new version instead.")
    print()
    print("#ifndef BITCOIN_NET_ZSTD_DICT_DATA_H")
    print("#define BITCOIN_NET_ZSTD_DICT_DATA_H")
    print()
    print("#include <cstdint>")
    print()
    print(f'static constexpr const char *P2P_ZSTD_DICT_V1_SHA256 = "{digest}";')
    print()
    print(f"inline constexpr uint8_t P2P_ZSTD_DICT_V1[{len(data)}] = {{")
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        print("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    print("};")
    print()
    print("#endif // BITCOIN_NET_ZSTD_DICT_DATA_H")


if __name__ == "__main__":
    main()
