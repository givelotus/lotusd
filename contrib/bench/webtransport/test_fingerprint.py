#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Small parser/algorithm checks; no sockets, nodes, browsers or benchmark load."""

import struct
import unittest

from capture_udp import checksum, packet
from clienthello import derive_ja4, parse_clienthello
from server_handshake import profile as server_profile


class FingerprintTest(unittest.TestCase):
    def test_foxio_published_vector(self):
        # Published algorithm example, not a measured browser profile.
        # https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
        ciphers = [
            int(x, 16)
            for x in "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035".split(
                ","
            )
        ]
        extensions = [
            int(x, 16)
            for x in "001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015".split(
                ","
            )
        ]
        signatures = [
            int(x, 16) for x in "0403,0804,0401,0503,0805,0501,0806,0601".split(",")
        ]
        expected = "q13d1516h2_8daaf6152771_e5627efa2ab1"
        actual = derive_ja4(ciphers, extensions, signatures, [0x0304], [b"h2"])
        self.assertEqual(actual["ja4"], expected)
        # Cipher/extension permutations and GREASE do not alter JA4;
        # signature ordering does. Raw ordered fields are compared separately.
        self.assertEqual(
            derive_ja4(
                ciphers[::-1] + [0x0A0A],
                extensions[::-1] + [0xFAFA],
                signatures,
                [0x0304, 0x2A2A],
                [b"h2"],
            )["ja4"],
            expected,
        )
        self.assertNotEqual(
            derive_ja4(ciphers, extensions, signatures[::-1], [0x0304], [b"h2"])["ja4"],
            expected,
        )

    def test_minimal_clienthello_and_truncation(self):
        ext = struct.pack("!HHBBB", 43, 3, 2, 3, 4)
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x13\x01\x01\x00"
        body += len(ext).to_bytes(2, "big") + ext
        hello = b"\x01" + len(body).to_bytes(3, "big") + body
        profile = parse_clienthello(hello)
        self.assertTrue(profile["ja4"].startswith("q13i010100_"))
        self.assertEqual(profile["ciphers_ordered"], [0x1301])
        for end in range(len(hello)):
            with self.assertRaises(ValueError):
                parse_clienthello(hello[:end])

    def test_server_selected_tls13_and_truncation(self):
        ext = struct.pack("!HHH", 43, 2, 0x0304)
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x13\x01\x00"
        body += len(ext).to_bytes(2, "big") + ext
        hello = b"\x02" + len(body).to_bytes(3, "big") + body
        result = server_profile(hello)
        self.assertEqual(result["selected_version"], 0x0304)
        self.assertEqual(result["cipher"], 0x1301)
        self.assertFalse(result["hello_retry_request"])
        with self.assertRaises(ValueError):
            server_profile(hello[:-1])

    def test_synthetic_pcap_packet_preserves_datagram(self):
        payload = b"\xc0\x00\x00\x00\x01quic"
        raw = packet(payload, ("127.0.0.1", 40000), ("127.0.0.1", 40001))
        self.assertEqual(raw[28:], payload)
        self.assertEqual(checksum(raw[:20]), 0)
        self.assertEqual(struct.unpack("!H", raw[2:4])[0], len(raw))


if __name__ == "__main__":
    unittest.main()
