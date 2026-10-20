#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mining descriptor matches header hashing, target order and template submission."""

from test_framework.messages import lotus_v2_tagged_hash
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MiningProofOfWorkTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    extra_args = [["-avalanche=0"]]

    def expected_kind(self):
        return "lotus-v2"

    def expected_currency(self):
        return ("XPI", "1000000", 6)

    def expected_pow(self):
        return {
            "version": 1,
            "algorithm": "lotus-v2-blockid",
            "headerbytes": 134,
            "nonceoffset": 42,
            "noncebytes": 8,
            "noncebyteorder": "little",
            "hashbyteorder": "little",
            "targetbyteorder": "big",
            "chainid": "00" * 32,
            "template_rpc": "getrawunsolvedblock",
            "submit_rpc": "submitblock",
        }

    def digest(self, header, chainid=bytes(32)):
        body = lotus_v2_tagged_hash("Lotus/v2/header/body", chainid + header[50:134])
        work = lotus_v2_tagged_hash("Lotus/v2/header/work", header[32:50] + body)
        return lotus_v2_tagged_hash("Lotus/v2/blockid", header[:32] + work)

    def bits_offset(self):
        return 32

    def check_known_vector(self):
        # Independent Python blake3 1.0.11 vector, also fixed in test_header.cpp.
        # A nonzero chain id exposes digest-order errors hidden by regtest's zeros.
        header = bytes.fromhex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "ffff001d0605040302010f0e0d0c0b0a0908020000008877665544332211"
            "00ffeeddccbbaa99404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        )
        assert_equal(len(header), 134)
        assert_equal(
            self.digest(header, bytes(range(32))).hex(),
            "fbe9243579627fc3a41043c80395d33a8a01b91a9b86b6c6e629530595c83370",
        )
        changed = bytearray(header)
        changed[42:50] = (int.from_bytes(header[42:50], "little") + 1).to_bytes(
            8, "little"
        )
        assert_equal(
            self.digest(changed, bytes(range(32))).hex(),
            "8a967f4522d06f683830cf003b9f456001e045f617bf4d4336754a91c75f5824",
        )

    def run_test(self):
        node = self.nodes[0]
        config = node.getchainconfig()
        assert_equal(config["version"], 1)
        identity = config["chain"]
        assert_equal(identity["family"], "bitcoin")
        assert_equal(identity["kind"], self.expected_kind())
        assert_equal(identity["network"], "regtest")
        assert_equal(identity["genesis"], node.getblockhash(0))
        assert_equal(
            identity["identifier"],
            self.expected_kind() + "-regtest:" + node.getblockhash(0),
        )
        ticker, atoms, decimals = self.expected_currency()
        assert_equal(
            config["currency"],
            {
                "ticker": ticker,
                "atomsperunit": atoms,
                "rpcdecimals": decimals,
                "displaydecimals": 2,
            },
        )
        assert_equal(
            node.getcurrencyinfo(),
            {
                "ticker": ticker,
                "satoshisperunit": int(atoms),
                "decimals": decimals,
            },
        )
        address = config["address"]
        assert_equal(address["format"], "cashaddr")
        assert_equal(address["types"], [0, 1])
        assert_equal(address["acceptedformats"], ["cashaddr", "base58check"])
        destination = node.validateaddress(node.get_deterministic_priv_key().address)
        assert_equal(destination["isvalid"], True)
        assert destination["address"].startswith(address["hrp"] + ":")
        assert_equal(
            config["features"],
            {
                "legacytransactions": True,
                "nativetransactions": self.expected_kind() == "lotus-v2",
                "message_signing": "legacy-p2pkh",
            },
        )
        assert config["node"]["client"]
        assert_equal(config["node"]["version"], node.getnetworkinfo()["version"])
        assert_equal(config["mining"]["testgeneration"], True)
        descriptor = config["mining"]["pow"]
        assert_equal(descriptor, node.getmininginfo()["pow"])
        if self.expected_kind() == "lotus-v2":
            assert_equal(identity["chainid"], descriptor["chainid"])
        else:
            assert "chainid" not in identity
        assert_equal(descriptor, self.expected_pow())
        self.check_known_vector()
        genesis = node.getblockheader(node.getblockhash(0), False)
        assert_equal(len(bytes.fromhex(genesis)), descriptor["headerbytes"])
        assert_equal(
            self.digest(bytes.fromhex(genesis))[::-1].hex(), node.getblockhash(0)
        )

        # Keep all coinbase/commitment bytes node-owned. Only the nonce changes.
        template = getattr(node, descriptor["template_rpc"])(
            node.get_deterministic_priv_key().address
        )
        block = bytearray.fromhex(template["blockhex"])
        header = bytes(block[: descriptor["headerbytes"]])
        bits_offset = self.bits_offset()
        bits = int.from_bytes(header[bits_offset : bits_offset + 4], "little")
        exponent, mantissa = bits >> 24, bits & 0x7FFFFF
        target = (
            (mantissa << (8 * (exponent - 3)))
            if exponent >= 3
            else (mantissa >> (8 * (3 - exponent)))
        )
        assert_equal(len(template["target"]), 64)
        assert_equal(int(template["target"], 16), target)
        before = bytes(block)
        offset, width = descriptor["nonceoffset"], descriptor["noncebytes"]
        for nonce in range(1000):
            block[offset : offset + width] = nonce.to_bytes(
                width, descriptor["noncebyteorder"]
            )
            digest = self.digest(bytes(block[: descriptor["headerbytes"]]))
            if int.from_bytes(digest, descriptor["hashbyteorder"]) <= target:
                break
        else:
            raise AssertionError("No regtest proof of work in 1000 attempts")
        assert_equal(block[:offset], before[:offset])
        assert_equal(block[offset + width :], before[offset + width :])
        assert_equal(getattr(node, descriptor["submit_rpc"])(block.hex()), None)
        assert_equal(node.getbestblockhash(), digest[::-1].hex())
        assert_equal(node.getblockcount(), 1)
        # Actual daemon address-output configuration is reflected without changing identity.
        self.restart_node(0, extra_args=["-avalanche=0", "-usecashaddr=0"])
        base58 = node.getchainconfig()
        assert_equal(base58["chain"], identity)
        assert_equal(base58["currency"], config["currency"])
        assert_equal(base58["mining"], config["mining"])
        assert_equal(base58["address"]["format"], "base58check")
        assert_equal(base58["address"]["hrp"], address["hrp"])
        assert_equal(base58["address"]["base58prefixes"], address["base58prefixes"])


if __name__ == "__main__":
    MiningProofOfWorkTest().main()
