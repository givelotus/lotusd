#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mining descriptor matches header hashing, target order and template submission."""

from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MiningProofOfWorkTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    extra_args = [["-avalanche=0"]]

    def expected_kind(self):
        return "ecash"

    def expected_currency(self):
        return ("XEC", "100", 2)

    def expected_pow(self):
        return {
            "version": 1,
            "algorithm": "sha256d",
            "headerbytes": 80,
            "nonceoffset": 76,
            "noncebytes": 4,
            "noncebyteorder": "little",
            "hashbyteorder": "little",
            "targetbyteorder": "big",
            "template_rpc": "getrawunsolvedblock",
            "submit_rpc": "submitblock",
        }

    def digest(self, header):
        return hash256(header)

    def bits_offset(self):
        return 72

    def check_known_vector(self):
        # Bitcoin genesis, independently published SHA256d header/hash pair.
        header = bytes.fromhex(
            "01000000"
            + "00" * 32
            + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
            + "29ab5f49ffff001d1dac2b7c"
        )
        assert_equal(len(header), 80)
        assert_equal(
            self.digest(header)[::-1].hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
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
