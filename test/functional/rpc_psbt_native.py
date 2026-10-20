#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see COPYING.
"""Two disconnected signers exchange native PSBTs over confirmed real coins.

Funding uses valid native VM programs. Ordinary CWallet native coin selection
and unmodified Bitcoin hardware wallets are outside this test's scope.
"""

from base64 import b64encode
from copy import deepcopy

from test_framework.key import ECKey
from test_framework.messages import (
    XEC,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    blake3_single_chunk,
    ser_compact_size,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import NativeMiniWallet
from test_framework.wallet_util import bytes_to_wif

VERSION = 0x4C560001


def prop(subtype, keydata=b""):
    return (b"\xfc\x08lotus-v2" + ser_compact_size(subtype) + keydata).hex()


def encode(document):
    maps = [document["global_map"], *document["inputs"], *document["outputs"]]
    wire = b"psbt\xff"
    for mapping in maps:
        wire += (
            b"".join(
                ser_string(bytes.fromhex(key)) + ser_string(bytes.fromhex(value))
                for key, value in sorted(mapping.items())
            )
            + b"\x00"
        )
    return b64encode(wire).decode()


def args(values):
    return (
        ser_compact_size(len(values)) + b"".join(ser_string(v) for v in values)
    ).hex()


class NativePsbtTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-coinbaseversion=7"], ["-coinbaseversion=7"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node, other = self.nodes
        wallets = [n.get_wallet_rpc(self.default_wallet_name) for n in self.nodes]
        miner = NativeMiniWallet(node)
        self.generate(miner, 101)
        keys, programs, funded = [], [], []
        amount = 1_000_000 * XEC
        for index, secret in enumerate((3, 1)):
            key = ECKey()
            key.set(secret.to_bytes(32, "big"), True)
            public = key.get_pubkey().get_bytes()[1:]
            # Canonical native type-1 program, independently reconstructed.
            program = b"\x7a\xba\x20" + blake3_single_chunk(public) + b"\x92\xbb"
            keys.append(public)
            programs.append(program)
            wallets[index].importprivkey(bytes_to_wif(key.get_bytes()), "", False)
            funded.append(
                miner.send_to(from_node=node, scriptPubKey=program, amount=amount)
            )
        self.generate(miner, 1)
        self.disconnect_nodes(0, 1)

        tx = CTransaction()
        tx.nVersion = 7
        for outpoint, program in zip(funded, programs):
            txin = CTxIn(
                COutPoint(int(outpoint[0], 16), outpoint[1]), nSequence=0xFFFFFFFF
            )
            txin.nFlags, txin.nPathIndex = 1, 0
            txin.vWitnesses = [(program, [], [])]
            tx.vin.append(txin)
        tx.vout = [CTxOut(amount - 10000, b"\x4e") for _ in range(2)]
        raw_template = tx.serialize().hex()
        converted = node.converttopsbt(raw_template)
        document = node.decodepsbt(converted)
        # This is the deliberate before-control: old converters wrap v7 in a
        # legacy v0 PSBT and cannot satisfy this explicit version assertion.
        assert_equal(document.get("psbt_version"), VERSION)
        assert_equal(document["coin_authentication"], "not_checked")
        for index, public in enumerate(keys):
            document["inputs"][index][prop(2, b"\x00\x00")] = args([b"", public])
            document["inputs"][index][prop(3, b"\x00" * 4)] = (
                b"\x00\x00" + public
            ).hex()
            document["inputs"][index][prop(0x80)] = "00ff"
        unsigned = node.utxoupdatepsbt(encode(document))
        updated = node.decodepsbt(unsigned)
        assert all(prop(1) in item for item in updated["inputs"])

        for mode, scope in (
            (1, "OWN_INPUT_ALL_OUTPUTS"),
            (2, "OWN_INPUT_PAIRED_OUTPUT"),
        ):
            partial_mode = deepcopy(updated)
            for item in partial_mode["inputs"]:
                request_key = prop(3, b"\x00" * 4)
                request = bytearray.fromhex(item[request_key])
                request[1] = mode
                item[request_key] = request.hex()
            mode_unsigned = encode(partial_mode)
            assert_raises_rpc_error(
                -4,
                "explicit authorization",
                wallets[0].walletprocesspsbt,
                mode_unsigned,
            )
            copies = [
                wallet.walletprocesspsbt(
                    mode_unsigned, sighashtype=scope, finalize=False
                )["psbt"]
                for wallet in wallets
            ]
            merged_mode = node.combinepsbt(copies)
            assert_equal(node.finalizepsbt(merged_mode)["complete"], True)

        first = wallets[0].walletprocesspsbt(unsigned, finalize=False)
        second = wallets[1].walletprocesspsbt(unsigned, finalize=False)
        assert_equal(first["signed_slots"], 1)
        assert_equal(second["signed_slots"], 1)
        assert_equal(first["complete"], False)
        assert_equal(second["complete"], False)
        assert_equal(node.finalizepsbt(first["psbt"])["complete"], False)
        combined = node.combinepsbt([first["psbt"], second["psbt"]])
        complete_psbt = node.finalizepsbt(combined, False)
        assert_equal(complete_psbt["complete"], True)
        complete = node.finalizepsbt(complete_psbt["psbt"])
        assert_equal(complete["complete"], True)
        decoded = node.decoderawtransaction(complete["hex"])
        assert_equal(decoded["txid"], document["tx"]["txid"])
        assert decoded["hash"] != document["tx"]["hash"]
        retained = node.decodepsbt(complete_psbt["psbt"])
        for item in retained["inputs"]:
            assert_equal(item[prop(0x80)], "00ff")
            assert prop(1) in item and prop(2, b"\x00\x00") in item
            assert prop(3, b"\x00" * 4) in item and prop(4, b"\x00" * 4) in item

        self.log.info(
            "Reject conflicts, untrusted provenance, wrong chain and final vector tampering"
        )
        wrong = deepcopy(updated)
        coin = bytearray.fromhex(wrong["inputs"][0][prop(1)])
        coin[-1] ^= 1
        wrong["inputs"][0][prop(1)] = coin.hex()
        assert_raises_rpc_error(
            -8,
            "conflicts with trusted state",
            wallets[0].walletprocesspsbt,
            encode(wrong),
        )
        wrong = deepcopy(updated)
        chain = bytearray.fromhex(wrong["global_map"][prop(1)])
        chain[0] ^= 1
        wrong["global_map"][prop(1)] = chain.hex()
        assert_raises_rpc_error(
            -8, "trusted chain", wallets[0].walletprocesspsbt, encode(wrong)
        )
        wrong = deepcopy(retained)
        final = bytearray.fromhex(wrong["inputs"][0][prop(5, b"\x00\x00")])
        final[-1] ^= 1
        wrong["inputs"][0][prop(5, b"\x00\x00")] = final.hex()
        assert_equal(node.finalizepsbt(encode(wrong))["complete"], False)
        wrong = deepcopy(retained)
        wrong["inputs"][0][prop(0x80)] = "01"
        assert_raises_rpc_error(
            -8, "conflicting", node.combinepsbt, [combined, encode(wrong)]
        )
        for permit in (False, True):
            assert_raises_rpc_error(
                -8,
                "template has arguments",
                node.converttopsbt,
                complete["hex"],
                permit,
            )

        self.log.info(
            "Legacy version-2 transactions keep their existing PSBT container"
        )
        legacy = CTransaction()
        legacy.nVersion = 2
        legacy.vin = [CTxIn(COutPoint(123, 0), nSequence=0xFFFFFFFF)]
        legacy.vout = [CTxOut(1000, b"\x51")]
        legacy_psbt = node.converttopsbt(legacy.serialize().hex())
        legacy_decoded = node.decodepsbt(legacy_psbt)
        assert_equal(legacy_decoded["tx"]["version"], 2)
        assert "global_map" not in legacy_decoded

        self.connect_nodes(0, 1)
        assert_equal(node.sendrawtransaction(complete["hex"]), decoded["txid"])
        self.sync_mempools()
        block = self.generate(miner, 1)[0]
        assert decoded["txid"] in node.getblock(block)["tx"]


if __name__ == "__main__":
    NativePsbtTest().main()
