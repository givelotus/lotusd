#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see COPYING.
"""Native keyhash message proofs, using the existing wallet RPC names."""

import base64
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import bytes_to_wif
from test_framework.xpiaddr import encode


class NativeMessageSigningTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    requires = {"wallet"}

    def run_test(self):
        node = self.nodes[0]
        # Known scalar 1; Python blake3 reference vector, not node output.
        key_hash = bytes.fromhex(
            "f9f2a0b353f482f415281da3a00929d08a7d9a6498054f5ef6623b5580e607f7"
        )
        address = encode("rxpi", key_hash, 1)
        wif = bytes_to_wif((1).to_bytes(32, "big"))
        node.createwallet("message-legacy", descriptors=False, load_on_startup=True)
        wallet = node.get_wallet_rpc("message-legacy")
        wallet.importprivkey(wif, "message key", False)
        message = "  Lotus message\nwith whitespace\t"
        signature = wallet.signmessage(address, message)
        assert_equal(
            signature,
            "IP7/Qe4Hwq9jlGfz3Gm0ADQN7fPip/HUDoSvozREAZ4bP2qZWMaD8HPLXthcQS5SPn9j59HTAEBdSsFTX3186ZM=",
        )
        assert node.verifymessage(address, signature, message)
        assert_equal(signature, node.signmessagewithprivkey(wif, message))
        assert not node.verifymessage(address, signature, message + " ")
        assert_raises_rpc_error(
            -3,
            "Invalid address",
            node.verifymessage,
            encode("xpi", key_hash, 1),
            signature,
            message,
        )
        assert_raises_rpc_error(
            -3,
            "does not refer to key",
            node.verifymessage,
            encode("rxpi", key_hash),
            signature,
            message,
        )
        assert_raises_rpc_error(
            -3,
            "does not refer to key",
            wallet.signmessage,
            encode("rxpi", key_hash),
            message,
        )
        assert_raises_rpc_error(
            -5, "Malformed base64", node.verifymessage, address, "!", message
        )
        raw = bytearray(base64.b64decode(signature, validate=True))
        assert_equal(len(raw), 65)
        assert 31 <= raw[0] <= 34
        for header in (0, 27, 30, 35, 255):
            malformed = raw.copy()
            malformed[0] = header
            assert not node.verifymessage(
                address, base64.b64encode(malformed).decode(), message
            )
        # Descriptor and legacy providers must agree on the x-only address.
        from test_framework.descriptors import descsum_create

        node.createwallet("message-descriptor", descriptors=True)
        descriptor_wallet = node.get_wallet_rpc("message-descriptor")
        result = descriptor_wallet.importdescriptors(
            [{"desc": descsum_create("pkh(" + wif + ")"), "timestamp": "now"}]
        )
        assert result[0]["success"]
        assert_equal(descriptor_wallet.signmessage(address, message), signature)
        node.createwallet("message-watch", disable_private_keys=True, descriptors=True)
        watcher = node.get_wallet_rpc("message-watch")
        pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        assert watcher.importdescriptors(
            [{"desc": descsum_create("pkh(" + pubkey + ")"), "timestamp": "now"}]
        )[0]["success"]
        assert_raises_rpc_error(
            -4, "Private key not available", watcher.signmessage, address, message
        )
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        # The template hashes x-only keys: d and n-d share spending authority.
        opposite_wif = bytes_to_wif((order - 1).to_bytes(32, "big"))
        opposite_signature = node.signmessagewithprivkey(opposite_wif, message)
        assert node.verifymessage(address, opposite_signature, message)
        unusual = "embedded\x00NUL and unicode \u2603\n"
        unusual_signature = wallet.signmessage(address, unusual)
        assert node.verifymessage(address, unusual_signature, unusual)
        assert not node.verifymessage(
            address, unusual_signature, unusual.replace("\x00", "")
        )
        # Genuine ECDSA high-S malleation (flip recovery parity as well).
        high = raw.copy()
        high[0] = 31 + ((high[0] - 31) ^ 1)
        high[33:] = (order - int.from_bytes(raw[33:], "big")).to_bytes(32, "big")
        assert not node.verifymessage(address, base64.b64encode(high).decode(), message)
        assert not node.verifymessage(
            address, base64.b64encode(raw[:-1]).decode(), message
        )
        # Independent pure-Python ECDSA verification of compact r,s.
        from test_framework.key import ECKey

        key = ECKey()
        key.set((1).to_bytes(32, "big"), compressed=True)

        def der_integer(value):
            value = value.lstrip(b"\x00") or b"\x00"
            if value[0] & 128:
                value = b"\x00" + value
            return b"\x02" + bytes([len(value)]) + value

        content = der_integer(bytes(raw[1:33])) + der_integer(bytes(raw[33:65]))
        der = b"\x30" + bytes([len(content)]) + content
        preimage = (
            b"\x16Lotus Signed Message:\n\x01"
            + bytes(32)
            + bytes([len(message.encode())])
            + message.encode()
        )
        digest = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
        assert_equal(
            digest.hex(),
            "7564181309ced3fbd11303d70a957bb62984da700bfd4c6078e16303f66503f7",
        )
        assert key.get_pubkey().verify_ecdsa(der, digest)
        wallet.encryptwallet("test passphrase")
        assert_raises_rpc_error(
            -13, "walletpassphrase", wallet.signmessage, address, message
        )
        wallet.walletpassphrase("test passphrase", 30)
        assert_equal(wallet.signmessage(address, message), signature)
        self.restart_node(0)
        wallet = self.nodes[0].get_wallet_rpc("message-legacy")
        wallet.walletpassphrase("test passphrase", 30)
        assert_equal(wallet.signmessage(address, message), signature)


if __name__ == "__main__":
    NativeMessageSigningTest().main()
