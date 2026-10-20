#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Receive genuine native keyhash coins without claiming ordinary funding works."""

from test_framework.address import base58_to_byte, key_to_p2pkh
from test_framework.messages import (
    COutPoint,
    CTransaction,
    FromHex,
    blake3_single_chunk,
    lotus_v2_branch_leaf,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.v7tx import (
    bip340_sign,
    coin_of,
    new_v7_tx,
    signing_message,
    v2_txout,
    v7_input,
)
from test_framework.xpiaddr import decode_typed, encode


class NativeReceiveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-coinbaseversion=7", "-gbtwithoutpeers=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        address = wallet.getnewaddress("native receive", "native")
        discovery = node.getchainconfig()
        assert_equal(
            discovery["wallet"]["native_receiving"],
            {
                "available": True,
                "address_type": "native",
                "format": "xpiaddr",
                "template": "keyhash",
            },
        )
        assert_equal(discovery["address"]["nativehrp"], "rxpi")
        assert "xpiaddr" in discovery["address"]["acceptedformats"]
        info = wallet.getaddressinfo(address)
        assert_equal(info["native"], True)
        assert_equal(info["type"], 1)
        assert_equal(info["ismine"], True)
        assert_equal(info["iswatchonly"], False)
        assert_equal(info["known_policy"], True)
        assert_equal(info["spendable"], False)
        assert_equal(info["solvable"], False)
        pubkey = bytes.fromhex(info["pubkey"])
        hrp, kind, keyhash = decode_typed(address)
        assert_equal((hrp, kind), ("rxpi", 1))
        assert_equal(keyhash, blake3_single_chunk(pubkey[1:]))
        assert_equal(set(wallet.getaddressesbylabel("native receive")), {address})
        wallet.setlabel(address, "renamed native")
        assert_equal(wallet.getaddressinfo(address)["labels"], ["renamed native"])
        assert_equal(node.validateaddress(address)["native"], True)
        legacy = wallet.getnewaddress("legacy control", "legacy")
        assert legacy.startswith("ecregtest:")
        assert "native" not in wallet.getaddressinfo(legacy)
        assert_raises_rpc_error(
            -8, "Unknown address_type", wallet.getnewaddress, "", "other"
        )
        unknown = encode("rxpi", bytes(32), 1)
        assert_equal(wallet.getaddressinfo(unknown)["ismine"], False)
        assert_equal(wallet.getaddressinfo(unknown)["known_policy"], False)
        assert_raises_rpc_error(
            -5, "Invalid address", wallet.getaddressinfo, encode("xpi", keyhash, 1)
        )
        assert_raises_rpc_error(
            -5,
            "Legacy coinbase requires a legacy address",
            node.rpc.generatetoaddress,
            1,
            address,
            1_000_000,
            2,
        )

        self.log.info("Mine and mature genuine wallet-key native payouts")
        blocks = node.rpc.generatetoaddress(101, address)
        cbid = node.getblock(blocks[0])["tx"][0]
        wire = node.getrawtransaction(cbid, False, blocks[0])
        coinbase = FromHex(CTransaction(), wire)
        assert_equal(coinbase.nVersion, 7)
        coins = wallet.listunspent(1, 9999999, [address])
        assert coins
        for coin in coins:
            assert_equal(coin["address"], address)
            assert_equal(coin["label"], "renamed native")
            assert_equal(coin["spendable"], False)
            assert_equal(coin["solvable"], False)
        assert_equal(wallet.listunspent(1, 9999999, [unknown]), [])
        assert_equal(wallet.gettransaction(cbid)["details"][0]["address"], address)
        assert wallet.getbalance() > 0
        assert_raises_rpc_error(
            -4,
            "Ordinary wallet native funding is unavailable",
            wallet.sendtoaddress,
            address,
            1,
        )

        # Exporting the test wallet's key through its explicit legacy key ID is
        # diagnostic only. The product never translates a payout address.
        secret, version = base58_to_byte(wallet.dumpprivkey(key_to_p2pkh(pubkey)))
        assert_equal(version, 239)
        assert_equal(secret[-1], 1)
        secret = secret[:32]
        program = bytes.fromhex("7aba20") + keyhash + bytes.fromhex("92bb")
        tx = new_v7_tx()
        tx.vin = [v7_input(COutPoint(int(cbid, 16), 0), program, [b"", pubkey[1:]])]
        # Another explicit native address receives a normal payment.
        recipient = wallet.getnewaddress("payment", "native")
        _, _, recipient_hash = decode_typed(recipient)
        recipient_program = (
            bytes.fromhex("7aba20") + recipient_hash + bytes.fromhex("92bb")
        )
        tx.vout = [
            v2_txout(
                coinbase.vout[0].nValue - 10_000,
                lotus_v2_branch_leaf(recipient_program),
            )
        ]
        digest = signing_message(tx, [coin_of(coinbase.vout[0])], 0, 0)
        tx.vin[0].vWitnesses = [
            (program, [], [bip340_sign((2).to_bytes(32, "big"), digest), pubkey[1:]])
        ]
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        tx.vin[0].vWitnesses = [
            (program, [], [bip340_sign(secret, digest), pubkey[1:]])
        ]
        spend_wire = tx.serialize().hex()
        txid = node.sendrawtransaction(spend_wire)
        block = node.rpc.generatetoaddress(1, address)[0]
        assert txid in node.getblock(block)["tx"]
        assert_equal(wallet.gettransaction(txid)["hex"], spend_wire)
        assert wallet.getreceivedbyaddress(recipient) > 0
        received = wallet.listreceivedbyaddress(1, False, False, recipient)
        assert_equal(received[0]["address"], recipient)
        assert_equal(received[0]["label"], "payment")

        self.log.info(
            "Native labels, exact wire and ownership survive restart/rescan/reorg"
        )
        self.restart_node(0)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(wallet.getaddressinfo(address)["pubkey"], info["pubkey"])
        assert_equal(wallet.getaddressinfo(address)["labels"], ["renamed native"])
        assert_equal(node.getrawtransaction(cbid, False, blocks[0]), wire)
        assert_equal(wallet.gettransaction(txid)["hex"], spend_wire)
        wallet.rescanblockchain()
        assert_equal(wallet.gettransaction(txid)["hex"], spend_wire)
        assert_equal(wallet.gettransaction(txid)["details"][0]["address"], recipient)
        node.invalidateblock(block)
        assert_equal(wallet.gettransaction(txid)["confirmations"], 0)
        node.reconsiderblock(block)
        assert_equal(wallet.gettransaction(txid)["confirmations"], 1)

        self.log.info(
            "Locked, public-only and descriptor wallets report ownership honestly"
        )
        node.createwallet("locked", passphrase="test passphrase")
        locked = node.get_wallet_rpc("locked")
        locked_address = locked.getnewaddress("locked native", "native")
        assert_equal(locked.getaddressinfo(locked_address)["ismine"], True)
        assert_equal(locked.getaddressinfo(locked_address)["spendable"], False)
        node.createwallet("watch", disable_private_keys=True)
        watch = node.get_wallet_rpc("watch")
        watch.importpubkey(pubkey.hex(), "watch", False)
        assert_equal(watch.getaddressinfo(address)["ismine"], False)
        assert_equal(watch.getaddressinfo(address)["iswatchonly"], True)
        assert_equal(watch.getaddressinfo(address)["known_policy"], True)
        node.createwallet("descriptor", descriptors=True)
        descriptor = node.get_wallet_rpc("descriptor")
        descriptor_address = descriptor.getnewaddress("descriptor native", "native")
        assert_equal(descriptor.getaddressinfo(descriptor_address)["ismine"], True)
        mined = node.rpc.generatetoaddress(1, descriptor_address)[0]
        assert_equal(
            descriptor.gettransaction(node.getblock(mined)["tx"][0])["details"][0][
                "address"
            ],
            descriptor_address,
        )


if __name__ == "__main__":
    NativeReceiveTest().main()
