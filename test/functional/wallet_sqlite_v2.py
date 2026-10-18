#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""V2 SQLite storage through inherited ABC wallet RPCs, without V2 chain claims."""

import sqlite3
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SQLiteWalletStorageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-discover=0", "-dnsseed=0", "-keypool=2"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet_dir = Path(node.datadir) / self.chain / "wallets"
        node.createwallet("storage")
        wallet = node.get_wallet_rpc("storage")
        address = wallet.getnewaddress("stored-label")
        wallet.encryptwallet("storage-test-passphrase")
        wallet.walletpassphrase("storage-test-passphrase", 30)
        signature = wallet.signmessage(address, "SQLite encrypted storage roundtrip")
        assert wallet.verifymessage(
            address, signature, "SQLite encrypted storage roundtrip"
        )
        backup = Path(self.options.tmpdir) / "encrypted-backup.sqlite"
        wallet.backupwallet(str(backup))
        wallet.walletlock()
        node.unloadwallet("storage")
        database = wallet_dir / "storage" / "wallet.sqlite"
        assert database.exists()
        assert not (database.parent / "wallet.dat").exists()
        assert_equal(database.read_bytes()[:16], b"SQLite format 3\x00")
        with sqlite3.connect(database) as db:
            assert_equal(db.execute("PRAGMA application_id").fetchone()[0], 0x4C563257)
            assert_equal(db.execute("PRAGMA user_version").fetchone()[0], 1)
            assert_equal(
                db.execute("SELECT profile FROM wallet_metadata").fetchone()[0],
                "lotus-v2-wallet-storage-development",
            )
            assert_equal(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        node.loadwallet("storage")
        wallet = node.get_wallet_rpc("storage")
        wallet.walletpassphrase("storage-test-passphrase", 30)
        assert address in wallet.getaddressesbylabel("stored-label")
        assert wallet.signmessage(address, "reopened encrypted wallet")
        node.restorewallet("restored", str(backup))
        restored = node.get_wallet_rpc("restored")
        restored.walletpassphrase("storage-test-passphrase", 30)
        assert address in restored.getaddressesbylabel("stored-label")
        assert restored.signmessage(address, "restored encrypted wallet")
        assert {"name": "storage"} in node.listwalletdir()["wallets"]

        legacy = wallet_dir / "legacy"
        legacy.mkdir()
        payload = bytearray(4096)
        payload[12:16] = bytes.fromhex("62310500")
        (legacy / "wallet.dat").write_bytes(payload)
        assert_raises_rpc_error(
            -18, "Legacy wallet.dat wallets are unsupported", node.loadwallet, "legacy"
        )
        assert_equal((legacy / "wallet.dat").read_bytes(), payload)
        assert not (legacy / "wallet.sqlite").exists()
        foreign = wallet_dir / "foreign"
        foreign.mkdir()
        with sqlite3.connect(foreign / "wallet.sqlite") as db:
            db.execute("CREATE TABLE valuable(data TEXT)")
            db.execute("INSERT INTO valuable VALUES ('untouched')")
        assert_raises_rpc_error(
            -18, "not a Lotus V2 SQLite wallet", node.loadwallet, "foreign"
        )
        with sqlite3.connect(foreign / "wallet.sqlite") as db:
            assert_equal(
                db.execute("SELECT data FROM valuable").fetchone()[0], "untouched"
            )
        node.unloadwallet("storage")
        with sqlite3.connect(database) as db:
            db.execute(
                "UPDATE wallet_metadata SET profile = 'different-explicit-profile'"
            )
        assert_raises_rpc_error(
            -18, "profile does not match", node.loadwallet, "storage"
        )


if __name__ == "__main__":
    SQLiteWalletStorageTest().main()
