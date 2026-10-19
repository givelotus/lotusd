#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise real eCash shard transport, reverse validation and durable restart.

Both nodes already validated the pivot, so its local anchor is authenticated.
This does not simulate acquiring a new anchor from an Avalanche quorum.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class EcashStateSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-avalanche=0"], ["-avalanche=0"]]

    def run_test(self):
        server, client = self.nodes
        self.generate(MiniWallet(server), 20)
        pivot = server.getbestblockhash()
        before = client.gettxoutsetinfo()
        assert_equal(client.getfastsyncinfo()["swarm_state"], "idle")
        assert_raises_rpc_error(
            -1, "pivot block header not found", client.syncutxoshardswarm, "01" * 32
        )
        client.syncutxoshardswarm(pivot, [], True)
        self.wait_until(lambda: client.getfastsyncinfo()["swarm_state"] == "completed")
        info = client.getfastsyncinfo()
        assert_equal(info["blocks_peeled"], 20)
        assert_equal(info["earliest_verified_height"], 0)
        assert not info["fast_sync_active"]
        assert_equal(info["verified_shards"], info["total_non_empty_shards"])
        assert info["coins_imported"] > 0
        after = client.gettxoutsetinfo()
        for key in ("bestblock", "txouts", "total_amount", "hash_serialized"):
            assert_equal(after[key], before[key])
        assert client.verifychain(4, 0)
        self.restart_node(1)
        assert_equal(client.getbestblockhash(), pivot)
        assert not client.getfastsyncinfo()["fast_sync_active"]
        assert client.verifychain(4, 0)
        self.restart_node(1, ["-avalanche=0", "-snapsync=0"])
        assert_raises_rpc_error(-1, "disabled", client.syncutxoshardswarm, pivot)


if __name__ == "__main__":
    EcashStateSyncTest().main()
