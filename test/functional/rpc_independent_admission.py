#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Concurrent individual admissions preserve errors, conflicts and array order."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier

from test_framework.authproxy import JSONRPCException
from test_framework.currency import RpcCurrency
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy
from test_framework.wallet import NativeMiniWallet


class IndependentAdmissionTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    supports_cli = False
    extra_args = [["-avalanche=0"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = NativeMiniWallet(node)
        wallet.generate(140)
        currency = RpcCurrency.from_node(node)
        transfers = [wallet.create_self_transfer() for _ in range(8)]
        missing = deepcopy(transfers[7]["tx"])
        missing.vin[0].prevout.txid = 1
        requests = [(tx["hex"], 0) for tx in transfers]
        requests[6] = (transfers[6]["hex"], currency.from_atoms(1))
        requests[7] = (missing.serialize().hex(), 0)
        gate = Barrier(8)

        def submit(raw, maximum, synchronized=True):
            proxy = get_rpc_proxy(node.url, 0, timeout=30)
            if synchronized:
                gate.wait()
            try:
                return {"result": proxy.sendrawtransaction(raw, maximum)}
            except JSONRPCException as error:
                return {"error": error.error}

        with ThreadPoolExecutor(max_workers=8) as workers:
            futures = [workers.submit(submit, *request) for request in requests]
            results = [future.result() for future in futures]
        for index in range(6):
            assert_equal(results[index]["result"], transfers[index]["txid"])
        assert "fee" in results[6]["error"]["message"].lower()
        assert "error" in results[7]
        assert_equal(set(node.getrawmempool()), {tx["txid"] for tx in transfers[:6]})

        # A rejected fee bound must not poison the transaction or other callers.
        assert_equal(node.sendrawtransaction(transfers[6]["hex"], 0), transfers[6]["txid"])
        assert_equal(node.sendrawtransaction(transfers[0]["hex"], 0), transfers[0]["txid"])

        # Independent conflicting requests cannot both reserve the same input.
        coin = wallet.get_utxo()
        first = wallet.create_self_transfer(utxo_to_spend=coin, sequence=0)
        second = wallet.create_self_transfer(utxo_to_spend=coin, sequence=1)
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(submit, tx["hex"], 0, False) for tx in (first, second)]
            conflict_results = [future.result() for future in futures]
        assert_equal(sum("result" in result for result in conflict_results), 1)
        assert_equal(sum("error" in result for result in conflict_results), 1)

        # One JSON-RPC array still runs parent then child; it is not a request
        # to decompose mutating calls into an unordered parallel package.
        chain = wallet.create_self_transfer_chain(chain_length=4)
        responses = node.batch(
            {"jsonrpc": "2.0", "id": i, "method": "sendrawtransaction", "params": [tx["hex"], 0]}
            for i, tx in enumerate(chain)
        )
        for response, tx in zip(responses, chain, strict=True):
            assert_equal(response["result"], tx["txid"])
        assert set(tx["txid"] for tx in chain).issubset(node.getrawmempool())
        wallet.generate(1)
        self.restart_node(0)
        assert_equal(self.nodes[0].getrawmempool(), [])


if __name__ == "__main__":
    IndependentAdmissionTest().main()
