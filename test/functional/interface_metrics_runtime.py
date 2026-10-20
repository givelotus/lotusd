#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the runtime metrics at /metrics: the RPC work queue (depth,
capacity, in-flight and suspended requests, refusals) and the standard
process_* metrics."""

import threading
import time

from test_framework.authproxy import JSONRPCException
from test_framework.metrics import m, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy


class RuntimeMetricsTest(BitcoinTestFramework):
    num_nodes = 1
    extra_args = [["-metrics", "-rpcworkqueue=7"]]

    def long_polls(self, count, timeout_ms):
        """Start count waitforblockheight long polls; return their threads
        and the list their refusals (503) are appended to"""
        node = self.nodes[0]
        target = node.getblockcount() + 100
        threads = []
        refused = []

        def poll(proxy):
            try:
                proxy.waitforblockheight(target, timeout_ms)
            except JSONRPCException as e:
                assert "503" in e.error["message"], e.error
                refused.append(e)

        for _ in range(count):
            proxy = get_rpc_proxy(node.url, 0, timeout=60)
            thread = threading.Thread(target=poll, args=(proxy,))
            thread.start()
            threads.append(thread)
        return threads, refused

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Process metrics, without the namespace")
        s = scrape(node)
        assert s.value("process_resident_memory_bytes") > 1e6
        assert s.value("process_virtual_memory_bytes") >= s.value(
            "process_resident_memory_bytes"
        )
        assert s.value("process_open_fds") > 10
        assert s.value("process_max_fds") >= s.value("process_open_fds")
        assert s.value("process_start_time_seconds") > 1e9

        self.log.info("Work queue capacity, and the scrape itself in flight")
        assert_equal(s.value(m("rpc_work_queue_capacity")), 7)
        assert s.value(m("rpc_work_in_flight")) >= 1
        assert_equal(s.value(m("rpc_work_suspended")), 0)
        assert_equal(s.value(m("rpc_work_queue_rejected_total")), 0)

        self.log.info("A long poll is suspended without a worker")
        threads, refused = self.long_polls(1, 4000)
        self.wait_until(lambda: scrape(node).value(m("rpc_work_suspended")) == 1)
        for t in threads:
            t.join()
        self.wait_until(lambda: scrape(node).value(m("rpc_work_suspended")) == 0)

        self.log.info("A full queue refuses requests, and counts them")
        self.restart_node(0, ["-metrics", "-rpcworkqueue=1", "-rpcthreads=1"])
        # Suspended long polls stay in flight: room for 1 queued + 1 thread
        threads, refused = self.long_polls(4, 3000)
        for t in threads:
            t.join()
        assert len(refused) >= 1
        time.sleep(1.05)  # past the rendering cache
        s = scrape(node)
        assert_equal(s.value(m("rpc_work_queue_rejected_total")), len(refused))
        assert_equal(s.value(m("rpc_work_queue_capacity")), 1)
        assert_equal(s.value(m("rpc_work_suspended")), 0)


if __name__ == "__main__":
    RuntimeMetricsTest().main()
