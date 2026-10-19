#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Last oversized RPC log field is explicitly marked when its bytes are cut."""

import http.client
import json
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str


class LastStringTruncationTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [
        [
            "-logformat=json",
            "-rpcwhitelistdefault=0",
            "-rpcwhitelist=user1:getblockcount",
            "-rpcauth=user1:50358aa884c841648e0700b073c32b2e$b73e95fff0748cc0b517859d2ca47d9bac1aa78231f3e48fa9222b612bd2083e",
        ]
    ]

    def run_test(self):
        node = self.nodes[0]
        original = "not_allowed_" + "x" * 1200
        url = urllib.parse.urlparse(node.url)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
        try:
            connection.request(
                "POST",
                "/",
                json.dumps({"method": original, "params": [], "id": 1}),
                {"Authorization": "Basic " + str_to_b64str("user1:12345")},
            )
            response = connection.getresponse()
            assert_equal(response.status, 403)
            response.read()
        finally:
            connection.close()
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        row = next(
            row for row in rows if row.get("event") == "rpc_method_access_denied"
        )
        shortened = row["original_method"]
        assert isinstance(shortened, str) and 0 < len(shortened) < len(original)
        assert original.startswith(shortened)
        assert_equal(row["rpc_user"], "user1")
        # Critical causal assertion: the last copied field may not truncate silently.
        assert row.get("fields_truncated") is True, (
            "last string was shortened without fields_truncated"
        )


if __name__ == "__main__":
    LastStringTruncationTest().main()
