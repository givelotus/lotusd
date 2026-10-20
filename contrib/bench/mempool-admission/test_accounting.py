#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Guard A/B reporting against incomplete-flood survivor bias."""

import unittest

from ab import summarize


class AccountingTests(unittest.TestCase):
    def test_incomplete_run_counted_but_not_averaged(self):
        rows = [
            {"config": "a", "complete": True, "tps_10_90": 100},
            {"config": "a", "complete": False, "tps_10_90": 1000000},
        ]
        table = summarize(rows, ["a"])
        self.assertIn("| a | 2 | 1/2 | 100 (100-100)", table)
        self.assertNotIn("1000000", table)

    def test_failed_runs_have_no_performance_claim(self):
        table = summarize([{"config": "a", "complete": False}], ["a"])
        self.assertIn("| a | 1 | 0/1 | - |", table)


if __name__ == "__main__":
    unittest.main()
