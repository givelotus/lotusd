#!/usr/bin/env python3
"""Coverage controls for the all-source log inventory."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from inventory import TIMER_PRODUCERS, inventory


class InventoryTest(unittest.TestCase):
    def test_all_scopes_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            for path, source in {
                "src/a.cpp": '// Unicode before call: …\nLogPrintf("x=%d", n); // LogInfo("not a call");\n',
                "chronik/bridge.cpp": 'LogInfo("ready");\n',
                "src/test/a.cpp": 'LogEvent(NET, "ready");\n',
                "chronik/test/bridge.cpp": 'logger.LogPrintStr("barrier");\n',
                "src/wallet.cpp": 'wallet->WalletLogPrintf("balance=%d", n);\n',
                "seeder/a.cpp": 'LogPrintLevel_(ALL, Info, false, "ready");\n',
                "src/timing.cpp": (
                    "void work() {\n"
                    'LOG_TIME_SECONDS("seconds");\n'
                    'LOG_TIME_MICROS_WITH_CATEGORY("micros", BCLog::LOCK);\n'
                    'LOG_TIME_MILLIS_WITH_CATEGORY("millis", BCLog::VALIDATION);\n'
                    'LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE("once", BCLog::ADDRMAN);\n'
                    '// LOG_TIME_SECONDS("not a call");\n}\n'
                ),
            }.items():
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(source)
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    directory,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            report = inventory(root)
            self.assertEqual(report["counts"], {"deferred": 9, "already_structured": 1})
            self.assertEqual(len(report["sites"]), 10)
            self.assertEqual(
                next(
                    s for s in report["sites"] if s["path"] == "chronik/test/bridge.cpp"
                )["scope"],
                "test_or_benchmark",
            )
            self.assertEqual(
                next(s for s in report["sites"] if s["path"] == "chronik/bridge.cpp")[
                    "scope"
                ],
                "production",
            )
            self.assertEqual(
                next(s for s in report["sites"] if s["path"] == "src/a.cpp")["line"], 2
            )
            self.assertEqual(
                {s["macro"] for s in report["sites"] if s["path"] == "src/timing.cpp"},
                TIMER_PRODUCERS,
            )
            self.assertEqual(report, inventory(root))
            identity = report["sites"][0]["id"]
            decision = {
                "disposition": "intentionally_freeform",
                "reason": "Explicitly reviewed fixture for legacy API coverage.",
            }
            reviewed = inventory(root, dispositions={identity: decision})
            self.assertEqual(
                reviewed["sites"][0]["disposition"], "intentionally_freeform"
            )
            with self.assertRaises(ValueError):
                inventory(root, dispositions={"stale:identity": decision})
            with self.assertRaises(ValueError):
                inventory(
                    root,
                    dispositions={identity: {"disposition": "intentionally_freeform"}},
                )


if __name__ == "__main__":
    unittest.main()
