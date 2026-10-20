#!/usr/bin/env python3
"""Coverage controls for the all-source log inventory."""
import subprocess
import tempfile
from pathlib import Path
import unittest
from inventory import inventory


class InventoryTest(unittest.TestCase):
    def test_all_scopes_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            for path, source in {
                'src/a.cpp': '// Unicode before call: …\nLogPrintf("x=%d", n); // LogInfo("not a call");\n',
                'chronik/bridge.cpp': 'LogInfo("ready");\n',
                'src/test/a.cpp': 'LogEvent(NET, "ready");\n',
                'chronik/test/bridge.cpp': 'logger.LogPrintStr("barrier");\n',
                'src/wallet.cpp': 'wallet->WalletLogPrintf("balance=%d", n);\n',
                'seeder/a.cpp': 'LogPrintLevel_(ALL, Info, false, "ready");\n',
            }.items():
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(source)
            subprocess.run(['git', '-C', directory, 'add', '.'], check=True)
            subprocess.run(['git', '-C', directory, '-c', 'user.name=Fixture', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm',
                            'fixture'], check=True)
            report = inventory(root)
            self.assertEqual(report['counts'], {'deferred': 5, 'already_structured': 1})
            self.assertEqual(len(report['sites']), 6)
            self.assertEqual(next(s for s in report['sites'] if s['path'] == 'chronik/test/bridge.cpp')['scope'], 'test_or_benchmark')
            self.assertEqual(next(s for s in report['sites'] if s['path'] == 'chronik/bridge.cpp')['scope'], 'production')
            self.assertEqual(next(s for s in report['sites'] if s['path'] == 'src/a.cpp')['line'], 2)
            self.assertEqual(report, inventory(root))


if __name__ == '__main__':
    unittest.main()
