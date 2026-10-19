"""Runner contract tests with simulated scanners; no network scans are performed."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location("live_scan", Path(__file__).parents[1] / "python/live_scan.py")
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class LiveScanTests(unittest.TestCase):
    def exercise(self, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "results").mkdir()
            (root / "results/lab-target-mac.txt").write_text("aa:bb:cc:dd:ee:ff")
            barrier = threading.Barrier(3)
            def command(args, log, timeout=360):
                log.write_text("simulated")
                if str(args[0]) in ("nmap", "masscan", "perl"):
                    barrier.wait(timeout=5)  # Fails if scanners run sequentially.
                    if fail and args[0] == "masscan":
                        raise RuntimeError("simulated permission failure")
                if any(str(arg).endswith("merge_scans.py") for arg in args):
                    (log.parent / "combined_scan.json").write_text("{}")
            response = MagicMock()
            response.__enter__.return_value.status = 200
            fake_report = {"target": "192.0.2.2", "findings": [], "incident": {"detected": False}}
            with patch.object(live, "ROOT", root), patch.object(live.shutil, "which", return_value="tool"), patch.object(Path, "is_file", return_value=True), patch.object(Path, "exists", return_value=True), patch.object(live, "urlopen", return_value=response), patch.object(live, "command", side_effect=command), patch.object(live.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(fake_report).encode(), b"")):
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "No complete assessment"):
                        live.run()
                else:
                    report = live.run()
                    self.assertEqual(report["target"], "192.0.2.2")
                    self.assertEqual(len(report["live_scan"]["scanners"]), 3)
            folders = list((root / "results").glob("live-*"))
            self.assertEqual(len(folders), 1)
            statuses = json.loads((folders[0] / "scanner_status.json").read_text())
            self.assertEqual(statuses["masscan"]["status"], "failed" if fail else "completed")
            self.assertEqual((folders[0] / "incident.json").is_file(), not fail)

    def test_concurrent_success(self):
        self.exercise()

    def test_failure_is_not_a_clean_result(self):
        self.exercise(fail=True)


if __name__ == "__main__":
    unittest.main()
