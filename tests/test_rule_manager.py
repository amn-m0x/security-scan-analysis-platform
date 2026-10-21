"""Integration checks: the actual Java manager edits a temporary project only."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from expert_system import ExpertSystem


class RuleManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for folder in ("rules", "python", ".venv/bin"):
            (self.root / folder).mkdir(parents=True)
        (self.root / ".venv/bin/python").symlink_to(sys.executable)
        for name in ("rule_codec.py", "validate_rules.py"):
            shutil.copy2(ROOT / "python" / name, self.root / "python" / name)
        self.active = self.root / "rules/rules.yaml"
        shutil.copy2(ROOT / "rules/rules.yaml", self.active)
        self.before = self.active.read_bytes()
        classes = Path(os.environ.get("RULE_MANAGER_CLASSES", ROOT / "build/java")).resolve()
        if not (classes / "RuleManager.class").is_file():
            self.fail("Compile java/RuleManager.java into build/java before running tests")
        self.command = ["java", "-cp", str(classes), "RuleManager"]
        self.candidate = {
            "name": "Учебный RDP 'example'", "category": "lab_test", "risk_score": 8.5,
            "conditions": [{"field": "port", "operator": "eq", "value": 3389},
                           {"field": "state", "operator": "in", "value": ["open", "filtered"]}],
            "recommendations": ["Проверить доступ; использовать VPN."], "version": "1.0"
        }

    def invoke(self, *args, success=True):
        result = subprocess.run(self.command + list(args), cwd=self.root, capture_output=True, text=True, timeout=60)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def candidate_file(self, rule, name="candidate.yaml"):
        path = self.root / name
        path.write_text(yaml.safe_dump(rule, allow_unicode=True), encoding="utf-8")
        return str(path)

    def test_add_search_engine_and_restore(self):
        self.invoke("snapshot", "test-before")
        self.invoke("add", self.candidate_file(self.candidate))
        after = yaml.safe_load(self.active.read_text())
        before = yaml.safe_load(self.before)
        self.assertEqual(after["threshold"], before["threshold"])
        self.assertEqual(after["rules"][:-1], before["rules"])
        self.assertEqual(after["rules"][-1], self.candidate)
        found = yaml.safe_load(self.invoke("findByCategory", "lab_test").stdout)
        self.assertEqual(found["rules"], [self.candidate])
        empty = yaml.safe_load(self.invoke("findByCategory", "absent").stdout)
        self.assertEqual(empty["rules"], [])
        self.assertEqual(len(yaml.safe_load(self.invoke("listRules").stdout)["rules"]), len(after["rules"]))
        incident = ExpertSystem(self.active).evaluate([{"port": 3389, "state": "open"}])
        self.assertTrue(incident["detected"])
        self.assertEqual(incident["risk_score"], 8.5)
        self.assertEqual(incident["category"], "lab_test")
        self.assertEqual(len(list((self.root / "rules/backups").glob("before-add-*"))), 1)
        self.invoke("restore", "test-before")
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_invalid_and_duplicate_leave_active_unchanged(self):
        invalid = copy.deepcopy(self.candidate)
        invalid["conditions"] = []
        self.invoke("add", self.candidate_file(invalid), success=False)
        self.assertEqual(self.active.read_bytes(), self.before)
        self.invoke("add", self.candidate_file(self.candidate))
        saved = self.active.read_bytes()
        self.invoke("add", self.candidate_file(self.candidate), success=False)
        self.assertEqual(self.active.read_bytes(), saved)
        self.invoke("snapshot", "../escape", success=False)

    def test_concurrent_adds_do_not_lose_rules(self):
        other = copy.deepcopy(self.candidate)
        other["name"] = "Second independent rule"
        first = self.candidate_file(self.candidate, "first.yaml")
        second = self.candidate_file(other, "second.yaml")
        processes = [subprocess.Popen(self.command + ["add", file], cwd=self.root,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for file in (first, second)]
        for process in processes:
            output, error = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, output + error)
        names = [r["name"] for r in yaml.safe_load(self.active.read_text())["rules"]]
        self.assertIn(self.candidate["name"], names)
        self.assertIn(other["name"], names)


if __name__ == "__main__":
    unittest.main()
