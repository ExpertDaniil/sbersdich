from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from evaluation.scaffold_results import read_scaffold_result, summarize_run


class ScaffoldResultsTests(unittest.TestCase):
    def test_usage_and_root_status_are_recovered_without_regrading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs").mkdir()
            original = {"passed": 0, "total": 1, "model_requests": 0, "total_tokens": 0,
                        "tasks": [{"task": "sample", "passed": False, "agent_status": "active",
                                   "verifier_exit_code": 1}]}
            (root / "summary.json").write_text(json.dumps(original))
            (root / "logs/sample.stdout.log").write_text(json.dumps({
                "status": "failed", "state": {"hypotheses": [{"status": "active"}]},
                "metrics": {"model_usage": {"requests": 3, "input_tokens": 600,
                           "output_tokens": 70, "total_tokens": 670, "estimated_tokens": 0}},
            }))
            result = summarize_run(root)
            self.assertEqual(result["model_requests"], 3)
            self.assertEqual(result["total_tokens"], 670)
            self.assertEqual(result["tasks"][0]["agent_status"], "failed")
            self.assertFalse(result["tasks"][0]["passed"])
            self.assertEqual(result["passed"], 0)
            self.assertEqual(json.loads((root / "summary.json").read_text()), original)

    def test_missing_usage_is_not_reported_as_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stdout.log"
            path.write_text('{"status":"failed"}')
            with self.assertRaises(KeyError):
                read_scaffold_result(path)


if __name__ == "__main__":
    unittest.main()
