from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secure_agent_runtime.config import PolicyConfig
from secure_agent_runtime.evaluation import load_corpus, run_evaluation, save_report
from secure_agent_runtime.policy import PolicyEngine


class EvaluationTests(unittest.TestCase):
    def test_repository_corpus_has_unique_cases(self) -> None:
        cases = load_corpus("evals/attack_corpus.jsonl")
        self.assertGreaterEqual(len(cases), 30)
        self.assertEqual(len(cases), len({case.case_id for case in cases}))

    def test_regression_metrics_are_computed(self) -> None:
        cases = load_corpus("evals/attack_corpus.jsonl")
        report = run_evaluation(PolicyEngine(PolicyConfig()), cases)
        self.assertEqual(report["cases"], len(cases))
        self.assertIn("attack_stop_rate", report["metrics"])

    def test_report_can_be_saved(self) -> None:
        cases = load_corpus("evals/attack_corpus.jsonl")
        report = run_evaluation(PolicyEngine(PolicyConfig()), cases)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            save_report(report, path)
            self.assertEqual(json.loads(path.read_text())["cases"], len(cases))

    def test_invalid_corpus_line_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("not json\n")
            with self.assertRaises(ValueError):
                load_corpus(path)


if __name__ == "__main__":
    unittest.main()
