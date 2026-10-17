"""Tests for deterministic evaluation probes and baseline interfaces."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from eval.baselines import detect_rules, mask_pii
from eval.gen_data import BASE_COUNTS, build_datasets, write_datasets


class EvaluationDataTests(unittest.TestCase):
    def test_same_seed_produces_identical_datasets(self) -> None:
        self.assertEqual(build_datasets(731), build_datasets(731))

    def test_default_files_reach_minimum_counts(self) -> None:
        datasets = build_datasets(731)
        for filename, minimum in BASE_COUNTS.items():
            with self.subTest(filename=filename):
                self.assertGreaterEqual(len(datasets[filename]), minimum)
        patients = {row["patient_id"] for row in datasets["role_boundary.jsonl"]}
        self.assertGreaterEqual(len(patients), 12)
        self.assertGreaterEqual(len(datasets["role_boundary.jsonl"]), 100)
        self.assertEqual(
            {row["obfuscation"] for row in datasets["injection_prompts.jsonl"]},
            {"plain", "obfuscated"},
        )

    def test_generated_spans_match_text_and_expected_decisions_exist(self) -> None:
        datasets = build_datasets(731)
        for filename, probes in datasets.items():
            with self.subTest(filename=filename):
                for probe in probes:
                    self.assertIn("expected_decision", probe)
                    self.assertIn(probe["expected_decision"], {"allow", "block"})
                    text = probe["text"]
                    for span in probe.get("ground_truth_spans", []):
                        self.assertEqual(text[span["start"]:span["end"]], span["text"])

    def test_jsonl_files_are_written_with_lf_endings(self) -> None:
        datasets = build_datasets(731)
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            written = write_datasets(directory, seed=731)
            self.assertEqual(written, datasets)
            for filename, expected_rows in datasets.items():
                data = (Path(directory) / filename).read_bytes()
                self.assertNotIn(b"\r", data)
                decoded = [json.loads(line) for line in data.decode("utf-8").splitlines()]
                self.assertEqual(decoded, expected_rows)

    def test_baselines_run_without_errors_on_every_probe(self) -> None:
        datasets = build_datasets(731)
        for filename, probes in datasets.items():
            for index, probe in enumerate(probes):
                with self.subTest(filename=filename, index=index):
                    mask_result = mask_pii(probe["text"])
                    rule_result = detect_rules(probe["text"])
                    self.assertIsInstance(mask_result.text, str)
                    self.assertIsInstance(mask_result.masked, tuple)
                    self.assertIsInstance(rule_result.blocked, bool)
                    self.assertTrue(rule_result.blocked == (rule_result.rule_code is not None))


if __name__ == "__main__":
    unittest.main()
