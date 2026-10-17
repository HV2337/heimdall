"""Independent prompt regression cases; never used for threshold selection."""

from __future__ import annotations

import unittest
from pathlib import Path

from gateway.contracts import ScannableText
from gateway.normalize import normalize_text
from gateway.threat import RuleAndModelClassifier, load_model


ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "scripts" / "regression_prompts.txt"
CANDIDATE = ROOT / "models" / "threat_model_candidate_D.json"


class PromptRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.classifier = RuleAndModelClassifier(load_model(str(CANDIDATE)))

    def test_eight_independent_prompts_match_expected_decisions(self) -> None:
        cases = []
        for line in PROMPTS.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            expected, prompt = line.split("\t", 1)
            cases.append((expected, prompt))
        self.assertEqual(len(cases), 8)
        for expected, prompt in cases:
            with self.subTest(expected=expected, prompt=prompt):
                item = ScannableText("user_prompt", None, normalize_text(prompt))
                result = self.classifier.scan((item,))
                self.assertEqual(result.blocked, expected == "block")


if __name__ == "__main__":
    unittest.main()
