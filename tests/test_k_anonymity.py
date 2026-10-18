"""Tests for the synthetic k-anonymity summary."""

from __future__ import annotations

import unittest

from eval.k_anonymity import summarize_records


class KAnonymityTests(unittest.TestCase):
    def test_handmade_six_row_fixture_has_expected_k_and_distribution(self) -> None:
        rows = [
            {"age_band": "30-44"},
            {"age_band": "30-44"},
            {"age_band": "45-59"},
            {"age_band": "45-59"},
            {"age_band": "45-59"},
            {"age_band": "60-74"},
        ]
        result = summarize_records(rows, ("age_band",))
        self.assertEqual(result["record_count"], 6)
        self.assertEqual(result["equivalence_class_count"], 3)
        self.assertEqual(result["k"], 1)
        self.assertEqual(result["class_size_distribution"], {"1": 1, "2": 1, "3": 1})
        self.assertEqual(result["records_in_classes_smaller_than"]["2"], {
            "records": 1, "total": 6, "percentage": 100.0 / 6,
        })
        self.assertEqual(result["records_in_classes_smaller_than"]["3"]["records"], 3)
        self.assertEqual(result["records_in_classes_smaller_than"]["5"]["records"], 6)


if __name__ == "__main__":
    unittest.main()
