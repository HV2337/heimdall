"""Measure k-anonymity before and after Stage 4 generalization."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "eval" / "results"
DEFAULT_TODAY = date(2026, 1, 15)

import sys

sys.path.insert(0, str(ROOT))

from data.seed_synthetic import seed
from gateway.contracts import GeneralizeTreatment
from gateway.data import PatientStore
from gateway.sanitize import _generalize, default_sanitization_policy


def summarize_records(records: Sequence[Mapping[str, Any]],
                      quasi_identifiers: Sequence[str]) -> dict[str, Any]:
    """Return equivalence-class sizes and small-class record counts."""
    fields = tuple(quasi_identifiers)
    if not fields:
        raise ValueError("at least one quasi-identifier is required")
    classes: Counter[tuple[str, ...]] = Counter()
    for row in records:
        try:
            key = tuple(str(row[field]) for field in fields)
        except KeyError as exc:
            raise ValueError(f"missing quasi-identifier field: {exc.args[0]}") from None
        classes[key] += 1
    sizes = list(classes.values())
    distribution = Counter(sizes)
    total = len(records)
    smaller = {}
    for threshold in (2, 3, 5):
        small_records = sum(size for size in sizes if size < threshold)
        smaller[str(threshold)] = {
            "records": small_records,
            "total": total,
            "percentage": 100.0 * small_records / total if total else 0.0,
        }
    return {
        "record_count": total,
        "equivalence_class_count": len(classes),
        "k": min(sizes) if sizes else 0,
        "class_size_distribution": {
            str(size): distribution[size] for size in sorted(distribution)
        },
        "records_in_classes_smaller_than": smaller,
    }


def build_report(count: int = 12, seed_value: int = 2026,
                 today: date = DEFAULT_TODAY) -> dict[str, Any]:
    """Seed patients and measure raw and Stage 4 generalized quasi-identifiers."""
    if count < 1:
        raise ValueError("count must be positive")
    policy = default_sanitization_policy(clinical_mode=False)
    generalized_fields = tuple(
        field for field, treatment in policy.field_treatments.items()
        if isinstance(treatment, GeneralizeTreatment)
    )
    with tempfile.TemporaryDirectory(prefix="heimdall-k-anon-", dir=ROOT) as directory:
        db_path = Path(directory) / "patients.sqlite3"
        seed(str(db_path), count=count, seed_value=seed_value)
        store = PatientStore(str(db_path))
        raw_rows = [store.get_patient("doctor", patient_id)
                    for patient_id in range(1, count + 1)]
    if any(row is None for row in raw_rows):
        raise RuntimeError("seeded patient record unavailable")
    records = [row for row in raw_rows if row is not None]
    generalized_rows = []
    for record in records:
        transformed = dict(record)
        for field in generalized_fields:
            treatment = policy.field_treatments[field]
            assert isinstance(treatment, GeneralizeTreatment)
            transformed[field] = _generalize(treatment.method, record[field], today)
        generalized_rows.append(transformed)

    generalized = summarize_records(generalized_rows, generalized_fields)
    raw = summarize_records(records, generalized_fields)
    return {
        "seed": seed_value,
        "today": today.isoformat(),
        "record_count": count,
        "quasi_identifiers": list(generalized_fields),
        "generalization_methods": {
            field: policy.field_treatments[field].method for field in generalized_fields
        },
        "generalized": generalized,
        "raw": raw,
        "low_k_threshold": 5,
        "generalized_k_is_low": generalized["k"] < 5,
    }


def _percentage(value: Mapping[str, Any]) -> str:
    return f"{value['percentage']:.1f}% ({value['records']}/{value['total']})"


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render measured counts and the explicit low-k assessment."""
    lines = [
        "# Synthetic dataset k-anonymity evaluation", "",
        f"Records: n={report['record_count']}; seed={report['seed']}; today={report['today']}.",
        "", "Quasi-identifiers used: " + ", ".join(f"`{item}`" for item in report["quasi_identifiers"]) + ".", "",
        "The generalized values are computed with the same Stage 4 methods used by the sanitizer:", "",
        "| Field | Stage 4 generalization |", "|---|---|",
    ]
    for field, method in report["generalization_methods"].items():
        lines.append(f"| `{field}` | `{method}` |")
    lines.extend(["", "| Dataset | Equivalence classes | Minimum class size (k) | Class-size distribution (size: number of classes) |",
                  "|---|---:|---:|---|"])
    for name in ("raw", "generalized"):
        values = report[name]
        distribution = ", ".join(
            f"{size}: {classes}" for size, classes in values["class_size_distribution"].items()
        ) or "none"
        lines.append(f"| {name} | {values['equivalence_class_count']} | {values['k']} | {distribution} |")
    lines.extend(["", "| Dataset | Records in classes smaller than k=2 | Smaller than k=3 | Smaller than k=5 |",
                  "|---|---:|---:|---:|"])
    for name in ("raw", "generalized"):
        values = report[name]["records_in_classes_smaller_than"]
        lines.append(f"| {name} | {_percentage(values['2'])} | {_percentage(values['3'])} | {_percentage(values['5'])} |")
    if report["generalized_k_is_low"]:
        lines.extend(["", f"Achieved generalized k is low: k={report['generalized']['k']}, below the report's stated low-k threshold of 5."])
    else:
        lines.extend(["", f"Achieved generalized k={report['generalized']['k']}; it is not low under this report's stated low-k threshold of 5."])
    lines.append("")
    return "\n".join(lines)


def write_report(report: Mapping[str, Any], output_dir: str | Path = RESULTS_DIR) -> tuple[Path, Path]:
    """Write the fixed-name Markdown and JSON k-anonymity reports."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    markdown_path = destination / "k-anonymity.md"
    json_path = destination / "k-anonymity.json"
    markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8", newline="\n")
    return markdown_path, json_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    report = build_report(count=args.count, seed_value=args.seed)
    markdown_path, json_path = write_report(report)
    print(f"Quasi-identifiers: {', '.join(report['quasi_identifiers'])}")
    for name in ("raw", "generalized"):
        item = report[name]
        print(f"{name}: n={item['record_count']}, classes={item['equivalence_class_count']}, "
              f"k={item['k']}, class_sizes={item['class_size_distribution']}")
        for threshold, values in item["records_in_classes_smaller_than"].items():
            print(f"  records in classes smaller than {threshold}: "
                  f"{values['records']}/{values['total']} ({values['percentage']:.1f}%)")
    if report["generalized_k_is_low"]:
        print(f"Achieved generalized k is low: k={report['generalized']['k']} (below 5).")
    else:
        print(f"Achieved generalized k={report['generalized']['k']} (not below 5).")
    print(f"Reports: {markdown_path} and {json_path}")


if __name__ == "__main__":
    main()
