"""Run the synthetic Heimdall evaluation and save timestamped reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from data.seed_synthetic import seed
from eval.baselines import detect_rules, mask_pii
from eval.gen_data import DATA_DIR, ROLE_FIELDS
from gateway.config import Settings
from gateway.contracts import PipelineRequest, RequestContext, ScannableText
from gateway.main import build_dependencies, run_pipeline
from gateway.normalize import normalize_text
from gateway.sanitize import sanitize_text

RESULTS_DIR = Path(__file__).resolve().parent / "results"
ROLE_NAMES = ("doctor", "nurse", "billing_clerk")
MARKER_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9]+\]")
CANARY_RE = re.compile(r"CANARY:\s*(HEIMDALL_CANARY_[A-Fa-f0-9]+)")
MISSED_FULL_IPV6 = (
    "eb8a:1321:df11:5aaa:5ec6:18b4:b6b8:6ac2",
    "8bce:6cd0:77e9:3bc1:dced:e855:5eb0:1065",
    "7601:72d8:d6a7:99a0:220a:6f17:5221:de0b",
)
OBFUSCATED_DESCRIPTIONS = {
    "base64_short_phone": "short phone; 15 non-padding chars, below 16-char decode minimum (known limitation)",
    "base64_email": "encoded email longer than 16 chars",
}
_REQUIRED_SECTIONS = (
    "PII detection", "Injection detection", "Unauthorized disclosure",
    "Output leakage", "Cross-session isolation", "End-to-end exposure after a missed injection",
    "IPv6 sanitizer check", "Corrections after first run", "Latency", "Answer utility",
    "Limitations of this evaluation",
)


class _MemoryAudit:
    """Capture per-request audit measurements without writing files."""

    def __init__(self) -> None:
        self.events = []

    def write(self, event, timeout_seconds: float) -> None:
        self.events.append(event)


class _ProbeOutputLLM:
    """Return one controlled synthetic output for output-scanner probes."""

    def __init__(self, answer: str | None = None, *, echo_canary: bool = False) -> None:
        self.answer = answer
        self.echo_canary = echo_canary

    def generate(self, prompt: str, timeout_seconds: float = 30.0) -> str:
        if self.echo_canary:
            match = CANARY_RE.search(prompt)
            return match.group(1) if match else "No canary was present."
        return self.answer or ""


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or not isinstance(value.get("text"), str):
                raise ValueError(f"invalid probe row in {path.name}:{line_number}")
            rows.append(value)
    return rows


def _load_datasets(data_dir: Path) -> dict[str, list[dict[str, Any]]]:
    names = (
        "pii_prompts.jsonl", "obfuscated_pii.jsonl", "benign_prompts.jsonl",
        "role_boundary.jsonl", "output_leaks.jsonl", "cross_session.jsonl",
        "injection_prompts.jsonl",
    )
    return {name: _load_jsonl(data_dir / name) for name in names}


def _ratio(numerator: int, denominator: int) -> str:
    """Format a measured ratio as a percentage and exact count pair."""
    if denominator == 0:
        return f"n/a [{numerator}/{denominator}]"
    percentage = 100.0 * numerator / denominator
    return f"{percentage:.1f}% [{numerator}/{denominator}]"


def _distinct_texts(rows: Iterable[Mapping[str, Any]]) -> int:
    return len({str(row.get("text", "")) for row in rows})


def _machine_name() -> str:
    """Return uname -m where available, with a Windows-compatible fallback."""
    return os.uname().machine if hasattr(os, "uname") else platform.machine() or "unknown"


def _span_count(row: Mapping[str, Any]) -> int:
    spans = row.get("ground_truth_spans", [])
    if not isinstance(spans, list):
        raise ValueError("ground_truth_spans must be a list")
    return len(spans)


def _pii_metrics(rows: list[dict[str, Any]], benign_rows: list[dict[str, Any]],
                 heimdall_predictions: list[int], baseline_predictions: list[int],
                 benign_heimdall: list[bool], benign_baseline: list[bool]) -> dict[str, Any]:
    expected = [_span_count(row) for row in rows]
    def summarize(predictions: list[int], negatives: list[bool]) -> dict[str, Any]:
        tp = sum(min(prediction, truth) for prediction, truth in zip(predictions, expected))
        fp = sum(max(0, prediction - truth) for prediction, truth in zip(predictions, expected))
        fn = sum(max(0, truth - prediction) for prediction, truth in zip(predictions, expected))
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": len(negatives) - sum(negatives),
            "n": sum(expected), "probe_n": len(rows), "negative_n": len(negatives),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "fpr": sum(negatives) / len(negatives) if negatives else None,
        }
    return {
        "heimdall": summarize(heimdall_predictions, benign_heimdall),
        "regex_proxy": summarize(baseline_predictions, benign_baseline),
    }


def _role_expected_answer(answer: str | None) -> dict[str, Any] | None:
    if not answer or not answer.startswith("Summary for the requested record(s): "):
        return None
    try:
        value = json.loads(answer.split(": ", 1)[1])
        return value[0] if isinstance(value, list) and value and isinstance(value[0], dict) else None
    except (ValueError, IndexError, TypeError):
        return None


def _run_ipv6_diagnostics(dependencies: Any) -> list[dict[str, str]]:
    """Run the three previously missed full IPv6 values alone and in sentences."""
    checks = []
    for index, value in enumerate(MISSED_FULL_IPV6):
        results = []
        for suffix, text in (("bare", value), ("sentence", f"IPv6 address: {value}.")):
            context = RequestContext(f"ipv6-check-{index}-{suffix}", "doctor-1", "doctor",
                                     f"ipv6-check-{index}-{suffix}")
            sanitized = sanitize_text(text, context, dependencies.vault,
                                      dependencies.token_ttl_seconds)
            count = int(sanitized.entity_counts.get("IP_ADDRESS", 0))
            results.append(("tokenized as IP_ADDRESS" if count == 1 else "not tokenized")
                           + ("; period preserved" if suffix == "sentence" and text.endswith(".")
                              and sanitized.text.endswith(".") else ""))
        checks.append({"value": value, "bare": results[0], "sentence": results[1]})
    return checks


def _metric_row(actual: list[bool], positives: list[bool], negatives: list[bool]) -> dict[str, Any]:
    tp = sum(prediction and expected for prediction, expected in zip(actual, positives))
    fp = sum(prediction and not expected for prediction, expected in zip(actual, positives))
    fn = sum((not prediction) and expected for prediction, expected in zip(actual, positives))
    tn = sum(not prediction for prediction in negatives)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "positive_n": len(positives), "negative_n": len(negatives),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "fpr": (len(negatives) - tn) / len(negatives) if negatives else None,
    }


def _metric_display(metric: Mapping[str, Any]) -> str:
    return (f"P {_ratio(metric['tp'], metric['tp'] + metric['fp'])}, "
            f"R {_ratio(metric['tp'], metric['tp'] + metric['fn'])}, "
            f"FPR {_ratio(metric['negative_n'] - metric['tn'], metric['negative_n'])}")


def _write_report(output_dir: Path, report: dict[str, Any], markdown: str,
                  *, final: bool = False) -> tuple[Path, Path, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"final-{stamp}" if final else stamp
    md_path = output_dir / f"{stem}.md"
    json_path = output_dir / f"{stem}.json"
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8", newline="\n")
    latest = None
    if final:
        latest = output_dir / "final-latest.md"
        latest.write_text(markdown, encoding="utf-8", newline="\n")
        (output_dir / "final-latest.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
    else:
        latest = output_dir / "latest.md"
        latest.write_text(markdown, encoding="utf-8", newline="\n")
        (output_dir / "latest.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
    return md_path, json_path, latest


def _render_report(report: Mapping[str, Any], misses: list[dict[str, Any]], *,
                   final_label: str | None = None) -> str:
    if final_label:
        final = report["final_threat"]
        lines = ["# Final threat evaluation", "", f"**{final_label}**", "",
                 f"Counts: total n={final['n']}; attack n={final['attack_n']}; benign n={final['benign_n']}.", "",
                 "| Layer | Precision | Recall | FPR |", "|---|---:|---:|---:|"]
        for layer in ("rules_only", "classifier_only", "combined"):
            metric = final["metrics"][layer]
            lines.append(f"| {layer} | {_ratio(metric['tp'], metric['tp'] + metric['fp'])} | "
                         f"{_ratio(metric['tp'], metric['tp'] + metric['fn'])} | "
                         f"{_ratio(metric['negative_n'] - metric['tn'], metric['negative_n'])} |")
        lines.extend(["", "| Text | Expected decision | Actual decision | Result | Layer | Score |",
                      "|---|---|---|---|---|---:|"])
        for item in final["prompts"]:
            text = item["text"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {text} | {item['expected']} | {item['actual']} | "
                         f"{'correct' if item['correct'] else 'wrong'} | "
                         f"{item['layer']} | {item['score']!r} |")
        misses = [item for item in final["prompts"] if not item["correct"]]
        lines.extend(["", "## Misses", ""])
        if misses:
            lines.extend(["| Text | Expected decision | Actual decision | Layer | Score |",
                          "|---|---|---|---|---:|"])
            for item in misses:
                text = item["text"].replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {text} | {item['expected']} | {item['actual']} | "
                             f"{item['layer']} | {item['score']!r} |")
        else:
            lines.append("None.")
        return "\n".join(lines) + "\n"
    machine_label = "Machine (`uname -m`; `platform.machine()` fallback on Windows)"
    sections = ["# Heimdall synthetic evaluation", "", f"{machine_label}: `{report['machine']}`; total pipeline requests: n={report['request_count']}.", ""]
    sections.extend(["## Probe inventory", "", "| File | n | Distinct probes |", "|---|---:|---:|"])
    for name, count in report["dataset_counts"].items():
        sections.append(f"| {name} | {count} | {report['distinct_counts'][name]['all']} |")
    sections.extend(["## PII detection", "", "Rates are percentages; counts are shown in brackets. A zero denominator is shown as n/a.", "",
                     "| Probe set | System | Precision | Recall | FPR |", "|---|---|---|---|---|"])
    for group_name, systems in report["pii"].items():
        for system_name, metric in systems.items():
            sections.append(
                f"| {group_name} | {system_name} | {_ratio(metric['tp'], metric['tp'] + metric['fp'])} | "
                f"{_ratio(metric['tp'], metric['tp'] + metric['fn'])} | "
                f"{_ratio(metric['negative_n'] - metric['tn'], metric['negative_n'])} |"
            )
    sections.extend(["", "Each obfuscated kind is one pattern repeated with different values. Split-email probes have empty ground-truth spans; excluded from recall and reported separately as a known limitation.", ""])
    sections.extend(["| Obfuscated kind | Description | n; distinct | Heimdall P / R / FPR | Regex proxy P / R / FPR |", "|---|---|---:|---|---|"])
    for kind, metrics in report["obfuscated_by_kind"].items():
        description = OBFUSCATED_DESCRIPTIONS.get(kind, "one pattern repeated with different values")
        sections.append(f"| {kind} | {description} | {metrics['heimdall']['probe_n']}; {report['distinct_counts']['obfuscated_pii.jsonl'][kind]} | {_metric_display(metrics['heimdall'])} | {_metric_display(metrics['regex_proxy'])} |")
    sections.append(f"| split_email (empty spans; excluded from recall) | empty spans | {report['split_email']['n']}; {report['distinct_counts']['obfuscated_pii.jsonl'].get('split_email', 0)} | Known limitation; no ground-truth span | Known limitation; no ground-truth span |")
    sections.extend(["", "### Plain PII false negatives", "", "| System | Kind | Expected span text |", "|---|---|---|"])
    for system in ("heimdall", "regex_proxy"):
        for miss in report["plain_pii_misses"][system]:
            escaped = miss["text"].replace("|", "\\|").replace("\n", " ")
            sections.append(f"| {system} | {miss['kind']} | `{escaped}` |")

    sections.extend(["", "### IPv6 sanitizer check", "",
                     "The three full-form values below were tried alone and in sentences ending with a period. Bare values sanitized; before the fix, sentence forms were missed because the candidate regex included the terminal period and address validation rejected the combined string. The scanner now trims trailing sentence punctuation before validation.",
                     "", "| IPv6 value | Bare | In sentence |", "|---|---|---|"])
    for check in report["ipv6_diagnostics"]:
        sections.append(f"| `{check['value']}` | {check['bare']} | {check['sentence']} |")

    sections.extend(["", "## Corrections after first run", "",
                     "1. Fixed PAN probe generation from 11 characters (5 letters, 5 digits, 1 letter) to valid 10-character PANs (5 letters, 4 digits, 1 letter). The original plain PII recall was 88.0% [132/150].",
                     "2. Split the original base64 kind into `base64_short_phone` and `base64_email`. The original base64 result was 0/10; the short phone pattern remains a known limitation because it is below the decoder's 16-character minimum, while email encodings are measured separately.", ""])

    sections.extend(["", "## Injection detection", "", 
                     f"Positive set: `injection_prompts.jsonl` (n={report['dataset_counts']['injection_prompts.jsonl']}, distinct={report['distinct_counts']['injection_prompts.jsonl']['all']}); "
                     f"negative set: `benign_prompts.jsonl` (n={report['dataset_counts']['benign_prompts.jsonl']}, distinct={report['distinct_counts']['benign_prompts.jsonl']['all']}).", "",
                     "| Detector | Precision | Recall | FPR |", "|---|---|---|---|"])
    for detector, metric in report["injection"].items():
        sections.append(f"| {detector} | {_ratio(metric['tp'], metric['tp'] + metric['fp'])} | "
                        f"{_ratio(metric['tp'], metric['tp'] + metric['fn'])} | "
                        f"{_ratio(metric['negative_n'] - metric['tn'], metric['negative_n'])} |")
    sections.extend(["", "## Unauthorized disclosure", "", "| Role | Rate | Queries |", "|---|---:|---:|"])
    for role, value in report["unauthorized_disclosure"].items():
        sections.append(f"| {role} | {_ratio(value['unauthorized'], value['n'])} | {value['n']}; {report['distinct_counts']['role_boundary.jsonl'].get(role, 0)} distinct |")
    sections.extend(["", "## Output leakage", "", f"Leak rate: {_ratio(report['output_leak']['leaks'], report['output_leak']['n'])}; n={report['output_leak']['n']}, distinct={report['distinct_counts']['output_leaks.jsonl']['all']}.", "",
                     "## Cross-session isolation", "", f"Attacks blocked as expected: {report['cross_session']['blocked_as_expected']}/{report['cross_session']['n']} ({_ratio(report['cross_session']['blocked_as_expected'], report['cross_session']['n'])}); attack success rate: {_ratio(report['cross_session']['attack_successes'], report['cross_session']['n'])}.", "",
                     "| Probe | Actual decision |", "|---|---|"])
    for item in report["cross_session"]["decisions"]:
        escaped = item["text"].replace("|", "\\|").replace("\n", " ")
        sections.append(f"| {escaped} | {item['actual']} |")
    sections.extend(["", "## End-to-end exposure after a missed injection", "",
                     f"Exposed runs: {_ratio(report['missed_injection_exposure']['exposed'], report['missed_injection_exposure']['runs'])}; "
                     f"missed injection prompts n={report['missed_injection_exposure']['prompt_n']}, distinct={report['missed_injection_exposure']['distinct_prompts']}; "
                     f"role-prompt runs n={report['missed_injection_exposure']['runs']}.",
                     "The LLM is a deterministic mock, so this measures the data boundary and not model behavior.", "",
                     "## Latency", "", f"{machine_label}: `{report['machine']}`; requests: n={report['request_count']}.", "",
                     "| Stage | p50 ms | p95 ms | n |", "|---|---:|---:|---:|"])
    for stage, values in report["latency_ms"].items():
        sections.append(f"| {stage} | {values['p50']:.2f} ms | {values['p95']:.2f} ms | {values['n']} |")
    sections.extend(["", "## Answer utility", "", "| Clinical mode | Expected-fact share |", "|---|---:|"])
    for mode, value in report["answer_utility"].items():
        sections.append(f"| {mode} | {_ratio(value['matched'], value['n'])} |")
    sections.extend(["", "## Heimdall misses", ""])
    if misses:
        sections.extend(["| Dataset | Kind | Expected | Actual | Text |", "|---|---|---|---|---|"])
        for item in misses:
            escaped = item["text"].replace("|", "\\|").replace("\n", " ")
            sections.append(f"| {item['dataset']} | {item.get('kind', 'unknown')} | {item['expected']} | {item['actual']} | {escaped} |")
        injection_misses = [item for item in misses if item["dataset"] == "injection_prompts.jsonl"]
        sections.extend(["", f"Injection misses: n={len(injection_misses)}, distinct={len({item['text'] for item in injection_misses})}."])
    else:
        sections.append("No decision misses in the evaluated decision-labeled probes.")
    sections.extend(["", "## Limitations of this evaluation", "",
                     "Probes are synthetic and made by the same team and tool as the system. The LLM is a deterministic mock. Some probe kinds are repeated patterns. The data is small.",
                     "The generated `base64_short_phone` values have 15 non-padding characters, below the normalizer's 16-character candidate minimum, so those encoded values are not decoded or flagged.", ""])
    return "\n".join(sections)


def run_evaluation(data_dir: str | Path = DATA_DIR,
                   output_dir: str | Path = RESULTS_DIR, *,
                   data_override: Mapping[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    """Run the synthetic evaluation and write timestamped Markdown and JSON."""
    datasets = dict(data_override) if data_override is not None else _load_datasets(Path(data_dir))
    required = ("pii_prompts.jsonl", "obfuscated_pii.jsonl", "benign_prompts.jsonl",
                "role_boundary.jsonl", "output_leaks.jsonl", "cross_session.jsonl",
                "injection_prompts.jsonl")
    if any(name not in datasets for name in required):
        raise ValueError("evaluation dataset is incomplete")

    stage_samples: dict[str, list[float]] = {}
    all_misses: list[dict[str, Any]] = []
    plain_pii_misses: dict[str, list[dict[str, str]]] = {"heimdall": [], "regex_proxy": []}
    audit = _MemoryAudit()
    request_count = 0

    with tempfile.TemporaryDirectory(dir=".") as temporary:
        db_path = Path(temporary) / "eval.sqlite3"
        seed(str(db_path), count=12, seed_value=2026)
        raw_keys = {role: secrets.token_urlsafe(32) for role in ROLE_NAMES}
        user_ids = {"doctor": "doctor-1", "nurse": "nurse-1", "billing_clerk": "billing-1"}
        configured = {
            key: {"user_id": user_ids[role], "role": role}
            for role, key in raw_keys.items()
        }
        hashed = {hashlib.sha256(key.encode("utf-8")).hexdigest():
                  (configured[key]["user_id"], configured[key]["role"])
                  for key in configured}
        settings = Settings(hashed, str(db_path), "mock", debug_trace=True,
                            vault_key=secrets.token_bytes(32))
        dependencies = replace(build_dependencies(settings), audit=audit)
        sessions: dict[str, str] = {}
        for role in ROLE_NAMES:
            sessions[role] = dependencies.sessions.create(
                user_ids[role], dependencies.session_ttl_seconds
            ).session_id

        def evaluate(prompt: str, *, role: str = "doctor", patient_ids: tuple[int, ...] = (),
                     llm: Any = None, clinical_mode: bool = False,
                     session_id: str | None = None) -> tuple[Any, Any, float]:
            nonlocal request_count
            chosen_deps = dependencies if llm is None and not clinical_mode else replace(
                dependencies,
                llm=dependencies.llm if llm is None else llm,
                clinical_mode=clinical_mode,
            )
            started = time.perf_counter()
            result = run_pipeline(PipelineRequest(
                raw_keys[role], session_id or sessions[role], prompt, patient_ids,
            ), chosen_deps)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            request_count += 1
            event = audit.events[-1]
            for stage, value in event.stage_latency_ms.items():
                stage_samples.setdefault(stage, []).append(value)
            stage_samples.setdefault("end_to_end", []).append(elapsed_ms)
            return result, event, elapsed_ms

        # PII prompts: use empty retrieval so audit entity counts describe only the prompt.
        pii_data = datasets["pii_prompts.jsonl"]
        benign_data = datasets["benign_prompts.jsonl"]
        pii_predictions: dict[str, list[int]] = {"heimdall": [], "regex_proxy": []}
        for row in pii_data:
            result, event, _ = evaluate(row["text"])
            truth = _span_count(row)
            tokens = sum(int(value) for value in event.entity_counts.values())
            encoded_hit = event.rule_code == "encoded_sensitive_content"
            detected = max(tokens, truth if encoded_hit else 0)
            pii_predictions["heimdall"].append(detected)
            regex_result = mask_pii(row["text"])
            pii_predictions["regex_proxy"].append(len(regex_result.masked))
            spans = row.get("ground_truth_spans", [])
            if not row.get("obfuscation"):
                for span in spans:
                    token_type = span.get("type")
                    span_text = span.get("text", "")
                    if tokens <= 0:
                        plain_pii_misses["heimdall"].append(
                            {"kind": row.get("kind", "unknown"), "text": span_text})
                    start, end = span.get("start"), span.get("end")
                    matched = any(candidate.start < end and candidate.end > start
                                  for candidate in regex_result.masked)
                    if not matched:
                        plain_pii_misses["regex_proxy"].append(
                            {"kind": row.get("kind", "unknown"), "text": span_text})
            expected = row.get("expected_decision", "allow")
            actual = "allow" if result.status_code == 200 else "block"
            if actual != expected:
                all_misses.append({"dataset": "pii_prompts.jsonl", "kind": row.get("kind"),
                                   "expected": expected, "actual": actual, "text": row["text"]})

        benign_pii_predictions: dict[str, list[bool]] = {"heimdall": [], "regex_proxy": []}
        for row in benign_data:
            result, event, _ = evaluate(row["text"])
            benign_pii_predictions["heimdall"].append(
                sum(int(value) for value in event.entity_counts.values()) > 0
            )
            benign_pii_predictions["regex_proxy"].append(bool(mask_pii(row["text"]).masked))
            expected = row.get("expected_decision", "allow")
            actual = "allow" if result.status_code == 200 else "block"
            if actual != expected:
                all_misses.append({"dataset": "benign_prompts.jsonl", "kind": row.get("kind"),
                                   "expected": expected, "actual": actual, "text": row["text"]})

        plain_pii = [row for row in pii_data if not row.get("obfuscation")]
        plain_pred_indices = [pii_data.index(row) for row in plain_pii]
        plain_group = _pii_metrics(
            plain_pii, benign_data,
            [pii_predictions["heimdall"][index] for index in plain_pred_indices],
            [pii_predictions["regex_proxy"][index] for index in plain_pred_indices],
            benign_pii_predictions["heimdall"], benign_pii_predictions["regex_proxy"],
        )
        obfuscated_rows = datasets["obfuscated_pii.jsonl"]
        obfuscated_rows = [row for row in obfuscated_rows if row.get("kind") != "split_email"]
        obfuscated_predictions: dict[str, list[int]] = {"heimdall": [], "regex_proxy": []}
        split_email = [row for row in datasets["obfuscated_pii.jsonl"] if row.get("kind") == "split_email"]
        for row in split_email:
            result, _, _ = evaluate(row["text"])
            actual = "allow" if result.status_code == 200 else "block"
            if actual != row.get("expected_decision", "allow"):
                all_misses.append({"dataset": "obfuscated_pii.jsonl", "kind": "split_email",
                                   "expected": row.get("expected_decision", "allow"),
                                   "actual": actual, "text": row["text"]})
        obfuscated_by_kind: dict[str, Any] = {}
        for row in obfuscated_rows:
            result, event, _ = evaluate(row["text"])
            truth = _span_count(row)
            tokens = sum(int(value) for value in event.entity_counts.values())
            encoded_hit = event.rule_code == "encoded_sensitive_content"
            obfuscated_predictions["heimdall"].append(max(tokens, truth if encoded_hit else 0))
            obfuscated_predictions["regex_proxy"].append(len(mask_pii(row["text"]).masked))
            if row.get("kind") not in obfuscated_by_kind:
                obfuscated_by_kind[row["kind"]] = {"rows": [], "heimdall": [], "regex_proxy": []}
            item = obfuscated_by_kind[row["kind"]]
            item["rows"].append(row)
            item["heimdall"].append(obfuscated_predictions["heimdall"][-1])
            item["regex_proxy"].append(obfuscated_predictions["regex_proxy"][-1])
            expected = row.get("expected_decision", "allow")
            actual = "allow" if result.status_code == 200 else "block"
            if actual != expected:
                all_misses.append({"dataset": "obfuscated_pii.jsonl", "kind": row.get("kind"),
                                   "expected": expected, "actual": actual, "text": row["text"]})
        obfuscated_group = _pii_metrics(
            obfuscated_rows, benign_data, obfuscated_predictions["heimdall"],
            obfuscated_predictions["regex_proxy"], benign_pii_predictions["heimdall"],
            benign_pii_predictions["regex_proxy"],
        )
        obfuscated_kind_metrics: dict[str, Any] = {}
        for kind, values in obfuscated_by_kind.items():
            obfuscated_kind_metrics[kind] = {
                "heimdall": _pii_metrics(values["rows"], benign_data, values["heimdall"],
                                           values["regex_proxy"], benign_pii_predictions["heimdall"],
                                           benign_pii_predictions["regex_proxy"])["heimdall"],
                "regex_proxy": _pii_metrics(values["rows"], benign_data, values["heimdall"],
                                             values["regex_proxy"], benign_pii_predictions["heimdall"],
                                             benign_pii_predictions["regex_proxy"])["regex_proxy"],
            }

        # Injection decisions: rules, pure classifier probability, and the combined pipeline.
        injection_rows = datasets["injection_prompts.jsonl"]
        positives = [row.get("expected_decision") == "block" for row in injection_rows]
        benign_prompts = datasets["benign_prompts.jsonl"]
        rule_positive = [detect_rules(row["text"]).blocked for row in injection_rows]
        classifier_positive = []
        combined_positive = []
        for row in injection_rows:
            normalized = normalize_text(row["text"])
            model_score = dependencies.classifier._probability(normalized.matching_text)
            classifier_positive.append(model_score >= dependencies.classifier.model.threshold)
            result, event, _ = evaluate(row["text"])
            combined_positive.append(result.status_code == 403 and event.blocking_stage == "threat")
            actual = "block" if combined_positive[-1] else "allow"
            if actual != row.get("expected_decision"):
                all_misses.append({"dataset": "injection_prompts.jsonl", "kind": row.get("kind", "injection"),
                                   "expected": row.get("expected_decision"), "actual": actual, "text": row["text"]})
        benign_rules, benign_classifier, benign_combined = [], [], []
        for row in benign_prompts:
            benign_rules.append(detect_rules(row["text"]).blocked)
            normalized = normalize_text(row["text"])
            benign_classifier.append(
                dependencies.classifier._probability(normalized.matching_text)
                >= dependencies.classifier.model.threshold
            )
            result, event, _ = evaluate(row["text"])
            benign_combined.append(result.status_code == 403 and event.blocking_stage == "threat")
        injection_metrics = {
            "rules_only": _metric_row(rule_positive, positives, benign_rules),
            "classifier_only": _metric_row(classifier_positive, positives, benign_classifier),
            "combined": _metric_row(combined_positive, positives, benign_combined),
        }

        classifier_missed = [row for row, blocked in zip(injection_rows, classifier_positive)
                             if not blocked]
        exposure_runs = 0
        exposure_count = 0
        target_patient = dependencies.patient_store.get_patient("doctor", 1, None) or {}
        target_values = {str(value) for value in target_patient.values()}
        other_patient_values = []
        for other_id in range(2, 13):
            other = dependencies.patient_store.get_patient("doctor", other_id, None)
            if other:
                other_patient_values.extend(
                    str(value) for value in other.values()
                    if value is not None and len(str(value)) >= 4 and str(value) not in target_values
                )
        for role in ROLE_NAMES:
            for row in classifier_missed:
                result, _, _ = evaluate(row["text"], role=role, patient_ids=(1,))
                exposure_runs += 1
                answer_record = _role_expected_answer(result.answer)
                exposed = False
                if result.status_code == 200:
                    if answer_record is None:
                        exposed = True
                    else:
                        exposed = bool(set(answer_record) - ROLE_FIELDS[role])
                        answer_text = result.answer or ""
                        exposed = exposed or any(value in answer_text for value in other_patient_values)
                exposure_count += int(exposed)

        # Role query IDs are synthetic labels; map each seeded fixture label to its corresponding DB row.
        role_rows = datasets["role_boundary.jsonl"]
        synthetic_patient_ids = sorted({row.get("patient_id") for row in role_rows if row.get("patient_id") is not None})
        seeded_patient_map = {identifier: index + 1 for index, identifier in enumerate(synthetic_patient_ids)}
        unauthorized = {role: {"unauthorized": 0, "n": 0} for role in ROLE_NAMES}
        for index, row in enumerate(role_rows):
            role = row.get("role", "doctor")
            if role not in ROLE_NAMES:
                continue
            actual_patient_id = seeded_patient_map.get(row.get("patient_id"), index % 12 + 1)
            result, _, _ = evaluate(row["text"], role=role, patient_ids=(actual_patient_id,))
            record = _role_expected_answer(result.answer)
            raw_record = dependencies.patient_store.get_patient("doctor", actual_patient_id, None)
            hidden_fields = row.get("expected_hidden_fields", [])
            leaked = result.status_code != 200 or record is None
            if not leaked:
                for field in hidden_fields:
                    if field in record:
                        leaked = True
                        break
                    raw_value = raw_record.get(field) if raw_record else None
                    if isinstance(raw_value, str) and len(raw_value) >= 4 and raw_value in result.answer:
                        leaked = True
                        break
            unauthorized[role]["n"] += 1
            unauthorized[role]["unauthorized"] += int(leaked)
            expected = "allow"
            actual = "allow" if result.status_code == 200 else "block"
            if actual != expected:
                all_misses.append({"dataset": "role_boundary.jsonl", "kind": "role_boundary",
                                   "expected": expected, "actual": actual, "text": row["text"]})
        unauthorized_metrics = {
            role: {**values, "rate": values["unauthorized"] / values["n"] if values["n"] else 0.0}
            for role, values in unauthorized.items()
        }

        # Drive the real pipeline output scanner with deterministic probe responses.
        output_rows = datasets["output_leaks.jsonl"]
        leak_count = 0
        for index, row in enumerate(output_rows):
            role = row.get("role", "doctor")
            if role not in ROLE_NAMES:
                role = "doctor"
            probe_text = row["text"]
            probe_llm: Any = _ProbeOutputLLM(probe_text)
            if row.get("kind") == "canary":
                probe_llm = _ProbeOutputLLM(echo_canary=True)
            session_id = dependencies.sessions.create(
                user_ids[role], dependencies.session_ttl_seconds
            ).session_id
            if row.get("kind") == "valid_disallowed_marker":
                context = RequestContext("eval-output", user_ids[role], role, session_id)
                marker = dependencies.vault.put(context, row.get("token_type", "DIAGNOSIS"),
                                                "synthetic diagnosis", dependencies.token_ttl_seconds)
                probe_llm = _ProbeOutputLLM(probe_text.replace("[DIAGNOSIS_1]", marker))
            result, _, _ = evaluate("Provide a brief synthetic summary.", role=role,
                                    llm=probe_llm, session_id=session_id)
            if row.get("expected_decision") == "block":
                successful = result.status_code == 403 and result.answer is None
            else:
                successful = result.status_code == 200 and "[REDACTED]" in (result.answer or "")
            leak_count += int(not successful)
            if not successful:
                all_misses.append({"dataset": "output_leaks.jsonl", "kind": row.get("kind"),
                                   "expected": "safe output",
                                   "actual": "unsafe output" if result.status_code == 200 else "blocked",
                                   "text": row["text"]})

        cross_rows = datasets["cross_session.jsonl"]
        cross_successes = 0
        cross_decisions = []
        for row in cross_rows:
            role = "doctor"
            source_session = dependencies.sessions.create(user_ids[role], dependencies.session_ttl_seconds).session_id
            target_session = dependencies.sessions.create(user_ids[role], dependencies.session_ttl_seconds).session_id
            source_context = RequestContext("eval-cross", user_ids[role], role, source_session)
            marker = dependencies.vault.put(source_context, "PATIENT_ID", "123456", dependencies.token_ttl_seconds)
            started = time.perf_counter()
            response = run_pipeline(PipelineRequest(raw_keys[role], target_session,
                                                    "Summarize the assigned record.", ()),
                                    replace(dependencies,
                                            llm=_ProbeOutputLLM(row["text"].replace("[PATIENT_ID_1]", marker))))
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            request_count += 1
            event = audit.events[-1]
            for stage, value in event.stage_latency_ms.items():
                stage_samples.setdefault(stage, []).append(value)
            stage_samples.setdefault("end_to_end", []).append(elapsed_ms)
            success = response.status_code == 403 and event.blocking_stage == "output_control"
            cross_successes += int(success)
            actual_decision = "blocked" if response.status_code == 403 else (
                "allowed" if response.status_code == 200 else f"status_{response.status_code}")
            cross_decisions.append({"text": row["text"], "actual": actual_decision})
            if not success:
                all_misses.append({"dataset": "cross_session.jsonl", "kind": row.get("kind"),
                                   "expected": "block", "actual": "allow" if response.status_code == 200 else "block",
                                   "text": row["text"]})

        # Utility uses scripted facts from the fresh deterministic seed, once per clinical mode.
        utility_patient = dependencies.patient_store.get_patient("doctor", 1, None)
        if utility_patient is None:
            raise RuntimeError("seeded utility patient is missing")
        utility_questions = (
            ("What diagnosis is recorded?", str(utility_patient["diagnosis"])),
            ("Which medication is listed?", str(utility_patient["meds"])),
            ("What are the recorded vitals?", str(utility_patient["vitals"])),
        )
        utility_metrics: dict[str, Any] = {}
        for clinical_mode in (False, True):
            matched = 0
            for question, expected_fact in utility_questions:
                result, _, _ = evaluate(question, role="doctor", patient_ids=(1,),
                                        clinical_mode=clinical_mode)
                matched += int(result.status_code == 200 and expected_fact in (result.answer or ""))
            key = "HEIMDALL_CLINICAL_MODE=1" if clinical_mode else "HEIMDALL_CLINICAL_MODE=0"
            utility_metrics[key] = {"matched": matched, "n": len(utility_questions),
                                    "share": matched / len(utility_questions)}

        latency_metrics = {}
        for stage, values in stage_samples.items():
            ordered = sorted(values)
            def percentile(fraction: float) -> float:
                if len(ordered) == 1:
                    return ordered[0]
                position = (len(ordered) - 1) * fraction
                lower = int(position)
                upper = min(lower + 1, len(ordered) - 1)
                weight = position - lower
                return ordered[lower] * (1.0 - weight) + ordered[upper] * weight
            latency_metrics[stage] = {"p50": percentile(0.50), "p95": percentile(0.95), "n": len(values)}

    report: dict[str, Any] = {
        "machine": _machine_name(),
        "request_count": request_count,
        "dataset_counts": {name: len(rows) for name, rows in datasets.items()},
        "distinct_counts": {
            name: {"all": _distinct_texts(rows), **{
                kind: _distinct_texts([row for row in rows if row.get("kind") == kind])
                for kind in sorted({str(row.get("kind", "unknown")) for row in rows})
            }, **({role: _distinct_texts([row for row in rows if row.get("role") == role])
                   for role in ROLE_NAMES} if name == "role_boundary.jsonl" else {})}
            for name, rows in datasets.items()
        },
        "plain_pii_misses": plain_pii_misses,
        "ipv6_diagnostics": _run_ipv6_diagnostics(dependencies),
        "pii": {"plain": plain_group, "obfuscated": obfuscated_group},
        "obfuscated_by_kind": obfuscated_kind_metrics,
        "split_email": {"n": len(split_email), "excluded_from_recall": True,
                        "limitation": "ground-truth spans are empty"},
        "injection": injection_metrics,
        "unauthorized_disclosure": unauthorized_metrics,
        "output_leak": {"leaks": leak_count, "n": len(output_rows),
                        "rate": leak_count / len(output_rows) if output_rows else 0.0},
        "cross_session": {"blocked_as_expected": cross_successes,
                          "attack_successes": len(cross_rows) - cross_successes,
                          "n": len(cross_rows), "decisions": cross_decisions},
        "missed_injection_exposure": {"exposed": exposure_count, "runs": exposure_runs,
                                       "prompt_n": len(classifier_missed),
                                       "distinct_prompts": _distinct_texts(classifier_missed)},
        "latency_ms": latency_metrics,
        "answer_utility": utility_metrics,
        "limitations": ["probes are synthetic and generated by the same team and tool as the system",
                        "LLM is a deterministic mock", "some probe kinds are repeated patterns", "data is small",
                        "generated base64 phones have 15 non-padding characters, below the normalizer's 16-character candidate minimum"],
        "misses": all_misses,
    }
    markdown = _render_report(report, all_misses)
    if any(section not in markdown for section in _REQUIRED_SECTIONS):
        raise RuntimeError("evaluation report is missing a required section")
    _write_report(Path(output_dir), report, markdown)
    return report


def _load_final_threat_file(path: Path) -> list[dict[str, str]]:
    """Load strict line-oriented ATTACK/BENIGN prompts with source line diagnostics."""
    rows: list[dict[str, str]] = []
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ValueError("final threat file must be UTF-8") from exc
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("ATTACK: "):
            label, text = "attack", line[len("ATTACK: "):].strip()
        elif line.startswith("BENIGN: "):
            label, text = "benign", line[len("BENIGN: "):].strip()
        else:
            raise ValueError(
                f"invalid final threat fixture at line {line_number}: expected 'ATTACK: <text>' or 'BENIGN: <text>'"
            )
        if not text:
            raise ValueError(f"invalid final threat fixture at line {line_number}: prompt text is empty")
        rows.append({"text": text, "label": label})
    if not rows:
        raise ValueError("final threat fixture contains no prompts")
    return rows


def evaluate_final_threat_file(path: str | Path, output_dir: str | Path = RESULTS_DIR,
                               *, force: bool = False) -> dict[str, Any]:
    """Evaluate the supplied final prompts once and save a separate final report."""
    source = Path(path)
    destination = Path(output_dir)
    if (destination / "final-latest.md").exists() and not force:
        raise FileExistsError("final-latest.md already exists; pass --force to overwrite it")
    # A single read; the protected fixture is handled only by the program when explicitly invoked.
    rows = _load_final_threat_file(source)
    with tempfile.TemporaryDirectory(dir=".") as temporary:
        db_path = Path(temporary) / "final-eval.sqlite3"
        seed(str(db_path), count=12, seed_value=2026)
        raw_key = secrets.token_urlsafe(32)
        user_id = "doctor-1"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        settings = Settings({key_hash: (user_id, "doctor")}, str(db_path), "mock",
                            debug_trace=True, vault_key=secrets.token_bytes(32))
        audit = _MemoryAudit()
        dependencies = replace(build_dependencies(settings), audit=audit)
        session_id = dependencies.sessions.create(user_id, dependencies.session_ttl_seconds).session_id
        expected = [row["label"] == "attack" for row in rows]
        rules_predictions: list[bool] = []
        classifier_predictions: list[bool] = []
        combined_predictions: list[bool] = []
        prompt_details: list[dict[str, Any]] = []
        for row, expected_attack in zip(rows, expected):
            normalized = normalize_text(row["text"])
            rules_result = detect_rules(
                normalized.matching_text,
                encoded_sensitive_content=normalized.encoded_sensitive_content,
            )
            score = dependencies.classifier._probability(normalized.matching_text)
            classifier_blocked = score >= dependencies.classifier.model.threshold
            result = run_pipeline(PipelineRequest(raw_key, session_id, row["text"], ()), dependencies)
            event = audit.events[-1]
            combined_blocked = result.status_code == 403 and event.blocking_stage == "threat"
            rules_predictions.append(rules_result.blocked)
            classifier_predictions.append(classifier_blocked)
            combined_predictions.append(combined_blocked)
            if rules_result.blocked:
                layer = f"rules:{rules_result.rule_code}"
                combined_score = 1.0
            elif classifier_blocked:
                layer = "classifier:classifier_threshold"
                combined_score = score
            else:
                layer = "allow"
                combined_score = score
            prompt_details.append({
                "text": row["text"],
                "expected": "block" if expected_attack else "allow",
                "actual": "block" if combined_blocked else "allow",
                "correct": ("block" if combined_blocked else "allow")
                           == ("block" if expected_attack else "allow"),
                "layer": layer,
                "score": combined_score,
            })
        benign_labels = [not label for label in expected]
        metrics = {
            "rules_only": _metric_row(rules_predictions, expected, [p for p, b in zip(rules_predictions, benign_labels) if b]),
            "classifier_only": _metric_row(classifier_predictions, expected, [p for p, b in zip(classifier_predictions, benign_labels) if b]),
            "combined": _metric_row(combined_predictions, expected, [p for p, b in zip(combined_predictions, benign_labels) if b]),
        }
    report = {
        "final_threat": {
            "n": len(rows),
            "attack_n": sum(expected),
            "benign_n": len(expected) - sum(expected),
            "metrics": metrics,
            "prompts": prompt_details,
        },
        "source_name": source.name,
    }
    label = (f"final held-out set, n={len(rows)}, written by a separate AI chat assistant "
             "(not the coding assistant) and not used for tuning. The file has been committed "
             "in the repository since M3 and the coding assistant was instructed not to open it. "
             "The set is small and two attack styles are similar to the development prompts.")
    markdown = _render_report(report, [], final_label=label)
    _write_report(destination, report, markdown, final=True)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--final-threat-file", type=Path)
    parser.add_argument("--force", action="store_true", help="overwrite final-latest.md for final evaluation")
    args = parser.parse_args()
    if args.final_threat_file:
        report = evaluate_final_threat_file(args.final_threat_file, args.output_dir, force=args.force)
        metric = report["final_threat"]
        print(f"final threat set: n={metric['n']} (attack={metric['attack_n']}, benign={metric['benign_n']})")
        for layer, values in metric["metrics"].items():
            print(f"{layer}: P={_ratio(values['tp'], values['tp'] + values['fp'])}, "
                  f"R={_ratio(values['tp'], values['tp'] + values['fn'])}, "
                  f"FPR={_ratio(values['negative_n'] - values['tn'], values['negative_n'])}")
        print(f"results: {args.output_dir / 'final-latest.md'}")
        return
    report = run_evaluation(args.data_dir, args.output_dir)
    for name, count in report["dataset_counts"].items():
        print(f"{name}: n={count}, distinct={report['distinct_counts'][name]['all']}")
    print(f"requests recorded: {report['request_count']} on {report['machine']}")
    print(f"results: {args.output_dir / 'latest.md'} and latest.json")
    print("Heimdall misses:")
    if not report["misses"]:
        print("none")
    for miss in report["misses"]:
        print(f"{miss['dataset']} | {miss.get('kind')} | expected={miss['expected']} "
              f"actual={miss['actual']} | {miss['text']}")


if __name__ == "__main__":
    main()
