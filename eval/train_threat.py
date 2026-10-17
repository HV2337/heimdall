"""Train and evaluate the portable JSON TF-IDF/logistic-regression model."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.threat_data import (
    Example,
    HAND_WRITTEN_HELD_OUT,
    generate_examples,
    split_train_validation_test_by_family,
)
from gateway.normalize import normalize_text
from gateway.threat import MODEL_FORMAT, RuleAndModelClassifier, ThreatModel, _rule_code, tokenize

EXTERNAL_DIR = ROOT / "eval" / "data" / "external"
MODEL_PATH = ROOT / "models" / "threat_model.json"
METRICS_PATH = ROOT / "models" / "threat_metrics.json"


def load_external_examples(split: str) -> tuple[Example, ...]:
    """Read only the requested split from downloader-produced JSONL files."""
    if split not in {"train", "test"}:
        raise ValueError("only external train/test splits may be loaded")
    examples: list[Example] = []
    for path in sorted(EXTERNAL_DIR.glob(f"*_{split}.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("split") != split:
                continue
            text, label, source = row.get("text"), row.get("label"), row.get("source")
            if (isinstance(text, str) and text.strip() and type(label) is int
                    and label in (0, 1) and isinstance(source, str)):
                examples.append(Example(text, label, f"external:{source}"))
    if not examples:
        raise RuntimeError(f"no external {split} rows found; run eval/fetch_external_data.py")
    return tuple(examples)


def _predictions(labels: Sequence[int], scores: Sequence[float], threshold: float) -> list[int]:
    return [int(score >= threshold) for score in scores]


def _metrics(labels: Sequence[int], predictions: Sequence[int]) -> dict[str, float | int]:
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    benign = sum(label == 0 for label in labels)
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / benign if benign else 0.0,
        "examples": len(labels),
        "attacks": sum(label == 1 for label in labels),
        "benign": benign,
    }


def _choose_threshold(labels: Sequence[int], scores: Sequence[float]) -> float:
    candidates = sorted(set(scores) | {1.0})
    allowed = [threshold for threshold in candidates
               if _metrics(labels, _predictions(labels, scores, threshold))["false_positive_rate"] <= 0.02]
    if not allowed:
        raise RuntimeError("no validation threshold satisfies the 2% false-positive-rate limit")
    return max(allowed, key=lambda value: (
        _metrics(labels, _predictions(labels, scores, value))["recall"],
        _metrics(labels, _predictions(labels, scores, value))["precision"],
        value,
    ))


def _rule_predictions(texts: Sequence[str]) -> list[int]:
    results = []
    for text in texts:
        normalized = normalize_text(text)
        results.append(int(_rule_code(
            normalized.matching_text, normalized.encoded_sensitive_content
        ) is not None))
    return results


def _hand_written_cases(
    layer_predictions: dict[str, Sequence[int]],
) -> dict[str, list[dict[str, str]]]:
    misses: list[dict[str, str]] = []
    benign_blocks: list[dict[str, str]] = []
    for index, (text, label) in enumerate(HAND_WRITTEN_HELD_OUT):
        for layer, predictions in layer_predictions.items():
            prediction = predictions[index]
            if label == 1 and prediction == 0:
                misses.append({"text": text, "layer": layer})
            elif label == 0 and prediction == 1:
                benign_blocks.append({"text": text, "layer": layer})
    return {"missed_attacks": misses, "blocked_benign": benign_blocks}


def main() -> None:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:
        raise SystemExit("scikit-learn is required to train the threat model") from exc

    generated_train, generated_validation, generated_test = split_train_validation_test_by_family(
        generate_examples()
    )
    external_train = load_external_examples("train")
    external_test = load_external_examples("test")
    training_data = (*generated_train, *external_train)
    if {item.label for item in training_data} != {0, 1}:
        raise SystemExit("combined training data must include both classes")

    vectorizer = TfidfVectorizer(
        analyzer=tokenize, lowercase=False, norm="l2", use_idf=True,
        smooth_idf=True, sublinear_tf=False,
    )
    train_matrix = vectorizer.fit_transform([item.text for item in training_data])
    classifier = LogisticRegression(
        random_state=2026, solver="liblinear", max_iter=1000, class_weight="balanced"
    )
    classifier.fit(train_matrix, [item.label for item in training_data])

    validation_scores = classifier.predict_proba(
        vectorizer.transform([item.text for item in generated_validation])
    )[:, 1].tolist()
    threshold = _choose_threshold([item.label for item in generated_validation], validation_scores)

    model_json = {
        "format": MODEL_FORMAT,
        "vocabulary": vectorizer.vocabulary_,
        "idf": vectorizer.idf_.tolist(),
        "coefficients": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
        "threshold": float(threshold),
        "model_version": "heimdall-m3-2026-10-17",
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model_json, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    model = RuleAndModelClassifier(ThreatModel(
        vocabulary=model_json["vocabulary"], idf=tuple(model_json["idf"]),
        coefficients=tuple(model_json["coefficients"]), intercept=model_json["intercept"],
        threshold=model_json["threshold"], model_version=model_json["model_version"],
    ))

    datasets = {
        "generated_family_held_out": generated_test,
        "external_test": external_test,
        "hand_written": tuple(Example(text, label, "hand_written")
                              for text, label in HAND_WRITTEN_HELD_OUT),
    }
    metrics: dict[str, object] = {
        "format": MODEL_FORMAT,
        "threshold": float(threshold),
        "threshold_selection": {
            "source": "generated_validation_families_only",
            "false_positive_rate_limit": 0.02,
            "examples": len(generated_validation),
            "metrics": _metrics(
                [item.label for item in generated_validation],
                _predictions([item.label for item in generated_validation], validation_scores, threshold),
            ),
        },
        "training": {
            "generated_examples": len(generated_train),
            "external_train_examples": len(external_train),
            "external_train_by_source": dict(Counter(item.family.removeprefix("external:") for item in external_train)),
            "total_examples": len(training_data),
            "class_weight": "balanced",
            "generated_validation_examples": len(generated_validation),
        },
        "datasets": {},
    }

    for set_name, examples in datasets.items():
        texts = [item.text for item in examples]
        labels = [item.label for item in examples]
        normalized = [normalize_text(text) for text in texts]
        classifier_scores = [model._probability(item.matching_text) for item in normalized]
        classifier_predictions = [int(score >= threshold) for score in classifier_scores]
        rules_predictions = _rule_predictions(texts)
        combined_predictions = [int(rule or learned) for rule, learned
                               in zip(rules_predictions, classifier_predictions)]
        per_layer = {
            "rules_only": rules_predictions,
            "classifier_only": classifier_predictions,
            "combined": combined_predictions,
        }
        set_metrics = {
            layer: _metrics(labels, predictions)
            for layer, predictions in per_layer.items()
        }
        if set_name == "hand_written":
            metrics["hand_written_cases"] = _hand_written_cases(per_layer)
        metrics["datasets"][set_name] = set_metrics  # type: ignore[index]

    METRICS_PATH.write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Generated examples: {len(generate_examples())}")
    print(f"Generated train/validation/family-test: {len(generated_train)}/{len(generated_validation)}/{len(generated_test)}")
    print(f"External train/test: {len(external_train)}/{len(external_test)}")
    print(f"External training by source: {metrics['training']['external_train_by_source']}")  # type: ignore[index]
    print(f"Hand-written held-out examples: {len(HAND_WRITTEN_HELD_OUT)}")
    print(f"Validation-selected threshold: {threshold:.12g}")
    for set_name, by_layer in metrics["datasets"].items():  # type: ignore[union-attr]
        print(f"{set_name}:")
        for layer, result in by_layer.items():
            print(f"  {layer}: precision={result['precision']:.4f} recall={result['recall']:.4f} "
                  f"false_positive_rate={result['false_positive_rate']:.4f} (n={result['examples']})")
    hand_cases = metrics["hand_written_cases"]
    print(f"Hand-written missed attack/layer cases: {len(hand_cases['missed_attacks'])}")
    print(f"Hand-written blocked benign/layer cases: {len(hand_cases['blocked_benign'])}")
    print(f"Saved model: {MODEL_PATH.relative_to(ROOT).as_posix()}")
    print(f"Saved metrics: {METRICS_PATH.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
