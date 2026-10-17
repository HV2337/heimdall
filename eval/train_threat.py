"""Train the portable JSON TF-IDF/logistic-regression threat model."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.threat_data import HAND_WRITTEN_HELD_OUT, generate_examples, split_by_template_family
from gateway.threat import MODEL_FORMAT, tokenize


def _metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, float | int]:
    predictions = [int(score >= threshold) for score in scores]
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    benign = sum(label == 0 for label in labels)
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / benign if benign else 0.0,
        "examples": len(labels),
    }


def main() -> None:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:
        raise SystemExit("scikit-learn is required to train the threat model") from exc

    examples = generate_examples()
    train, family_test = split_by_template_family(examples)
    vectorizer = TfidfVectorizer(
        analyzer=tokenize, lowercase=False, norm="l2", use_idf=True,
        smooth_idf=True, sublinear_tf=False,
    )
    train_matrix = vectorizer.fit_transform([item.text for item in train])
    classifier = LogisticRegression(random_state=2026, solver="liblinear", max_iter=1000)
    classifier.fit(train_matrix, [item.label for item in train])

    family_scores = classifier.predict_proba(
        vectorizer.transform([item.text for item in family_test])
    )[:, 1].tolist()
    family_labels = [item.label for item in family_test]
    candidates = sorted(set(family_scores) | {1.0})
    acceptable = [threshold for threshold in candidates
                  if _metrics(family_labels, family_scores, threshold)["false_positive_rate"] <= 0.02]
    if not acceptable:
        raise SystemExit("no threshold satisfies the 2% false-positive-rate limit")
    threshold = max(
        acceptable,
        key=lambda value: (
            _metrics(family_labels, family_scores, value)["recall"],
            _metrics(family_labels, family_scores, value)["precision"],
            value,
        ),
    )

    hand_texts = [text for text, _ in HAND_WRITTEN_HELD_OUT]
    hand_labels = [label for _, label in HAND_WRITTEN_HELD_OUT]
    hand_scores = classifier.predict_proba(vectorizer.transform(hand_texts))[:, 1].tolist()
    model = {
        "format": MODEL_FORMAT,
        "vocabulary": vectorizer.vocabulary_,
        "idf": vectorizer.idf_.tolist(),
        "coefficients": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
        "threshold": float(threshold),
        "model_version": "heimdall-m3-2026-10-17",
    }
    model_path = ROOT / "models" / "threat_model.json"
    metrics_path = ROOT / "models" / "threat_metrics.json"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(model, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    metrics = {
        "format": MODEL_FORMAT,
        "threshold": float(threshold),
        "family_held_out": _metrics(family_labels, family_scores, threshold),
        "hand_written_held_out": _metrics(hand_labels, hand_scores, threshold),
        "training_examples": len(train),
        "family_test_examples": len(family_test),
        "hand_written_examples": len(HAND_WRITTEN_HELD_OUT),
        "train_families": sorted({item.family for item in train}),
        "test_families": sorted({item.family for item in family_test}),
    }
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Generated examples: {len(examples)}")
    print(f"Train/test by template family: {len(train)}/{len(family_test)}")
    print(f"Hand-written held-out examples: {len(HAND_WRITTEN_HELD_OUT)}")
    print(f"Threshold: {threshold:.12g}")
    for name in ("family_held_out", "hand_written_held_out"):
        result = metrics[name]
        print(f"{name}: precision={result['precision']:.4f} recall={result['recall']:.4f} "
              f"false_positive_rate={result['false_positive_rate']:.4f} "
              f"(n={result['examples']})")
    print(f"Saved model: {model_path.relative_to(ROOT).as_posix()}")
    print(f"Saved metrics: {metrics_path.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
