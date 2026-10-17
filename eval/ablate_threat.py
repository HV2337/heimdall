"""Compare M3 training mixes without changing the saved production artifact."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.threat_data import (
    Example, HAND_WRITTEN_HELD_OUT, generate_ablation_examples, generate_examples,
    split_train_validation_test_by_family,
)
from eval.train_threat import _choose_threshold, _metrics, load_external_examples
from gateway.normalize import normalize_text
from gateway.threat import _rule_code, tokenize


def _fit(train: tuple[Example, ...], validation: tuple[Example, ...]):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    vectorizer = TfidfVectorizer(
        analyzer=tokenize, lowercase=False, norm="l2", use_idf=True,
        smooth_idf=True, sublinear_tf=False,
    )
    matrix = vectorizer.fit_transform([item.text for item in train])
    classifier = LogisticRegression(
        random_state=2026, solver="liblinear", max_iter=1000, class_weight="balanced",
    )
    classifier.fit(matrix, [item.label for item in train])
    validation_matrix = vectorizer.transform([item.text for item in validation])
    scores = classifier.predict_proba(validation_matrix)[:, 1].tolist()
    threshold = _choose_threshold([item.label for item in validation], scores)
    return vectorizer, classifier, threshold


def _rule(text: str) -> int:
    normalized = normalize_text(text)
    return int(_rule_code(normalized.matching_text, normalized.encoded_sensitive_content) is not None)


def run() -> tuple[dict[str, object], list[str]]:
    generated = generate_examples()
    external_train = load_external_examples("train")
    external_test = load_external_examples("test")
    handwritten = tuple(Example(text, label, "hand_written") for text, label in HAND_WRITTEN_HELD_OUT)
    report: dict[str, object] = {}
    blocked_benign: list[str] = []

    for option in "ABCD":
        corpus = generated
        if option in "CD":
            corpus += generate_ablation_examples(option)
        gen_train, validation, gen_test = split_train_validation_test_by_family(corpus)
        external = external_train
        if option == "B":
            external = tuple(
                item for item in external_train
                if not (item.family == "external:jackhhao/jailbreak-classification" and item.label == 0)
            )
        vectorizer, classifier, threshold = _fit((*gen_train, *external), validation)
        if option == "D":
            candidate = {
                "format": "heimdall-tfidf-logreg-v1",
                "vocabulary": vectorizer.vocabulary_,
                "idf": vectorizer.idf_.tolist(),
                "coefficients": classifier.coef_[0].tolist(),
                "intercept": float(classifier.intercept_[0]),
                "threshold": float(threshold),
                "model_version": "heimdall-m3-ablation-D-2026-10-17",
            }
            (ROOT / "models" / "threat_model_candidate_D.json").write_text(
                json.dumps(candidate, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
            )
        sets = {
            "family_test": gen_test,
            "external_test": external_test,
            "hand_written": handwritten,
        }
        option_metrics: dict[str, object] = {"threshold": threshold, "sets": {}}
        for set_name, examples in sets.items():
            texts = [item.text for item in examples]
            labels = [item.label for item in examples]
            normalized = [normalize_text(text) for text in texts]
            rule_predictions = [_rule(text) for text in texts]
            scores = classifier.predict_proba(
                vectorizer.transform([item.matching_text for item in normalized])
            )[:, 1].tolist()
            classifier_predictions = [int(score >= threshold) for score in scores]
            combined = [int(rule or learned) for rule, learned in zip(rule_predictions, classifier_predictions)]
            layer_predictions = {
                "rules": rule_predictions,
                "classifier": classifier_predictions,
                "combined": combined,
            }
            option_metrics["sets"][set_name] = {
                layer: _metrics(labels, predictions)
                for layer, predictions in layer_predictions.items()
            }
            if set_name in {"family_test", "external_test", "hand_written"}:
                for index, (text, label, prediction) in enumerate(zip(texts, labels, combined)):
                    if label == 0 and prediction:
                        if set_name == "hand_written":
                            blocked_benign.append(f"{option} | {set_name} | case {index + 1} (text withheld)")
                        else:
                            blocked_benign.append(f"{option} | {set_name} | {text}")
        report[option] = option_metrics

    return report, blocked_benign


def main() -> None:
    report, blocked_benign = run()
    for option, result in report.items():
        print(f"Option {option} (threshold={result['threshold']:.6f})")
        for set_name, layers in result["sets"].items():
            for layer, metrics in layers.items():
                print(f"  {set_name}/{layer}: P={metrics['precision']:.4f} "
                      f"R={metrics['recall']:.4f} FPR={metrics['false_positive_rate']:.4f} "
                      f"(n={metrics['examples']})")
    blocked_path = ROOT / "models" / "threat_ablation_blocked_benign.txt"
    blocked_path.write_text("\n".join(blocked_benign) + ("\n" if blocked_benign else ""), encoding="utf-8")
    print(f"\nBlocked benign cases across all test sets: {len(blocked_benign)}")
    print(f"Complete list: {blocked_path.relative_to(ROOT).as_posix()}")
    print("Hand-written prompts are identified by case number; their text is not copied.")
    out_path = ROOT / "models" / "threat_ablation_metrics.json"
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\nAblation metrics saved: {out_path.relative_to(ROOT).as_posix()}")
    print("Saved production model unchanged; D candidate is separate.")


if __name__ == "__main__":
    main()
