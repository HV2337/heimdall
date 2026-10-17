#!/usr/bin/env python3
"""Check one prompt against Heimdall's threat rules and trained model."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.contracts import ScannableText, ThreatError
from gateway.normalize import normalize_text
from gateway.threat import RuleAndModelClassifier, load_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a prompt with Heimdall's threat rules and model."
    )
    parser.add_argument(
        "prompt", nargs="?", help="prompt text; if omitted, read stdin"
    )
    args = parser.parse_args()
    prompt = args.prompt if args.prompt is not None else sys.stdin.read()
    if not prompt.strip():
        parser.error("provide prompt text as an argument or through stdin")

    try:
        model = load_model(str(ROOT / "models" / "threat_model.json"))
        assessment = RuleAndModelClassifier(model).scan(
            (
                ScannableText(
                    source="user_prompt",
                    record_id=None,
                    text=normalize_text(prompt),
                ),
            )
        )
    except ThreatError as exc:
        print(f"Threat check failed: {exc}", file=sys.stderr)
        return 2

    if assessment.blocked:
        layer = "classifier" if assessment.rule_code == "classifier_threshold" else "rules"
    else:
        layer = "none"
    print(f"blocked: {'yes' if assessment.blocked else 'no'}")
    print(f"score: {assessment.score:.6f}")
    print(f"rule_code: {assessment.rule_code or 'none'}")
    print(f"layer: {layer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
