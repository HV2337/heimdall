"""Rule and portable TF-IDF/logistic-regression threat detection."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from gateway.contracts import (
    ScannableText,
    ThreatAssessment,
    ThreatClassifier,
    ThreatError,
)

MODEL_FORMAT = "heimdall-tfidf-logreg-v1"


@dataclass(frozen=True)
class ThreatModel:
    vocabulary: Mapping[str, int]
    idf: tuple[float, ...]
    coefficients: tuple[float, ...]
    intercept: float
    threshold: float
    model_version: str


def tokenize(text: str) -> tuple[str, ...]:
    """Return lowercase sklearn-compatible word unigrams followed by bigrams."""
    words = re.findall(r"(?u)\b\w\w+\b", text.lower())
    return tuple(words + [f"{left} {right}" for left, right in zip(words, words[1:])])


_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:the\s+)?"
        r"(?:previous|prior|above|earlier)\s+(?:system\s+)?(?:instructions?|prompts?|directives?|rules?)\b", re.I)),
    ("role_jailbreak", re.compile(
        r"\b(?:you are now|act as|pretend to be|roleplay as)\s+(?:an?\s+)?"
        r"(?:unrestricted|unfiltered|uncensored|jailbroken|DAN|system administrator|developer mode)\b", re.I)),
    ("system_prompt_extraction", re.compile(
        r"\b(?:reveal|show|print|repeat|quote|display|output|divulge)\s+(?:me\s+)?"
        r"(?:the\s+)?(?:hidden\s+|original\s+|full\s+|internal\s+)?"
        r"(?:system prompt|system instructions|developer prompt|hidden prompt|"
        r"(?:gateway|system|internal) configuration|operating instructions)\b", re.I)),
    ("credential_request", re.compile(
        r"\b(?:show|reveal|retrieve|print|give|send|list|dump|exfiltrate|disclose|expose|provide|request)\s+(?:me\s+)?"
        r"(?:the\s+)?(?:passwords?|credentials?|api keys?|access tokens?|secret keys?)\b", re.I)),
    ("credential_disclosure_request", re.compile(
        r"(?is)(?=.*\b(?:reveal|show|give|print|tell|send|paste|provide|share|list)\b"
        r"(?:[\W_]+\w+){0,5}[\W_]+\b(?:passwords?|credentials?|api\s+keys?|"
        r"secrets?|tokens?|logins?)\b)"
        r"(?=.*(?:\b(?:database|system|service|admin|server|root|config|production)\b"
        r"(?:[\W_]+\w+){0,3}[\W_]+\b(?:passwords?|credentials?|api\s+keys?|"
        r"secrets?|tokens?|logins?)\b|"
        r"\b(?:passwords?|credentials?|api\s+keys?|secrets?|tokens?|logins?)\b"
        r"(?:[\W_]+\w+){0,3}[\W_]+\b(?:database|system|service|admin|server|root|config|production)\b)).+")),
    ("cross_user_data_request", re.compile(
        r"\b(?:show|retrieve|give|list|dump|export|reveal)\s+(?:me\s+)?"
        r"(?:all\s+|any\s+)?(?:other|different|all other)\s+(?:users|patients|customers)\b", re.I)),
    ("security_bypass", re.compile(
        r"\b(?:bypass|disable|turn off|deactivate|circumvent)\s+(?:the\s+)?"
        r"(?:security|safety|guardrails?|filters?|access controls?|authentication|authorization|privacy checks?|protections?)\b", re.I)),
    ("privileged_role_data_request", re.compile(
        r"(?is)(?=.*\b(?:i am|i'm|this is|acting as|as|on behalf of|the)\s+"
        r"(?:the\s+)?(?:hospital administrator|administrator|admin|internal auditor|"
        r"auditor|it staff|it administrator|manager|security officer|system administrator)\b)"
        r"(?=.*\b(?:credentials?|passwords?|api keys?|access tokens?|secret keys?|"
        r"bulk(?:\s+export|\s+data|\s+records?)?|"
        r"(?:complete|full|all|every|bulk)\s+(?:patient\s+)?(?:data|records?|charts?)"
        r"(?:\s+export)?|export\s+(?:all|every|bulk|complete|full)|"
        r"all\s+patients|every\s+patient|other\s+users?|other\s+patients?|"
        r"patients?\s+outside\s+(?:my|this|their)\s+(?:assignment|account|care)\b)).+")),
)


def _rule_code(text: str, encoded_sensitive_content: bool = False) -> str | None:
    if encoded_sensitive_content:
        return "encoded_sensitive_content"
    return next((code for code, pattern in _RULES if pattern.search(text)), None)


def _sigmoid(value: float) -> float:
    if value >= 0:
        exp_value = math.exp(-value)
        return 1.0 / (1.0 + exp_value)
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def _validate_model(model: ThreatModel) -> None:
    if not isinstance(model, ThreatModel):
        raise ValueError("invalid model")
    if not isinstance(model.vocabulary, Mapping) or not model.vocabulary:
        raise ValueError("invalid vocabulary")
    size = len(model.vocabulary)
    indices = list(model.vocabulary.values())
    if any(not isinstance(term, str) or not term for term in model.vocabulary):
        raise ValueError("invalid vocabulary term")
    if any(type(index) is not int for index in indices) or sorted(indices) != list(range(size)):
        raise ValueError("invalid vocabulary indices")
    if len(model.idf) != size or len(model.coefficients) != size:
        raise ValueError("invalid vector dimensions")
    numbers = (*model.idf, *model.coefficients, model.intercept, model.threshold)
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in numbers):
        raise ValueError("non-finite model value")
    if not 0.0 <= model.threshold <= 1.0:
        raise ValueError("invalid threshold")
    if not isinstance(model.model_version, str) or not model.model_version:
        raise ValueError("invalid model version")


def load_model(path: str) -> ThreatModel:
    """Load and validate the portable JSON model; pickle is never accepted."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != MODEL_FORMAT:
            raise ValueError("unsupported model format")
        vocabulary = raw["vocabulary"]
        if not isinstance(vocabulary, dict):
            raise ValueError("invalid vocabulary")
        model = ThreatModel(
            vocabulary=vocabulary,
            idf=tuple(raw["idf"]),
            coefficients=tuple(raw["coefficients"]),
            intercept=raw["intercept"],
            threshold=raw["threshold"],
            model_version=raw["model_version"],
        )
        _validate_model(model)
        return model
    except Exception:
        raise ThreatError("threat_model_invalid") from None


class RuleAndModelClassifier(ThreatClassifier):
    """Apply deterministic rules first, then portable sparse linear inference."""

    def __init__(self, model: ThreatModel) -> None:
        try:
            _validate_model(model)
            self.model = model
        except Exception:
            raise ThreatError("threat_model_invalid") from None

    def _probability(self, text: str) -> float:
        terms = tokenize(text)
        counts: dict[int, float] = {}
        for term in terms:
            index = self.model.vocabulary.get(term)
            if index is not None:
                counts[index] = counts.get(index, 0.0) + 1.0
        weighted = {index: count * self.model.idf[index]
                    for index, count in counts.items()}
        norm = math.sqrt(sum(value * value for value in weighted.values()))
        score = self.model.intercept
        if norm:
            score += sum((value / norm) * self.model.coefficients[index]
                         for index, value in weighted.items())
        return _sigmoid(score)

    def scan(self, texts: tuple[ScannableText, ...]) -> ThreatAssessment:
        try:
            if not isinstance(texts, tuple):
                raise ValueError("texts must be tuple")
            best_score = -1.0
            best_source: str | None = None
            best_rule: str | None = None
            best_blocked = False
            for item in texts:
                if item.source not in {"user_prompt", "retrieved_record"}:
                    raise ValueError("invalid source")
                normalized = item.text
                text = normalized.matching_text
                matched = _rule_code(text, normalized.encoded_sensitive_content)
                if matched is not None:
                    if 1.0 > best_score:
                        best_score = 1.0
                        best_source = item.source
                        best_rule = matched
                        best_blocked = True
                    continue
                probability = self._probability(text)
                if probability > best_score:
                    best_score = probability
                    best_source = item.source
                    best_blocked = probability >= self.model.threshold
                    best_rule = "classifier_threshold" if best_blocked else None
            if best_source is None:
                return ThreatAssessment(False, 0.0, None, None)
            return ThreatAssessment(best_blocked, best_score, best_source, best_rule)
        except ThreatError:
            raise
        except Exception:
            raise ThreatError("threat_scan_failed") from None
