"""Threat classification stage interfaces."""
from dataclasses import dataclass
from typing import Mapping
from gateway.contracts import ScannableText, ThreatAssessment, ThreatClassifier, ThreatError


@dataclass(frozen=True)
class ThreatModel:
    vocabulary: Mapping[str, int]
    idf: tuple[float, ...]
    coefficients: tuple[float, ...]
    intercept: float
    threshold: float
    model_version: str


class RuleAndModelClassifier(ThreatClassifier):
    def __init__(self, model: ThreatModel) -> None:
        raise NotImplementedError
    def scan(self, texts: tuple[ScannableText, ...]) -> ThreatAssessment:
        raise NotImplementedError


def load_model(path: str) -> ThreatModel:
    raise NotImplementedError
