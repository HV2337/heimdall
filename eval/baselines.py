"""Small standard-library PII and rules-only evaluation baselines."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from gateway.threat import _rule_code

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("API_KEY", re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9._~+/=-]{7,}[A-Za-z0-9]")),
    ("SECRET", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{7,}[A-Za-z0-9]")),
    ("FILE_PATH", re.compile(r"(?<!\w)(?:[A-Za-z]:[\\/](?:[^\s<>:\"|?*]+[\\/]?)*[A-Za-z0-9._-]*[A-Za-z0-9_-]|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]*[A-Za-z0-9_-])(?![A-Za-z0-9_-])")),
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+", re.I)),
    ("GOV_ID", re.compile(r"(?<![A-Za-z0-9])(?:\d{4}[ -]?){2}\d{4}(?![A-Za-z0-9])")),
    ("GOV_ID", re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")),
    ("PHONE", re.compile(r"(?<!\d)(?:\+91[ -]?|0[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")),
    ("PHONE", re.compile(r"(?<!\w)\+?\d[\d\s().-]{5,}\d(?!\w)")),
    ("IP_ADDRESS", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    ("IP_ADDRESS", re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{0,39}(?![\w:])")),
)


@dataclass(frozen=True)
class MaskedSpan:
    start: int
    end: int
    text: str
    token_type: str


@dataclass(frozen=True)
class MaskResult:
    text: str
    masked: tuple[MaskedSpan, ...]


@dataclass(frozen=True)
class RuleResult:
    blocked: bool
    rule_code: str | None


def mask_pii(text: str) -> MaskResult:
    """Mask detectable regex PII and return original matched spans."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    candidates: list[tuple[int, int, int, str]] = []
    for priority, (token_type, pattern) in enumerate(_PATTERNS):
        for match in pattern.finditer(text):
            value = match.group(0)
            if token_type == "IP_ADDRESS":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
            if token_type == "PHONE":
                digits = sum(character.isdigit() for character in value)
                if not 7 <= digits <= 15:
                    continue
            candidates.append((match.start(), match.end(), priority, token_type))
    candidates.sort(key=lambda item: (item[0], item[2], -(item[1] - item[0])))
    selected: list[MaskedSpan] = []
    cursor = -1
    for start, end, _, token_type in candidates:
        if start < cursor:
            continue
        selected.append(MaskedSpan(start, end, text[start:end], token_type))
        cursor = end
    pieces: list[str] = []
    cursor = 0
    for span in selected:
        pieces.extend((text[cursor:span.start], f"[{span.token_type}]")
                      )
        cursor = span.end
    pieces.append(text[cursor:])
    return MaskResult("".join(pieces), tuple(selected))


def detect_rules(text: str, *, encoded_sensitive_content: bool = False) -> RuleResult:
    """Return the first deterministic gateway keyword rule decision."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    rule_code = _rule_code(text, encoded_sensitive_content)
    return RuleResult(rule_code is not None, rule_code)
