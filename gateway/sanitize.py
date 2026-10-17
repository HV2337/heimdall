"""PII scanning, tokenization, and irreversible patient-field generalization."""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from datetime import date, datetime, timezone
from typing import Mapping

from gateway.config import WARD_TO_DEPARTMENT
from gateway.contracts import (
    FieldTreatment,
    GeneralizeTreatment,
    PassthroughTreatment,
    RequestContext,
    SanitizationPolicy,
    SanitizedRecord,
    SanitizedText,
    SanitizeError,
    TokenType,
    TokenVault,
    TokenizeTreatment,
    VaultError,
)
from gateway.policy import ROLE_FIELDS

_MARKER_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9]+\]")
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+", re.I)
_API_KEY_RE = re.compile(
    r"(?i)(?:\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}"
    r"|\bsk-[A-Za-z0-9_-]{12,}|\bAKIA[0-9A-Z]{16}\b)"
)
_SECRET_RE = re.compile(
    r"(?i)(?:\b(?:bearer|token|access[_-]?token|secret)\s*[:=]?\s*[A-Za-z0-9._~+/=-]{8,}"
    r"|\bpassword\s*[:=]\s*\S+|\b[0-9a-f]{32,}\b"
    r"|\b[A-Za-z0-9+/_-]{32,}={0,2}\b)"
)
_PATH_RE = re.compile(r"(?<!\w)(?:[A-Za-z]:[\\/](?:[^\s<>:\"|?*]+[\\/]?)+|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+)")
_SSN_RE = re.compile(r"(?<![A-Za-z0-9])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9])")
_AADHAAR_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d{4}[ -]?){2}\d{4}(?![A-Za-z0-9])")
_PAN_RE = re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
_IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{0,39}(?![\w:])")
_PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{5,}\d(?!\w)")
_INDIAN_MOBILE_RE = re.compile(
    r"(?<!\d)(?:\+91[ -]?|0[ -]?)?[6-9]\d{2}[ -]?\d{3}[ -]?\d{4}(?!\d)|"
    r"(?<!\d)(?:\+91[ -]?|0[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)"
)
_LONG_RANDOM_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9])")

_TOKEN_SCAN_ORDER = (
    ("SECRET", _SECRET_RE),
    ("API_KEY", _API_KEY_RE),
    ("FILE_PATH", _PATH_RE),
    ("EMAIL", _EMAIL_RE),
    ("GOV_ID", _SSN_RE),
    ("GOV_ID", _AADHAAR_RE),
    ("GOV_ID", _PAN_RE),
    ("SECRET", _LONG_RANDOM_RE),
)


def _clean_and_neutralize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    clean = "".join(char for char in normalized if unicodedata.category(char) != "Cf")
    return _MARKER_RE.sub(lambda match: f"［{match.group(0)[1:-1]}］", clean)


def _validated_ip_matches(text: str) -> list[tuple[int, int, TokenType]]:
    found: list[tuple[int, int, TokenType]] = []
    for pattern in (_IPV4_CANDIDATE_RE, _IPV6_CANDIDATE_RE):
        for match in pattern.finditer(text):
            try:
                ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            found.append((match.start(), match.end(), "IP_ADDRESS"))
    return found


def _sensitive_spans(text: str, known_names: tuple[str, ...] = ()) -> list[tuple[int, int, TokenType]]:
    """Locate sanitizer token candidates, ordered to prefer specific patterns."""
    candidates: list[tuple[int, int, int, TokenType]] = []
    priority = 0
    for token_type, pattern in _TOKEN_SCAN_ORDER:
        for match in pattern.finditer(text):
            candidates.append((match.start(), match.end(), priority, token_type))
        priority += 1
    for start, end, token_type in _validated_ip_matches(text):
        candidates.append((start, end, priority, token_type))
    priority += 1
    phone_matches = list(_INDIAN_MOBILE_RE.finditer(text)) + list(_PHONE_RE.finditer(text))
    for match in phone_matches:
        digits = sum(char.isdigit() for char in match.group(0))
        date_like = re.fullmatch(r"(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{2,4})", match.group(0).strip())
        if 7 <= digits <= 15 and date_like is None:
            candidates.append((match.start(), match.end(), priority, "PHONE"))
    priority += 1
    normalized_names = {
        _clean_and_neutralize(name).strip()
        for name in known_names if isinstance(name, str) and name.strip()
    }
    for name in sorted(normalized_names,
                       key=lambda item: len(item), reverse=True):
        pattern = re.compile(r"(?<!\w)" + re.escape(name) + r"(?!\w)", re.I)
        for match in pattern.finditer(text):
            candidates.append((match.start(), match.end(), priority, "PERSON"))

    candidates.sort(key=lambda item: (item[0], item[2], -(item[1] - item[0])))
    selected: list[tuple[int, int, TokenType]] = []
    cursor = -1
    for start, end, _, token_type in candidates:
        if start < cursor:
            continue
        selected.append((start, end, token_type))
        cursor = end
    return selected


def contains_tokenizable_content(text: str, *, known_names: tuple[str, ...] = ()) -> bool:
    """Return whether normalized text contains a span the sanitizer tokenizes."""
    if not isinstance(text, str):
        return False
    try:
        return bool(_sensitive_spans(_clean_and_neutralize(text), known_names))
    except Exception:
        # Normalization faults are fail-closed for the caller that uses this flag.
        return True


def _scan_and_replace(text: str, context: RequestContext, vault: TokenVault,
                      ttl_seconds: int, known_names: tuple[str, ...]
                      ) -> tuple[str, Counter[TokenType], list[tuple[int, int, TokenType]]]:
    spans = _sensitive_spans(text, known_names)
    counts: Counter[TokenType] = Counter()
    pieces: list[str] = []
    cursor = 0
    for start, end, token_type in spans:
        pieces.append(text[cursor:start])
        marker = vault.put(context, token_type, text[start:end], ttl_seconds)
        pieces.append(marker)
        counts[token_type] += 1
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), counts, spans


def sanitize_text(text: str, context: RequestContext, vault: TokenVault,
                  ttl_seconds: int, *, known_names: tuple[str, ...] = ()) -> SanitizedText:
    """Normalize, neutralize caller markers, and tokenize sensitive spans."""
    try:
        if not isinstance(text, str):
            raise SanitizeError("invalid_text")
        clean_text = _clean_and_neutralize(text)
        sanitized, counts, _ = _scan_and_replace(clean_text, context, vault,
                                                  ttl_seconds, known_names)
        return SanitizedText(sanitized, dict(counts))
    except VaultError:
        raise
    except SanitizeError:
        raise
    except Exception:
        raise SanitizeError("sanitize_text_failed") from None


def default_sanitization_policy(clinical_mode: bool = False) -> SanitizationPolicy:
    """Build the contract field treatments for the selected clinical mode."""
    treatments: dict[str, FieldTreatment] = {
        "id": TokenizeTreatment("PATIENT_ID"),
        "name": TokenizeTreatment("PERSON"),
        "phone": TokenizeTreatment("PHONE"),
        "dob": GeneralizeTreatment("age_band"),
        "ward": GeneralizeTreatment("department"),
        "diagnosis": (TokenizeTreatment("DIAGNOSIS") if clinical_mode
                      else PassthroughTreatment()),
        "vitals": (TokenizeTreatment("VITAL") if clinical_mode
                   else GeneralizeTreatment("vital_ranges")),
        "meds": (TokenizeTreatment("MEDICATION") if clinical_mode
                 else PassthroughTreatment()),
        "billing_amount": GeneralizeTreatment("billing_range"),
        "notes": TokenizeTreatment("NOTE") if clinical_mode else PassthroughTreatment(),
        "created_at": GeneralizeTreatment("calendar_month"),
    }
    return SanitizationPolicy(dict(ROLE_FIELDS), treatments)


def _as_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise SanitizeError("unsafe_numeric_value")
        return str(value)
    raise SanitizeError("unsafe_field_value")


def _generalize(method: str, value: object, today: date) -> str:
    raw = _as_text(value).strip()
    if method == "age_band":
        try:
            born = date.fromisoformat(raw)
            age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
            if age < 0:
                raise ValueError
        except ValueError:
            raise SanitizeError("invalid_date_of_birth") from None
        if age <= 17:
            return "0–17"
        if age <= 29:
            return "18–29"
        if age <= 44:
            return "30–44"
        if age <= 59:
            return "45–59"
        if age <= 74:
            return "60–74"
        return "75+"
    if method == "department":
        return WARD_TO_DEPARTMENT.get(raw, "Other")
    if method == "billing_range":
        try:
            amount = float(raw)
            if not math.isfinite(amount) or amount < 0:
                raise ValueError
        except ValueError:
            raise SanitizeError("invalid_billing_amount") from None
        if amount < 1000:
            return "[0,999]"
        if amount < 5000:
            return "[1000,4999]"
        if amount < 10000:
            return "[5000,9999]"
        if amount < 25000:
            return "[10000,24999]"
        return "[25000+]"
    if method == "calendar_month":
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return stamp.strftime("%Y-%m")
        except ValueError:
            try:
                return date.fromisoformat(raw).strftime("%Y-%m")
            except ValueError:
                raise SanitizeError("invalid_timestamp") from None
    if method == "vital_ranges":
        match = re.search(
            r"(?i)\b(?:bp\s*)?(\d{2,3})\s*/\s*(\d{2,3})\b.*?\bpulse\s*[:=]?\s*(\d{2,3})\b",
            raw,
        )
        if match is None:
            raise SanitizeError("invalid_vitals")
        systolic, diastolic, pulse = (int(part) for part in match.groups())
        if not (40 <= systolic <= 300 and 20 <= diastolic <= 200 and 20 <= pulse <= 300):
            raise SanitizeError("invalid_vitals")
        systolic_band = "<90" if systolic < 90 else "90–119" if systolic < 120 else "120–139" if systolic < 140 else "140+"
        diastolic_band = "<60" if diastolic < 60 else "60–79" if diastolic < 80 else "80–89" if diastolic < 90 else "90+"
        pulse_band = "<50" if pulse < 50 else "50–59" if pulse < 60 else "60–99" if pulse < 100 else "100+"
        return f"systolic {systolic_band}; diastolic {diastolic_band}; pulse {pulse_band}"
    raise SanitizeError("unknown_generalization")


def _clinical_field_text(text: str, token_type: TokenType, context: RequestContext,
                         vault: TokenVault, ttl_seconds: int,
                         known_names: tuple[str, ...]) -> tuple[str, Counter[TokenType]]:
    spans = _sensitive_spans(text, known_names)
    counts: Counter[TokenType] = Counter()
    pieces: list[str] = []
    cursor = 0
    for start, end, detected_type in spans:
        safe_span = text[cursor:start]
        if safe_span:
            pieces.append(vault.put(context, token_type, safe_span, ttl_seconds))
            counts[token_type] += 1
        marker = vault.put(context, detected_type, text[start:end], ttl_seconds)
        pieces.append(marker)
        counts[detected_type] += 1
        cursor = end
    tail = text[cursor:]
    if tail:
        pieces.append(vault.put(context, token_type, tail, ttl_seconds))
        counts[token_type] += 1
    return "".join(pieces), counts


def sanitize_record(record: Mapping[str, object], context: RequestContext,
                    vault: TokenVault, ttl_seconds: int,
                    policy: SanitizationPolicy, *,
                    today: date | None = None) -> SanitizedRecord:
    """Sanitize each authorized field; generalized values never enter the vault."""
    try:
        if not isinstance(record, Mapping):
            raise SanitizeError("invalid_record")
        allowed = policy.role_fields.get(context.role)
        if allowed is None or any(not isinstance(name, str) for name in record):
            raise SanitizeError("invalid_record_policy")
        if any(name not in allowed for name in record):
            raise SanitizeError("field_forbidden")
        if any(name not in policy.field_treatments for name in record):
            raise SanitizeError("field_treatment_missing")
        current_date = today or datetime.now(timezone.utc).date()
        values = {name: _clean_and_neutralize(_as_text(value)) for name, value in record.items()}
        record_names = (values["name"],) if "name" in values else ()
        result: dict[str, str] = {}
        counts: Counter[TokenType] = Counter()
        for field, value in values.items():
            treatment = policy.field_treatments[field]
            if isinstance(treatment, GeneralizeTreatment):
                if treatment.irreversible is not True or treatment.not_stored_in_vault is not True:
                    raise SanitizeError("unsafe_generalization_policy")
                result[field] = _generalize(treatment.method, value, current_date)
            elif isinstance(treatment, PassthroughTreatment):
                if treatment.free_text_pii_scan is not True:
                    raise SanitizeError("unsafe_passthrough_policy")
                scanned, field_counts, _ = _scan_and_replace(
                    value, context, vault, ttl_seconds, record_names
                )
                result[field] = scanned
                counts.update(field_counts)
            elif isinstance(treatment, TokenizeTreatment):
                if treatment.token_type in {"DIAGNOSIS", "VITAL", "MEDICATION", "NOTE"}:
                    tokenized, field_counts = _clinical_field_text(
                        value, treatment.token_type, context, vault, ttl_seconds, record_names
                    )
                    result[field] = tokenized
                    counts.update(field_counts)
                else:
                    result[field] = vault.put(context, treatment.token_type, value, ttl_seconds)
                    counts[treatment.token_type] += 1
            else:
                raise SanitizeError("unknown_field_treatment")
        return SanitizedRecord(result, dict(counts))
    except VaultError:
        raise
    except SanitizeError:
        raise
    except Exception:
        raise SanitizeError("sanitize_record_failed") from None
