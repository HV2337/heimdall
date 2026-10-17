"""Scan model output and resolve only role-authorized vault markers."""

from __future__ import annotations

import ipaddress
import re
from typing import get_args

from gateway.contracts import (
    CheckedOutput,
    OutputBlocked,
    OutputControlError,
    RequestContext,
    Role,
    TokenType,
    TokenVault,
    VaultError,
    VaultExpiredToken,
    VaultUnknownToken,
)

_TOKEN_TYPES = frozenset(get_args(TokenType))
_MARKER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)_([0-9]+)\]")
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+", re.I)
_PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{5,}\d(?!\w)")
_INDIAN_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[ -]?|0[ -]?)?[6-9]\d{2}[ -]?\d{3}[ -]?\d{4}(?!\d)|(?<!\d)(?:\+91[ -]?|0[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
_ID_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])(?:\d{4}[ -]?){2}\d{4}(?![A-Za-z0-9])"),
    re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])"),
)
_API_KEY_RE = re.compile(
    r"(?i)(?:\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9._~+/=-]{7,}[A-Za-z0-9]"
    r"|\bsk-[A-Za-z0-9_-]{11,}[A-Za-z0-9]|\bAKIA[0-9A-Z]{16}\b)"
)
_PATH_RE = re.compile(
    r"(?<!\w)(?:[A-Za-z]:[\\/](?:[^\s<>:\"|?*]+[\\/]?)*[A-Za-z0-9._-]*[A-Za-z0-9_-]"
    r"|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]*[A-Za-z0-9_-])(?![A-Za-z0-9_-])"
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{0,39}(?![\w:])")


def allowed_token_types(role: Role, clinical_mode: bool) -> frozenset[TokenType]:
    """Return token types whose values the caller's role may receive."""
    try:
        if role == "doctor":
            allowed: set[TokenType] = {
                "PERSON", "PATIENT_ID", "PHONE", "EMAIL", "GOV_ID",
                "IP_ADDRESS", "API_KEY", "FILE_PATH", "SECRET",
            }
            if clinical_mode:
                allowed.update({"DIAGNOSIS", "VITAL", "MEDICATION", "NOTE"})
            return frozenset(allowed)
        if role == "nurse":
            return frozenset({"PATIENT_ID", "VITAL", "MEDICATION"}) if clinical_mode else frozenset({"PATIENT_ID"})
        if role == "billing_clerk":
            return frozenset({"PERSON", "PATIENT_ID", "PHONE", "EMAIL", "GOV_ID", "IP_ADDRESS", "API_KEY", "FILE_PATH", "SECRET"})
        raise ValueError("invalid role")
    except Exception:
        raise OutputControlError("invalid_role") from None


def _contains_ip(text: str) -> bool:
    for pattern in (_IPV4_RE, _IPV6_RE):
        for match in pattern.finditer(text):
            try:
                ipaddress.ip_address(match.group(0))
                return True
            except ValueError:
                continue
    return False


def _has_sensitive_pattern(text: str) -> bool:
    if _EMAIL_RE.search(text) or _API_KEY_RE.search(text) or _PATH_RE.search(text):
        return True
    if any(pattern.search(text) for pattern in _ID_PATTERNS):
        return True
    for match in (*_INDIAN_PHONE_RE.finditer(text), *_PHONE_RE.finditer(text)):
        digits = sum(char.isdigit() for char in match.group())
        if 7 <= digits <= 15:
            return True
    return _contains_ip(text)


def check_output(text: str, canary_values: tuple[str, ...], role: Role,
                 clinical_mode: bool) -> CheckedOutput:
    """Reject raw sensitive values, canaries, and unknown token marker types."""
    try:
        if not isinstance(text, str) or not isinstance(canary_values, tuple):
            raise ValueError("invalid scanner input")
        if any(not isinstance(value, str) or not value for value in canary_values):
            raise ValueError("invalid canary")
        allowed_token_types(role, clinical_mode)  # Validate the supplied role/mode.
        if any(value in text for value in canary_values) or _has_sensitive_pattern(text):
            raise OutputBlocked("output_content_blocked")
        for match in _MARKER_RE.finditer(text):
            token_type = match.group(1)
            if token_type not in _TOKEN_TYPES:
                raise OutputBlocked("unknown_output_marker")
        # Bracketed marker-shaped values that do not match the grammar are forged.
        if re.search(r"\[(?![A-Z][A-Z0-9]*_[0-9]+\])[A-Z][A-Z0-9_]*_[^\]\s]*\]", text):
            raise OutputBlocked("invalid_output_marker")
        return CheckedOutput(text)
    except (OutputBlocked, OutputControlError):
        raise
    except Exception:
        raise OutputControlError("output_scan_failed") from None


def detokenize_output(output: CheckedOutput, context: RequestContext,
                      vault: TokenVault, clinical_mode: bool) -> str:
    """Resolve allowed markers and redact valid markers outside role scope."""
    try:
        if not isinstance(output, CheckedOutput) or not isinstance(output.text, str):
            raise ValueError("invalid checked output")
        allowed = allowed_token_types(context.role, clinical_mode)
        pieces: list[str] = []
        cursor = 0
        for match in _MARKER_RE.finditer(output.text):
            token_type = match.group(1)
            if token_type not in _TOKEN_TYPES:
                raise OutputBlocked("unknown_output_marker")
            pieces.append(output.text[cursor:match.start()])
            marker = match.group(0)
            if token_type not in allowed:
                pieces.append("[REDACTED]")
            else:
                pieces.append(vault.resolve(context, marker, allowed))
            cursor = match.end()
        pieces.append(output.text[cursor:])
        result = "".join(pieces)
        if re.search(r"\[(?![A-Z][A-Z0-9]*_[0-9]+\])[A-Z][A-Z0-9_]*_[^\]\s]*\]", result):
            raise OutputBlocked("invalid_output_marker")
        return result
    except (VaultUnknownToken, VaultExpiredToken):
        raise OutputBlocked("unknown_output_marker") from None
    except (OutputBlocked, OutputControlError, VaultError):
        raise
    except Exception:
        raise OutputControlError("output_detokenize_failed") from None
