"""Normalize Unicode while keeping decoded candidates out of prompt text."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from gateway.contracts import NormalizeError, NormalizedText

_BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9_+/=-])"
)
_HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12,}(?![0-9A-Fa-f])")


def _clean_unicode(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(char for char in normalized if unicodedata.category(char) != "Cf")


def _decode_base64(candidate: str) -> str | None:
    try:
        unpadded = candidate.rstrip("=")
        supplied_padding = len(candidate) - len(unpadded)
        if supplied_padding and len(candidate) % 4 != 0:
            return None
        padded = unpadded + ("=" * (-len(unpadded) % 4))
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        return decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _decode_hex(candidate: str) -> str | None:
    if len(candidate) % 2:
        return None
    try:
        return bytes.fromhex(candidate).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None


def normalize_text(text: str, *, known_names: tuple[str, ...] = ()) -> NormalizedText:
    """Return exact input, clean text, decoded match text and encoded PII flag."""
    if not isinstance(text, str):
        raise NormalizeError("invalid_text")
    try:
        clean_text = _clean_unicode(text)
        candidates: list[tuple[int, int, int, str]] = []
        for match in _HEX_CANDIDATE.finditer(clean_text):
            candidates.append((match.start(), match.end(), 0, "hex"))
        for match in _BASE64_CANDIDATE.finditer(clean_text):
            candidates.append((match.start(), match.end(), 1, "base64"))
        candidates.sort(key=lambda item: (item[0], -(item[1] - item[0]), item[2]))

        from gateway.sanitize import contains_tokenizable_content

        decoded_segments: list[tuple[int, int, str]] = []
        encoded_sensitive_content = False
        occupied_until = -1
        for start, end, _, kind in candidates:
            if start < occupied_until:
                continue
            candidate = clean_text[start:end]
            decoded = _decode_hex(candidate) if kind == "hex" else _decode_base64(candidate)
            if decoded is None:
                continue
            decoded_segments.append((start, end, decoded))
            occupied_until = end
            if contains_tokenizable_content(decoded, known_names=known_names):
                encoded_sensitive_content = True

        output: list[str] = []
        cursor = 0
        for start, end, decoded in decoded_segments:
            output.extend((clean_text[cursor:start], decoded))
            cursor = end
        output.append(clean_text[cursor:])
        return NormalizedText(
            original=text,
            clean_text=clean_text,
            matching_text="".join(output),
            encoded_sensitive_content=encoded_sensitive_content,
        )
    except NormalizeError:
        raise
    except Exception:
        raise NormalizeError("normalization_failure") from None
