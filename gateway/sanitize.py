"""Sanitization stage interfaces."""
from datetime import date
from typing import Mapping
from gateway.contracts import (RequestContext, SanitizationPolicy, SanitizedRecord,
                               SanitizedText, SanitizeError, TokenVault)


def sanitize_text(text: str, context: RequestContext, vault: TokenVault,
                  ttl_seconds: int, *, known_names: tuple[str, ...] = ()) -> SanitizedText:
    raise NotImplementedError


def sanitize_record(record: Mapping[str, object], context: RequestContext,
                    vault: TokenVault, ttl_seconds: int,
                    policy: SanitizationPolicy, *,
                    today: date | None = None) -> SanitizedRecord:
    raise NotImplementedError
