"""API key authentication."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from gateway.config import hash_api_key


@dataclass(frozen=True)
class Principal:
    """Authenticated caller identity."""

    user_id: str
    role: str


class AuthenticationError(Exception):
    """Raised when an API key is missing or unknown."""


def authenticate(api_key: str | None, key_users: dict[str, tuple[str, str]]) -> Principal:
    """Resolve an API key using the configured hashed key map."""
    if not api_key:
        raise AuthenticationError("Authentication required")
    digest = hash_api_key(api_key)
    for configured, identity in key_users.items():
        if hmac.compare_digest(digest, configured):
            return Principal(*identity)
    raise AuthenticationError("Authentication required")
