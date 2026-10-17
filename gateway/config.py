"""Environment-backed gateway configuration."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime settings with hashed API key lookup values."""

    api_key_users: dict[str, tuple[str, str]]
    database_path: str
    llm_backend: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Load API key-to-user mappings from environment JSON."""
        raw = os.environ.get("HEIMDALL_API_KEYS", "{}")
        entries = json.loads(raw)
        if not isinstance(entries, dict):
            raise ValueError("HEIMDALL_API_KEYS must be a JSON object")
        hashed: dict[str, tuple[str, str]] = {}
        for key, identity in entries.items():
            if not isinstance(key, str) or not isinstance(identity, dict):
                raise ValueError("Invalid API key configuration")
            user_id, role = identity.get("user_id"), identity.get("role")
            if not isinstance(user_id, str) or role not in {"doctor", "nurse", "billing_clerk"}:
                raise ValueError("Invalid API key identity")
            hashed[hash_api_key(key)] = (user_id, role)
        return cls(
            api_key_users=hashed,
            database_path=os.environ.get("HEIMDALL_DATABASE", "heimdall.sqlite3"),
            llm_backend=os.environ.get("HEIMDALL_LLM_BACKEND", "mock"),
        )


def hash_api_key(api_key: str) -> str:
    """Return a SHA-256 digest for constant-size key lookup."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
