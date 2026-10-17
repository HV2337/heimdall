"""Environment-backed gateway configuration."""

from __future__ import annotations

import hashlib
import base64
import json
import os
from dataclasses import dataclass

WARD_TO_DEPARTMENT = {
    "Cardiology": "Cardiology", "General": "General Medicine",
    "Neurology": "Neurology", "Pediatrics": "Pediatrics",
}


@dataclass(frozen=True)
class Settings:
    """Runtime settings with hashed API key lookup values."""

    api_key_users: dict[str, tuple[str, str]]
    database_path: str
    llm_backend: str
    clinical_mode: bool = False
    debug_trace: bool = False
    session_ttl_seconds: int = 3600
    max_prompt_bytes: int = 8192
    vault_key: bytes | None = None

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
        clinical_mode = _bool_env("HEIMDALL_CLINICAL_MODE", "0")
        debug_trace = _bool_env("HEIMDALL_DEBUG_TRACE", "0")
        session_ttl = _positive_int("HEIMDALL_SESSION_TTL_SECONDS", "3600")
        max_prompt = _positive_int("HEIMDALL_MAX_PROMPT_BYTES", "8192")
        encoded_vault_key = os.environ.get("HEIMDALL_VAULT_KEY")
        vault_key = None
        if encoded_vault_key is not None:
            try:
                vault_key = base64.b64decode(encoded_vault_key, validate=True)
            except ValueError as exc:
                raise ValueError("Invalid vault key configuration") from exc
            if len(vault_key) != 32:
                raise ValueError("Invalid vault key configuration")
        return cls(
            api_key_users=hashed,
            database_path=os.environ.get("HEIMDALL_DATABASE", "heimdall.sqlite3"),
            llm_backend=os.environ.get("HEIMDALL_LLM_BACKEND", "mock"),
            clinical_mode=clinical_mode,
            debug_trace=debug_trace,
            session_ttl_seconds=session_ttl,
            max_prompt_bytes=max_prompt,
            vault_key=vault_key,
        )


def _bool_env(name: str, default: str) -> bool:
    value = os.environ.get(name, default)
    if value not in {"0", "1"}:
        raise ValueError(f"{name} must be 0 or 1")
    return value == "1"


def _positive_int(name: str, default: str) -> int:
    try:
        result = int(os.environ.get(name, default))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if result <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return result


def hash_api_key(api_key: str) -> str:
    """Return a SHA-256 digest for constant-size key lookup."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
