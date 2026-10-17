"""Thread-safe in-memory AES-GCM token vault with session-scoped indexes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Callable, get_args

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gateway.contracts import (
    RequestContext,
    TokenType,
    TokenVault,
    VaultError,
    VaultExpiredToken,
    VaultUnknownToken,
)

_MARKER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)_([0-9]+)\]")
_TOKEN_TYPES = frozenset(get_args(TokenType))


@dataclass(frozen=True)
class _VaultEntry:
    token_type: TokenType
    nonce: bytes
    ciphertext: bytes
    expires_at: float
    lookup_digest: bytes


class InMemoryTokenVault(TokenVault):
    """AES-GCM vault; canonical values are NFKC text with Unicode Cf removed.

    Canonicalization intentionally preserves case, whitespace, and punctuation.
    It gives a stable typed HMAC lookup without retaining a plaintext lookup key.
    """

    def __init__(self, key: bytes | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if key is None:
                encoded_key = os.environ.get("HEIMDALL_VAULT_KEY")
                if not encoded_key:
                    raise ValueError("missing key")
                key = base64.b64decode(encoded_key, validate=True)
            if not isinstance(key, bytes) or len(key) != 32:
                raise ValueError("invalid key")
            if not callable(clock):
                raise ValueError("invalid clock")
            self._key = key
            self._lookup_key = hmac.new(key, b"heimdall-vault-lookup-v1", hashlib.sha256).digest()
            self._clock = clock
            self._lock = threading.RLock()
            self._entries: dict[tuple[str, str, str], _VaultEntry] = {}
            self._lookups: dict[bytes, tuple[str, str, str]] = {}
        except Exception:
            raise VaultError("vault_initialization_failed") from None

    @staticmethod
    def _canonical_value(value: str) -> str:
        """NFKC-normalize and remove Cf code points; preserve case and spacing."""
        return "".join(
            char for char in unicodedata.normalize("NFKC", value)
            if unicodedata.category(char) != "Cf"
        )

    def _time(self) -> float:
        try:
            now = float(self._clock())
            if now != now or now in (float("inf"), float("-inf")):
                raise ValueError("invalid clock value")
            return now
        except Exception:
            raise VaultError("vault_clock_failed") from None

    def _session_key(self, user_id: str, session_id: str) -> bytes:
        material = (b"heimdall-vault-session-aes-v1\0" + user_id.encode("utf-8")
                    + b"\0" + session_id.encode("utf-8"))
        return hmac.new(self._key, material, hashlib.sha256).digest()

    def _lookup_digest(self, context: RequestContext, token_type: TokenType,
                       canonical_value: str) -> bytes:
        material = (context.user_id.encode("utf-8") + b"\0"
                    + context.session_id.encode("utf-8") + b"\0"
                    + token_type.encode("ascii") + b"\0"
                    + canonical_value.encode("utf-8"))
        return hmac.new(self._lookup_key, material, hashlib.sha256).digest()

    def _discard(self, key: tuple[str, str, str], entry: _VaultEntry) -> None:
        self._entries.pop(key, None)
        if self._lookups.get(entry.lookup_digest) == key:
            self._lookups.pop(entry.lookup_digest, None)

    def put(self, context: RequestContext, token_type: TokenType,
            value: str, ttl_seconds: int) -> str:
        """Encrypt a value and deduplicate only within this user/session/type."""
        try:
            if token_type not in _TOKEN_TYPES or not isinstance(value, str) or not value:
                raise VaultError("invalid_token_value")
            if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
                raise VaultError("invalid_token_ttl")
            canonical = self._canonical_value(value)
            if not canonical:
                raise VaultError("invalid_token_value")
            digest = self._lookup_digest(context, token_type, canonical)
            now = self._time()
            with self._lock:
                old_key = self._lookups.get(digest)
                if old_key is not None:
                    old_entry = self._entries.get(old_key)
                    if old_entry is not None and old_entry.expires_at > now:
                        return old_key[2]
                    if old_entry is not None:
                        self._discard(old_key, old_entry)
                    else:
                        self._lookups.pop(digest, None)

                marker = ""
                entry_key: tuple[str, str, str]
                while True:
                    marker = f"[{token_type}_{secrets.randbits(128)}]"
                    entry_key = (context.user_id, context.session_id, marker)
                    if entry_key not in self._entries:
                        break
                nonce = secrets.token_bytes(12)
                aad = (context.user_id + "\0" + context.session_id + "\0" + token_type).encode("utf-8")
                ciphertext = AESGCM(self._session_key(context.user_id, context.session_id)).encrypt(
                    nonce, value.encode("utf-8"), aad
                )
                entry = _VaultEntry(token_type, nonce, ciphertext, now + ttl_seconds, digest)
                self._entries[entry_key] = entry
                self._lookups[digest] = entry_key
                return marker
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_store_failed") from None

    def resolve(self, context: RequestContext, token: str,
                allowed_types: frozenset[TokenType]) -> str:
        """Resolve a marker only for its owning session and allowed type."""
        try:
            if not isinstance(token, str):
                raise VaultUnknownToken("unknown_token")
            match = _MARKER_RE.fullmatch(token)
            if match is None or match.group(1) not in _TOKEN_TYPES:
                raise VaultUnknownToken("unknown_token")
            token_type = match.group(1)
            if token_type not in allowed_types:
                raise VaultUnknownToken("unknown_token")
            key = (context.user_id, context.session_id, token)
            now = self._time()
            with self._lock:
                entry = self._entries.get(key)
                if entry is None or entry.token_type != token_type:
                    raise VaultUnknownToken("unknown_token")
                if entry.expires_at <= now:
                    self._discard(key, entry)
                    raise VaultExpiredToken("expired_token")
                aad = (context.user_id + "\0" + context.session_id + "\0" + token_type).encode("utf-8")
                plaintext = AESGCM(self._session_key(context.user_id, context.session_id)).decrypt(
                    entry.nonce, entry.ciphertext, aad
                )
                return plaintext.decode("utf-8", errors="strict")
        except (VaultUnknownToken, VaultExpiredToken):
            raise
        except Exception:
            raise VaultError("vault_resolve_failed") from None

    def clear_session(self, session_id: str) -> None:
        """Remove all encrypted entries and HMAC indexes belonging to a session."""
        try:
            if not isinstance(session_id, str):
                raise ValueError("invalid session")
            with self._lock:
                for key, entry in tuple(self._entries.items()):
                    if key[1] == session_id:
                        self._discard(key, entry)
        except Exception:
            raise VaultError("vault_clear_failed") from None
