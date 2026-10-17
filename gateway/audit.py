"""Redacted JSON-lines audit writer."""

from __future__ import annotations

import json
import math
import re
import threading
import time
from pathlib import Path
from typing import get_args

from gateway.contracts import AuditError, AuditEvent, AuditWriter, TokenType

_STAGES = frozenset({
    "auth", "session", "policy", "retrieve", "normalize", "threat",
    "sanitize", "llm", "output_control", "detokenize", "audit",
})
_TOKEN_TYPES = frozenset(get_args(TokenType))
_SAFE_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_WRITE_LOCK = threading.RLock()


class JsonlAuditWriter(AuditWriter):
    """Append validated, allowlisted event fields as one JSON object per line."""

    def __init__(self, path: str | Path) -> None:
        try:
            if not isinstance(path, (str, Path)) or not str(path):
                raise ValueError("invalid audit path")
            self._path = Path(path)
        except Exception:
            raise AuditError("audit_initialization_failed") from None

    @staticmethod
    def _payload(event: AuditEvent) -> dict[str, object]:
        if not isinstance(event, AuditEvent):
            raise ValueError("invalid audit event")
        if event.decision not in {"allow", "block"}:
            raise ValueError("invalid decision")
        if event.role is not None and event.role not in {"doctor", "nurse", "billing_clerk"}:
            raise ValueError("invalid role")
        if not isinstance(event.status_code, int) or isinstance(event.status_code, bool):
            raise ValueError("invalid status")
        entity_counts = dict(event.entity_counts)
        if any(key not in _TOKEN_TYPES or not isinstance(value, int) or isinstance(value, bool) or value < 0
               for key, value in entity_counts.items()):
            raise ValueError("invalid entity counts")
        stage_latency = dict(event.stage_latency_ms)
        if any(key not in _STAGES or isinstance(value, bool) or not isinstance(value, (int, float))
               or not math.isfinite(value) or value < 0 for key, value in stage_latency.items()):
            raise ValueError("invalid stage latency")
        if event.threat_score is not None and (
            isinstance(event.threat_score, bool) or not isinstance(event.threat_score, (int, float))
            or not math.isfinite(event.threat_score) or not 0 <= event.threat_score <= 1
        ):
            raise ValueError("invalid threat score")
        for value in (event.timestamp_utc, event.request_id, event.session_id, event.user_id,
                      event.blocking_stage, event.rule_code):
            if value is not None and not isinstance(value, str):
                raise ValueError("invalid audit field")
        if event.blocking_stage is not None and event.blocking_stage not in _STAGES | {"input_validation"}:
            raise ValueError("invalid blocking stage")
        if event.rule_code is not None and _SAFE_CODE_RE.fullmatch(event.rule_code) is None:
            raise ValueError("invalid rule code")
        # Construct explicitly: no arbitrary event attributes can enter the log.
        return {
            "timestamp_utc": event.timestamp_utc,
            "request_id": event.request_id,
            "session_id": event.session_id,
            "user_id": event.user_id,
            "role": event.role,
            "decision": event.decision,
            "blocking_stage": event.blocking_stage,
            "status_code": event.status_code,
            "threat_score": event.threat_score,
            "rule_code": event.rule_code,
            "entity_counts": entity_counts,
            "stage_latency_ms": stage_latency,
        }

    def write(self, event: AuditEvent, timeout_seconds: float) -> None:
        """Append a single redacted line or raise an error with a safe code."""
        try:
            if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                    or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
                raise ValueError("invalid timeout")
            payload = self._payload(event)
            line = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n"
            started = time.monotonic()
            with _WRITE_LOCK:
                with self._path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(line)
                    stream.flush()
            if time.monotonic() - started > timeout_seconds:
                raise TimeoutError("audit timeout")
        except Exception:
            raise AuditError("audit_write_failed") from None
