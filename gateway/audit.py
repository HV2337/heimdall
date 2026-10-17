"""JSON-lines audit writer interface."""
from pathlib import Path
from gateway.contracts import AuditError, AuditEvent, AuditWriter


class JsonlAuditWriter(AuditWriter):
    def __init__(self, path: str | Path) -> None:
        raise NotImplementedError
    def write(self, event: AuditEvent, timeout_seconds: float) -> None:
        raise NotImplementedError
