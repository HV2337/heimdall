"""Focused M4 tests for output scanning, role limits, and audit redaction."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gateway.audit import JsonlAuditWriter
from gateway.contracts import (
    AuditError,
    AuditEvent,
    CheckedOutput,
    OutputBlocked,
    RequestContext,
    VaultError,
    VaultUnknownToken,
)
from gateway.output_control import (
    allowed_token_types,
    check_output,
    detokenize_output,
)
from gateway.vault import InMemoryTokenVault


class OutputAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = RequestContext("req-1", "user-1", "doctor", "session-1")
        self.vault = InMemoryTokenVault(b"k" * 32)

    def test_allowed_types_respect_role_and_clinical_mode(self) -> None:
        self.assertIn("PERSON", allowed_token_types("doctor", False))
        self.assertNotIn("DIAGNOSIS", allowed_token_types("doctor", False))
        self.assertIn("DIAGNOSIS", allowed_token_types("doctor", True))
        self.assertNotIn("PERSON", allowed_token_types("nurse", True))
        self.assertIn("PERSON", allowed_token_types("billing_clerk", False))

    def test_check_output_blocks_sensitive_patterns_and_canaries(self) -> None:
        for value in (
            "Call +1 (212) 555-0188",
            "Email a.person@example.com",
            "ID 123-45-6789",
            "Server 192.0.2.4",
            "Key sk-1234567890abcdef",
            "File /etc/passwd",
            "marker CANARY-abc",
        ):
            with self.subTest(value=value):
                with self.assertRaises(OutputBlocked):
                    check_output(value, ("CANARY-abc",), "doctor", True)

    def test_unknown_and_forged_markers_are_blocked(self) -> None:
        with self.assertRaises(OutputBlocked):
            check_output("value [UNKNOWN_1]", (), "doctor", False)
        with self.assertRaises(OutputBlocked):
            check_output("value [PERSON_x]", (), "doctor", False)

    def test_allowed_marker_round_trip_and_disallowed_redaction(self) -> None:
        marker = self.vault.put(self.context, "PERSON", "Ada Example", 60)
        checked = check_output(f"Hello {marker}", (), "doctor", False)
        self.assertEqual(detokenize_output(checked, self.context, self.vault, False), "Hello Ada Example")
        nurse_context = RequestContext("req-2", "user-1", "nurse", "session-1")
        nurse_output = check_output(marker, (), "nurse", False)
        self.assertEqual(detokenize_output(nurse_output, nurse_context, self.vault, False), "[REDACTED]")

    def test_forged_known_marker_blocks_and_vault_fault_propagates(self) -> None:
        with self.assertRaises(OutputBlocked):
            detokenize_output(CheckedOutput("[PERSON_404]"), self.context, self.vault, False)

        class BrokenVault:
            def resolve(self, *args: object, **kwargs: object) -> str:
                raise VaultError("vault_resolve_failed")

        marker = self.vault.put(self.context, "PERSON", "Ada Example", 60)
        with self.assertRaises(VaultError):
            detokenize_output(CheckedOutput(marker), self.context, BrokenVault(), False)  # type: ignore[arg-type]

    def test_audit_writes_only_contract_fields(self) -> None:
        event = AuditEvent(
            timestamp_utc="2026-10-17T00:00:00Z",
            request_id="req-1",
            session_id="session-1",
            user_id="user-1",
            role="doctor",
            decision="block",
            blocking_stage="output_control",
            status_code=403,
            threat_score=1.0,
            rule_code="output_content_blocked",
            entity_counts={"PHONE": 1},
            stage_latency_ms={"output_control": 2.5},
        )
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "audit.jsonl"
            JsonlAuditWriter(path).write(event, 1.0)
            rows = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 1)
            payload = json.loads(rows[0])
            self.assertEqual(payload["entity_counts"], {"PHONE": 1})
            self.assertNotIn("prompt", payload)
            self.assertNotIn("output", payload)

    def test_audit_invalid_event_and_file_fault_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "audit.jsonl"
            writer = JsonlAuditWriter(path)
            invalid = AuditEvent(
                "time", "req", None, None, None, "allow", None, 200,
                None, None, {"raw_patient_value": 1}, {},  # type: ignore[dict-item]
            )
            with self.assertRaises(AuditError):
                writer.write(invalid, 1.0)
            with self.assertRaises(AuditError):
                JsonlAuditWriter(Path(directory)).write(
                    AuditEvent("t", "r", None, None, None, "allow", None, 200, None, None, {}, {}),
                    1.0,
                )


if __name__ == "__main__":
    unittest.main()
