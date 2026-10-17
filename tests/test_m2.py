"""M2 tests for normalization, token vault, and record sanitization."""

from __future__ import annotations

import base64
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from gateway.contracts import (
    RequestContext,
    SanitizeError,
    VaultExpiredToken,
    VaultUnknownToken,
)
from gateway.normalize import normalize_text
from gateway.sanitize import (
    default_sanitization_policy,
    sanitize_record,
    sanitize_text,
)
from gateway.vault import InMemoryTokenVault


class Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class NormalizeVaultSanitizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.vault = InMemoryTokenVault(b"k" * 32, self.clock)
        self.context = RequestContext("request-1", "doctor-1", "doctor", "session-1")

    def test_vault_round_trip(self) -> None:
        marker = self.vault.put(self.context, "PERSON", "Ada Patient", 60)
        self.assertEqual(self.vault.resolve(self.context, marker, frozenset({"PERSON"})), "Ada Patient")

    def test_vault_session_isolation(self) -> None:
        marker = self.vault.put(self.context, "PERSON", "Ada Patient", 60)
        other_session = RequestContext("request-2", "doctor-1", "doctor", "session-2")
        other_marker = self.vault.put(other_session, "PERSON", "Grace Patient", 60)
        # Counter labels may coincide; the session-scoped vault entries do not.
        self.assertEqual(marker, "[PERSON_1]")
        self.assertEqual(other_marker, "[PERSON_1]")
        # The same label in another session resolves only that session's entry.
        self.assertEqual(
            self.vault.resolve(other_session, marker, frozenset({"PERSON"})),
            "Grace Patient",
        )
        self.assertEqual(
            self.vault.resolve(self.context, marker, frozenset({"PERSON"})),
            "Ada Patient",
        )

    def test_vault_ttl_expiry(self) -> None:
        marker = self.vault.put(self.context, "PHONE", "+1 212 555 0100", 5)
        self.clock.value += 5
        with self.assertRaises(VaultExpiredToken):
            self.vault.resolve(self.context, marker, frozenset({"PHONE"}))

    def test_vault_rejects_disallowed_role_token_type(self) -> None:
        marker = self.vault.put(self.context, "PHONE", "+1 212 555 0100", 60)
        with self.assertRaises(VaultUnknownToken):
            self.vault.resolve(self.context, marker, frozenset({"PERSON"}))

    def test_same_typed_value_in_session_uses_same_marker(self) -> None:
        first = self.vault.put(self.context, "PERSON", "Ada Patient", 60)
        second = self.vault.put(self.context, "PERSON", "Ada Patient", 90)
        self.assertEqual(first, second)

    def test_marker_counters_are_per_session_and_token_type(self) -> None:
        first_person = self.vault.put(self.context, "PERSON", "Ada Patient", 60)
        first_email = self.vault.put(self.context, "EMAIL", "ada@example.test", 60)
        second_person = self.vault.put(self.context, "PERSON", "Grace Patient", 60)
        self.assertEqual((first_person, first_email, second_person),
                         ("[PERSON_1]", "[EMAIL_1]", "[PERSON_2]"))

    def test_concurrent_put_deduplicates_safely(self) -> None:
        barrier = threading.Barrier(8)

        def put_once(_: int) -> str:
            barrier.wait(timeout=3)
            return self.vault.put(self.context, "EMAIL", "ada@example.test", 60)

        with ThreadPoolExecutor(max_workers=8) as executor:
            markers = list(executor.map(put_once, range(8)))
        self.assertEqual(len(set(markers)), 1)

    def test_zero_width_phone_is_tokenized(self) -> None:
        normalized = normalize_text("Call +1-202-\u200b555-0198 today")
        self.assertEqual(normalized.clean_text, "Call +1-202-555-0198 today")
        result = sanitize_text(normalized.clean_text, self.context, self.vault, 60)
        self.assertEqual(result.entity_counts.get("PHONE"), 1)
        self.assertIn("[PHONE_", result.text)

    def test_base64_hidden_pii_is_flagged_for_threat_stage(self) -> None:
        encoded = base64.b64encode(b"Call +1-202-555-0198").decode("ascii")
        normalized = normalize_text(f"encoded value: {encoded}")
        self.assertTrue(normalized.encoded_sensitive_content)
        self.assertIn("+1-202-555-0198", normalized.matching_text)
        self.assertNotIn("+1-202-555-0198", normalized.clean_text)

    def test_hex_hidden_pii_and_encoded_known_name_are_flagged(self) -> None:
        hex_phone = b"Call +1-202-555-0198".hex()
        self.assertTrue(normalize_text(hex_phone).encoded_sensitive_content)
        encoded_name = base64.b64encode(b"Ada Patient Smith").decode("ascii")
        self.assertTrue(
            normalize_text(encoded_name, known_names=("Ada Patient Smith",)).encoded_sensitive_content
        )

    def test_marker_spoofing_is_neutralized_in_text_and_record(self) -> None:
        result = sanitize_text("User supplied [PERSON_71].", self.context, self.vault, 60)
        self.assertIn("［PERSON_71］", result.text)
        record = {"notes": "Imported marker [PHONE_22]"}
        policy = default_sanitization_policy()
        sanitized = sanitize_record(record, self.context, self.vault, 60, policy)
        self.assertIn("［PHONE_22］", sanitized.fields["notes"])

    def test_generalization_bands(self) -> None:
        record = {
            "dob": "1980-02-03", "ward": "General", "billing_amount": 1200,
            "vitals": "BP 120/80; pulse 72", "created_at": "2026-03-15T10:00:00Z",
        }
        sanitized = sanitize_record(
            record, self.context, self.vault, 60,
            default_sanitization_policy(), today=date(2026, 1, 1),
        )
        self.assertEqual(sanitized.fields["dob"], "45–59")
        self.assertEqual(sanitized.fields["ward"], "General Medicine")
        self.assertEqual(sanitized.fields["billing_amount"], "[1000,4999]")
        self.assertEqual(sanitized.fields["vitals"], "systolic 120–139; diastolic 80–89; pulse 60–99")
        self.assertEqual(sanitized.fields["created_at"], "2026-03")

    def test_unsafe_values_raise_sanitize_error(self) -> None:
        for field, value in (("dob", "not-a-date"), ("vitals", "BP 999/4; pulse 0"),
                             ("billing_amount", float("nan"))):
            with self.subTest(field=field):
                with self.assertRaises(SanitizeError):
                    sanitize_record(
                        {field: value}, self.context, self.vault, 60,
                        default_sanitization_policy(), today=date(2026, 1, 1),
                    )

    def test_indian_government_id_formats(self) -> None:
        result = sanitize_text(
            "Aadhaar 123456789012; grouped 1234-5678-9012; PAN ABCDE1234F",
            self.context, self.vault, 60,
        )
        self.assertEqual(result.entity_counts.get("GOV_ID"), 3)
        self.assertNotIn("123456789012", result.text)
        self.assertNotIn("ABCDE1234F", result.text)

    def test_indian_and_international_phone_formats(self) -> None:
        samples = (
            "+91 98765 43210", "098765-43210", "98765 43210",
            "+1 (212) 555-0198", "+44 20 7946 0958",
        )
        for index, sample in enumerate(samples):
            with self.subTest(sample=sample):
                context = RequestContext(f"req-{index}", "doctor-1", "doctor", f"phone-{index}")
                result = sanitize_text(sample, context, self.vault, 60)
                self.assertEqual(result.entity_counts.get("PHONE"), 1)
                self.assertNotIn(sample, result.text)

    def test_api_keys_secrets_and_long_random_strings(self) -> None:
        samples = (
            ("api_key=abcdEFGH12345678", "API_KEY"),
            ("token: abcdefghijklmnop", "SECRET"),
            ("sk-live-0123456789abcdef", "API_KEY"),
            ("AKIA1234567890ABCDEF", "API_KEY"),
            ("hex 0123456789abcdef0123456789abcdef", "SECRET"),
            ("base64 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456==", "SECRET"),
            ("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature123456789", "SECRET"),
        )
        for index, (sample, token_type) in enumerate(samples):
            with self.subTest(sample=sample):
                context = RequestContext(f"req-{index}", "doctor-1", "doctor", f"secret-{index}")
                result = sanitize_text(sample, context, self.vault, 60)
                self.assertEqual(result.entity_counts.get(token_type), 1)

    def test_email_addresses_and_ipv4_ipv6(self) -> None:
        result = sanitize_text(
            "mail user.name+tag@example.test; hosts 192.0.2.4 and 2001:db8::1",
            self.context, self.vault, 60,
        )
        self.assertEqual(result.entity_counts.get("EMAIL"), 1)
        self.assertEqual(result.entity_counts.get("IP_ADDRESS"), 2)

    def test_windows_and_unix_paths(self) -> None:
        result = sanitize_text(
            r"files C:\Users\Ari\records\patient.txt and /var/lib/heimdall/patient.db",
            self.context, self.vault, 60,
        )
        self.assertEqual(result.entity_counts.get("FILE_PATH"), 2)

    def test_trailing_period_is_not_consumed_by_path_or_bearer_match(self) -> None:
        path = sanitize_text(
            "Open /var/lib/heimdall/patient.db.", self.context, self.vault, 60
        )
        self.assertTrue(path.text.endswith("."), path.text)
        self.assertEqual(path.entity_counts.get("FILE_PATH"), 1)

        bearer = sanitize_text(
            "Bearer abc123456789.", self.context, self.vault, 60
        )
        self.assertTrue(bearer.text.endswith("."), bearer.text)
        self.assertEqual(bearer.entity_counts.get("SECRET"), 1)


if __name__ == "__main__":
    unittest.main()
