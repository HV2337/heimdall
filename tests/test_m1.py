"""Milestone 1 tests."""

import unittest
import uuid
from unittest.mock import patch
from pathlib import Path

from gateway.auth import AuthenticationError, authenticate
from gateway.config import Settings, hash_api_key
from gateway.data import PatientStore
from gateway.llm_adapter import MockLLM
from gateway.policy import PolicyError, allowed_fields


class MilestoneOneTests(unittest.TestCase):
    def test_settings_hashes_keys_and_defaults_to_mock(self) -> None:
        with patch.dict("os.environ", {"HEIMDALL_API_KEYS": '{"sample-key":{"user_id":"u1","role":"doctor"}}'}, clear=True):
            settings = Settings.from_env()
        self.assertIn(hash_api_key("sample-key"), settings.api_key_users)
        self.assertEqual(settings.llm_backend, "mock")
        self.assertEqual(len(hash_api_key("sample-key")), 64)

    def test_authentication_resolves_identity_and_rejects_unknown(self) -> None:
        mapping = {hash_api_key("key-1"): ("user-1", "nurse")}
        self.assertEqual(authenticate("key-1", mapping).role, "nurse")
        with self.assertRaises(AuthenticationError):
            authenticate("wrong", mapping)

    def test_policy_denies_unauthorized_and_unknown_fields(self) -> None:
        self.assertEqual(set(allowed_fields("nurse")), {"id", "ward", "vitals", "meds"})
        with self.assertRaises(PolicyError):
            allowed_fields("nurse", ["diagnosis"])
        with self.assertRaises(PolicyError):
            allowed_fields("doctor", ["secret"])

    def test_retrieval_returns_only_role_permitted_fields(self) -> None:
        database = Path(f".test-{uuid.uuid4().hex}.sqlite3")
        try:
            store = PatientStore(str(database))
            store.initialize()
            patient_id = store.add_patient({
                "name": "Ari Sen", "phone": "+91-90000-00001", "dob": "1980-02-03",
                "ward": "General", "diagnosis": "Routine follow-up", "vitals": "BP 120/80",
                "meds": "Medication A", "billing_amount": 1000.0, "notes": "synthetic",
                "created_at": "2026-01-15T10:00:00Z",
            })
            record = store.get_patient("nurse", patient_id)
            self.assertEqual(set(record or {}), {"id", "ward", "vitals", "meds"})
            with self.assertRaises(PolicyError):
                store.get_patient("nurse", patient_id, ["diagnosis"])
        finally:
            database.unlink(missing_ok=True)

    def test_mock_llm_is_deterministic(self) -> None:
        model = MockLLM()
        self.assertEqual(model.generate("hello"), "Mock response: hello")


if __name__ == "__main__":
    unittest.main()
