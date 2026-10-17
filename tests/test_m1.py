"""Milestone 1 tests."""

import unittest
import uuid
import hmac
import sqlite3
from pathlib import Path
from unittest.mock import patch

from gateway.auth import AuthenticationError, authenticate
from gateway.config import Settings, WARD_TO_DEPARTMENT, hash_api_key
from gateway.contracts import RequestContext
from gateway.data import PatientStore
from gateway.llm_adapter import MockLLM
from gateway.main import app, health
from gateway.policy import PolicyError, allowed_fields
from data.seed_synthetic import seed


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
        errors = []
        with patch("gateway.auth.hmac.compare_digest", wraps=hmac.compare_digest) as compare:
            for invalid_key in ("unknown-user-key", "wrong-key"):
                with self.assertRaises(AuthenticationError) as raised:
                    authenticate(invalid_key, mapping)
                errors.append(str(raised.exception))
            compare.assert_called()
        self.assertEqual(errors[0], errors[1])

    def test_policy_denies_unauthorized_and_unknown_fields(self) -> None:
        self.assertEqual(set(allowed_fields("nurse")), {"id", "ward", "vitals", "meds"})
        with self.assertRaises(PolicyError):
            allowed_fields("nurse", ["diagnosis"])
        with self.assertRaises(PolicyError):
            allowed_fields("doctor", ["secret"])

    def _store_with_patient(self) -> tuple[Path, PatientStore, int]:
        database = Path(f".test-{uuid.uuid4().hex}.sqlite3")
        store = PatientStore(str(database))
        store.initialize()
        patient_id = store.add_patient({
            "name": "Ari Sen", "phone": "+91-90000-00001", "dob": "1980-02-03",
            "ward": "General", "diagnosis": "Routine follow-up", "vitals": "BP 120/80",
            "meds": "Medication A", "billing_amount": 1000.0, "notes": "synthetic",
            "created_at": "2026-01-15T10:00:00Z",
        })
        return database, store, patient_id

    def test_unknown_role_is_denied_by_default(self) -> None:
        with self.assertRaises(PolicyError):
            allowed_fields("administrator")

    def test_retrieval_filters_fields_for_every_role(self) -> None:
        database, store, patient_id = self._store_with_patient()
        try:
            expected = {
                "doctor": set(allowed_fields("doctor")),
                "nurse": {"id", "ward", "vitals", "meds"},
                "billing_clerk": {"id", "name", "phone", "billing_amount"},
            }
            for role, fields in expected.items():
                with self.subTest(role=role):
                    record = store.get_patient(role, patient_id)
                    self.assertEqual(set(record or {}), fields)
            with self.assertRaises(PolicyError):
                store.get_patient("nurse", patient_id, ["diagnosis"])
        finally:
            database.unlink(missing_ok=True)

    def test_select_columns_come_from_policy_and_values_are_parameterized(self) -> None:
        database, store, patient_id = self._store_with_patient()
        real_connect = sqlite3.connect

        class RecordingConnection:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self.connection = connection
                self.calls: list[tuple[str, tuple[object, ...]]] = []

            @property
            def row_factory(self) -> object:
                return self.connection.row_factory

            @row_factory.setter
            def row_factory(self, value: object) -> None:
                self.connection.row_factory = value  # type: ignore[assignment]

            def __getattr__(self, name: str) -> object:
                return getattr(self.connection, name)

            def execute(self, query: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                self.calls.append((query, parameters))
                return self.connection.execute(query, parameters)

            def close(self) -> None:
                self.connection.close()

        recorded: list[RecordingConnection] = []

        def connect(path: str) -> RecordingConnection:
            connection = RecordingConnection(real_connect(path))
            recorded.append(connection)
            return connection

        try:
            with patch("gateway.data.sqlite3.connect", side_effect=connect):
                store.get_patient("nurse", patient_id)
            query, parameters = recorded[0].calls[0]
            expected_columns = ", ".join(allowed_fields("nurse"))
            self.assertEqual(query, f"SELECT {expected_columns} FROM patients WHERE id = ?")
            self.assertEqual(parameters, (patient_id,))
        finally:
            database.unlink(missing_ok=True)

    def test_mock_llm_is_deterministic(self) -> None:
        model = MockLLM()
        self.assertEqual(model.generate("hello"), "Mock response: hello")

    def test_health_route(self) -> None:
        self.assertEqual(health(), {"status": "ok"})
        self.assertTrue(any(route.path == "/health" and "GET" in route.methods for route in app.routes))

    def test_faker_seed_keeps_patient_schema(self) -> None:
        database = Path(f".test-{uuid.uuid4().hex}.sqlite3")
        try:
            seed(str(database), count=2, seed_value=17)
            records = PatientStore(str(database)).list_patients("doctor")
            self.assertEqual(len(records), 2)
            self.assertEqual(set(records[0]), set(allowed_fields("doctor")))
        finally:
            database.unlink(missing_ok=True)

    def test_seeded_row_assignments_filter_retrieval(self) -> None:
        database = Path(f".test-{uuid.uuid4().hex}.sqlite3")
        try:
            seed(str(database), count=2, seed_value=17)
            store = PatientStore(str(database))
            patients = store.list_patients("doctor")
            patient_id = int(patients[0]["id"])
            doctor = RequestContext("r1", "doctor-1", "doctor", "s1")
            nurse = RequestContext("r1", "nurse-1", "nurse", "s1")
            outsider = RequestContext("r1", "nurse-2", "nurse", "s1")
            self.assertTrue(store.can_access_patient(doctor, patient_id))
            self.assertTrue(store.can_access_patient(nurse, patient_id))
            self.assertFalse(store.can_access_patient(outsider, patient_id))
            self.assertIsNone(store.get_patient(outsider, patient_id))
            self.assertEqual(set(store.get_patient(doctor, patient_id) or {}), set(allowed_fields("doctor")))
            self.assertEqual(set(store.get_scan_identifiers(patient_id)), {
                patients[0]["name"], patients[0]["phone"]
            })
        finally:
            database.unlink(missing_ok=True)

    def test_config_flags_and_ward_department_mapping(self) -> None:
        with patch.dict("os.environ", {
            "HEIMDALL_API_KEYS": "{}", "HEIMDALL_CLINICAL_MODE": "1",
            "HEIMDALL_DEBUG_TRACE": "1", "HEIMDALL_SESSION_TTL_SECONDS": "42",
        }, clear=True):
            settings = Settings.from_env()
        self.assertTrue(settings.clinical_mode)
        self.assertTrue(settings.debug_trace)
        self.assertEqual(settings.session_ttl_seconds, 42)
        self.assertEqual(WARD_TO_DEPARTMENT["General"], "General Medicine")
        with patch.dict("os.environ", {"HEIMDALL_CLINICAL_MODE": "yes"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()


if __name__ == "__main__":
    unittest.main()
