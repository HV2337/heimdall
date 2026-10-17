"""SQLite patient storage with permission-filtered retrieval."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import Any, Mapping

from gateway.contracts import PolicyError as DataPolicyError, RequestContext
from gateway.policy import allowed_fields


CREATE_TABLE = """CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    dob TEXT NOT NULL,
    ward TEXT NOT NULL,
    diagnosis TEXT NOT NULL,
    vitals TEXT NOT NULL,
    meds TEXT NOT NULL,
    billing_amount REAL NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT NOT NULL
)"""

ASSIGNMENT_TABLES = (
    """CREATE TABLE IF NOT EXISTS patient_assignments (
        user_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('doctor', 'billing_clerk')),
        patient_id INTEGER NOT NULL REFERENCES patients(id),
        PRIMARY KEY (user_id, role, patient_id))""",
    """CREATE TABLE IF NOT EXISTS nurse_ward_assignments (
        user_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role = 'nurse'), ward TEXT NOT NULL,
        PRIMARY KEY (user_id, ward))""",
)


class PatientStore:
    """Small SQLite repository for synthetic patient records."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        """Create the patient table if needed."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(CREATE_TABLE)
                for statement in ASSIGNMENT_TABLES:
                    connection.execute(statement)

    def add_patient(self, record: dict[str, Any]) -> int:
        """Insert a patient record and return its database id."""
        fields = tuple(sorted(record))
        if set(fields) != set(allowed_fields("doctor")) - {"id"}:
            raise ValueError("Patient record has missing or unknown fields")
        columns = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                cursor = connection.execute(
                    f"INSERT INTO patients ({columns}) VALUES ({marks})",
                    tuple(record[field] for field in fields),
                )
                return int(cursor.lastrowid)

    def assign_patient(self, user_id: str, role: str, patient_id: int) -> None:
        if role not in {"doctor", "billing_clerk"}:
            raise ValueError("Only doctors and billing clerks receive patient assignments")
        with closing(sqlite3.connect(self.database_path)) as connection, connection:
            connection.execute("INSERT OR IGNORE INTO patient_assignments VALUES (?, ?, ?)",
                               (user_id, role, patient_id))

    def assign_nurse_ward(self, user_id: str, ward: str) -> None:
        with closing(sqlite3.connect(self.database_path)) as connection, connection:
            connection.execute("INSERT OR IGNORE INTO nurse_ward_assignments VALUES (?, 'nurse', ?)",
                               (user_id, ward))

    def can_access_patient(self, context: RequestContext, patient_id: int) -> bool:
        """Check assignments without fetching patient data; missing IDs are false."""
        query = """SELECT EXISTS (
            SELECT 1 FROM patients p
            WHERE p.id = ? AND (
                EXISTS (SELECT 1 FROM patient_assignments a
                        WHERE a.patient_id = p.id AND a.user_id = ? AND a.role = ?)
                OR EXISTS (SELECT 1 FROM nurse_ward_assignments n
                           WHERE n.user_id = ? AND n.role = ? AND n.ward = p.ward)
            ))"""
        try:
            with closing(sqlite3.connect(self.database_path)) as connection:
                result = connection.execute(query, (patient_id, context.user_id, context.role,
                                                    context.user_id, context.role)).fetchone()
                return bool(result and result[0])
        except sqlite3.Error as exc:
            raise DataPolicyError("patient_authorization_fault") from exc

    def get_patient(self, role: str | RequestContext, patient_id: int,
                    fields: list[str] | tuple[str, ...] | None = None) -> Mapping[str, Any] | None:
        """Fetch only permitted fields; context calls also enforce row assignments."""
        context = role if isinstance(role, RequestContext) else None
        effective_role = context.role if context is not None else role
        selected = allowed_fields(effective_role, None if fields is None else tuple(fields))
        columns = ", ".join(selected)
        try:
            with closing(sqlite3.connect(self.database_path)) as connection:
                connection.row_factory = sqlite3.Row
                if context is None:
                    row = connection.execute(f"SELECT {columns} FROM patients WHERE id = ?", (patient_id,)).fetchone()
                else:
                    assignment = """EXISTS (SELECT 1 FROM patient_assignments a
                        WHERE a.patient_id=p.id AND a.user_id=? AND a.role=?) OR
                        EXISTS (SELECT 1 FROM nurse_ward_assignments n
                        WHERE n.user_id=? AND n.role=? AND n.ward=p.ward)"""
                    row = connection.execute(
                        f"SELECT {columns} FROM patients p WHERE p.id = ? AND ({assignment})",
                        (patient_id, context.user_id, context.role, context.user_id, context.role),
                    ).fetchone()
                return dict(row) if row is not None else None
        except sqlite3.Error as exc:
            raise DataPolicyError("patient_retrieval_fault") from exc

    def get_scan_identifiers(self, patient_id: int) -> tuple[str, ...]:
        """Return a patient's own name and phone for internal free-text scrubbing."""
        try:
            with closing(sqlite3.connect(self.database_path)) as connection:
                row = connection.execute("SELECT name, phone FROM patients WHERE id = ?", (patient_id,)).fetchone()
                return tuple(str(value) for value in row) if row is not None else ()
        except sqlite3.Error as exc:
            raise DataPolicyError("scan_identifier_fault") from exc

    def list_patients(self, role: str, fields: list[str] | None = None) -> list[dict[str, Any]]:
        """List only fields permitted to the caller, before retrieval."""
        selected = allowed_fields(role, fields)
        columns = ", ".join(selected)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(f"SELECT {columns} FROM patients ORDER BY id").fetchall()
            return [dict(row) for row in rows]
