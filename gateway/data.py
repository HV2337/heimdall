"""SQLite patient storage with permission-filtered retrieval."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import Any

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


class PatientStore:
    """Small SQLite repository for synthetic patient records."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        """Create the patient table if needed."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(CREATE_TABLE)

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

    def get_patient(self, role: str, patient_id: int, fields: list[str] | None = None) -> dict[str, Any] | None:
        """Fetch only fields permitted to the caller, before retrieval."""
        selected = allowed_fields(role, fields)
        columns = ", ".join(selected)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                f"SELECT {columns} FROM patients WHERE id = ?", (patient_id,)
            ).fetchone()
            return dict(row) if row is not None else None

    def list_patients(self, role: str, fields: list[str] | None = None) -> list[dict[str, Any]]:
        """List only fields permitted to the caller, before retrieval."""
        selected = allowed_fields(role, fields)
        columns = ", ".join(selected)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(f"SELECT {columns} FROM patients ORDER BY id").fetchall()
            return [dict(row) for row in rows]
