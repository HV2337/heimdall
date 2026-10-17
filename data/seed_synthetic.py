"""Create a small synthetic patient dataset using only the standard library."""

from __future__ import annotations

import argparse

from faker import Faker

from gateway.data import PatientStore


def seed(database_path: str, count: int = 12, seed_value: int = 2026) -> None:
    """Populate the database with reproducible fictional records."""
    fake = Faker("en_IN")
    fake.seed_instance(seed_value)
    store = PatientStore(database_path)
    store.initialize()
    wards = ["Cardiology", "General", "Neurology", "Pediatrics"]
    diagnoses = ["Routine follow-up", "Seasonal allergy", "Hypertension", "Migraine"]
    for index in range(count):
        patient_id = store.add_patient({
            "name": fake.name(),
            "phone": f"+91-90000-{index:05d}",
            "dob": fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
            "ward": fake.random_element(wards),
            "diagnosis": fake.random_element(diagnoses),
            "vitals": f"BP {fake.random_int(100, 150)}/{fake.random_int(60, 100)}; pulse {fake.random_int(55, 110)}",
            "meds": fake.random_element(["Medication A", "Medication B", "None"]),
            "billing_amount": float(fake.random_int(5, 500) * 100),
            "notes": "Synthetic record for demonstration.",
            "created_at": "2026-01-15T10:00:00Z",
        })
        store.assign_patient("doctor-1", "doctor", patient_id)
        store.assign_patient("billing-1", "billing_clerk", patient_id)
    for ward in wards:
        store.assign_nurse_ward("nurse-1", ward)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", nargs="?", default="heimdall.sqlite3")
    parser.add_argument("--count", type=int, default=12)
    args = parser.parse_args()
    seed(args.database, args.count)


if __name__ == "__main__":
    main()
