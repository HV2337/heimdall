"""Create a small synthetic patient dataset using only the standard library."""

from __future__ import annotations

import argparse
import random

from gateway.data import PatientStore


def seed(database_path: str, count: int = 12, seed_value: int = 2026) -> None:
    """Populate the database with reproducible fictional records."""
    rng = random.Random(seed_value)
    store = PatientStore(database_path)
    store.initialize()
    first_names = ["Ari", "Mina", "Noor", "Dev", "Ira", "Kiran", "Sam", "Leela"]
    last_names = ["Sen", "Rao", "Das", "Shah", "Khan", "Iyer", "Mehta"]
    wards = ["Cardiology", "General", "Neurology", "Pediatrics"]
    diagnoses = ["Routine follow-up", "Seasonal allergy", "Hypertension", "Migraine"]
    for index in range(count):
        store.add_patient({
            "name": f"{rng.choice(first_names)} {rng.choice(last_names)}",
            "phone": f"+91-90000-{index:05d}",
            "dob": f"19{rng.randrange(60, 99):02d}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 28):02d}",
            "ward": rng.choice(wards),
            "diagnosis": rng.choice(diagnoses),
            "vitals": f"BP {rng.randrange(100, 151)}/{rng.randrange(60, 101)}; pulse {rng.randrange(55, 111)}",
            "meds": rng.choice(["Medication A", "Medication B", "None"]),
            "billing_amount": float(rng.randrange(500, 50001, 100)),
            "notes": "Synthetic record for demonstration.",
            "created_at": "2026-01-15T10:00:00Z",
        })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", nargs="?", default="heimdall.sqlite3")
    parser.add_argument("--count", type=int, default=12)
    args = parser.parse_args()
    seed(args.database, args.count)


if __name__ == "__main__":
    main()
