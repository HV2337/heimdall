"""Role-based patient field permissions."""

from __future__ import annotations


PATIENT_FIELDS = frozenset({
    "id", "name", "phone", "dob", "ward", "diagnosis", "vitals", "meds",
    "billing_amount", "notes", "created_at",
})

ROLE_FIELDS: dict[str, frozenset[str]] = {
    "doctor": PATIENT_FIELDS,
    "nurse": frozenset({"id", "ward", "vitals", "meds"}),
    "billing_clerk": frozenset({"id", "name", "phone", "billing_amount"}),
}


class PolicyError(Exception):
    """Raised when a role or field request is not permitted."""


def allowed_fields(role: str, requested: list[str] | None = None) -> tuple[str, ...]:
    """Return requested patient fields allowed for the role; deny unknowns."""
    permitted = ROLE_FIELDS.get(role)
    if permitted is None:
        raise PolicyError("Unknown role")
    fields = sorted(permitted if requested is None else set(requested))
    if any(field not in PATIENT_FIELDS for field in fields):
        raise PolicyError("Unknown patient field")
    denied = set(fields) - permitted
    if denied:
        raise PolicyError("Requested fields are not permitted")
    return tuple(fields)
