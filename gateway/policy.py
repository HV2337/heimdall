"""Role field permissions and row-level patient authorization."""
from __future__ import annotations

from typing import TYPE_CHECKING

from gateway.contracts import PolicyDenied, RequestContext

if TYPE_CHECKING:
    from gateway.data import PatientStore

PATIENT_FIELDS = frozenset({
    "id", "name", "phone", "dob", "ward", "diagnosis", "vitals", "meds",
    "billing_amount", "notes", "created_at",
})
ROLE_FIELDS: dict[str, frozenset[str]] = {
    "doctor": PATIENT_FIELDS,
    "nurse": frozenset({"id", "ward", "vitals", "meds"}),
    "billing_clerk": frozenset({"id", "name", "phone", "billing_amount"}),
}


class PolicyError(PolicyDenied):
    """Compatibility name for field-policy denials (HTTP 403)."""


def allowed_fields(role: str, requested_fields: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """Return fields permitted for a role, with deny-by-default validation."""
    permitted = ROLE_FIELDS.get(role)
    if permitted is None:
        raise PolicyError("unknown_role")
    fields = tuple(sorted(permitted if requested_fields is None else set(requested_fields)))
    if any(field not in PATIENT_FIELDS for field in fields):
        raise PolicyError("unknown_field")
    if not set(fields).issubset(permitted):
        raise PolicyError("field_forbidden")
    return fields


class PatientPolicy:
    def __init__(self, patient_store: PatientStore) -> None:
        self.patient_store = patient_store

    def can_access_patient(self, context: RequestContext, patient_id: int) -> bool:
        return self.patient_store.can_access_patient(context, patient_id)
