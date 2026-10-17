"""Shared immutable contracts for Heimdall gateway stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping, Protocol, TypeAlias

Role = Literal["doctor", "nurse", "billing_clerk"]
TokenType = Literal[
    "PERSON", "PATIENT_ID", "PHONE", "EMAIL", "GOV_ID", "IP_ADDRESS",
    "API_KEY", "FILE_PATH", "SECRET", "DIAGNOSIS", "VITAL", "MEDICATION", "NOTE",
]


class SafeStageError(Exception):
    """Stage error containing only a stable, non-sensitive code."""
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PolicyDenied(SafeStageError): pass
class PolicyError(SafeStageError): pass
class NormalizeError(SafeStageError): pass
class VaultError(SafeStageError): pass
class VaultExpiredToken(VaultError): pass
class VaultUnknownToken(VaultError): pass
class SanitizeError(SafeStageError): pass
class ThreatError(SafeStageError): pass
class OutputBlocked(SafeStageError): pass
class OutputControlError(SafeStageError): pass
class AuditError(SafeStageError): pass
class LLMError(SafeStageError): pass
class SessionAccessDenied(SafeStageError): pass
class SessionStoreError(SafeStageError): pass


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    user_id: str
    role: Role
    session_id: str


@dataclass(frozen=True)
class NormalizedText:
    original: str
    clean_text: str
    matching_text: str
    encoded_sensitive_content: bool = False


@dataclass(frozen=True)
class ScannableText:
    source: Literal["user_prompt", "retrieved_record"]
    record_id: int | None
    text: NormalizedText


@dataclass(frozen=True)
class ThreatAssessment:
    blocked: bool
    score: float
    source: Literal["user_prompt", "retrieved_record"] | None
    rule_code: str | None


@dataclass(frozen=True)
class SanitizedText:
    text: str
    entity_counts: Mapping[TokenType, int]


@dataclass(frozen=True)
class SanitizedRecord:
    fields: Mapping[str, str]
    entity_counts: Mapping[TokenType, int]


@dataclass(frozen=True)
class CheckedOutput:
    text: str


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    user_id: str
    expires_at_monotonic: float
    ttl_seconds: int


@dataclass(frozen=True)
class AuditEvent:
    timestamp_utc: str
    request_id: str
    session_id: str | None
    user_id: str | None
    role: Role | None
    decision: Literal["allow", "block"]
    blocking_stage: str | None
    status_code: int
    threat_score: float | None
    rule_code: str | None
    entity_counts: Mapping[TokenType, int]
    stage_latency_ms: Mapping[str, float]


@dataclass(frozen=True)
class PipelineRequest:
    api_key: str
    session_id: str
    prompt: str
    patient_ids: tuple[int, ...]
    requested_fields: tuple[str, ...] | None = None


@dataclass(frozen=True)
class PipelineResponse:
    request_id: str
    status_code: Literal[200, 403, 413, 503]
    answer: str | None
    message: str
    sanitized_prompt: str | None = None


@dataclass(frozen=True)
class TokenizeTreatment:
    token_type: TokenType


@dataclass(frozen=True)
class GeneralizeTreatment:
    method: Literal["age_band", "department", "vital_ranges", "billing_range", "calendar_month"]
    irreversible: Literal[True] = True
    not_stored_in_vault: Literal[True] = True


@dataclass(frozen=True)
class PassthroughTreatment:
    free_text_pii_scan: Literal[True] = True


FieldTreatment: TypeAlias = TokenizeTreatment | GeneralizeTreatment | PassthroughTreatment


@dataclass(frozen=True)
class SanitizationPolicy:
    role_fields: Mapping[Role, frozenset[str]]
    field_treatments: Mapping[str, FieldTreatment]


class TokenVault(Protocol):
    def put(self, context: RequestContext, token_type: TokenType, value: str,
            ttl_seconds: int) -> str: ...
    def resolve(self, context: RequestContext, token: str,
                allowed_types: frozenset[TokenType]) -> str: ...
    def clear_session(self, session_id: str) -> None: ...


class ThreatClassifier(Protocol):
    def scan(self, texts: tuple[ScannableText, ...]) -> ThreatAssessment: ...


class LLMAdapter(Protocol):
    def generate(self, prompt: str, timeout_seconds: float) -> str: ...


class AuditWriter(Protocol):
    def write(self, event: AuditEvent, timeout_seconds: float) -> None: ...


class SessionManager(Protocol):
    def create(self, user_id: str, ttl_seconds: int) -> SessionRecord: ...
    def require_owner(self, session_id: str, user_id: str) -> SessionRecord: ...
    def delete(self, session_id: str, user_id: str, vault: TokenVault) -> None: ...


@dataclass(frozen=True)
class PipelineDependencies:
    key_users: Mapping[str, tuple[str, Role]]
    patient_store: "PatientStore"
    patient_policy: "PatientPolicy"
    sessions: SessionManager
    classifier: ThreatClassifier
    vault: TokenVault
    llm: LLMAdapter
    audit: AuditWriter
    timeout_seconds: float
    token_ttl_seconds: int
    session_ttl_seconds: int
    debug_trace: bool
    clinical_mode: bool = False
