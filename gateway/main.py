"""Minimal FastAPI application entry point."""

from typing import Callable

from fastapi import FastAPI

from gateway.contracts import (PipelineDependencies, PipelineRequest, PipelineResponse,
                               SessionManager, SessionRecord, TokenVault)
from gateway.config import Settings

app = FastAPI(title="Heimdall")


@app.get("/health")
def health() -> dict[str, str]:
    """Report that the gateway process is responding."""
    return {"status": "ok"}


class InMemorySessionManager(SessionManager):
    """Session manager interface; implementation is deferred to M4."""

    def __init__(self, clock: Callable[[], float]) -> None:
        raise NotImplementedError

    def create(self, user_id: str, ttl_seconds: int) -> SessionRecord:
        raise NotImplementedError

    def require_owner(self, session_id: str, user_id: str) -> SessionRecord:
        raise NotImplementedError

    def delete(self, session_id: str, user_id: str, vault: TokenVault) -> None:
        raise NotImplementedError


def build_dependencies(settings: Settings) -> PipelineDependencies:
    """Construct configured pipeline dependencies (M4 implementation)."""
    raise NotImplementedError


def run_pipeline(request: PipelineRequest,
                 dependencies: PipelineDependencies) -> PipelineResponse:
    """Run the fail-closed pipeline (M4 implementation)."""
    raise NotImplementedError
