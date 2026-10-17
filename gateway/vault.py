"""Encrypted token vault stage interface."""
from typing import Callable
from gateway.contracts import RequestContext, TokenType, TokenVault, VaultError, VaultExpiredToken, VaultUnknownToken


class InMemoryTokenVault(TokenVault):
    def __init__(self, key: bytes, clock: Callable[[], float]) -> None:
        raise NotImplementedError
    def put(self, context: RequestContext, token_type: TokenType, value: str, ttl_seconds: int) -> str:
        raise NotImplementedError
    def resolve(self, context: RequestContext, token: str, allowed_types: frozenset[TokenType]) -> str:
        raise NotImplementedError
    def clear_session(self, session_id: str) -> None:
        raise NotImplementedError
