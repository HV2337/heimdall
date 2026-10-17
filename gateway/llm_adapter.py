"""LLM adapter interfaces and deterministic mock backend."""

from gateway.contracts import LLMAdapter, LLMError


class MockLLM(LLMAdapter):
    """Deterministic local response adapter used by tests and demos."""

    def generate(self, prompt: str, timeout_seconds: float = 30.0) -> str:
        if not isinstance(prompt, str):
            raise TypeError("prompt must be text")
        return f"Mock response: {prompt[:240]}"


class LocalLLM(LLMAdapter):
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError

    def generate(self, prompt: str, timeout_seconds: float) -> str:
        raise NotImplementedError


class ExternalLLM(LLMAdapter):
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError

    def generate(self, prompt: str, timeout_seconds: float) -> str:
        raise NotImplementedError
