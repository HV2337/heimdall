"""LLM adapter interfaces and deterministic mock backend."""

import json

from gateway.contracts import LLMAdapter, LLMError


class MockLLM(LLMAdapter):
    """Deterministic local response adapter used by tests and demos."""

    def generate(self, prompt: str, timeout_seconds: float = 30.0) -> str:
        """Summarize only the sanitized permitted-record JSON in the prompt."""
        try:
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError
            marker = "Permitted records: "
            start = prompt.rfind(marker)
            if start < 0:
                raise ValueError
            records = json.loads(prompt[start + len(marker):])
            if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
                raise ValueError
            if not records:
                return "No permitted records were requested."
            rendered = json.dumps(records, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":"))
            return f"Summary for the requested record(s): {rendered}"
        except Exception:
            raise LLMError("mock_generation_failed") from None


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
