"""Mock LLM backend for development and tests."""


class MockLLM:
    """Deterministic local response adapter."""

    def generate(self, prompt: str) -> str:
        """Return a short response without external network access."""
        if not isinstance(prompt, str):
            raise TypeError("prompt must be text")
        return f"Mock response: {prompt[:240]}"
