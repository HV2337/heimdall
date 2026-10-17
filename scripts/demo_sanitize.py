"""Show sanitizer output for synthetic input examples."""

from __future__ import annotations

import base64
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.contracts import RequestContext
from gateway.normalize import normalize_text
from gateway.sanitize import sanitize_text
from gateway.vault import InMemoryTokenVault


def main() -> None:
    context = RequestContext("demo-request", "demo-doctor", "doctor", "demo-session")
    vault = InMemoryTokenVault(secrets.token_bytes(32), time.monotonic)
    hidden_email = base64.b64encode(b"patient@example.test").decode("ascii")
    samples = (
        "Call me on +91 98765 43210.",
        "Alternate phone: 098765-43210.",
        "Aadhaar: 1234 5678 9012.",
        "PAN: ABCDE1234F.",
        "Contact: patient@example.test.",
        "Server 192.0.2.8 at /var/lib/heimdall/patient.db.",
        "Use api_key=demoKey123456789 and Bearer demo-token-value-12345.",
        f"Encoded email: {hidden_email}",
    )

    for index, before in enumerate(samples, start=1):
        normalized = normalize_text(before)
        if normalized.encoded_sensitive_content:
            model_input = "[BLOCKED before LLM: encoded_sensitive_content]"
        else:
            sanitized = sanitize_text(normalized.clean_text, context, vault, 300)
            model_input = sanitized.text
        print(f"Sample {index}")
        print(f"  Before: {before}")
        print(f"  Model sees: {model_input}")


if __name__ == "__main__":
    main()
