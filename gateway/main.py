"""Minimal FastAPI application entry point."""

from fastapi import FastAPI

app = FastAPI(title="Heimdall")


@app.get("/health")
def health() -> dict[str, str]:
    """Report that the gateway process is responding."""
    return {"status": "ok"}
