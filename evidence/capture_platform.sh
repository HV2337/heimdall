#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
mkdir -p evidence
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="evidence/platform-${STAMP}.txt"

{
    echo "Captured UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "== Architecture =="
    uname -m
    echo
    echo "== CPU =="
    lscpu
    echo
    echo "== Memory =="
    free -h
    echo
    echo "== Processor count =="
    nproc
    echo
    echo "== Container status =="
    if command -v docker >/dev/null 2>&1; then
        docker ps --format 'table {{.Names}}\t{{.Status}}' || echo "docker status unavailable"
    elif command -v podman >/dev/null 2>&1; then
        podman ps --format 'table {{.Names}}\t{{.Status}}' || echo "podman status unavailable"
    else
        echo "No Docker or Podman executable found"
    fi
    echo
    echo "== Python =="
    python --version
    python -m pip --version
    echo
    echo "== Library versions =="
    python - <<'PY'
from importlib import import_module

for module_name, display_name in (
    ("numpy", "numpy"),
    ("scipy", "scipy"),
    ("sklearn", "scikit-learn"),
    ("cryptography", "cryptography"),
    ("fastapi", "FastAPI"),
    ("uvicorn", "Uvicorn"),
    ("faker", "Faker"),
):
    try:
        module = import_module(module_name)
        version = getattr(module, "__version__", "version unavailable")
        print(f"{display_name}: {version}")
    except ImportError:
        print(f"{display_name}: not installed")
PY
} > "${OUTPUT}"

echo "Platform evidence saved to ${OUTPUT}"
