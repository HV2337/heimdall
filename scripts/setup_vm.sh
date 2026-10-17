#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -eq 0 ]]; then
    apt-get update
    apt-get install -y python3-numpy python3-scipy python3-sklearn python3-cryptography python3-venv python3-pip
else
    sudo apt-get update
    sudo apt-get install -y python3-numpy python3-scipy python3-sklearn python3-cryptography python3-venv python3-pip
fi

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    VENV_DIR="${VIRTUAL_ENV}"
elif [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    VENV_DIR="${ROOT_DIR}/.venv"
elif [[ -x "${ROOT_DIR}/venv/bin/python" ]]; then
    VENV_DIR="${ROOT_DIR}/venv"
else
    VENV_DIR="${ROOT_DIR}/.venv"
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv --system-site-packages "${VENV_DIR}"
fi

VENV_CONFIG="${VENV_DIR}/pyvenv.cfg"
if [[ ! -f "${VENV_CONFIG}" ]]; then
    echo "Missing virtual environment config: ${VENV_CONFIG}" >&2
    exit 1
fi
if grep -q '^include-system-site-packages[[:space:]]*=' "${VENV_CONFIG}"; then
    sed -i 's/^include-system-site-packages[[:space:]]*=.*/include-system-site-packages = true/' "${VENV_CONFIG}"
else
    printf '\ninclude-system-site-packages = true\n' >> "${VENV_CONFIG}"
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
"${VENV_PYTHON}" -m pip install -r "${ROOT_DIR}/requirements.txt"
"${VENV_PYTHON}" - <<'PY'
import cryptography
import numpy
import scipy
import sklearn

print(f"numpy {numpy.__version__}")
print(f"scipy {scipy.__version__}")
print(f"scikit-learn {sklearn.__version__}")
print(f"cryptography {cryptography.__version__}")
if not sklearn.__version__.startswith("1.4."):
    raise SystemExit("Expected the VM scikit-learn 1.4.x package")
PY
