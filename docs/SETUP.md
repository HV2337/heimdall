# Development setup

## Windows laptop

Use Python 3.12 for the laptop development environment. From the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
./.venv/Scripts/Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-laptop.txt
```

Run the Windows developer tasks with the PowerShell helper:

```powershell
./scripts/dev.ps1 test
./scripts/dev.ps1 run
./scripts/dev.ps1 eval
```

`test` and `eval` run the standard-library `unittest` suite. `run` starts the FastAPI app on port 8000. The Makefile and Bash setup/evidence scripts remain available for the LinuxONE VM.

Check a prompt with `python scripts/check_prompt.py "prompt text"`, or pipe prompt text to `python scripts/check_prompt.py`.
