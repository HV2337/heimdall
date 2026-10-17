# Heimdall: instructions for AI coding assistants

Project: Heimdall (H.E.I.M.D.A.L.L), a secure AI gateway / reverse proxy.
Event: IBM Z Datathon 2026 (24 hours), theme "AI Secured: Innovation Without Exposure".
Team: Aegis. Event code: SSF2026. Target platform: IBM LinuxONE Community Cloud (s390x, Linux, no GPU).

## Before you do anything
1. Read `docs/SPEC.md` (architecture, interfaces, evaluation, milestones).
2. Read `docs/PROGRESS.md` to see what is done. Update it when you finish work.
3. Work on ONE milestone at a time. Run the tests, show me the results, then stop and wait.
4. If something is ambiguous, choose the simplest option and tell me what you assumed.

## Hard rules
### Security behavior
- Fail closed: if auth, policy, classifier, vault or output scanner errors or times out, block the request (403/503, generic message) and write an audit entry. Never fall through.
- Permissions are enforced BEFORE retrieval. The LLM must never see fields the caller's role may not see.
- Session isolation: token maps and any conversation state are per session. No shared memory between sessions.
- Never log raw PII, raw prompts or secrets. Audit logs hold counts, types, decisions and ids only.
- Never hardcode secrets. Use env vars. Commit only `.env.example`.
- Do not write comments, docs or UI text that claim guarantees ("absolute", "zero leakage", "unbreakable"). State measured results and limitations.

### Platform (LinuxONE)
- Must run on s390x. Prefer the standard library. Before adding any dependency, tell me and flag anything that may lack s390x wheels or need compiling.
- On the LinuxONE VM, install `numpy`, `scipy`, `scikit-learn`, and `cryptography` from Ubuntu apt packages; the VM lacks PyPI wheels for SciPy/scikit-learn and has no `gfortran`. Keep the existing venv configured with `include-system-site-packages = true` so it can import those apt packages.
- Keep pure-Python dependencies in `requirements.txt`; compiled ML/crypto dependencies belong in `requirements-laptop.txt` for laptop development. Use `make setup-vm` or `make setup-laptop` as appropriate.
- Save trained classifier artifacts in portable JSON or NPZ format, never pickle. Train the classifier on the LinuxONE VM because it is big-endian; report its held-out metrics.
- LLM backend priority: (1) local model on the VM, (2) mock LLM (used by tests and as demo fallback), (3) external provider only as a last resort and only with sanitized text to an allowlisted URL. Default config is local or mock.
- The threat classifier must be a real trained model (training script, saved artifact, reported metrics). This is the "predictive AI" half; the LLM is the "generative AI" half.
- Keep everything containerizable (Dockerfile, compose file).

### Originality and credits
- All code is written from scratch in this repo during the event. Do not copy code from other projects or tutorials.
- Keep `THIRD_PARTY.md` updated with every library and dataset (name, link, license).
- Use only synthetic data (Faker) and properly licensed open datasets.

### Process
- Keep `main` runnable. `make test` must pass before any commit to `main`.
- Small commits with clear messages. Do not rewrite files you were not asked to touch.
- Add or update tests with every change.
- Use Python's standard-library `unittest` for tests (`python -m unittest discover -s tests -v`); do not use pytest.
- Code style: Python 3.11+, type hints, short docstrings, no dead code.

## Commands (create these in the Makefile)
`make setup`, `make setup-vm`, `make setup-laptop`, `make test`, `make run`, `make eval`, `make demo`, `make evidence`
