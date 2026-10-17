# Heimdall: build spec

## 1. Goal
A FastAPI gateway between a client and an LLM. For every request it:
authenticates, resolves role, enforces data permissions before retrieval, normalizes input, detects prompt injection, masks and generalizes PII, calls the LLM, scans the output for leaks, detokenizes only what the role may see, and writes an audit log. Any failure blocks the request.

## 2. Scope
- Healthcare only. Roles: `doctor`, `nurse`, `billing_clerk`. Banking and education are future work (mention only in docs).
- Synthetic data only (Faker). SQLite for patient records.
- Patient fields: name, phone, dob, ward, diagnosis, vitals, meds, billing_amount, notes, timestamps.
- Example policy: doctor sees clinical fields; nurse sees vitals, meds and ward but not billing; billing_clerk sees name, phone and billing but not diagnosis or notes.

### LinuxONE dependencies and model artifacts
- Install `numpy`, `scipy`, `scikit-learn`, and `cryptography` from Ubuntu apt packages on the LinuxONE VM. PyPI does not provide s390x wheels for SciPy/scikit-learn, and the VM has no `gfortran`; the existing venv must include system site packages.
- Keep those compiled dependencies out of `requirements.txt`; `requirements-laptop.txt` is for laptop installs and pins scikit-learn to `1.4.*` to match the VM.
- Save classifier artifacts as portable JSON or NPZ, never pickle. Train the classifier on the LinuxONE VM to account for its big-endian architecture; save the training metrics with the artifact.

## 3. Pipeline (one module per stage)
Request flow:
`auth -> policy -> retrieve -> normalize -> threat -> sanitize -> llm -> output_control -> detokenize -> audit`

1. **auth**: API key to user and role. Keys stored hashed in config. Unknown key = reject.
2. **policy**: role to allowed fields per table, deny by default. The data layer only returns permitted fields.
3. **normalize**: Unicode NFKC, strip zero-width chars, decode suspicious base64 or hex segments, keep the original text plus a normalized copy for matching.
4. **threat**:
   - Layer 1: deterministic rules (jailbreak phrases, system-prompt extraction, "ignore previous instructions", credential requests).
   - Layer 2: TF-IDF + logistic regression (scikit-learn) with a configurable threshold.
   - Scan BOTH the user prompt and retrieved record text (indirect injection).
   - Block and audit on detection.
5. **sanitize**:
   - Detect PII: regex for phone, email, IDs, IPs, API keys, file paths; name list or light NER fallback.
   - Replace with session-scoped random tokens like `[PERSON_3]`.
   - Token map lives in an encrypted in-memory vault (AES-GCM, key from env), keyed by session id, with TTL.
   - Generalize: dates to month/year or age band, timestamps to date windows, numbers to ranges, wards to departments.
6. **llm adapter**: `generate(prompt) -> str` with backends `local`, `mock`, `external`, selected by env var.
7. **output_control**: scan the response for raw PII patterns, canary strings planted in the system prompt, secrets, and tokens the role may not resolve. Redact or block. Detokenize only tokens the role's policy allows.
8. **audit**: JSON-lines log: timestamp, request id, user id, role, decision, blocking stage, threat score, entity counts by type. Never raw PII or raw prompts.

Failure rule: an exception or timeout in any stage returns a generic 403/503 and an audit entry.

## 4. Repo layout
```
heimdall/
  gateway/  main.py auth.py policy.py normalize.py threat.py sanitize.py
            vault.py llm_adapter.py output_control.py audit.py config.py
  data/     seed_synthetic.py
  models/   (trained classifier artifacts; large model files not in git)
  eval/     gen_data.py run_eval.py baselines.py k_anonymity.py
  tests/
  ui/       app.py
  demo/     DEMO_SCRIPT.md seed_demo.sh
  evidence/ capture_platform.sh bench.py
  scripts/  setup_vm.sh
  docs/     SPEC.md PROGRESS.md INTERFACES.md THREAT_MODEL.md
  AGENTS.md README.md THIRD_PARTY.md Makefile requirements.txt requirements-laptop.txt Dockerfile docker-compose.yml .env.example
```

`docs/INTERFACES.md` is the implementation contract for remaining pipeline modules and must be read before parallel module work.

## 5. Evaluation harness
Generate labeled sets: PII prompts, benign prompts, injection prompts, role-boundary queries, output-leak probes, cross-session probes.
Compare three systems: (a) Heimdall, (b) regex-only PII masking proxy, (c) rules-only threat detector.
Output a markdown table with:
- PII precision, recall, false-positive rate
- Injection precision, recall, false-positive rate (held-out set)
- Unauthorized disclosure rate per role
- Output leak rate
- Latency p50 and p95 per stage and end to end
- Answer utility with and without sanitization (small question set)
- k-anonymity: compute k and list quasi-identifiers on the generalized synthetic dataset
Save every run to `eval/results/` with a timestamp.

## 6. Tests
- Use Python's standard-library `unittest`; run the suite with `python -m unittest discover -s tests -v` (also exposed as `make test`).
- Fail-closed tests: simulate each component failing and assert the request is blocked.
- End-to-end: doctor vs nurse vs billing_clerk asking the same question get different, correct answers.
- Cross-session isolation test.

## 7. Demo UI (Streamlit or single HTML page)
Role selector, chat box, a panel showing what the LLM actually saw (sanitized prompt), allow/block status, live audit-log tail.

## 8. Deliverables
- `README.md`: title "Aegis_IBM Z Datathon 2026 Project", event code SSF2026, problem statement with three placeholders for cited statistics (the team fills these in), mermaid architecture diagram, tech stack, how it uses LinuxONE, setup/run, evaluation table, threat model summary, limitations, and a note that AI coding assistance was used.
- `docs/THREAT_MODEL.md`: attackers (curious insider, malicious prompter, poisoned record), assets, trust boundaries, out-of-scope items.
- `demo/DEMO_SCRIPT.md`: 3-minute video script (problem 30s, architecture 30s, live demo 90s, LinuxONE 30s) with exact demo inputs.
- `scripts/setup_vm.sh`: installs the LinuxONE apt packages, ensures the venv includes system site packages, installs pure-Python requirements, and checks imports. `evidence/capture_platform.sh`: saves `uname -m`, `lscpu`, `free -h`, `nproc`, container status, Python/pip and library versions to `evidence/*.txt`. `evidence/bench.py`: vault throughput, classifier latency, end-to-end latency.
- `THIRD_PARTY.md`.

## 9. Milestones (stop after each and wait for review)
- **M1** Skeleton, config, mock LLM, auth, policy, data layer, synthetic seed, tests. Done when `make test` passes on laptop and VM.
- **M2** normalize, sanitize, vault, tests.
- **M3** threat detection: rules first, then trained classifier with training script and metrics, tests.
- **M4** real LLM adapter (local), output control, audit, full pipeline end to end, fail-closed tests.
- **M5** eval harness, baselines, results table, k-anonymity script.
- **M6** demo UI, Dockerfile and compose, README, threat model, demo script, evidence scripts.

## 10. Definition of done
Demo path works from a clean checkout with `make setup && make demo` on the LinuxONE VM. Tests pass. Results table is generated from real runs. README claims match measured results.
