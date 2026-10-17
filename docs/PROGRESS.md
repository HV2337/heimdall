# Progress

Update this file at the end of every task. Keep it short.

## Milestones
- [x] M1 Skeleton, config, mock LLM, auth, policy, data layer, synthetic seed, tests
- [x] M1.5 shared contracts and module scaffolding (LinuxONE VM verified; user-confirmed)
- [ ] M2 normalize, sanitize, vault (implemented; LinuxONE VM verification pending)
- [ ] M3 threat detection (rules + trained classifier)
- [ ] M4 LLM adapter, output control, audit, full pipeline
- [ ] M5 eval harness, baselines, results table
- [ ] M6 demo UI, Docker, README, threat model, demo script, evidence

## Decisions
(Record choices here, e.g. which local model runtime is used.)
- M1 uses Faker for reproducible synthetic patient data.
- Development LLM backend defaults to the deterministic mock adapter.
- No milestone is considered complete until laptop tests and LinuxONE VM verification pass and are confirmed.
- LinuxONE VM is s390x, Ubuntu 24.04, Python 3.12; 9 `unittest` tests pass, Faker works, and NumPy, SciPy, scikit-learn 1.4.1, and cryptography import from apt packages in the venv with system site packages enabled.
- Compiled ML/crypto dependencies use apt on LinuxONE and `requirements-laptop.txt` on laptops; portable classifier artifacts use JSON/NPZ and are trained on the big-endian VM.
- M1 and M1.5 are complete. `docs/INTERFACES.md` defines the M2–M4 contracts; M2 implementation is complete locally and awaits VM verification. M3 has not started.

## Known issues
(Record problems and dependency limits on s390x here.)
- Windows development uses `scripts/dev.ps1`; Makefile and Bash setup/evidence scripts are retained for LinuxONE/Linux.
- PyPI has no s390x wheels for SciPy/scikit-learn, and the LinuxONE VM has no `gfortran`; use the Ubuntu apt packages and `make setup-vm`.
- M3 still needs the VM training script, portable classifier artifact, and measured metrics.
- The new VM setup and evidence scripts pass Bash syntax checks but have not yet been run on the LinuxONE VM.

## Verified on LinuxONE VM
(Record what has actually been run and passed on the VM.)
- M1 verified on s390x Ubuntu 24.04 with Python 3.12: 9 `unittest` tests passed; Faker and apt-provided NumPy, SciPy, scikit-learn 1.4.1, and cryptography imported successfully in the system-site-enabled venv (user-confirmed).
- M1.5 shared contracts, module scaffolding, and M1 assignment/config updates verified on the LinuxONE VM (user-confirmed).

## M1 status
- Complete, including LinuxONE VM verification (user-confirmed).
- Laptop suite: 9 `unittest` tests passed with `python -m unittest discover -s tests -v`.

## Current task verification
- Windows setup and commands are documented in `docs/SETUP.md`; line endings are forced to LF for shell scripts, Makefile, and Python files.
- `python -m unittest discover -s tests -v`: 23 tests passed from the activated Windows project venv (9 original M1 tests, 2 M1 assignment/config tests, and 12 M2 tests).
- All new gateway scaffolding modules import successfully.
- M2 sanitizer hardening covers Indian identity/phone formats, keys/secrets, email, IP addresses, and filesystem paths; VM verification remains pending and M3 remains not started.
- `python scripts/demo_sanitize.py`: 8 synthetic before/model-input examples displayed; encoded email was blocked before model input.
- `python -m unittest discover -s tests -v` from the activated Windows venv: 30 tests passed after marker-counter and punctuation fixes.
- `bash -n scripts/setup_vm.sh` and `bash -n evidence/capture_platform.sh`: passed.
- `make test` could not run in the Windows workspace because GNU Make is unavailable.
- M2 follow-up: markers now use per-session, per-token-type counters (`[TYPE_n]`); HMAC deduplication and session-scoped encrypted entries remain in place. Path and bearer-token scans preserve trailing periods.
- `python scripts/demo_sanitize.py`: all eight examples displayed correctly; sample 6 preserves the period after `patient.db`, and encoded email is blocked before LLM input.
- M2 remains pending LinuxONE VM verification; M3 has not started.
