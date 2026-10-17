# Progress

Update this file at the end of every task. Keep it short.

## Milestones
- [x] M1 Skeleton, config, mock LLM, auth, policy, data layer, synthetic seed, tests
- [x] M1.5 shared contracts and module scaffolding (LinuxONE VM verified; user-confirmed)
- [ ] M2 normalize, sanitize, vault
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
- M1 is complete. `docs/INTERFACES.md` defines the M2–M4 contracts; M2 implementation has not started.

## Known issues
(Record problems and dependency limits on s390x here.)
- Windows development uses `scripts/dev.ps1`; Makefile and Bash setup/evidence scripts are retained for LinuxONE/Linux.
- PyPI has no s390x wheels for SciPy/scikit-learn, and the LinuxONE VM has no `gfortran`; use the Ubuntu apt packages and `make setup-vm`.
- M3 still needs the VM training script, portable classifier artifact, and measured metrics.
- The new VM setup and evidence scripts pass Bash syntax checks but have not yet been run on the LinuxONE VM.

## Verified on LinuxONE VM
(Record what has actually been run and passed on the VM.)
- M1 verified on s390x Ubuntu 24.04 with Python 3.12: 9 `unittest` tests passed; Faker and apt-provided NumPy, SciPy, scikit-learn 1.4.1, and cryptography imported successfully in the system-site-enabled venv (user-confirmed).
- M1.5 shared contracts, module scaffolding, and M1 assignment/config updates verified on the LinuxONE VM (user-confirmed); M2 implementation has not started.

## M1 status
- Complete, including LinuxONE VM verification (user-confirmed).
- Laptop suite: 9 `unittest` tests passed with `python -m unittest discover -s tests -v`.

## Current task verification
- Windows setup and commands are documented in `docs/SETUP.md`; line endings are forced to LF for shell scripts, Makefile, and Python files.
- `python -m unittest discover -s tests -v`: 11 tests passed (9 original tests plus 2 M1 assignment/config tests).
- All new gateway scaffolding modules import successfully.
- M1.5 adds shared contracts and importable module interfaces without pipeline-stage logic; assignment tables, seeded assignments, policy checks, config flags, and ward-to-department mapping are covered by tests.
- `bash -n scripts/setup_vm.sh` and `bash -n evidence/capture_platform.sh`: passed.
- `make test` could not run in the Windows workspace because GNU Make is unavailable.
