# Progress

## Milestones
- [x] M1
- [x] M1.5
- [x] M2 normalize, sanitize, vault
- [x] M3 threat detection
- [ ] M4 LLM adapter, output control, audit, full pipeline
- [ ] M5 eval harness, baselines, results table
- [ ] M6 demo UI, Docker, README, threat model, demo script, evidence

## M4 output-control and audit implementation
- Implemented `gateway/output_control.py` and `gateway/audit.py` against the M4 module interfaces.
- Added focused unit coverage for raw output leak blocking, canary and marker checks, role-limited detokenization, vault faults, audit fields, and audit failures.
- M4 Part 2 now implements the in-memory session manager, fail-closed orchestrator, HTTP session/chat/delete routes, deterministic record-based mock responses, and an in-process pipeline demo.
- Hardened orchestration: only the pre-normalization size check maps to 413; dependency initialization returns the generic 503 response with a best-effort redacted audit; a missing row after authorization is attributed to policy. Scan identifiers are used internally for free-text scrubbing for every role and are excluded from the LLM context.
- Added orchestrator coverage for equivalent unassigned/nonexistent patient responses and audit fields, unknown/wrong-owner/expired session equivalence, debug-trace exclusion on blocked/fault responses, per-request canaries, identifier scrubbing, hidden-name scrubbing, vault cleanup order on deletion/expiry, dependency-initialization failures on all three routes, and stage timing order. The current Windows laptop run passes 69 `unittest` tests.
- `LocalLLM` and `ExternalLLM` remain unimplemented stubs. The output scanner currently rejects marker-shaped `PATIENT_ID` strings due its forged-marker pattern, so the mock omits the `id` field from its answer. M4 remains incomplete pending resolution and backend work.

## Decisions
- Markers are per-session counters `[TYPE_n]`.
- Sanitization uses `clean_text`.
- Base64/hex that decodes to sensitive content is blocked at the threat stage with `rule_code` `encoded_sensitive_content`.
- Indian formats supported: Aadhaar, PAN, and +91 phones.
- Threat classification uses deterministic rules plus portable JSON TF-IDF/logistic-regression inference; generated training data is split by template family.
- M3 training used balanced TF-IDF/logistic regression with a validation-selected threshold; external test splits were reserved for evaluation.

## Known limitations
- The threat classifier is trained on templated and public data.
- The eight regression prompts and the 41 hand-written prompts were used to choose the model, so they are development sets and not accuracy measurements.
- Benign clinical sentences containing "ignore the previous" were observed as borderline.
- Heavier transformer models were not available on the VM (no torch or onnxruntime packages for s390x).

## Verified on LinuxONE VM
- 30 `unittest` tests pass on s390x (Python 3.12.3) and on the Windows laptop (Python 3.12.4).
- AES-GCM vault runs on s390x with cryptography 41.0.7 from apt.
- `make test` passes.

## M3 results — complete
- `python eval/train_threat.py` trained on 600 generated family-train examples and 1,785 external TRAIN examples; threshold validation used 180 generated examples.
- Held-out sets: 180 generated family-test examples, 364 external TEST examples, and 41 hand-written examples.
- `python -m unittest discover -s tests -v`: 38 tests passed, including M3 rule, indirect-injection, obfuscation, sklearn-parity, artifact-validation, and tie-order tests.
- The deepset dataset was skipped because its card declares conflicting Apache-2.0 and CC-BY-4.0 licenses.
- M3 is complete. Training and verification were completed on the LinuxONE VM as well as the laptop.

## M3 classifier improvement ablation
- M3 complete. Option D is the saved model in `models/threat_model.json`; its threshold is recorded in `models/threat_metrics.json`. D was selected for its lowest observed false-positive rate (tied at 0.0) with the same external-test recall as A (0.8926).
- Added a narrowly scoped `privileged_role_data_request` rule and expanded system-prompt extraction to hidden/system configuration and operating instructions; both have benign look-alike coverage.
- Added the `credential_disclosure_request` rule for disclosure verbs near qualified system/service credentials, with benign look-alike tests.
- `eval/ablate_threat.py` compares A-D with family-based generated validation, external test splits, and the existing 41-row hand-written set. It writes `models/threat_ablation_metrics.json`, a separate D candidate artifact, and a false-positive list; the production artifact is not written by this script.
- Added eight independent regression prompts in `scripts/regression_prompts.txt`; tests evaluate them against the D candidate. They are not used in training or threshold selection.
- The ablation shows B (dropping jackhhao benign rows) is not viable: 97.5% external-test FPR. A, C and D satisfy the validation threshold constraint; D is the recommended candidate for the targeted persona-attack gap, with a modest decrease in generated family-test recall relative to C.
- Follow-up regression review expanded the privileged-role rule to cover internal auditors and role-attributed complete/bulk exports; benign role-only workflow look-alikes remain allowed. All eight regression prompts were rerun against A-D after this rule-only change; the saved model artifact was not rewritten.
- Trainer defaults to option D and prints metrics without saving; explicit `--option` runs write only under `models/ablation/<option>/`, and the main artifact requires `--save`. Metrics record the option, dataset hashes, scikit-learn version, platform machine value, and threshold. Laptop run printed threshold 0.622653; the saved model hash stayed unchanged.
