# Progress

## Milestones
- [x] M1
- [x] M1.5
- [x] M2
- [x] M3
- [x] M4
- [ ] M5 evaluation — not started
- [ ] M6

## M4
- M4 complete, with the PATIENT_ID issue open: output control and audit (PR #1 by Muhammed Shifas NK), orchestrator, session manager, HTTP routes (`POST /v1/session`, `POST /v1/chat`, `DELETE /v1/session`, `GET /health`), demo script, review-driven fixes. 69 `unittest` tests pass on the Windows laptop (Python 3.12.4).
- Not implemented: `LocalLLM` and `ExternalLLM` are stubs that raise `LLMError`; the demo uses the deterministic `MockLLM`.

## Verified on LinuxONE VM
M1.5: 11 `unittest` tests passed on s390x (Python 3.12.3). M2: 30 passed, including the AES-GCM vault with cryptography 41.0.7 from apt. M3: 38 passed, including the sklearn parity test, and the threat classifier was trained on the VM (threshold 0.622653, option D). M4 and later: pending VM verification.
- Platform: s390x, big endian, z/VM 7.3, 3 CPUs, 7.8 GiB RAM, no swap, no Docker or Podman installed. Evidence: `evidence/platform-*.txt`.

## M3 results
- Option D was chosen for its lower false-positive rate with the same external recall as option A; figures are in `models/threat_metrics.json` and `models/threat_ablation_metrics.json`.
- The deepset dataset was skipped because its card declares two licenses.
- Dropping jackhhao benign rows gave 97.5% external FPR.
- The development sets are not accuracy measurements.
- No torch or onnxruntime for s390x are available on the VM.

## Decisions
- Threat classifier option D chosen and frozen.
- `get_scan_identifiers` is used only to scrub free text and never reaches callers or the LLM prompt.
- Sessions are in-memory and the vault is cleared before a session is discarded.
- The audit stage duration is not included in the event it writes.

## Known issues and limitations
- Classifier trained on templated and public data.
- The eight regression prompts and 41 hand-written prompts were used to choose the model, so they are development sets.
- A benign clinical sentence containing "ignore the previous" was borderline.
- Names in free text are only caught when known from the patient record.
- Encoding detection is heuristic.
- Sessions are lost on restart (single process).
- Doctors can see `billing_amount` by policy.
- The demo LLM is a mock.
- The output scanner rejects marker-shaped `PATIENT_ID` strings, so `PATIENT_ID` tokens cannot currently appear in model answers and the mock omits the id field. Detokenization of `PATIENT_ID` is therefore not exercised end to end. Under investigation.
