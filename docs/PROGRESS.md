# Progress

## Milestones
- [x] M1
- [x] M1.5
- [x] M2
- [x] M3
- [x] M4
- [ ] M5 evaluation — in progress (scaled synthetic probes, baselines, and runner implemented; k-anonymity remains)
- [ ] M6

## M4
- M4 complete: output control and audit (PR #1 by Muhammed Shifas NK), orchestrator, session manager, HTTP routes (`POST /v1/session`, `POST /v1/chat`, `DELETE /v1/session`, `GET /health`), demo script, review-driven fixes. 72 `unittest` tests pass on the Windows laptop (Python 3.12.4).
- Fixed output marker parsing to support underscore token types; the mock includes the `id` field again.
- Not implemented: `LocalLLM` and `ExternalLLM` are stubs that raise `LLMError`; the demo uses the deterministic `MockLLM`.

## Verified on LinuxONE VM
M1.5: 11 `unittest` tests passed on s390x (Python 3.12.3). M2: 30 passed, including the AES-GCM vault with cryptography 41.0.7 from apt. M3: 38 passed, including the sklearn parity test, and the threat classifier was trained on the VM (threshold 0.622653, option D). M4: 72 unittest tests passed on s390x and scripts/demo_pipeline.py ran. M5 and later: pending VM verification.
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

## M5 evaluation
- Laptop run results are in `eval/results/latest.md` and `eval/results/latest.json`; the report includes percentage metrics, counts and distinct counts, per-probe cross-session decisions, PII false negatives, latency, and missed-injection data-boundary checks.
- PAN probes now match the valid 10-character format. Plain PII recall is Heimdall 100.0% [150/150] and regex proxy 98.0% [147/150]; the proxy's remaining three plain misses are full-form IPv6 values.
- The old base64 probes are now `base64_short_phone` (0/10 detected; 15 non-padding characters, below the decoder's 16-character minimum) and `base64_email` (10/10 detected; longer than 16 characters).
- The three previously missed full IPv6 values tokenize when bare and in sentences after trimming trailing punctuation before address validation. The bare `08463223705` value tokenizes as `PHONE`.
- The regex and rules-only baselines have no imports from `gateway/`; `eval/baselines.py` contains independent evaluation definitions.
- Classifier recall on the generated injection set is 33/100 (33.0%); 67 missed prompts (13 distinct) were sent through `run_pipeline` for all three roles, with 0/201 observed unauthorized exposure runs using the deterministic MockLLM.
- Role-boundary probe IDs are synthetic labels (starting at 1000), not IDs in the seeded database; the runner maps them by order to seeded records. Aligning those IDs is a data-generation follow-up.
