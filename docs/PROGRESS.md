# Progress

## Milestones
- [x] M1
- [x] M1.5
- [x] M2 normalize, sanitize, vault
- [ ] M3 threat detection (implemented and tested on laptop; LinuxONE VM verification and training pending)
- [ ] M4 LLM adapter, output control, audit, full pipeline
- [ ] M5 eval harness, baselines, results table
- [ ] M6 demo UI, Docker, README, threat model, demo script, evidence

## Decisions
- Markers are per-session counters `[TYPE_n]`.
- Sanitization uses `clean_text`.
- Base64/hex that decodes to sensitive content is blocked at the threat stage with `rule_code` `encoded_sensitive_content`.
- Indian formats supported: Aadhaar, PAN, and +91 phones.
- Threat classification uses deterministic rules plus portable JSON TF-IDF/logistic-regression inference; generated training data is split by template family.

## Known issues
- Free-text names are only caught when known from the record.
- Encoding detection is heuristic.

## Verified on LinuxONE VM
- 30 `unittest` tests pass on s390x (Python 3.12.3) and on the Windows laptop (Python 3.12.4).
- AES-GCM vault runs on s390x with cryptography 41.0.7 from apt.
- `make test` passes.

## M3 laptop results
- `python eval/train_threat.py` generated 720 synthetic examples and trained on 480; 240 family-held-out examples and 41 hand-written examples were evaluated.
- Family-held-out: precision 1.0000, recall 1.0000, false-positive rate 0.0000 at threshold 0.723883148912.
- Hand-written held-out: precision 1.0000, recall 0.3125, false-positive rate 0.0000 at threshold 0.723883148912.
- `python -m unittest discover -s tests -v`: 38 tests passed, including M3 rule, indirect-injection, obfuscation, sklearn-parity, artifact-validation, and tie-order tests.
- M3 LinuxONE VM verification is pending. M4 has not started.
