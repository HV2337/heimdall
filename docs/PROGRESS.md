# Progress

## Milestones
- [x] M1
- [x] M1.5
- [x] M2 normalize, sanitize, vault
- [ ] M3 threat detection
- [ ] M4 LLM adapter, output control, audit, full pipeline
- [ ] M5 eval harness, baselines, results table
- [ ] M6 demo UI, Docker, README, threat model, demo script, evidence

## Decisions
- Markers are per-session counters `[TYPE_n]`.
- Sanitization uses `clean_text`.
- Base64/hex that decodes to sensitive content is blocked at the threat stage with `rule_code` `encoded_sensitive_content`.
- Indian formats supported: Aadhaar, PAN, and +91 phones.

## Known issues
- Free-text names are only caught when known from the record.
- Encoding detection is heuristic.

## Verified on LinuxONE VM
- 30 `unittest` tests pass on s390x (Python 3.12.3) and on the Windows laptop (Python 3.12.4).
- AES-GCM vault runs on s390x with cryptography 41.0.7 from apt.
- `make test` passes.
