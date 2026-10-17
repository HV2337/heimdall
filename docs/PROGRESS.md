# Progress

Update this file at the end of every task. Keep it short.

## Milestones
- [ ] M1 code complete, VM verification pending
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

## Known issues
(Record problems and dependency limits on s390x here.)
- The local environment does not provide GNU Make; the test target command was run directly with Python.
- FastAPI depends on Pydantic Core, which publishes Linux s390x wheels; VM installation and runtime remain unverified.

## Verified on LinuxONE VM
(Record what has actually been run and passed on the VM.)
- Not yet run on LinuxONE.

## M1 status
- Code complete; LinuxONE VM verification pending.
- No milestone is marked complete until LinuxONE VM verification is confirmed by the user.
