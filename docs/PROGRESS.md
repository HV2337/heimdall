# Progress

Update this file at the end of every task. Keep it short.

## Milestones
- [x] M1 Skeleton, config, mock LLM, auth, policy, data layer
- [ ] M2 normalize, sanitize, vault
- [ ] M3 threat detection (rules + trained classifier)
- [ ] M4 LLM adapter, output control, audit, full pipeline
- [ ] M5 eval harness, baselines, results table
- [ ] M6 demo UI, Docker, README, threat model, demo script, evidence

## Decisions
(Record choices here, e.g. which local model runtime is used.)
- M1 uses Python standard-library modules only; synthetic seed data is generated locally without Faker.
- Development LLM backend defaults to the deterministic mock adapter.

## Known issues
(Record problems and dependency limits on s390x here.)
- `make test` uses `unittest` because pytest is not installed in the current laptop environment; no dependency was added.

## Verified on LinuxONE VM
(Record what has actually been run and passed on the VM.)
- Not yet run on LinuxONE.
