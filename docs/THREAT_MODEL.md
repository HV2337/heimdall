# Heimdall threat model

Scope: the Heimdall gateway between a client and a language model, in the healthcare scenario with three roles (doctor, nurse, billing clerk), synthetic data only.

## Protected assets

- Patient identifiers and contact data (names, phones, IDs, dates of birth).
- Clinical and billing fields that a role is not permitted to see.
- Secrets: API keys, vault key, system instructions, credentials in text.
- The audit log, which must not become a second copy of the data.

## Actors

| Actor | Capability |
|---|---|
| Curious insider | Valid API key for one role; asks for patients or fields outside their role |
| Malicious prompter | Crafts prompts to override rules, extract instructions, or fish for credentials |
| Poisoned record | A patient note or billing text that contains instructions for the model |
| Careless user | Pastes personal data (phones, ID numbers, keys) into a prompt |
| Session thief | Holds a session id belonging to someone else |

Out of scope: a compromised server or VM, a stolen vault key, side channels, attacks on the underlying model, denial of service beyond the prompt size limit.

## Trust boundaries

1. Client to gateway: nothing from the client is trusted, including the session id and the claimed role.
2. Gateway to data store: only fields permitted to the authenticated role are requested, using a policy whitelist and parameterized queries.
3. Gateway to language model: only sanitized text crosses this boundary.
4. Model output to client: output is untrusted and checked before any real value is restored.

## Threats and controls

| Threat | Control | Evidence |
|---|---|---|
| Insider requests another role's fields | Deny-by-default field policy before retrieval | Role-boundary probes: 0/60 disclosures per role |
| Insider requests an unassigned patient | Row-level authorization; the same 403 for unassigned and nonexistent patients | Test comparing both |
| Session reuse across users | Sessions bound to the user; same 403 for unknown, expired or foreign sessions | Three-case test; 30/30 cross-session probes blocked |
| Prompt injection in the prompt | Deterministic rules plus a trained classifier | Final set: 12/15 attacks blocked, 0/15 benign blocked |
| Injection hidden in a record | Retrieved records are scanned too | Orchestrator test |
| A missed injection leads to data exposure | Permissions and masking apply before the model | 0/201 exposure runs (mock model) |
| PII pasted into prompts | Typed tokens, generalized dates and numbers | Plain recall 150/150; obfuscated 50/60 |
| Hidden or encoded PII | Unicode normalization; base64 and hex decoded for detection | Zero-width, hex and base64 emails caught |
| Model leaks data or instructions | Output scan for raw patterns, a per-request canary, and forged markers | 0/60 leak probes |
| Forged or cross-session tokens in output | Markers are checked against the session vault | Unit tests per token type |
| Logs become a leak | Audit stores ids, counts and decisions only | Test that the audit file never contains raw prompts |
| Failure bypasses security | Every stage fails closed with a generic 403 or 503 | Fault-injection tests |

## Residual risks

- The classifier misses many novel attacks (about two in three of our own injection probes), including persona impersonation and fake system messages.
- Free-text names are masked only when they are known from the record.
- Short encoded values and PII split across sentences are not caught.
- The real behavior of a language model is untested (the model is a mock).
- Roles are coarse and a doctor can read billing amounts by policy.
- Single-process, in-memory sessions and vault.
- Stage 4 generalization does not guarantee k-anonymity; measured k was 1 on raw values and k=1 after generalization (11 equivalence classes) on the seeded 12-record dataset.

## Trust assumptions

The server, its memory and the vault key are trusted. The vault key is supplied at runtime and is not stored in the repository.
