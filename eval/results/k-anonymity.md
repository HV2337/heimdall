# Synthetic dataset k-anonymity evaluation

Records: n=12; seed=2026; today=2026-01-15.

Quasi-identifiers used: `dob`, `ward`, `vitals`, `billing_amount`, `created_at`.

The generalized values are computed with the same Stage 4 methods used by the sanitizer:

| Field | Stage 4 generalization |
|---|---|
| `dob` | `age_band` |
| `ward` | `department` |
| `vitals` | `vital_ranges` |
| `billing_amount` | `billing_range` |
| `created_at` | `calendar_month` |

| Dataset | Equivalence classes | Minimum class size (k) | Class-size distribution (size: number of classes) |
|---|---:|---:|---|
| raw | 12 | 1 | 1: 12 |
| generalized | 11 | 1 | 1: 10, 2: 1 |

| Dataset | Records in classes smaller than k=2 | Smaller than k=3 | Smaller than k=5 |
|---|---:|---:|---:|
| raw | 100.0% (12/12) | 100.0% (12/12) | 100.0% (12/12) |
| generalized | 83.3% (10/12) | 100.0% (12/12) | 100.0% (12/12) |

Achieved generalized k is low: k=1, below the report's stated low-k threshold of 5.
