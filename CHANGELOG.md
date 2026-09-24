# 0.1.2a1 — 2026-09-23

- Quarantine every unresolved overlapping conflict using strict canonical values.
- Require explicit tenant scope for correction and lineage lookups.
- Bind full records, lifecycle events, counters and state to integrity checks.
- Add atomic retention limits, detached views and byte-aware recall pagination.
- Add 38 regressions, packaging, cross-platform CI and documented trust boundaries.
- Include README and Apache 2.0 LICENSE/NOTICE; full certification remains open.

# Changelog — JY-S038-P001 n02-semantic-memory

## 0.1.1-partial (2026-09-14)

Repairs-only hardening release (patch bump). Baseline fingerprint:
build-0001 product.zip sha256
2fe637f3ec7a6de4070a0a6ca00b22f62b7a7f2415a90115edb4380204ea52f0
(17571 bytes), version 0.1.0-partial, baseline tests 13/13 PASS.
All findings below were reproduced live on the baseline before fixing.

### Findings fixed

- A028-F1 (aliasing/isolation, HIGH): mutable fact values were stored
  and returned by reference. Observed: mutating the caller's input dict
  after assert_fact tampered the stored record (verify -> FAIL); mutating
  a recall result's nested value corrupted the store. Expected: store
  state isolated from caller mutation. Fix: deep-copy on assert_fact /
  correct input and on every recall result.
- A028-F2 (error-contract leak, MEDIUM): non-numeric validity bounds and
  non-JSON-serializable values escaped as bare TypeError instead of the
  documented MemoryError_. Fix: shared _validate() type checks; _digest
  wraps canonicalization failures in MemoryError_ (raised before any
  state change).
- A028-F3 (NaN / strict canonicalization, MEDIUM): valid_from=NaN was
  accepted (all comparisons false), producing a fact invisible to any
  point-in-time recall, and digests used non-strict JSON (NaN allowed).
  Fix: finite-number validation for valid_from/valid_to (bool refused);
  json.dumps(allow_nan=False) in _digest.
- A028-F4 (contradiction-containment bypass, HIGH): correct() never ran
  the contradiction check, so a correction could create two conflicting
  ACTIVE facts (silent-winner state the TMS design forbids). Observed
  live. Fix: corrections run _find_contradiction; on conflict both facts
  are quarantined, exactly like assert_fact.
- A028-F5 (correction schema bypass, MEDIUM): correct() skipped all
  field validation — confidence_basis="vibes" and valid_to <= valid_from
  were accepted. Fix: merged correction is validated with the same
  _validate() as assertions, before the original is superseded (a
  refused correction leaves the original ACTIVE and uncorrected).
- A028-F6 (tamper-detection gap + crash, MEDIUM): a dangling
  corrected_by pointer passed verify() (PASS) and made lineage() crash
  with a bare KeyError. Fix: verify() flags dangling corrected_by as
  "dangling correction lineage"; lineage() raises MemoryError_ on any
  broken link; verify() also treats non-canonicalizable tampered values
  as "fact tampered" instead of raising.

### Compatibility

Public API unchanged (assert_fact / correct / lineage / recall /
verify). Behavioral tightening only: inputs that previously crashed
with TypeError/KeyError or were wrongly accepted (NaN validity,
invalid corrections, contradiction-creating corrections) are now
refused or quarantined per the documented contract. No baseline test
asserted the old weaker behavior; all 13 baseline tests pass unchanged.

### Rollback

Restore build-0001 product.zip (sha256 above). No data-format change;
store is in-memory only, so no migration is involved.
