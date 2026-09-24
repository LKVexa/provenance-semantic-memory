# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S038-P001 / 0.1.1-partial / run-0001 / product.
Reviewed fact validation, contradiction handling, corrections, tenant scope,
validity queries, lineage, integrity and capacity. Original source remains separate.

## Repaired findings

- Contradiction search stopped at the first ACTIVE fact and ignored quarantined
  evidence. Every unresolved overlapping canonical-value conflict is now contained,
  including later assertions and corrections into already disputed subjects.
- Python equality equated booleans/integers/floats in conflict checks. Comparison
  now uses explicit canonical JSON encodings with documented type distinctions.
- Fact labels, nested values, unknown fields and query arguments lacked strict
  contracts. Exact bounded JSON/text/enum/time validation now covers read/write paths.
- Correction/lineage calls did not declare tenant scope. They now require a matching
  explicit tenant keyword and share an unavailable error for wrong-scope/missing IDs.
  This is a selection guard; administrative object access still requires external auth.
- Content digests omitted lifecycle metadata and ledger/counters. Full record,
  event and state hashes now cover them; reciprocal chronological same-tenant
  lineage, sequences and counters are verified, and corruption blocks use.
- Lineage cycles could loop indefinitely. Integrity checks and bounded visited-node
  traversal fail closed. Malformed/deleted private records return integrity failures.
- Retention/recall were unbounded. Fact/store/ledger budgets, prospective atomic
  commits and byte-aware paginated recall now bound accepted work and responses.
- Public ledger mutation and concurrent corrections could corrupt state. Detached
  views and an RLock isolate supported operations; one racing correction wins.

## Verification

27 baseline tests passed; a source-inspection fixture leaked an open file, now fixed
with UTF-8 Path reading. Inherited calls were migrated to explicit tenant keywords
for correction/lineage while keeping their behavioral assertions intact.

All 65 source and installed-wheel tests pass, including 38 new regressions for
multi-record conflicts, quarantined reassertion/order, touching/bridging intervals,
typed JSON equality, malformed inputs, atomic capacity failures, detached views,
tenant guards, paging/digests, full lifecycle corruption and concurrent mutations.
CHECK_RUNS.json records current evidence; BASELINE_CHECK_RUNS.json retains historical
evidence. CI covers Linux Python 3.10/3.12/3.14 and Windows 3.12.

No factual validation, adversarial service authorization test, throughput benchmark,
independent security audit, build-tool vulnerability scan or original 171-parent /
801-child certification was performed. Runtime dependencies remain empty.
Strict JSON choices address the documented default key coercion/nonfinite-number
behavior in the primary [Python JSON documentation](https://docs.python.org/3/library/json.html).
Raw JSON parsing and duplicate textual key handling remain caller responsibilities.

Version advanced from 0.1.1-partial to 0.1.2a1. Added packaging, pinned-action CI,
README, security guidance and Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON.
