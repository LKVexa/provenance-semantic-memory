# Provenance Semantic Memory

**0.1.2a1 — experimental partial candidate, JY-S038-P001 / N02**

A bounded in-memory fact store with caller-declared provenance, validity intervals,
contradiction quarantine, correction lineage and tenant-scoped evidence recall.
Python 3.10+; no third-party runtime dependencies or network/file operations.

## Use

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from n02.core import SemanticStore

store = SemanticStore()
old = store.assert_fact({
    "subject": "service-api", "predicate": "owner", "value": "team-red",
    "source": "inventory review", "tenant": "team-space", "valid_from": 100,
    "confidence_basis": "reported",
})
new = store.correct(old["fact_id"], {"value": "team-blue"}, tenant="team-space")
assert store.lineage(new["fact_id"], tenant="team-space") == [old["fact_id"], new["fact_id"]]
evidence = store.recall("team-space", at=150, limit=100)
assert evidence["authority"] == "evidence-only"
assert store.verify()["verdict"] == "PASS"
~~~

## Fact contract

Required fields: subject, predicate, value, source, tenant, valid_from,
confidence_basis. Optional valid_to defaults to null. Unknown fields, including
caller-supplied IDs/status/digests, are refused. Required values cannot be null;
value may otherwise be any supported JSON type, including false, zero and empty
strings/containers. Nested null values are supported.

Tenant labels are at most 128 UTF-8 bytes, subject/predicate 256, source 1024.
Labels are exact, case-sensitive, nonblank valid Unicode without outer whitespace
or C0/DEL controls. Sources are unverified text labels, not fetched URLs or trusted
identities. confidence_basis is observed, reported, derived or asserted; it records
the caller's classification, not a calibrated score or verified truth.

Validity/query times must be exact int/float values, finite and within
-62135596800..253402300799 Unix seconds. Booleans and huge integers are refused.
Intervals are half-open [valid_from, valid_to), with null end meaning unbounded;
an explicit end must be greater than the start. No clock is consulted. Omitting
at returns all matching current records regardless of their validity intervals.

Values use exact built-in JSON dictionaries with string keys, lists, strings,
booleans, null, finite floats and integers within -(2**53-1)..(2**53-1). Tuples,
custom objects, invalid Unicode and nonfinite numbers are refused. A value is
limited to depth 16, 10000 visited values/keys and 64 KiB canonical JSON. Canonical
JSON sorts keys, uses compact separators and ASCII escapes; escaping counts
toward the byte cap. Callers parsing raw JSON must handle duplicate textual keys.

## Contradictions and corrections

A contradiction means the same exact tenant/subject/predicate, overlapping validity
and different canonical JSON values. Equality is type-sensitive: 1, 1.0 and true
are distinct; 0.0 and -0.0 also have distinct encodings. Dictionary key order is
irrelevant. There is no ontology, semantic equivalence or inference engine.

Every conflicting unresolved record is quarantined, including previously
quarantined records. A later assertion cannot bypass a dispute merely because
the earlier records left ACTIVE status. Results list all conflict_ids; legacy
conflicts_with exposes only the first ID. Conflicts quarantine entire records,
including portions of their intervals outside the overlap.

Quarantine is sticky: removing a conflict by correction does not automatically
reactivate older quarantined records. A new explicit correction may be ACTIVE
when it has no remaining conflicting unresolved record. Superseded records are
excluded from future conflict checks. No silent winner or automatic resolution
is selected.

correct requires an explicit tenant keyword and a nonempty dictionary of fact
fields. It inherits omitted fields, validates the merged fact, retains the old
content, supersedes the old record and creates a linked replacement. Subject,
predicate, source, value, confidence and validity may be corrected; tenant cannot
change. A fact can be corrected only once. All conflict/lineage/status changes
are prepared before commit; rejected corrections leave state and IDs unchanged.

lineage requires the same explicit tenant scope and returns the full chain of IDs
from root to latest replacement, starting from any chain member. It does not
return historical fact bodies. Superseded records remain internally retained.
Recall always excludes superseded records: at filters the validity of current
knowledge, not what the store knew at an earlier transaction time. This is not a
bitemporal or historical snapshot query API.

## Recall and tenant boundaries

recall(tenant, subject=None, predicate=None, at=None,
include_quarantined=False, limit=100, after_id=None) returns n02/recall/v2.
include_quarantined must be an exact boolean. limit is an exact integer 1..1000.
Results are sorted by generated fact ID and bounded to 1 MiB canonical response
bytes; the byte cap may return fewer records than requested. has_more/next_after
support continuation with the same filters. after_id has form fact-000001.

total_matching counts the complete filtered view. view_digest binds its ordered
IDs and current record digests; compare it across pages to detect changes in that
view. Pagination is not a persistent snapshot: concurrent corrections/assertions
may change results between requests. recall_digest binds the full page, filters,
pagination and evidence marker. Returned records and ledger views are detached.

Tenant arguments prevent accidental cross-tenant selection; they are not
authentication or authorization. Any caller holding the object can choose a
tenant label. The administrative ledger and verify summary cover the whole store.
Keep the object/ledger behind a trusted coordinator and enforce access separately
before exposing a tenant-facing API. Wrong-scope and missing IDs share one error.

The evidence-only marker is metadata. Stored text remains untrusted and may
contain instructions; downstream systems must keep it separate from instruction
authority. The library does not execute or sanitize that text.

## Integrity, concurrency and capacity

Each fact has an immutable content fact_digest. Its current record_digest also
binds schema, ID, status and correction links, so it changes on quarantine or
supersession. Each successful assertion/correction appends one sequenced event
binding its result and complete conflict list. Event digests describe that event's
historical record snapshot; the current record may later have a different digest.

A full state hash binds all retained records, ledger, ID counter and byte counter.
verify checks content/record/event digests, sequences, counters, reciprocal
same-tenant chronological lineage and supersession status. Normal reads and writes
fail closed on detected corruption via IntegrityError, a MemoryError_ subclass.
Hashes are unsigned consistency checks; a process owner can rewrite consistent
state and hashes. They do not authenticate sources, prove factual truth or provide
an externally anchored audit trail. No import/persistence interface is supplied.

An RLock serializes supported operations. Capacities are 1000 retained facts
(including superseded records), 16 MiB canonical fact-map bytes and 8 MiB ledger
bytes. Corrections consume another fact slot; capacity exhaustion can refuse them.
There is no pruning or deletion. Failed operations add no audit event. Mutations
copy prospective state and verify/hash retained data; costs grow with store size.
Bounds describe normal accepted workloads, not OS memory/time quotas. Do not
mutate caller inputs concurrently while the library validates them.

## Verification and migration

65 tests: 27 inherited plus 38 new regressions, including multiple/quarantined
conflicts, assertion order, interval bridges, canonical type distinctions, atomic
correction rejection, tenant scope, paging, full record/state tampering and racing
assertions/corrections. [CHECK_RUNS](docs/CHECK_RUNS.json) records source and
installed-wheel results. CI covers Linux Python 3.10/3.12/3.14 and Windows 3.12.
See [AUDIT](docs/AUDIT.md).

0.1.1-partial -> 0.1.2a1 adds v2 records/recall, complete record/event/state digests,
explicit tenant keywords for correct/lineage, pagination, stricter JSON/text/time
bounds and complete conflict lists. Update callers that relied on unlimited recall,
truthy flags, mutable public ledger data or Python's cross-type numeric equality.
Inherited tests were updated for explicit tenant arguments; behavior assertions
remain. Old/new recall and record receipts are not interchangeable.

Ontology, HDC/VSA, MSSL, persistence, 2PC and G0–G9 certification remain open.
The original 171-parent / 801-child program and N02-AUD-DEC-01..12 are outside
this partial candidate.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party source is vendored; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
