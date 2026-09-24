# Security boundaries

This in-memory store holds caller-declared facts as untrusted evidence. Source,
confidence and validity labels do not prove truth. The evidence-only marker is
not prompt-injection protection; consumers must separate data from instructions.
The library performs no network calls, file writes or execution of stored text.

Tenant scope is a selection guard, not authorization. Any object holder can choose
another tenant; ledger and verify expose administrative whole-store information.
Enforce caller permissions outside this object before exposing a service API.

Hashes detect consistency changes, not an owner rewriting private state and hashes.
No authenticated provenance, persistence, external anchoring or rollback protection
is provided. Recall excludes superseded records even for past validity times; it
does not reconstruct prior knowledge. Quarantine is conservative and sticky, not
a factual judgment. Capacity exhaustion may refuse further corrections, and full
state copies/hashes have growing costs. No independent security audit, build-tool
vulnerability scan or full original certification is claimed.
