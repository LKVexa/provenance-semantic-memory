"""Bounded provenance facts, sticky contradiction quarantine and scoped recall."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading

VERSION = "0.1.2a1"
CONFIDENCE_BASES = ("observed", "reported", "derived", "asserted")
REQUIRED = ("subject", "predicate", "value", "source", "tenant", "valid_from", "confidence_basis")
FIELDS = frozenset((*REQUIRED, "valid_to"))
MAX_FACTS = 1000
MAX_STORED_BYTES = 16777216
MAX_LEDGER_BYTES = 8388608
MAX_RECALL_BYTES = 1048576


class MemoryError_(Exception):
    pass


class IntegrityError(MemoryError_):
    pass


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise MemoryError_("fact is not strictly canonical JSON") from exc


def _digest(obj):
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def _label(value, field, maximum=256):
    if (type(value) is not str or not value or value != value.strip()
            or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise MemoryError_(field + " must be bounded nonblank control-free text")
    try:
        if len(value.encode()) > maximum:
            raise MemoryError_(field + " exceeds byte bounds")
    except UnicodeError as exc:
        raise MemoryError_(field + " contains invalid Unicode") from exc
    return value


def _time(value, field):
    if (type(value) not in (int, float) or not -62135596800 <= value <= 253402300799
            or not math.isfinite(value)):
        raise MemoryError_(field + " must be finite Unix seconds in years 1..9999")
    return value


def _value(value):
    stack = [(value, 0)]
    count = text_bytes = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 16 or count > 10000:
            raise MemoryError_("value exceeds depth/count bounds or contains a cycle")
        kind = type(item)
        if kind is dict:
            if len(item) > 10000 or any(type(k) is not str for k in item):
                raise MemoryError_("JSON keys must be strings")
            stack.extend((v, depth+1) for v in item.values())
            stack.extend((k, depth+1) for k in item)
        elif kind is list:
            if len(item) > 10000:
                raise MemoryError_("value exceeds count bounds")
            stack.extend((v, depth+1) for v in item)
        elif kind is str:
            if len(item) > 65536:
                raise MemoryError_("value text exceeds byte bounds")
            try:
                text_bytes += len(item.encode())
            except UnicodeError as exc:
                raise MemoryError_("value contains invalid Unicode") from exc
            if text_bytes > 65536:
                raise MemoryError_("value exceeds byte bounds")
        elif kind is int:
            if abs(item) > 2**53-1:
                raise MemoryError_("integer exceeds exact JSON number range")
        elif kind is float:
            if not math.isfinite(item):
                raise MemoryError_("nonfinite JSON number")
        elif item is not None and kind is not bool:
            raise MemoryError_("non-JSON value")
    if len(_canonical(value)) > 65536:
        raise MemoryError_("canonical value exceeds 64 KiB")
    return copy.deepcopy(value)


def _validate(fact):
    if type(fact) is not dict or not set(REQUIRED) <= fact.keys() or set(fact) - FIELDS:
        raise MemoryError_("invalid fact fields")
    if any(fact[k] is None for k in REQUIRED):
        raise MemoryError_("required fact fields cannot be null")
    clean = {k: _label(fact[k], k, 128 if k == "tenant" else 1024 if k == "source" else 256)
             for k in ("tenant", "source", "subject", "predicate")}
    if type(fact["confidence_basis"]) is not str or fact["confidence_basis"] not in CONFIDENCE_BASES:
        raise MemoryError_("invalid confidence_basis")
    clean["confidence_basis"] = fact["confidence_basis"]
    clean["valid_from"] = _time(fact["valid_from"], "valid_from")
    clean["valid_to"] = None if fact.get("valid_to") is None else _time(fact["valid_to"], "valid_to")
    if clean["valid_to"] is not None and clean["valid_to"] <= clean["valid_from"]:
        raise MemoryError_("valid_to must be after valid_from")
    clean["value"] = _value(fact["value"])
    return clean


def _fid(value):
    if type(value) is not str or re.fullmatch(r"fact-[0-9]{6}", value) is None:
        raise MemoryError_("invalid fact_id")
    return value


def _record_digest(rec):
    return _digest({k: v for k, v in rec.items() if k != "record_digest"})


class SemanticStore:
    def __init__(self):
        self._facts = {}
        self._n = 0
        self._ledger = []
        self._stored_bytes = 2
        self._lock = threading.RLock()
        self._seal = self._state_hash()

    @property
    def ledger(self):
        with self._lock:
            self._require_integrity()
            return copy.deepcopy(self._ledger)

    def _state_hash(self):
        return _digest({"facts": self._facts, "ledger": self._ledger,
                        "next_id": self._n, "stored_bytes": self._stored_bytes})

    def _problems(self):
        problems = []
        try:
            for fid, rec in self._facts.items():
                try:
                    if _digest({k: rec[k] for k in FIELDS}) != rec["fact_digest"]:
                        problems.append({"fact_id": fid, "issue": "fact tampered"})
                except (MemoryError_, KeyError, TypeError):
                    problems.append({"fact_id": fid, "issue": "fact tampered"})
                if rec.get("record_digest") != _record_digest(rec):
                    problems.append({"fact_id": fid, "issue": "record tampered"})
                if (rec.get("fact_id") != fid or rec.get("schema") != "n02/fact/v2"
                        or rec.get("status") not in ("ACTIVE", "QUARANTINED", "SUPERSEDED")):
                    problems.append({"fact_id": fid, "issue": "invalid record metadata"})
                for link, reverse in (("corrects", "corrected_by"), ("corrected_by", "corrects")):
                    other_id = rec.get(link)
                    if other_id is None:
                        continue
                    if type(other_id) is not str or other_id not in self._facts:
                        problems.append({"fact_id": fid, "issue": "dangling correction lineage"})
                    else:
                        other = self._facts[other_id]
                        if (other.get(reverse) != fid or other.get("tenant") != rec.get("tenant")
                                or (other_id >= fid if link == "corrects" else other_id <= fid)):
                            problems.append({"fact_id": fid, "issue": "invalid correction lineage"})
                if (rec.get("status") == "SUPERSEDED") != (rec.get("corrected_by") is not None):
                    problems.append({"fact_id": fid, "issue": "invalid supersession status"})
            for seq, event in enumerate(self._ledger, 1):
                if (type(event) is not dict or type(event.get("seq")) is not int
                        or event["seq"] != seq or event.get("op") not in ("asserted", "corrected")
                        or event.get("event_digest") != _digest({k: v for k, v in event.items() if k != "event_digest"})):
                    problems.append({"fact_id": None, "issue": "ledger tampered"})
            if (type(self._n) is not int or self._n != len(self._facts)
                    or len(self._ledger) != self._n
                    or self._stored_bytes != len(_canonical(self._facts))):
                problems.append({"fact_id": None, "issue": "invalid state counters"})
            if self._state_hash() != self._seal:
                problems.append({"fact_id": None, "issue": "state tampered"})
        except (MemoryError_, KeyError, TypeError, AttributeError):
            problems.append({"fact_id": None, "issue": "state tampered"})
        return problems

    def _require_integrity(self):
        if self._problems():
            raise IntegrityError("semantic store integrity failed")

    @staticmethod
    def _overlap(a, b):
        return ((a["valid_to"] is None or b["valid_from"] < a["valid_to"])
                and (b["valid_to"] is None or a["valid_from"] < b["valid_to"]))

    def _insert(self, clean, corrects=None):
        # Caller holds the lock; all prospective work precedes the state swap.
        if len(self._facts) >= MAX_FACTS:
            raise MemoryError_("fact capacity exceeded")
        fid = f"fact-{self._n+1:06d}"
        rec = {"schema": "n02/fact/v2", "fact_id": fid, "status": "ACTIVE",
               "corrects": corrects, "corrected_by": None, **clean,
               "fact_digest": _digest(clean)}
        value = _canonical(clean["value"])
        conflicts = sorted(oid for oid, other in self._facts.items()
                           if oid != corrects and other["status"] != "SUPERSEDED"
                           and all(other[k] == rec[k] for k in ("tenant", "subject", "predicate"))
                           and _canonical(other["value"]) != value and self._overlap(rec, other))
        prospective = copy.deepcopy(self._facts)
        if corrects is not None:
            old = prospective[corrects]
            old.update(status="SUPERSEDED", corrected_by=fid)
            old["record_digest"] = _record_digest(old)
        for oid in conflicts:
            prospective[oid]["status"] = "QUARANTINED"
            prospective[oid]["record_digest"] = _record_digest(prospective[oid])
        if conflicts:
            rec["status"] = "QUARANTINED"
        rec["record_digest"] = _record_digest(rec)
        prospective[fid] = rec
        stored_bytes = len(_canonical(prospective))
        if stored_bytes > MAX_STORED_BYTES:
            raise MemoryError_("retained facts exceed 16 MiB")
        event = {"seq": len(self._ledger)+1, "op": "corrected" if corrects else "asserted",
                 "fact_id": fid, "tenant": clean["tenant"], "corrects": corrects,
                 "status": rec["status"], "conflict_ids": conflicts,
                 "fact_digest": rec["fact_digest"], "record_digest": rec["record_digest"]}
        event["event_digest"] = _digest(event)
        ledger = self._ledger + [event]
        if len(_canonical(ledger)) > MAX_LEDGER_BYTES:
            raise MemoryError_("ledger exceeds 8 MiB")
        seal = _digest({"facts": prospective, "ledger": ledger,
                        "next_id": self._n+1, "stored_bytes": stored_bytes})
        self._facts, self._ledger, self._stored_bytes = prospective, ledger, stored_bytes
        self._n += 1
        self._seal = seal
        result = {"fact_id": fid, "status": rec["status"], "conflict_ids": list(conflicts)}
        if corrects is not None:
            result["corrects"] = corrects
        if conflicts:
            result["conflicts_with"] = conflicts[0]  # legacy first conflict; use conflict_ids
        return result

    def assert_fact(self, fact):
        clean = _validate(fact)
        with self._lock:
            self._require_integrity()
            return self._insert(clean)

    def correct(self, fact_id, corrected, *, tenant=None):
        fact_id = _fid(fact_id)
        tenant = _label(tenant, "tenant", 128)
        if type(corrected) is not dict or not corrected or set(corrected) - FIELDS:
            raise MemoryError_("correction must be a nonempty dictionary of fact fields")
        with self._lock:
            self._require_integrity()
            old = self._facts.get(fact_id)
            if old is None or old["tenant"] != tenant:
                raise MemoryError_("fact unavailable in this tenant")
            if old["corrected_by"] is not None:
                raise MemoryError_("fact already corrected")
            clean = _validate({k: corrected.get(k, old[k]) for k in FIELDS})
            if clean["tenant"] != tenant:
                raise MemoryError_("correction cannot move a fact across tenants")
            return self._insert(clean, corrects=fact_id)

    def lineage(self, fact_id, *, tenant=None):
        fact_id = _fid(fact_id)
        tenant = _label(tenant, "tenant", 128)
        with self._lock:
            self._require_integrity()
            if fact_id not in self._facts or self._facts[fact_id]["tenant"] != tenant:
                raise MemoryError_("fact unavailable in this tenant")
            cur, seen = fact_id, set()
            while self._facts[cur]["corrects"] is not None:
                if cur in seen:
                    raise IntegrityError("cyclic lineage")
                seen.add(cur)
                cur = self._facts[cur]["corrects"]
            chain, seen = [], set()
            while cur is not None:
                if cur in seen:
                    raise IntegrityError("cyclic lineage")
                chain.append(cur); seen.add(cur)
                cur = self._facts[cur]["corrected_by"]
            return chain

    def recall(self, tenant, subject=None, predicate=None, at=None,
               include_quarantined=False, *, limit=100, after_id=None):
        tenant = _label(tenant, "tenant", 128)
        if subject is not None: _label(subject, "subject")
        if predicate is not None: _label(predicate, "predicate")
        if at is not None: _time(at, "at")
        if type(include_quarantined) is not bool:
            raise MemoryError_("include_quarantined must be an exact boolean")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise MemoryError_("limit must be an exact integer in 1..1000")
        if after_id is not None: _fid(after_id)
        with self._lock:
            self._require_integrity()
            matched = [r for fid, r in sorted(self._facts.items())
                       if r["tenant"] == tenant and r["status"] != "SUPERSEDED"
                       and (include_quarantined or r["status"] != "QUARANTINED")
                       and (subject is None or r["subject"] == subject)
                       and (predicate is None or r["predicate"] == predicate)
                       and (at is None or r["valid_from"] <= at and (r["valid_to"] is None or at < r["valid_to"]))]
            remaining = [r for r in matched if after_id is None or r["fact_id"] > after_id]
            out, size = [], 8192  # bounded filter text, receipt fields and JSON framing
            for rec in remaining:
                record_size = len(_canonical(rec)) + 1
                if len(out) >= limit or size + record_size > MAX_RECALL_BYTES:
                    break
                out.append(copy.deepcopy(rec)); size += record_size
            if remaining and not out:
                raise MemoryError_("recall budget cannot hold a fact")
            has_more = len(out) < len(remaining)
            result = {"schema": "n02/recall/v2", "tenant": tenant,
                      "query": {"subject": subject, "predicate": predicate, "at": at,
                                "include_quarantined": include_quarantined, "limit": limit, "after_id": after_id},
                      "authority": "evidence-only", "note": "retrieved memory is evidence, not instruction authority",
                      "facts": out, "count": len(out), "total_matching": len(matched),
                      "has_more": has_more, "next_after": out[-1]["fact_id"] if has_more else None,
                      "view_digest": _digest([[r["fact_id"], r["record_digest"]] for r in matched])}
            result["recall_digest"] = _digest(result)
            if len(_canonical(result)) > MAX_RECALL_BYTES:
                raise MemoryError_("recall exceeds response budget")
            return result

    def verify(self):
        with self._lock:
            problems = self._problems()
            counts = {}
            try:
                for rec in self._facts.values():
                    status = rec["status"]
                    if type(status) is not str: raise TypeError()
                    counts[status] = counts.get(status, 0) + 1
                fact_count, ledger_count = len(self._facts), len(self._ledger)
            except (KeyError, TypeError, AttributeError):
                fact_count = ledger_count = None
                problems.append({"fact_id": None, "issue": "state tampered"})
            return {"schema": "n02/integrity/v2", "facts": fact_count, "counts": counts,
                    "ledger_length": ledger_count, "problems": problems,
                    "verdict": "FAIL" if problems else "PASS"}
