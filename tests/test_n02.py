import unittest
from pathlib import Path

from n02.core import MemoryError_, SemanticStore


def fact(**kw):
    base = {"subject": "svc-api", "predicate": "owner", "value": "team-a",
            "source": "cmdb", "tenant": "t1", "valid_from": 100.0,
            "confidence_basis": "reported"}
    base.update(kw)
    return base


class Assertion(unittest.TestCase):
    def setUp(self):
        self.s = SemanticStore()

    def test_required_fields_and_bases(self):
        with self.assertRaises(MemoryError_):
            self.s.assert_fact({"subject": "x"})
        with self.assertRaises(MemoryError_):
            self.s.assert_fact(fact(confidence_basis="vibes"))
        with self.assertRaises(MemoryError_):
            self.s.assert_fact(fact(valid_to=50.0))

    def test_assert_with_digest(self):
        r = self.s.assert_fact(fact())
        self.assertEqual(r["status"], "ACTIVE")
        rec = self.s._facts[r["fact_id"]]
        self.assertTrue(rec["fact_digest"].startswith("sha256:"))


class Contradiction(unittest.TestCase):
    def setUp(self):
        self.s = SemanticStore()
        self.a = self.s.assert_fact(fact())["fact_id"]

    def test_conflicting_fact_quarantines_both(self):
        r = self.s.assert_fact(fact(value="team-b"))
        self.assertEqual(r["status"], "QUARANTINED")
        self.assertEqual(r["conflicts_with"], self.a)
        self.assertEqual(self.s._facts[self.a]["status"], "QUARANTINED")
        # neither is served by default recall
        self.assertEqual(self.s.recall("t1")["count"], 0)
        self.assertEqual(
            self.s.recall("t1", include_quarantined=True)["count"], 2)

    def test_same_value_not_contradiction(self):
        r = self.s.assert_fact(fact())
        self.assertEqual(r["status"], "ACTIVE")

    def test_disjoint_validity_not_contradiction(self):
        s = SemanticStore()
        s.assert_fact(fact(valid_from=100.0, valid_to=200.0))
        r = s.assert_fact(fact(value="team-b", valid_from=200.0))
        self.assertEqual(r["status"], "ACTIVE")


class Correction(unittest.TestCase):
    def setUp(self):
        self.s = SemanticStore()
        self.a = self.s.assert_fact(fact())["fact_id"]

    def test_correction_supersedes_with_lineage(self):
        r = self.s.correct(self.a, {"value": "team-b"}, tenant="t1")
        old = self.s._facts[self.a]
        self.assertEqual(old["status"], "SUPERSEDED")
        self.assertEqual(old["corrected_by"], r["fact_id"])
        self.assertEqual(self.s.lineage(r["fact_id"], tenant="t1"),
                         [self.a, r["fact_id"]])
        rec = self.s.recall("t1")
        self.assertEqual(rec["count"], 1)
        self.assertEqual(rec["facts"][0]["value"], "team-b")

    def test_double_correction_refused(self):
        self.s.correct(self.a, {"value": "team-b"}, tenant="t1")
        with self.assertRaises(MemoryError_):
            self.s.correct(self.a, {"value": "team-c"}, tenant="t1")

    def test_correction_cannot_cross_tenants(self):
        with self.assertRaises(MemoryError_):
            self.s.correct(self.a, {"tenant": "t2"}, tenant="t1")


class Recall(unittest.TestCase):
    def setUp(self):
        self.s = SemanticStore()
        self.s.assert_fact(fact())
        self.s.assert_fact(fact(subject="svc-db", value="team-b",
                                tenant="t2"))

    def test_tenant_isolation_structural(self):
        r1 = self.s.recall("t1")
        self.assertEqual(r1["count"], 1)
        self.assertTrue(all(f["tenant"] == "t1" for f in r1["facts"]))
        self.assertEqual(self.s.recall("t3")["count"], 0)

    def test_evidence_only_authority(self):
        r = self.s.recall("t1")
        self.assertEqual(r["authority"], "evidence-only")
        self.assertIn("not instruction authority", r["note"])

    def test_point_in_time_validity(self):
        s = SemanticStore()
        s.assert_fact(fact(valid_from=100.0, valid_to=200.0))
        self.assertEqual(s.recall("t1", at=150.0)["count"], 1)
        self.assertEqual(s.recall("t1", at=250.0)["count"], 0)
        self.assertEqual(s.recall("t1", at=50.0)["count"], 0)


class Integrity(unittest.TestCase):
    def test_verify_pass_and_tamper(self):
        s = SemanticStore()
        fid = s.assert_fact(fact())["fact_id"]
        self.assertEqual(s.verify()["verdict"], "PASS")
        s._facts[fid]["value"] = "evil"
        rep = s.verify()
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertEqual(rep["problems"][0]["issue"], "fact tampered")

    def test_no_network_imports(self):
        import n02.core as m
        imports = " ".join(l for l in Path(m.__file__).read_text(encoding="utf-8").splitlines()
                           if l.startswith(("import ", "from ")))
        for bad in ("socket", "http", "urllib", "requests"):
            self.assertNotIn(bad, imports)


if __name__ == "__main__":
    unittest.main()


# ---- 0.1.1-partial hardening tests (findings A028-F1..F6) -----------

def _fact(**kw):
    base = {"subject": "svc-api", "predicate": "owner", "value": "team-a",
            "source": "cmdb", "tenant": "t1", "valid_from": 100.0,
            "confidence_basis": "reported"}
    base.update(kw)
    return base


class AliasingIsolation(unittest.TestCase):
    """A028-F1: caller-side mutation must never reach the store."""

    def test_input_mutation_does_not_tamper_store(self):
        s = SemanticStore()
        v = {"team": "a"}
        fid = s.assert_fact(_fact(value=v))["fact_id"]
        v["team"] = "EVIL"
        self.assertEqual(s._facts[fid]["value"], {"team": "a"})
        self.assertEqual(s.verify()["verdict"], "PASS")

    def test_recall_result_mutation_does_not_tamper_store(self):
        s = SemanticStore()
        fid = s.assert_fact(_fact(value={"team": "a"}))["fact_id"]
        s.recall("t1")["facts"][0]["value"]["team"] = "EVIL"
        self.assertEqual(s._facts[fid]["value"], {"team": "a"})
        self.assertEqual(s.verify()["verdict"], "PASS")

    def test_correction_input_isolated(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        newv = {"team": "b"}
        r = s.correct(a, {"value": newv}, tenant="t1")
        newv["team"] = "EVIL"
        self.assertEqual(s._facts[r["fact_id"]]["value"], {"team": "b"})


class ErrorContract(unittest.TestCase):
    """A028-F2/F3: only MemoryError_ escapes; NaN/non-numeric refused."""

    def test_non_numeric_validity_raises_memory_error(self):
        s = SemanticStore()
        with self.assertRaises(MemoryError_):
            s.assert_fact(_fact(valid_from="abc", valid_to=200.0))
        with self.assertRaises(MemoryError_):
            s.assert_fact(_fact(valid_to="later"))

    def test_bool_validity_refused(self):
        s = SemanticStore()
        with self.assertRaises(MemoryError_):
            s.assert_fact(_fact(valid_from=True))

    def test_non_canonicalizable_value_raises_memory_error(self):
        s = SemanticStore()
        with self.assertRaises(MemoryError_):
            s.assert_fact(_fact(value={1, 2}))
        self.assertEqual(len(s._facts), 0)  # no partial state

    def test_nan_and_inf_validity_refused(self):
        s = SemanticStore()
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(MemoryError_):
                s.assert_fact(_fact(valid_from=bad))
            with self.assertRaises(MemoryError_):
                s.assert_fact(_fact(valid_to=bad))

    def test_finite_validity_still_accepted(self):
        s = SemanticStore()
        r = s.assert_fact(_fact(valid_from=1, valid_to=2.5))
        self.assertEqual(r["status"], "ACTIVE")


class CorrectionHardening(unittest.TestCase):
    """A028-F4/F5: corrections obey schema + contradiction containment."""

    def test_correction_cannot_bypass_contradiction_check(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        b = s.assert_fact(_fact(subject="other"))["fact_id"]
        r = s.correct(b, {"subject": "svc-api", "value": "DIFFERENT"}, tenant="t1")
        self.assertEqual(r["status"], "QUARANTINED")
        self.assertEqual(r["conflicts_with"], a)
        self.assertEqual(s._facts[a]["status"], "QUARANTINED")
        self.assertEqual(s.recall("t1", subject="svc-api")["count"], 0)

    def test_non_conflicting_correction_stays_active(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        r = s.correct(a, {"value": "team-b"}, tenant="t1")
        self.assertEqual(r["status"], "ACTIVE")

    def test_correction_validates_fields(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        with self.assertRaises(MemoryError_):
            s.correct(a, {"confidence_basis": "vibes"}, tenant="t1")
        with self.assertRaises(MemoryError_):
            s.correct(a, {"valid_from": 300.0, "valid_to": 10.0}, tenant="t1")
        with self.assertRaises(MemoryError_):
            s.correct(a, {"valid_from": float("nan")}, tenant="t1")
        # refused corrections must not supersede the original
        self.assertEqual(s._facts[a]["status"], "ACTIVE")
        self.assertIsNone(s._facts[a]["corrected_by"])


class LineageIntegrity(unittest.TestCase):
    """A028-F6: broken lineage detected, never a bare KeyError."""

    def test_verify_flags_dangling_corrected_by(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        s._facts[a]["corrected_by"] = "fact-999999"
        rep = s.verify()
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertIn("dangling correction lineage",
                      [p["issue"] for p in rep["problems"]])

    def test_lineage_broken_link_raises_memory_error(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        s._facts[a]["corrected_by"] = "fact-999999"
        with self.assertRaises(MemoryError_):
            s.lineage(a, tenant="t1")
        s._facts[a]["corrected_by"] = None
        s._facts[a]["corrects"] = "fact-888888"
        with self.assertRaises(MemoryError_):
            s.lineage(a, tenant="t1")

    def test_verify_handles_non_canonical_tamper(self):
        s = SemanticStore()
        a = s.assert_fact(_fact())["fact_id"]
        s._facts[a]["value"] = {1, 2}   # tamper with unserializable value
        rep = s.verify()
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertEqual(rep["problems"][0]["issue"], "fact tampered")
