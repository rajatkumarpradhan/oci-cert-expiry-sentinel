"""Expiry ladder, crypto strength, wildcard matching and coverage pairing."""
import unittest
from datetime import datetime, timezone
from pathlib import Path

from oci_cert_sentinel import (audit, audit_listeners, hostname_matches,
                               load_export, worst_severity)
from oci_cert_sentinel.rules import audit_certificate, parse_instant

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
FIXTURES = Path(__file__).resolve().parents[1] / "examples"


def cert(**kw):
    base = {"name": "c", "not_after": "2027-01-01T00:00:00Z",
            "signature_algorithm": "sha256WithRSAEncryption",
            "key_algorithm": "RSA", "key_size": 2048, "sans": ["a.example.com"]}
    base.update(kw)
    return base


class ExpiryLadderTests(unittest.TestCase):
    def rules(self, c):
        return {f.rule for f in audit_certificate(c, 0, "t", NOW)}

    def test_expired_is_critical(self):
        found = self.rules(cert(not_after="2026-10-01T00:00:00Z"))
        self.assertIn("EXP001", found)
        self.assertNotIn("EXP002", found)

    def test_ladder_boundaries(self):
        self.assertEqual(self.rules(cert(not_after="2026-11-08T00:00:00Z")), {"EXP002"})  # 6 days
        self.assertEqual(self.rules(cert(not_after="2026-11-15T00:00:00Z")), {"EXP003"})  # 13 days
        self.assertEqual(self.rules(cert(not_after="2026-12-01T00:00:00Z")), {"EXP004"})  # 29 days
        self.assertEqual(self.rules(cert(not_after="2027-06-01T00:00:00Z")), set())

    def test_bad_record_never_crashes(self):
        f = audit_certificate({"name": "broken"}, 3, "t", NOW)
        self.assertEqual([x.rule for x in f], ["BAD001"])
        f = audit_certificate(cert(not_after="soon"), 0, "t", NOW)
        self.assertEqual([x.rule for x in f], ["BAD001"])


class CryptoStrengthTests(unittest.TestCase):
    def rules(self, c):
        return {f.rule for f in audit_certificate(c, 0, "t", NOW)}

    def test_weak_signature(self):
        self.assertIn("SIG001", self.rules(cert(signature_algorithm="sha1WithRSAEncryption")))
        self.assertNotIn("SIG001", self.rules(cert()))

    def test_small_keys(self):
        self.assertIn("KEY001", self.rules(cert(key_size=1024)))
        self.assertIn("KEY001", self.rules(cert(key_algorithm="EC", key_size=192)))
        self.assertNotIn("KEY001", self.rules(cert(key_algorithm="EC", key_size=256)))


class WildcardTests(unittest.TestCase):
    def test_exact_and_wildcard(self):
        self.assertTrue(hostname_matches("api.example.com", "api.example.com"))
        self.assertTrue(hostname_matches("*.example.com", "api.example.com"))
        self.assertFalse(hostname_matches("*.example.com", "deep.api.example.com"))
        self.assertFalse(hostname_matches("*.example.com", "example.com"))
        self.assertFalse(hostname_matches("api.example.com", "www.example.com"))
        self.assertTrue(hostname_matches("API.Example.com.", "api.example.com"))


class CoverageTests(unittest.TestCase):
    def test_orphan_and_uncovered(self):
        certs = [cert(name="orphan", sans=["zzz.other.com"]), cert(name="used")]
        listeners = [{"name": "l1", "hostname": "a.example.com"},
                     {"name": "l2", "hostname": "pay.example.com"}]
        rules = {f.rule for f in audit_listeners(certs, listeners, "t", NOW)}
        self.assertIn("SAN001", rules)   # orphan cert
        self.assertIn("SAN002", rules)   # uncovered listener
        self.assertNotIn("SAN003", rules)

    def test_expired_cert_does_not_cover(self):
        certs = [cert(not_after="2020-01-01T00:00:00Z")]
        listeners = [{"name": "l1", "hostname": "a.example.com"}]
        rules = {f.rule for f in audit_listeners(certs, listeners, "t", NOW)}
        self.assertIn("SAN002", rules)      # expired cert covers nothing
        self.assertNotIn("SAN001", rules)   # and is not an orphan either


class ReportTests(unittest.TestCase):
    def test_example_export_summary_and_citations(self):
        report = audit(load_export(FIXTURES / "certificates.json"), NOW, "certificates.json")
        self.assertEqual(report["certificates"], 4)
        self.assertEqual(report["summary"]["critical"], 2)  # legacy expired + api 3 days
        self.assertEqual(worst_severity(report), "critical")
        rules = [f["rule"] for f in report["findings"]]
        self.assertEqual(rules.count("SAN002"), 1)          # pay.example.com uncovered
        self.assertTrue(all("#" in f["citation"] for f in report["findings"]))
        self.assertIn("no revocation", report["limits"])
        # deterministic ordering: most severe first
        sevs = [f["severity"] for f in report["findings"]]
        self.assertEqual(sevs, sorted(sevs, key=lambda s: -{"critical": 3, "high": 2, "medium": 1, "low": 0}[s]))


class ParseTests(unittest.TestCase):
    def test_naive_instant_gets_utc(self):
        self.assertEqual(parse_instant("2026-11-02T01:00:00", "t").tzinfo, timezone.utc)
        with self.assertRaises(ValueError):
            parse_instant("tomorrow", "t")


if __name__ == "__main__":
    unittest.main()
