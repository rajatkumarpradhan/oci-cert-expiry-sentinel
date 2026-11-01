"""Misclassification eval gate: fixture cases must produce the expected rule set."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oci_cert_sentinel import audit

def main() -> int:
    fixture = json.loads((Path(__file__).resolve().parents[1] / "examples" / "eval-fixture.json").read_text())
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    failures = 0
    for i, case in enumerate(fixture["cases"], 1):
        report = audit({"certificates": [case["certificate"]],
                        "listeners": case.get("listeners", [])}, now, "eval-fixture")
        got = sorted({f["rule"] for f in report["findings"]})
        want = sorted(case["expect_rules"])
        ok = got == want
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} case {i}: {case['name']}"
              + ("" if ok else f"  expected {want}, got {got}"))
    print(f"eval gate: {len(fixture['cases']) - failures}/{len(fixture['cases'])} cases classified as expected")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
