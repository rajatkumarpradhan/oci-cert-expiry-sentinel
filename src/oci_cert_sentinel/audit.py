"""Load an export, run all rules, and build the review report."""
from __future__ import annotations

import json
from pathlib import Path

from .rules import (SEVERITY_ORDER, Finding, audit_certificate, audit_listeners,
                    parse_instant)


def load_export(path) -> dict:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        assert isinstance(raw.get("certificates"), list), "missing 'certificates' list"
        assert isinstance(raw.get("listeners", []), list)
        return raw
    except (OSError, json.JSONDecodeError, AssertionError) as e:
        raise ValueError(f"cannot load certificate export {path}: {e}") from e


def audit(export: dict, now, source: str = "export") -> dict:
    findings: list[Finding] = []
    certs = export["certificates"]
    for i, cert in enumerate(certs):
        if not isinstance(cert, dict):
            findings.append(Finding("BAD001", "high", f"{source}#certificate-{i}",
                                    "unusable record (not an object); verify it manually"))
            continue
        findings += audit_certificate(cert, i, source, now)
    findings += audit_listeners(certs, export.get("listeners", []), source, now)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    return {
        "generated_at": now.isoformat(),
        "certificates": len(certs),
        "listeners": len(export.get("listeners", [])),
        "findings": [f.__dict__ for f in sorted(
            findings, key=lambda f: -SEVERITY_ORDER[f.severity])],
        "summary": counts | {"total": len(findings)},
        "limits": ("Static export audit: no live certificate fetch, no chain-of-trust "
                   "validation, no revocation (OCSP/CRL) check. Pairing coverage uses "
                   "exact and single-label wildcard matching only."),
    }


def worst_severity(report: dict) -> str | None:
    for s in ("critical", "high", "medium", "low"):
        if report["summary"].get(s):
            return s
    return None
