"""Deterministic certificate expiry and configuration audit rules.

Every rule is a small documented check over a JSON export. The auditor never
fetches live certificates, validates chain of trust, or checks revocation;
it reports what a static export shows, with citations to the export index.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# (rule, max days to expiry, severity) - expiry ladder
EXPIRY_LADDER = [
    ("EXP002", 7, "critical"),
    ("EXP003", 14, "high"),
    ("EXP004", 30, "medium"),
]
WEAK_SIGNATURES = ("md2", "md5", "sha1")
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    citation: str
    message: str


def parse_instant(value: str, what: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError) as e:
        raise ValueError(f"{what}: unparseable RFC3339 instant {value!r}") from e


def hostname_matches(pattern: str, hostname: str) -> bool:
    """Exact match, or RFC 6125-style single-label wildcard (*.example.com)."""
    pattern, hostname = pattern.lower().rstrip("."), hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not hostname.endswith("." + suffix):
            return False
        return hostname[: -(len(suffix) + 1)].count(".") == 0
    return pattern == hostname


def audit_certificate(cert: dict, index: int, source: str, now: datetime) -> list[Finding]:
    citation = f"{source}#certificate-{index}"
    findings = []
    name = cert.get("name", f"certificate-{index}")
    try:
        not_after = parse_instant(cert["not_after"], f"{citation} not_after")
    except (KeyError, ValueError) as e:
        return [Finding("BAD001", "high", citation, f"{name}: unusable record ({e}); verify it manually")]
    days = (not_after - now).days
    if not_after <= now:
        findings.append(Finding("EXP001", "critical", citation,
                                f"{name}: EXPIRED {abs(days)} day(s) ago (not_after {cert['not_after']})"))
    else:
        for rule, max_days, severity in EXPIRY_LADDER:
            if days <= max_days:
                findings.append(Finding(rule, severity, citation,
                                        f"{name}: expires in {days} day(s) on {cert['not_after']}"))
                break
    sig = str(cert.get("signature_algorithm", "")).lower()
    if any(w in sig for w in WEAK_SIGNATURES):
        findings.append(Finding("SIG001", "high", citation,
                                f"{name}: weak signature algorithm {cert.get('signature_algorithm')!r}"))
    key_alg = str(cert.get("key_algorithm", "")).upper()
    size = cert.get("key_size")
    if key_alg == "RSA" and isinstance(size, int) and size < MIN_RSA_BITS:
        findings.append(Finding("KEY001", "high", citation,
                                f"{name}: RSA key {size} bits below {MIN_RSA_BITS}"))
    if key_alg == "EC" and isinstance(size, int) and size < MIN_EC_BITS:
        findings.append(Finding("KEY001", "high", citation,
                                f"{name}: EC key {size} bits below {MIN_EC_BITS}"))
    return findings


def audit_listeners(certs: list[dict], listeners: list[dict], source: str,
                    now: datetime) -> list[Finding]:
    """Coverage pairing: orphan certs and uncovered listener hostnames."""
    findings = []
    valid = [c for c in certs if "not_after" in c
             and parse_instant(c["not_after"], "not_after") > now]
    hostnames = [str(l.get("hostname", "")) for l in listeners if l.get("hostname")]
    for i, cert in enumerate(certs):
        if cert not in valid:
            continue
        sans = [str(s) for s in cert.get("sans", [])]
        if not sans:
            findings.append(Finding("SAN003", "medium", f"{source}#certificate-{i}",
                                    f"{cert.get('name', i)}: no SANs recorded; cannot prove any coverage"))
            continue
        if hostnames and not any(hostname_matches(s, h) for s in sans for h in hostnames):
            findings.append(Finding("SAN001", "low", f"{source}#certificate-{i}",
                                    f"{cert.get('name', i)}: SANs cover no listener hostname in this export (orphan or used elsewhere)"))
    for j, listener in enumerate(listeners):
        host = str(listener.get("hostname", ""))
        if not host:
            continue
        covered = any(hostname_matches(s, host) for c in valid for s in [str(x) for x in c.get("sans", [])])
        if not covered:
            findings.append(Finding("SAN002", "high", f"{source}#listener-{j}",
                                    f"listener {listener.get('name', j)} ({host}): no unexpired certificate in this export covers it"))
    return findings
