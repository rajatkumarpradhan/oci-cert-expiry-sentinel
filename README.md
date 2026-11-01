# oci-cert-expiry-sentinel

An **offline audit** of OCI-style certificate exports. It takes a JSON export of certificates (and optionally load-balancer listeners) and reports expiring and expired certificates, weak cryptography, and SAN coverage gaps - every finding cited to its exact record in the export. It **never fetches live certificates** or contacts any OCI service.

> **Portfolio project.** The included export is synthetic. No OCI account or live tenancy was connected or tested. The audit is static: it does not validate chain of trust, does not check revocation (OCSP/CRL), and does not prove what is actually serving traffic - it reports what the export shows.

## Quickstart

```bash
python -m pip install -e .
oci-cert-sentinel examples/certificates.json --now 2026-11-02T01:00:00Z --output report.json
python -m unittest discover -s tests -v
```

Input shape: `{"certificates": [{"name", "not_after", "signature_algorithm", "key_algorithm", "key_size", "sans": [...]}], "listeners": [{"name", "hostname", "port"}]}`. This is a **project-defined JSON interchange format**, not a claim that OCI exports certificates in this exact shape - convert your own export offline. `--now` pins the reference instant (RFC3339) so runs and tests are deterministic; default is current UTC.

The example export produces 7 findings: one expired legacy certificate (also SHA-1 signed with a 1024-bit key), one production certificate 2 days from expiry, one internal certificate expiring in 9 days that covers no listener, and one listener (`pay.example.com`) no unexpired certificate covers.

## Rules

| Rule | Severity | Meaning |
| --- | --- | --- |
| EXP001 | critical | certificate already expired |
| EXP002 / EXP003 / EXP004 | critical / high / medium | expires within 7 / 14 / 30 days |
| SIG001 | high | weak signature algorithm (MD2/MD5/SHA-1 family) |
| KEY001 | high | RSA key below 2048 bits, or EC key below 256 bits |
| SAN001 | low | unexpired certificate covers no listener hostname in the export (orphan, or used elsewhere) |
| SAN002 | high | listener hostname covered by no unexpired certificate in the export |
| SAN003 | medium | no SANs recorded, so coverage cannot be proven |
| BAD001 | high | unusable record (missing/unparseable `not_after`) - flagged, never silently skipped |

Hostname matching is exact or single-label wildcard (`*.example.com` matches `api.example.com`, not `deep.api.example.com` or the bare apex), per RFC 6125 wildcard semantics. Expired certificates neither cover listeners (they count as uncovered) nor count as orphans.

`--fail-on <severity>` exits 2 when any finding meets or beats that severity, so CI can gate on it. Unparseable records become BAD001 findings instead of crashing the audit.

## Verification in CI

Three gates run on every push: the unittest suite (19 tests across Python 3.10-3.12), `scripts/eval_gate.py` (6 fixture cases must classify exactly as expected - including a stack of simultaneous defects, wildcard coverage, and unparseable records), and a CLI smoke run over the example export with `--fail-on medium` asserting exit 2.

## Honest limits

- Static export audit only: no live fetch, no chain-of-trust validation, no revocation checking (OCSP/CRL), no proof of what is actually serving.
- Coverage pairing is exact/wildcard string matching within one export; certificates used outside the exported listeners are reported as orphans with that caveat in the message.
- Key/signature thresholds (RSA 2048, EC 256, SHA-1 family weak) are common industry baselines (e.g. CA/Browser Forum baseline requirements), not an Oracle rule.

## References

- Oracle, [Certificates service](https://docs.oracle.com/en-us/iaas/Content/certificates/home.htm): certificate management concepts this export models.
- RFC 6125: wildcard certificate name matching (single-label `*.` only).
