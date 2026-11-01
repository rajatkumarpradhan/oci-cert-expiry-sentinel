import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .audit import audit, load_export, worst_severity
from .rules import SEVERITY_ORDER, parse_instant


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline certificate expiry and config audit")
    parser.add_argument("export", help="JSON export, e.g. examples/certificates.json")
    parser.add_argument("--now", help="reference instant (RFC3339) for deterministic runs; default: current UTC")
    parser.add_argument("--output", help="report JSON path; default stdout")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                        help="exit 2 when any finding meets or beats this severity")
    args = parser.parse_args(argv)
    try:
        now = parse_instant(args.now, "--now") if args.now else datetime.now(timezone.utc)
        report = audit(load_export(args.export), now, Path(args.export).name)
    except ValueError as exc:
        parser.error(str(exc))
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    worst = worst_severity(report)
    if args.fail_on and worst and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[args.fail_on]:
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
