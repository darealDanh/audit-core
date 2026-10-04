#!/usr/bin/env python3
"""audit.py - verb dispatch for the audit suite."""
import argparse
import dataclasses
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import audit_core  # noqa: E402
from audit_core import budget as budget_mod       # noqa: E402
from audit_core import transcript as transcript_mod  # noqa: E402


def cmd_selftest(_args: argparse.Namespace) -> int:
    print(f"audit_core {audit_core.__version__} ok")
    return 0


def cmd_budget(args: argparse.Namespace) -> int:
    payloads = []
    for raw in args.report:
        path = pathlib.Path(raw).expanduser()
        if not path.is_file():
            print(f"not found: {path}", file=sys.stderr)
            return 1
        blob = path.read_bytes()
        provenance = {
            "source_bytes": len(blob),
            "source_sha256": hashlib.sha256(blob).hexdigest(),
        }
        payloads.append((budget_mod.analyze(transcript_mod.parse(path)), provenance))
    if args.json:
        print(json.dumps(
            [dataclasses.asdict(r) | p for r, p in payloads], indent=2))
    else:
        for r, p in payloads:
            print(budget_mod.render(r))
            print(f"  source_bytes {p['source_bytes']:,}   "
                  f"source_sha256 {p['source_sha256'][:16]}")
            print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit.py")
    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("selftest", help="verify the vendored core is importable")
    b = sub.add_parser("budget", help="economics report for session transcripts")
    b.add_argument("--report", nargs="+", required=True, metavar="JSONL")
    b.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"selftest": cmd_selftest, "budget": cmd_budget}[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
