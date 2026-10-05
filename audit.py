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
from audit_core import bench as bench_mod      # noqa: E402
from audit_core import goldens as goldens_mod  # noqa: E402
from audit_core import workspace as workspace_mod  # noqa: E402


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


def cmd_bench(args: argparse.Namespace) -> int:
    golden = pathlib.Path(args.golden).expanduser()
    db = pathlib.Path(args.db).expanduser()
    if not (golden / "reference.json").is_file():
        print(f"not found: {golden / 'reference.json'}", file=sys.stderr)
        return 1
    if not db.is_file():
        print(f"not found: {db}", file=sys.stderr)
        return 1

    refs = goldens_mod.load_reference(golden / "reference.json")
    adjudicated = goldens_mod.load_matches(golden / "matches.json")
    findings = bench_mod.load_findings_from_db(db)
    result = bench_mod.score(refs, findings, adjudicated, cost_usd=args.cost)

    if args.json:
        print(json.dumps(dataclasses.asdict(result), indent=2))
        return 0

    print(f"golden   {golden.name}")
    print(f"recall   {len(result.matched)}/{result.reference_count} "
          f"({100 * result.recall:.1f}%)")
    print(f"findings {result.finding_count}")
    if result.cost_per_match is not None:
        print(f"cost per matched finding  ${result.cost_per_match:.2f}")
    if result.unmatched_references:
        print("missed:     " + ", ".join(result.unmatched_references))
    if result.candidates:
        print("candidates needing adjudication:")
        for c in result.candidates:
            print(f"  {c.reference_id} ~ {c.finding_id}  ({c.reason})")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    run = workspace_mod.init_run(args.root, timestamp=args.timestamp)
    print(f"tables: {', '.join(workspace_mod.apply_schema(run / 'audit.db'))}")
    print(run)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit.py")
    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("selftest", help="verify the vendored core is importable")
    b = sub.add_parser("budget", help="economics report for session transcripts")
    b.add_argument("--report", nargs="+", required=True, metavar="JSONL")
    b.add_argument("--json", action="store_true")
    n = sub.add_parser("bench", help="score a run against a golden reference set")
    n.add_argument("--golden", required=True, metavar="DIR")
    n.add_argument("--db", required=True, metavar="AUDIT_DB")
    n.add_argument("--cost", type=float, default=None)
    n.add_argument("--json", action="store_true")
    i = sub.add_parser("init", help="create an audit run directory and its schema")
    i.add_argument("--root", default=".", metavar="DIR")
    i.add_argument("--timestamp", default=None, metavar="TS")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"selftest": cmd_selftest, "budget": cmd_budget,
            "bench": cmd_bench, "init": cmd_init}[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
