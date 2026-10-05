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
from audit_core import preflight as preflight_mod  # noqa: E402
from audit_core import briefs as briefs_mod  # noqa: E402
from audit_core import skill_lint as skill_lint_mod  # noqa: E402
from audit_core import db as db_mod  # noqa: E402


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


def cmd_preflight(args: argparse.Namespace) -> int:
    servers: dict[str, dict] = {}
    if args.keep:
        if not args.from_config:
            print("--keep requires --from-config PATH", file=sys.stderr)
            return 1
        try:
            servers.update(preflight_mod.load_servers(args.from_config, args.keep))
        except preflight_mod.PreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    elif args.from_config:
        print("--from-config requires at least one --keep NAME", file=sys.stderr)
        return 1
    for spec in args.server:
        name, sep, command = spec.partition("=")
        if not sep or not name or not command:
            print(f"bad --server {spec!r}; expected NAME=COMMAND", file=sys.stderr)
            return 1
        servers[name] = {"command": command}
    out = pathlib.Path(args.out).expanduser()
    try:
        preflight_mod.write_config(out, servers, force=args.force)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"wrote {out} with {len(servers)} server(s): {', '.join(sorted(servers)) or '(none)'}")
    if not servers:
        print("warning: no servers written - relaunching strict against this "
              "config gives the run zero MCP servers. That is correct only if "
              "the target needs no MCP tooling at all; otherwise copy a real "
              "server definition with --from-config PATH --keep NAME.",
              file=sys.stderr)
    print("relaunch with:")
    print(f"  {preflight_mod.launch_command(out)}")
    return 0


def cmd_brief(args: argparse.Namespace) -> int:
    variables: dict[str, str] = {}
    for spec in args.var:
        name, sep, value = spec.partition("=")
        if not sep or not name:
            print(f"bad --var {spec!r}; expected NAME=VALUE", file=sys.stderr)
            return 1
        variables[name] = value
    try:
        path = briefs_mod.write_brief(args.phase, args.unit, args.run, variables,
                                      template_dir=args.template_dir,
                                      allow_empty=args.allow_empty)
    except briefs_mod.BriefError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(path)
    return 0


def cmd_lint_skill(args: argparse.Namespace) -> int:
    # A linter that prints "clean" about a path it never read is the exact
    # failure this verb exists to prevent.
    try:
        findings = skill_lint_mod.lint(args.root, set(HANDLERS))
    except skill_lint_mod.SkillLintError as exc:
        print(f"skill lint: {exc}", file=sys.stderr)
        return 1
    if not findings:
        print("skill lint: clean")
        return 0
    for f in findings:
        print(f"  [{f.rule}] {f.path}: {f.detail}")
    print(f"skill lint: {len(findings)} finding(s)")
    return 1


def _parse_set(pairs: list[str]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    for spec in pairs:
        name, sep, value = spec.partition("=")
        if not sep or not name:
            print(f"bad --set {spec!r}; expected NAME=VALUE", file=sys.stderr)
            return None
        out[name] = value
    return out


def _open_db(path: str, read_only: bool = False):
    try:
        return db_mod.connect(pathlib.Path(path).expanduser(), read_only=read_only)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return None


def cmd_put(args: argparse.Namespace) -> int:
    row = _parse_set(args.set)
    if row is None:
        return 1
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        db_mod.put(con, args.table, row, replace=args.replace)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"{args.table}: 1 row")
    return 0


def cmd_rows(args: argparse.Namespace) -> int:
    where = _parse_set(args.where)
    if where is None:
        return 1
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        got = db_mod.rows(con, args.table, where=where or None,
                          columns=tuple(args.columns.split(",")) if args.columns else None,
                          limit=args.limit)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    if args.json:
        print(json.dumps([dict(r) for r in got], indent=2))
        return 0
    for r in got:
        print("\t".join("" if v is None else str(v) for v in r))
    print(f"({len(got)} row(s), capped at {db_mod.MAX_ROWS})", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        s = db_mod.status(con)
    finally:
        con.close()
    if args.json:
        print(json.dumps(dataclasses.asdict(s), indent=2))
    else:
        print(db_mod.render_status(s))
    return 0


def cmd_dedup(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        pairs = db_mod.duplicates(con)
    finally:
        con.close()
    if args.json:
        print(json.dumps([dataclasses.asdict(p) for p in pairs], indent=2))
        return 0
    if not pairs:
        print("dedup: no cross-group duplicate candidates")
        return 0
    for p in pairs:
        print(f"  keep {p.keep}  drop {p.drop}  shared: {', '.join(p.shared_locations)}")
    print(f"dedup: {len(pairs)} candidate pair(s) - these are proposals. "
          f"Record a decision with `audit.py put --table cba_fp_verdicts "
          f"--set finding_id=<drop> --set verdict=DUPLICATE --set merged_into=<keep>`.")
    return 0


# The single source of truth for which verbs exist. `main` dispatches through
# it and `lint-skill` reads its keys, so a verb cannot exist in one and not
# the other.
HANDLERS = {
    "selftest": cmd_selftest,
    "budget": cmd_budget,
    "bench": cmd_bench,
    "init": cmd_init,
    "preflight": cmd_preflight,
    "brief": cmd_brief,
    "lint-skill": cmd_lint_skill,
    "put": cmd_put,
    "rows": cmd_rows,
    "status": cmd_status,
    "dedup": cmd_dedup,
}


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
    pf = sub.add_parser("preflight", help="write a project-scoped MCP config")
    pf.add_argument("--out", default=preflight_mod.MCP_CONFIG_NAME, metavar="PATH")
    pf.add_argument("--server", action="append", default=[], metavar="NAME=COMMAND",
                    help="simple stdio server: a bare command, no args or env")
    pf.add_argument("--from-config", default=None, metavar="PATH",
                    help="an existing MCP config to copy server objects out of")
    pf.add_argument("--keep", action="append", default=[], metavar="NAME",
                    help="copy this server verbatim from --from-config "
                         "(repeatable); keeps type/url/args/env intact")
    pf.add_argument("--force", action="store_true")
    br = sub.add_parser("brief", help="render a subagent dispatch brief")
    br.add_argument("--phase", required=True)
    br.add_argument("--unit", required=True)
    br.add_argument("--run", required=True, metavar="RUN_DIR")
    br.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    br.add_argument("--template-dir", default=None, metavar="DIR")
    br.add_argument("--allow-empty", action="store_true",
                    help="accept an empty --var value for a section that is "
                         "genuinely empty (e.g. no known findings yet)")
    ls = sub.add_parser("lint-skill", help="check the skill against the economics contract")
    ls.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent),
                    metavar="DIR")
    pu = sub.add_parser("put", help="insert one validated row into a run's audit.db")
    pu.add_argument("--db", required=True, metavar="AUDIT_DB")
    pu.add_argument("--table", required=True)
    pu.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    pu.add_argument("--replace", action="store_true")
    ro = sub.add_parser("rows", help="read bounded rows out of a run's audit.db")
    ro.add_argument("--db", required=True, metavar="AUDIT_DB")
    ro.add_argument("--table", required=True)
    ro.add_argument("--where", action="append", default=[], metavar="NAME=VALUE")
    ro.add_argument("--columns", default=None, metavar="A,B,C")
    ro.add_argument("--limit", type=int, default=db_mod.MAX_ROWS)
    ro.add_argument("--json", action="store_true")
    st = sub.add_parser("status", help="group, finding and verdict counts for a run")
    st.add_argument("--db", required=True, metavar="AUDIT_DB")
    st.add_argument("--json", action="store_true")
    dd = sub.add_parser("dedup", help="propose cross-group duplicate findings")
    dd.add_argument("--db", required=True, metavar="AUDIT_DB")
    dd.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return HANDLERS[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
