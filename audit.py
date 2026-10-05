#!/usr/bin/env python3
"""audit.py - verb dispatch for the audit suite."""
import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3
import sys
import tempfile

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
from audit_core import coverage as coverage_mod  # noqa: E402
from audit_core import extract as extract_mod  # noqa: E402
from audit_core import annotations as annotations_mod  # noqa: E402
from audit_core import ceiling as ceiling_mod  # noqa: E402
from audit_core import sweep as sweep_mod  # noqa: E402


def cmd_selftest(_args: argparse.Namespace) -> int:
    """Verify the vendored core is importable AND internally consistent.

    Printing a version number proves an import. These two checks prove the
    things that actually break a run six phases in, and each compares two
    structures that were built independently - per Stage 0's finding that a
    tool's output is only trustworthy when validated against something it did
    not produce.
    """
    problems: list[str] = []

    # 1. Verbs: HANDLERS against the argument parser's subcommands.
    parser = build_parser()
    sub = next((a for a in parser._actions                     # noqa: SLF001
                if isinstance(a, argparse._SubParsersAction)), None)
    declared = set(sub.choices) if sub is not None else set()
    for verb in sorted(set(HANDLERS) - declared):
        problems.append(f"verb {verb!r} has a handler but no subparser")
    for verb in sorted(declared - set(HANDLERS)):
        problems.append(f"verb {verb!r} has a subparser but no handler")

    # 2. Tables: TABLE_SPECS against the database schema.sql actually builds.
    tables: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        db_path = pathlib.Path(tmp) / "selftest.db"
        try:
            tables = list(workspace_mod.apply_schema(db_path))
        except Exception as exc:                       # noqa: BLE001
            print(f"selftest: schema.sql does not apply: {exc}", file=sys.stderr)
            return 1
        con = sqlite3.connect(db_path)
        try:
            for table, spec in sorted(db_mod.TABLE_SPECS.items()):
                if table not in tables:
                    problems.append(f"{table} is in TABLE_SPECS but not in schema.sql")
                    continue
                actual = {r[1] for r in con.execute(
                    f"PRAGMA table_info({table})")}
                for column in sorted(set(spec.columns) - actual):
                    problems.append(f"{table}.{column} is in TABLE_SPECS "
                                    f"but not in schema.sql")
                for column in sorted(c for c in spec.required if c not in actual):
                    problems.append(f"{table}.{column} is required by "
                                    f"TABLE_SPECS but does not exist")
        finally:
            con.close()

    if problems:
        print(f"selftest: {len(problems)} inconsistenc(ies)", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"audit_core {audit_core.__version__} ok")
    print(f"  verbs  {len(HANDLERS)} declared, all dispatchable")
    print(f"  tables {len(tables)} in schema.sql, "
          f"{len(db_mod.TABLE_SPECS)} under contract, columns agree")
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
            if args.project:
                print()
                print(ceiling_mod.render_projection(ceiling_mod.project(
                    r.stats.prefix_floor, r.stats.growth_per_turn)))
                print(ceiling_mod.render_linearity(ceiling_mod.linearity(r)))
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
    rejected = goldens_mod.load_rejections(golden / "rejections.json")
    findings = bench_mod.load_findings_from_db(db)
    result = bench_mod.score(refs, findings, adjudicated,
                             rejected=rejected, cost_usd=args.cost)

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
    if result.suppressed_candidates:
        print(f"({result.suppressed_candidates} candidate(s) suppressed by "
              f"rejections.json)")
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
    # On stderr, and before the JSON return: a consumer piping stdout to `jq`
    # otherwise gets a silently truncated result set with no signal that it
    # was truncated. The notice is the only place the bound is stated.
    print(f"({len(got)} row(s), capped at {db_mod.MAX_ROWS})", file=sys.stderr)
    if args.json:
        print(json.dumps([dict(r) for r in got], indent=2))
        return 0
    for r in got:
        print("\t".join("" if v is None else str(v) for v in r))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        s = db_mod.status(con)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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


def cmd_coverage(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        r = coverage_mod.report(con, phase=args.phase)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    if args.json:
        print(json.dumps(dataclasses.asdict(r) | {"fraction": r.fraction}, indent=2))
    else:
        print(coverage_mod.render(r))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    if args.batch_size < 1:
        # `range(start, stop, 0)` is a ValueError, and a traceback is not the
        # clean stderr/exit-1 path every other bad input on this verb gets.
        print(f"--batch-size must be at least 1, not {args.batch_size}",
              file=sys.stderr)
        return 1
    store = extract_mod.ExtractStore(pathlib.Path(args.run).expanduser())
    backend = extract_mod.SourceTree(pathlib.Path(args.root).expanduser())
    items = list(args.path)
    if args.from_file:
        src = pathlib.Path(args.from_file).expanduser()
        if not src.is_file():
            print(f"not found: {src}", file=sys.stderr)
            return 1
        items += [ln.strip() for ln in src.read_text().splitlines() if ln.strip()]
    if args.refresh and not items:
        items = store.items(args.unit)
        if not items:
            print(f"--refresh: unit {args.unit!r} has no snapshots yet",
                  file=sys.stderr)
            return 1
    if not items:
        print("nothing to extract; pass --path, --from-file or --refresh",
              file=sys.stderr)
        return 1
    try:
        recs = extract_mod.extract_batch(store, backend, args.unit, items,
                                         batch_size=args.batch_size)
    except extract_mod.ExtractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"backend read failed: {exc}", file=sys.stderr)
        return 1
    changed = sum(1 for r in recs if r.version > 1)
    truncated = sum(1 for r in recs if r.truncated)
    # Bounded on purpose: R1 applies to this tool's own output. The manifest
    # holds the per-file detail, and it is a file, not a paste.
    print(f"extract {args.unit}: {len(recs)} snapshot(s), {changed} changed, "
          f"{truncated} truncated")
    print(store.manifest_path)
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    row = {"phase": args.phase, "reason": args.reason}
    if args.turns is not None:
        row["turns"] = str(args.turns)
    if args.resume_note:
        note = pathlib.Path(args.resume_note).expanduser()
        if not note.is_file():
            print(f"resume note not found: {note}; write it before "
                  f"checkpointing - the note is the restart", file=sys.stderr)
            return 1
        row["resume_note"] = str(note)
    projection = None
    if args.prefix is not None and args.growth is not None:
        projection = ceiling_mod.project(args.prefix, args.growth)
        if args.turns is not None:
            row["projected_context"] = str(
                int(args.prefix + args.growth * args.turns))
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        db_mod.put(con, "cba_checkpoints", row)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"checkpoint recorded: phase={args.phase} reason={args.reason}")
    if projection is not None:
        print(ceiling_mod.render_projection(projection))
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        found = db_mod.rows(con, "cba_patterns", where={"id": args.pattern},
                            columns=("id", "regex"))
        if not found:
            print(f"no pattern {args.pattern!r}; register one with "
                  f"`audit.py put --table cba_patterns --set id=... "
                  f"--set name=... --set regex=...`", file=sys.stderr)
            return 1
        result = sweep_mod.run(
            pathlib.Path(args.root).expanduser(), found[0]["regex"],
            pattern_id=args.pattern,
            suffixes=tuple(args.suffix) or None, max_hits=args.max_hits)
        print(sweep_mod.render(result))
        if args.record:
            if result.truncated:
                print("refusing to record a truncated sweep; narrow the "
                      "pattern first", file=sys.stderr)
                return 1
            print(f"recorded {sweep_mod.record(con, result)} hit(s)")
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except re.error as exc:
        print(f"stored regex does not compile: {exc}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    if args.text is not None and not (args.key or "").strip():
        print("--text requires --key", file=sys.stderr)
        return 1
    path = pathlib.Path(args.run).expanduser() / annotations_mod.JOURNAL_NAME
    if args.text is not None:
        try:
            annotations_mod.append(path, args.key, args.kind, args.text,
                                   source=args.source)
        except annotations_mod.AnnotationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"{path}: 1 entry")
        return 0
    if args.key:
        entries, bad = annotations_mod.read(path, key=args.key, tolerate=True)
        for e in entries:
            print(f"{e.recorded_at}  {e.kind}\n{e.text}\n")
    else:
        rows, bad = annotations_mod.index(path)
        if args.json:
            print(json.dumps([dataclasses.asdict(r) for r in rows], indent=2))
        else:
            for r in rows:
                print(f"  {r.key:40.40s} {r.kind:10s} x{r.entries:<3d} {r.summary}")
            print(f"({len(rows)} key(s); read one with "
                  f"`audit.py note --run {args.run} --key <key>`)")
    if bad:
        print(f"warning: {path} line(s) {', '.join(map(str, bad))} are not "
              f"journal entries and were not read", file=sys.stderr)
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
    "coverage": cmd_coverage,
    "extract": cmd_extract,
    "note": cmd_note,
    "checkpoint": cmd_checkpoint,
    "sweep": cmd_sweep,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit.py")
    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("selftest", help="verify the vendored core is importable")
    b = sub.add_parser("budget", help="economics report for session transcripts")
    b.add_argument("--report", nargs="+", required=True, metavar="JSONL")
    b.add_argument("--json", action="store_true")
    b.add_argument("--project", action="store_true",
                   help="project turns to the R3 checkpoint, with the linear "
                        "model's fit")
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
    cv = sub.add_parser("coverage", help="analyzed vs inventoried, with reasons for every gap")
    cv.add_argument("--db", required=True, metavar="AUDIT_DB")
    cv.add_argument("--phase", default=None)
    cv.add_argument("--json", action="store_true")
    ex = sub.add_parser("extract", help="snapshot source into <run>/extract/ once, for unbounded fan-out")
    ex.add_argument("--run", required=True, metavar="RUN_DIR")
    ex.add_argument("--root", required=True, metavar="SRC_DIR")
    ex.add_argument("--unit", required=True, help="feature group id, e.g. G1")
    ex.add_argument("--path", action="append", default=[], metavar="RELPATH")
    ex.add_argument("--from-file", default=None, metavar="LIST",
                    help="a file of one source path per line")
    ex.add_argument("--refresh", action="store_true",
                    help="re-read every item already snapshotted for this unit")
    ex.add_argument("--batch-size", type=int, default=extract_mod.BATCH_SIZE)
    nt = sub.add_parser("note", help="append to, or index, the run's annotation journal")
    nt.add_argument("--run", required=True, metavar="RUN_DIR")
    nt.add_argument("--key", default=None,
                    help="with --text, the entry key; alone, read that key")
    nt.add_argument("--kind", default="semantics",
                    choices=list(annotations_mod.KINDS))
    nt.add_argument("--text", default=None, help="append this entry")
    nt.add_argument("--source", default=None, metavar="FILE_OR_ADDR")
    nt.add_argument("--json", action="store_true")
    ck = sub.add_parser("checkpoint", help="record a phase exit or a ceiling trip")
    ck.add_argument("--db", required=True, metavar="AUDIT_DB")
    ck.add_argument("--phase", required=True)
    ck.add_argument("--reason", required=True,
                    choices=list(db_mod.CHECKPOINT_REASONS))
    ck.add_argument("--turns", type=int, default=None)
    ck.add_argument("--resume-note", default=None, metavar="PATH")
    ck.add_argument("--prefix", type=int, default=None,
                    help="measured prefix floor, from `audit.py budget`")
    ck.add_argument("--growth", type=float, default=None,
                    help="measured tokens per turn, from `audit.py budget`")
    sw = sub.add_parser("sweep", help="scan a tree for a registered bug pattern")
    sw.add_argument("--db", required=True, metavar="AUDIT_DB")
    sw.add_argument("--pattern", required=True, metavar="PATTERN_ID")
    sw.add_argument("--root", required=True, metavar="SRC_DIR")
    sw.add_argument("--suffix", action="append", default=[], metavar=".c")
    sw.add_argument("--max-hits", type=int, default=sweep_mod.MAX_HITS)
    sw.add_argument("--record", action="store_true",
                    help="write the hits to cba_pattern_hits")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return HANDLERS[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
