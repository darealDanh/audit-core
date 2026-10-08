#!/usr/bin/env python3
"""The project's verification harness: every gate that must pass before a merge.

Seven gates, each independently runnable and each reporting pass / fail / skip:

    tests     the pytest suite
    selftest  audit.py's internal consistency checks (verbs, tables, migrations)
    lint      audit.py lint-skill - the shipped skill against the economics contract
    eol       the mixed line-ending contract (scripts/eol-manifest.txt)
    manifest  feature_lists.json against the tree it claims to describe
    install   a sandboxed install.sh run that cannot touch the real install
    bench     the golden-set benchmark (opt-in; skips when its corpus is absent)

Why a harness at all. Five of these seven were run by hand at the end of every
stage, from memory, in an order nobody wrote down. The other two - `eol` and
`manifest` - plus the real-install safety assertion inside `install` were not
checked by anything at all, and depended on whoever was driving remembering
that they mattered.

The install gate is the reason this file is Python rather than a Makefile
recipe. `install.sh` resolves its destinations from $HOME and $CODEX_HOME at
runtime, so an unguarded run overwrites the operator's real, working skill
install. This gate builds its own throwaway HOME, refuses to run if that HOME
would resolve to the real one, and asserts afterwards that the real install's
mtime did not move. A Makefile recipe that forgets one `env` assignment does
the damage silently; this cannot.

Stdlib only, Python 3.10+, no network - the same constraints as audit_core.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable or "python3"

PASS, FAIL, SKIP = "pass", "fail", "skip"

# The golden corpus lives outside the repo, under a read-only tree. The bench
# gate skips rather than fails when it is absent, so the harness stays usable
# on a machine that has the code but not the measurement corpus.
BENCH_GOLDEN = ROOT / "tests" / "goldens" / "tplink-dl110v2-1.0.11"
BENCH_DB = pathlib.Path(
    "~/Documents/Offsec/Opswat/Devices/tplink/reports/"
    "audit-20260928-073457/audit.db").expanduser()
BENCH_COST = "658.37"

# Expected results, from docs/baselines/2026-10-05-tplink-baseline.md. The gate
# reports drift against these; it does not silently accept a new number.
BENCH_EXPECT = {"matched": 9, "reference_count": 19, "finding_count": 45,
                "true_positives": 39, "false_positives": 1}


class Result:
    __slots__ = ("name", "status", "summary", "detail", "seconds")

    def __init__(self, name: str, status: str, summary: str,
                 detail: str = "", seconds: float = 0.0) -> None:
        self.name, self.status = name, status
        self.summary, self.detail, self.seconds = summary, detail, seconds

    def as_dict(self) -> dict:
        return {"gate": self.name, "status": self.status,
                "summary": self.summary, "seconds": round(self.seconds, 2),
                "detail": self.detail}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Capture both streams as text. Never inherits a shell."""
    return subprocess.run(cmd, cwd=kw.pop("cwd", ROOT), capture_output=True,
                          text=True, **kw)


def tail(text: str, lines: int = 25) -> str:
    kept = [ln for ln in text.strip().splitlines() if ln.strip()]
    return "\n".join(kept[-lines:])


# ---------------------------------------------------------------- gate: tests

def gate_tests() -> Result:
    """The pytest suite. The only gate that covers audit_core's behaviour."""
    proc = run([PY, "-m", "pytest", "-q"])
    out = proc.stdout + proc.stderr
    last = tail(out, 1) or "no output"
    if proc.returncode != 0:
        return Result("tests", FAIL, last, tail(out, 40))
    return Result("tests", PASS, last)


# ------------------------------------------------------------- gate: selftest

def gate_selftest() -> Result:
    """audit.py selftest: verbs vs parser, TABLE_SPECS vs schema.sql,
    MIGRATIONS vs the frozen pre-Stage-3 baseline."""
    proc = run([PY, "audit.py", "selftest"])
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        return Result("selftest", FAIL, tail(out, 1), out)
    return Result("selftest", PASS, " / ".join(
        ln.strip() for ln in out.splitlines()[1:]) or out)


# ----------------------------------------------------------------- gate: lint

def gate_lint() -> Result:
    """lint-skill: the shipped prose against the economics contract."""
    proc = run([PY, "audit.py", "lint-skill"])
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        return Result("lint", FAIL, tail(out, 1), out)
    return Result("lint", PASS, tail(out, 1) or "clean")


# ------------------------------------------------------------------ gate: eol

MANIFEST = ROOT / "scripts" / "eol-manifest.txt"


def read_manifest() -> set[str]:
    if not MANIFEST.exists():
        raise FileNotFoundError(MANIFEST)
    out: set[str] = set()
    for raw in MANIFEST.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def tracked_text_files() -> list[str]:
    # --others --exclude-standard includes files that are new but not
    # ignored. Tracked-only would let a freshly added CRLF file pass the gate
    # right up until the commit that makes it everyone's problem.
    proc = run(["git", "ls-files", "-z", "--cached", "--others",
                "--exclude-standard"])
    if proc.returncode != 0:
        raise RuntimeError("git ls-files failed: " + proc.stderr.strip())
    paths = [p for p in proc.stdout.split("\0") if p]
    keep: list[str] = []
    for rel in paths:
        path = ROOT / rel
        if not path.is_file():
            continue
        head = path.read_bytes()[:65536]
        if b"\0" in head:          # binary; line endings are not a contract
            continue
        keep.append(rel)
    return keep


def crlf_files() -> set[str]:
    found: set[str] = set()
    for rel in tracked_text_files():
        if b"\r\n" in (ROOT / rel).read_bytes():
            found.add(rel)
    return found


def gate_eol() -> Result:
    """The mixed line-ending contract.

    Six shipped files carry CRLF and the rest carry LF. That split is not an
    accident of history that wants tidying: install.sh sed-substitutes
    __SKILL_DIR__ line by line, and a normalising edit to one of these files
    changes every line of its diff, which is how a prose edit hides an
    accidental deletion. Nothing in the test suite pins which files are in the
    set - test_install.py checks only that whatever shipped with CRLF keeps it
    through an install. This gate pins the set itself.
    """
    try:
        expected = read_manifest()
        actual = crlf_files()
    except Exception as exc:                                   # noqa: BLE001
        return Result("eol", FAIL, f"gate could not run: {exc}")
    gained = sorted(actual - expected)
    lost = sorted(expected - actual)
    if not gained and not lost:
        return Result("eol", PASS, f"{len(expected)} CRLF files, "
                                   f"{len(tracked_text_files()) - len(expected)} LF")
    detail = []
    for rel in gained:
        detail.append(f"  gained CRLF (not in the manifest): {rel}")
    for rel in lost:
        detail.append(f"  lost CRLF (manifest says it should have it): {rel}")
    detail.append("")
    detail.append("If the change was deliberate, edit scripts/eol-manifest.txt "
                  "in the same commit and say why in the message.")
    return Result("eol", FAIL,
                  f"{len(gained)} gained, {len(lost)} lost", "\n".join(detail))


# -------------------------------------------------------------- gate: install

CLIENT_ROOTS = (
    ".claude/skills/codebase-audit",
    ".copilot/skills/codebase-audit",
    ".agents/skills/codebase-audit",
)


def real_install_dirs() -> list[pathlib.Path]:
    home = pathlib.Path(os.path.expanduser("~"))
    dirs = [home / rel for rel in CLIENT_ROOTS]
    codex = os.environ.get("CODEX_HOME")
    dirs.append((pathlib.Path(codex) if codex else home / ".codex")
                / "skills" / "codebase-audit")
    return dirs


def snapshot(dirs: list[pathlib.Path]) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    for d in dirs:
        out[str(d)] = d.stat().st_mtime if d.exists() else None
    return out


def gate_install() -> Result:
    """A full install.sh run into a throwaway HOME, then four assertions.

    1. The sandbox HOME is not the real HOME, and the real install directories
       are not inside it. Checked BEFORE install.sh is invoked - this is the
       assertion that stands between a routine `make check` and overwriting the
       operator's working skill.
    2. install.sh exits 0.
    3. No __SKILL_DIR__ sentinel survives in installed markdown. A survivor
       means every documented `python3 __SKILL_DIR__/audit.py ...` command in
       the installed skill is a file-not-found at run time.
    4. The real install directories' mtimes are byte-identical before and
       after. This is the one that catches a future install.sh that learns a
       new destination and forgets to read it from the environment.
    """
    if not (ROOT / "install.sh").exists():
        return Result("install", SKIP, "install.sh is not present")
    if shutil.which("bash") is None:
        return Result("install", SKIP, "bash is not on PATH")

    real_dirs = real_install_dirs()
    before = snapshot(real_dirs)

    with tempfile.TemporaryDirectory(prefix="cba-harness-home-") as tmp:
        home = pathlib.Path(tmp).resolve()

        # Assertion 1, before anything is executed.
        true_home = pathlib.Path(os.path.expanduser("~")).resolve()
        if home == true_home:
            return Result("install", FAIL,
                          "refused: the sandbox HOME resolved to the real HOME")
        for d in real_dirs:
            try:
                d.resolve().relative_to(home)
            except ValueError:
                continue
            return Result("install", FAIL,
                          f"refused: real install dir {d} lies inside the sandbox")

        env = {**os.environ,
               "HOME": str(home),
               "CLAUDE_CONFIG_DIR": str(home / ".claude"),
               "CODEX_HOME": str(home / ".codex")}
        proc = run(["bash", str(ROOT / "install.sh")], env=env)
        if proc.returncode != 0:
            return Result("install", FAIL, f"install.sh exited {proc.returncode}",
                          tail(proc.stdout + proc.stderr, 30))

        # Assertion 3.
        survivors: list[str] = []
        installed_files = 0
        # Markdown only. audit_core/skill_lint.py contains the sentinel as a
        # string literal because it is the checker for it; a sweep over .py
        # flags the detector as the defect.
        for path in home.rglob("*.md"):
            if not path.is_file():
                continue
            installed_files += 1
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if "__SKILL_DIR__" in text:
                survivors.append(str(path.relative_to(home)))
        if survivors:
            return Result("install", FAIL,
                          f"{len(survivors)} markdown file(s) kept the "
                          f"__SKILL_DIR__ sentinel",
                          "\n".join("  " + s for s in survivors[:20]))

        # The installed tree must be able to run its own selftest - a copy that
        # imports but cannot self-check is a copy nobody will notice is broken.
        installed = home / ".claude" / "skills" / "codebase-audit" / "audit.py"
        if installed.exists():
            st = run([PY, str(installed), "selftest"], env=env, cwd=installed.parent)
            if st.returncode != 0:
                return Result("install", FAIL,
                              "the installed tree fails its own selftest",
                              tail(st.stdout + st.stderr, 20))

    # Assertion 4.
    after = snapshot(real_dirs)
    moved = [k for k in before if before[k] != after.get(k)]
    if moved:
        return Result("install", FAIL,
                      "the real install was modified by a sandboxed run",
                      "\n".join("  " + m for m in moved))

    return Result("install", PASS,
                  f"{installed_files} markdown files installed, 0 sentinel "
                  f"survivors, "
                  f"real install untouched")


# ---------------------------------------------------------------- gate: bench

def gate_bench() -> Result:
    """The golden benchmark. Opt-in: skips when the measurement corpus is absent.

    The corpus lives outside the repo under a read-only tree, so a clone on
    another machine has the scorer but not the thing to score. A skip here is
    the honest answer; a pass would be a lie and a fail would be noise.
    """
    if not BENCH_GOLDEN.exists():
        return Result("bench", SKIP, f"golden set absent: {BENCH_GOLDEN}")
    if not BENCH_DB.exists():
        return Result("bench", SKIP, f"audit.db absent: {BENCH_DB}")
    proc = run([PY, "audit.py", "bench", "--golden", str(BENCH_GOLDEN),
                "--db", str(BENCH_DB), "--cost", BENCH_COST, "--json"])
    if proc.returncode != 0:
        return Result("bench", FAIL, "bench exited non-zero",
                      tail(proc.stdout + proc.stderr, 20))
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return Result("bench", FAIL, f"bench --json did not parse: {exc}",
                      tail(proc.stdout, 10))
    prec = data.get("precision") or {}
    got = {"matched": len(data.get("matched") or []),
           "reference_count": data.get("reference_count"),
           "finding_count": data.get("finding_count"),
           "true_positives": prec.get("true_positives"),
           "false_positives": prec.get("false_positives")}
    summary = (f"recall {got['matched']}/{got['reference_count']}, "
               f"{got['finding_count']} findings, precision "
               f"{got['true_positives']}/"
               f"{(got['true_positives'] or 0) + (got['false_positives'] or 0)}, "
               f"${data.get('cost_per_match', 0):.2f} per match")
    if got != BENCH_EXPECT:
        return Result("bench", FAIL, "benchmark moved off the recorded baseline",
                      f"  expected {BENCH_EXPECT}\n  got      {got}\n"
                      f"  If this is a real improvement, record it in a NEW dated "
                      f"file under docs/baselines/ and update BENCH_EXPECT.")
    return Result("bench", PASS, summary)


# ------------------------------------------------------------- gate: manifest

MANIFEST_JSON = ROOT / "feature_lists.json"


def gate_manifest() -> Result:
    """feature_lists.json against the tree it claims to describe.

    A hand-written inventory rots the moment a file is renamed, and a rotted
    inventory is worse than none: it reads as current. So every claim in it is
    checked against something it did not produce - paths against the
    filesystem, verbs against audit.py's dispatch table, stage and status
    names against the enums the file itself declares.
    """
    if not MANIFEST_JSON.exists():
        return Result("manifest", SKIP, f"{MANIFEST_JSON.name} is not present")
    try:
        data = json.loads(MANIFEST_JSON.read_text())
    except json.JSONDecodeError as exc:
        return Result("manifest", FAIL, f"feature_lists.json does not parse: {exc}")

    problems: list[str] = []
    statuses = set(data.get("status_enum") or [])
    areas = set(data.get("area_enum") or [])
    stage_ids = {s.get("id") for s in data.get("stages") or []}
    # Features may be attributed to work done after the last planned stage.
    stage_ids.add("post-stage3")

    # Verbs, read out of audit.py rather than hardcoded here.
    sys.path.insert(0, str(ROOT))
    try:
        import audit as audit_mod                                 # noqa: PLC0415
        verbs = set(audit_mod.HANDLERS)
    except Exception as exc:                                      # noqa: BLE001
        return Result("manifest", FAIL, f"could not import audit.py: {exc}")
    finally:
        sys.path.pop(0)

    seen: set[str] = set()
    features = data.get("features") or []
    for feat in features:
        fid = feat.get("id") or "<no id>"
        if fid in seen:
            problems.append(f"{fid}: duplicate id")
        seen.add(fid)
        if feat.get("status") not in statuses:
            problems.append(f"{fid}: status {feat.get('status')!r} is not in status_enum")
        if feat.get("area") not in areas:
            problems.append(f"{fid}: area {feat.get('area')!r} is not in area_enum")
        if feat.get("stage") not in stage_ids:
            problems.append(f"{fid}: stage {feat.get('stage')!r} is not a declared stage")
        for verb in feat.get("verbs") or []:
            if verb not in verbs:
                problems.append(f"{fid}: verb {verb!r} is not dispatchable by audit.py")
        for key in ("modules", "tests", "docs"):
            for rel in feat.get(key) or []:
                if not (ROOT / rel).exists():
                    problems.append(f"{fid}: {key} path does not exist: {rel}")

    for item in data.get("open_items") or []:
        iid = item.get("id") or "<no id>"
        for rel in item.get("docs") or []:
            if not (ROOT / rel).exists():
                problems.append(f"open_item {iid}: path does not exist: {rel}")

    # A shipped feature with no test and no doc is a claim with no evidence.
    for feat in features:
        if feat.get("status") == "shipped" and not (
                feat.get("tests") or feat.get("docs")):
            problems.append(f"{feat.get('id')}: shipped but names neither a "
                            f"test nor a doc")

    if problems:
        return Result("manifest", FAIL, f"{len(problems)} stale entr(ies)",
                      "\n".join("  " + p for p in problems))
    return Result("manifest", PASS,
                  f"{len(features)} features, {len(data.get('stages') or [])} "
                  f"stages, {len(data.get('open_items') or [])} open items, "
                  f"all paths and verbs resolve")


def gate_coverage() -> Result:
    """Every unexecuted statement in audit_core is listed, with a reason.

    The probe runs in a subprocess, never in-process: it is only correct from
    a cold import graph, and earlier gates may already have imported
    audit_core. SKIPs below 3.12 (no sys.monitoring; 3.10 is the declared
    floor). A skip is reported, not swallowed.
    """
    if sys.version_info < (3, 12):
        return Result("coverage", SKIP,
                      f"needs Python 3.12+ for sys.monitoring; running "
                      f"{sys.version_info[0]}.{sys.version_info[1]}")

    from types import SimpleNamespace                             # noqa: PLC0415
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import coverage_allowlist as allowlist                    # noqa: PLC0415
    finally:
        sys.path.pop(0)

    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "coverage.json"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "coverage_probe.py"),
             "--package", "audit_core", "--tests", "tests",
             "--json-out", str(out)],
            cwd=ROOT, capture_output=True, text=True)
        if proc.returncode != 0 or not out.exists():
            return Result("coverage", FAIL,
                          f"the probe did not run (rc {proc.returncode})",
                          detail=(proc.stderr or proc.stdout)[-2000:])
        data = json.loads(out.read_text())

    if data["pytest_rc"] != 0:
        return Result("coverage", FAIL,
                      "the suite did not pass, so the measurement is from a "
                      f"partial run (pytest rc {data['pytest_rc']})")

    report = SimpleNamespace(modules=[SimpleNamespace(**m)
                                      for m in data["modules"]])
    entries = allowlist.parse(
        (ROOT / "scripts" / "coverage-allowlist.txt").read_text())
    result = allowlist.compare(report, entries, ROOT / "audit_core")

    summary = (f"{data['total_unexecuted']} unexecuted / "
               f"{data['total_executable']} statements, "
               f"{len(result.permitted)} allowed")
    if result.ok:
        return Result("coverage", PASS, summary)

    detail = []
    for label, items in (("unlisted", result.regressed),
                         ("stale", result.stale),
                         ("now executed, remove from the list",
                          result.executed_but_listed)):
        for item in items:
            detail.append(f"  {label}: {item}")
    return Result("coverage", FAIL, summary, detail="\n".join(detail))


GATES = {
    "tests": gate_tests,
    "selftest": gate_selftest,
    "lint": gate_lint,
    "eol": gate_eol,
    "manifest": gate_manifest,
    "install": gate_install,
    "coverage": gate_coverage,
    "bench": gate_bench,
}

# `make check` runs these; `bench` is opt-in via --only bench or --all.
DEFAULT = ["tests", "selftest", "lint", "eol", "manifest", "install", "coverage"]

GLYPH = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="scripts/harness.py",
        description="Run the project's verification gates.")
    ap.add_argument("--only", action="append", metavar="GATE",
                    help="run just this gate (repeatable)")
    ap.add_argument("--skip", action="append", metavar="GATE", default=[],
                    help="skip this gate (repeatable)")
    ap.add_argument("--all", action="store_true",
                    help="include the opt-in gates (bench)")
    ap.add_argument("--list", action="store_true", help="list the gates and exit")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON object instead of the table")
    args = ap.parse_args(argv)

    if args.list:
        for name, fn in GATES.items():
            default = "default" if name in DEFAULT else "opt-in "
            head = (fn.__doc__ or "").strip().splitlines()[0]
            print(f"  {name:<9} {default}  {head}")
        return 0

    if args.only:
        unknown = [g for g in args.only if g not in GATES]
        if unknown:
            print(f"unknown gate(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        selected = list(dict.fromkeys(args.only))
    else:
        selected = list(GATES) if args.all else list(DEFAULT)
    selected = [g for g in selected if g not in set(args.skip)]

    results: list[Result] = []
    for name in selected:
        if not args.json:
            print(f"  .. {name}", flush=True)
        start = time.monotonic()
        try:
            res = GATES[name]()
        except Exception as exc:                               # noqa: BLE001
            res = Result(name, FAIL, f"gate raised {type(exc).__name__}: {exc}")
        res.seconds = time.monotonic() - start
        results.append(res)

    failed = [r for r in results if r.status == FAIL]

    if args.json:
        print(json.dumps({"gates": [r.as_dict() for r in results],
                          "failed": [r.name for r in failed]}, indent=2))
        return 1 if failed else 0

    print()
    for r in results:
        print(f"  {GLYPH[r.status]}  {r.name:<9} {r.seconds:6.1f}s  {r.summary}")
    for r in results:
        if r.detail and r.status == FAIL:
            print(f"\n--- {r.name} ---\n{r.detail}")
    print()
    if failed:
        print(f"{len(failed)} gate(s) failed: {', '.join(r.name for r in failed)}")
        return 1
    skipped = [r.name for r in results if r.status == SKIP]
    note = f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""
    print(f"all {len(results) - len(skipped)} gate(s) passed{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
