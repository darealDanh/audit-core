"""The contract for statements permitted to go unexecuted.

Format, one entry per line:

    <module>:<line>:<digest>  <reason>

`digest` is the first 8 hex of the SHA-1 of the stripped source line. It is
there because a line-number key re-aims itself at an unrelated statement the
moment anyone inserts a line above it - the gate would then permit the wrong
thing and still report green. With the digest there are three outcomes, not
two: permitted, regressed, and stale.

A percentage floor was rejected for the same family of reason: it lets a new
untested refusal path hide behind new tested code elsewhere, which is exactly
how 115 unexecuted statements accumulated while every stage reported its tests
passing.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ENTRY = re.compile(r"^(?P<module>[\w.\-]+\.py):(?P<line>\d+):(?P<digest>[0-9a-f]{8})"
                   r"(?:\s+(?P<reason>\S.*))?$")


class AllowlistError(Exception):
    """The allowlist file is malformed."""


@dataclasses.dataclass(frozen=True, slots=True)
class Entry:
    module: str
    line: int
    digest: str
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class Comparison:
    regressed: tuple[str, ...]
    stale: tuple[str, ...]
    permitted: tuple[str, ...]
    executed_but_listed: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (self.regressed or self.stale or self.executed_but_listed)


def line_digest(text: str) -> str:
    """Compute first 8 hex of SHA-1 of stripped text.

    Strips leading/trailing whitespace so reindenting a block does not
    invalidate every entry inside it. Trade-off: moving a statement into
    or out of a conditional (changing control-flow meaning while keeping
    text identical) is also undetected.
    """
    return hashlib.sha1(text.strip().encode()).hexdigest()[:8]


def format_entry(module: str, line: int, source_line: str, reason: str) -> str:
    return f"{module}:{line}:{line_digest(source_line)}  {reason}"


def parse(text: str) -> tuple[Entry, ...]:
    out: list[Entry] = []
    seen: set[tuple[str, int]] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = ENTRY.match(line)
        if not match:
            raise AllowlistError(
                f"line {number}: malformed entry {line!r}; expected "
                "<module>.py:<line>:<8-hex digest>  <reason>")
        if not (match.group("reason") or "").strip():
            raise AllowlistError(
                f"line {number}: {match.group('module')}:{match.group('line')} "
                "needs a reason. A gap recorded without one makes the "
                "denominator look accounted for.")
        key = (match.group("module"), int(match.group("line")))
        if key in seen:
            raise AllowlistError(f"line {number}: {key[0]}:{key[1]} is listed twice")
        seen.add(key)
        out.append(Entry(module=key[0], line=key[1],
                         digest=match.group("digest"),
                         reason=match.group("reason").strip()))
    return tuple(out)


def _source_line(package: pathlib.Path, module: str, line: int) -> str | None:
    path = package / module
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8").split("\n")
    if not 1 <= line <= len(lines):
        return None
    return lines[line - 1]


def compare(report, entries, package: pathlib.Path) -> Comparison:
    by_key = {(e.module, e.line): e for e in entries}
    unexecuted = {(m.name, line) for m in report.modules for line in m.unexecuted}

    regressed: list[str] = []
    stale: list[str] = []
    permitted: list[str] = []
    executed_but_listed: list[str] = []

    for key in sorted(unexecuted):
        module, line = key
        entry = by_key.get(key)
        source = _source_line(package, module, line)
        if entry is None:
            regressed.append(f"{module}:{line}  {(source or '').strip()}")
            continue
        if source is None or line_digest(source) != entry.digest:
            stale.append(
                f"{module}:{line}  the listed line moved or changed; "
                f"re-check the reason and update the digest "
                f"({entry.reason})")
            continue
        permitted.append(f"{module}:{line}  {entry.reason}")

    for key in sorted(set(by_key) - unexecuted):
        module, line = key
        # Check if this is a stale entry (file deleted or line past EOF)
        # rather than a line that now runs.
        source = _source_line(package, module, line)
        if source is None:
            # File deleted or line past EOF: classify as stale, not executed.
            stale.append(
                f"{module}:{line}  the listed line no longer exists; "
                f"re-check the reason and update the digest "
                f"({by_key[key].reason})")
        else:
            executed_but_listed.append(f"{module}:{line}  {by_key[key].reason}")

    return Comparison(tuple(regressed), tuple(stale), tuple(permitted),
                      tuple(executed_but_listed))


ALLOWLIST_PATH = pathlib.Path(__file__).resolve().parent / "coverage-allowlist.txt"
PACKAGE_PATH = pathlib.Path(__file__).resolve().parent.parent / "audit_core"


def add_entry(text: str, module: str, line: int, source_line: str,
              reason: str, unexecuted: "set[tuple[str, int]]") -> str:
    """Return `text` with a new entry appended in the module's section.

    Refuses an empty reason, a line that is currently executed (there is
    nothing to permit) and a duplicate. Pure: the caller supplies the
    measured `unexecuted` set and the source line.
    """
    if not reason.strip():
        raise AllowlistError("a reason is required; a gap recorded without "
                             "one makes the denominator look accounted for")
    if (module, line) not in unexecuted:
        raise AllowlistError(f"{module}:{line} is executed (or not a "
                             "statement); there is nothing to permit")
    if any((e.module, e.line) == (module, line) for e in parse(text)):
        raise AllowlistError(f"{module}:{line} is already listed")
    entry = format_entry(module, line, source_line, reason.strip())
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    header = f"# --- {module} ---"
    if header not in lines:
        return "\n".join([*lines, "", header, entry]) + "\n"
    i = lines.index(header) + 1
    last = i - 1
    while i < len(lines) and not lines[i].startswith("# ---"):
        if lines[i].strip() and not lines[i].lstrip().startswith("#"):
            last = i
        i += 1
    lines.insert(last + 1, entry)
    return "\n".join(lines) + "\n"


def _measure_unexecuted() -> "set[tuple[str, int]]":
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "coverage.json"
        root = PACKAGE_PATH.parent
        proc = subprocess.run(
            [sys.executable, str(root / "scripts" / "coverage_probe.py"),
             "--package", "audit_core", "--tests", "tests",
             "--json-out", str(out)], cwd=root, capture_output=True, text=True)
        if not out.exists():
            raise AllowlistError("the probe did not run:\n"
                                 + (proc.stderr or proc.stdout)[-1000:])
        data = json.loads(out.read_text())
    if data["pytest_rc"] != 0:
        raise AllowlistError("the suite did not pass; the measurement is partial")
    return {(m["name"], n) for m in data["modules"] for n in m["unexecuted"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="scripts/coverage_allowlist.py",
        description="Append a correctly-formed entry to coverage-allowlist.txt.")
    ap.add_argument("--add", nargs=2, metavar=("MODULE:LINE", "REASON"),
                    required=True)
    args = ap.parse_args(argv)
    target, reason = args.add
    m = re.fullmatch(r"([\w.\-]+\.py):(\d+)", target)
    if not m:
        print(f"expected <module>.py:<line>, got {target!r}", file=sys.stderr)
        return 2
    module, line = m.group(1), int(m.group(2))
    try:
        source = _source_line(PACKAGE_PATH, module, line)
        if source is None:
            raise AllowlistError(f"{module}:{line} does not exist in audit_core")
        text = ALLOWLIST_PATH.read_text()
        # Cheap refusals first: they need no suite run.
        if not reason.strip():
            raise AllowlistError("a reason is required")
        if any((e.module, e.line) == (module, line) for e in parse(text)):
            raise AllowlistError(f"{module}:{line} is already listed")
        new = add_entry(text, module, line, source, reason, _measure_unexecuted())
    except AllowlistError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    ALLOWLIST_PATH.write_text(new)
    print(format_entry(module, line, source, reason.strip()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
