# Stage 4b — `acquire` and `triage`, the slice that owns a firmware run

**Status:** design approved 2026-10-08, not yet planned.
**Derives from:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md)
§4 (the `firmware-audit` phase table, rows `acquire` and `triage`), §3.4 (state
model), §3.3 (core boundary) and §5 (the economics contract);
[`2026-10-07-stage4a-qualify-design.md`](2026-10-07-stage4a-qualify-design.md)
§6, which defers the first firmware run directory to "the first slice that owns
a firmware run" — this one; and
`~/Documents/Offsec/Opswat/Devices/TARGET-HUNTING-PLAN.md` §5 steps 1 and 2.

The parent spec remains the binding authority. This document settles what §4's
two table rows state in a sentence each and do not specify.

---

## 1. Why this, and why only this

Stage 4 is built as vertical slices because eleven phases is not one
implementation plan. `qualify` was the first. This is the second, and it is
second because nothing else can be third without it: `diff` needs two carved
trees, `surface` needs to know which binaries exist, `hunt` needs an
architecture to reason about, and `coverage` needs a denominator. All four come
out of this slice.

It also discharges a debt Stage 4a took on deliberately. 4a §6 refused to write
a verdict row because "no firmware run directory exists yet; inventing a schema
for a verdict with nowhere to live is speculation." This slice creates the
place.

And it is verifiable at zero audit cost, which the operator's standing
instruction (`SESSION_HANDOFF.md` §3) requires of everything until the
benchmark budget is spent deliberately. Hashing a file and reading an ELF
header dispatch no model and cost no tokens.

## 2. Goals and non-goals

### Goals

1. Record the provenance of an acquired firmware image — vendor, model,
   version, role, sha256, size, source — so that later phases can state which
   build a finding came from and a reader can check it.
2. Model the **pair** §4 requires: the latest build as the attack `target` and
   the CVE-affected build as the `diff-reference`. `diff` is built on that
   pairing existing as data.
3. Turn an already-carved rootfs into rows: an inventory of every file, the ELF
   facts of every binary, and the services started at boot.
4. Give `coverage` a real firmware denominator, using the existing
   `cba_inventory` and `cba_coverage` tables unchanged.
5. Leave behind a reusable, tested ELF reader that `diff`, `surface`, `hunt`
   and `dive` inherit rather than each reinvent.
6. Ship both halves of the phase — the script and its dispatch brief — so that
   following the shipped instructions exactly produces a correct run.

### Non-goals

See §7. The short form: this slice does not carve, does not derive open ports,
does not touch the kernel or bootloader, does not diff, does not create a
`firmware-audit` skill tree, and does not run an audit.

### Constraints taken as given

- `audit_core` is stdlib-only and reaches no network. `pyproject.toml` declares
  `dependencies = []` and this slice does not change that. Consequently
  `acquire` cannot fetch and `triage` cannot carve; both are recorders of work
  done elsewhere, which is what spec §4 already says by putting `acquire`'s
  work location at "orchestrator".
- `~/Documents/Offsec/Opswat/Devices/` is read-only. `triage` reads a carved
  tree there and writes only into the run directory.
- The benchmark gates are deferred on cost. Everything here is verified by unit
  tests and by one self-consistency check against a tree already on disk.

## 3. Why the agent half ships with the script half

Both the Stage 2 and the Stage 3 whole-branch reviews found Criticals that
every task-scoped review was structurally blind to, and Stage 3's was exactly
this shape: the coverage gate shipped with a reader and no writer, so following
the shipped workflow on a correct run produced FAIL / exit 1. A phase whose
script half exists and whose agent half does not is the same defect with the
halves swapped.

`triage` is "script + 1 agent" in spec §4. Both halves ship here.

## 4. The three modules

The CLI surface is two verbs. The module boundary is three, because the ELF
reader is needed by phases this slice does not build and should not be buried
inside the one that happens to need it first.

### 4.1 `audit_core/elf.py` — a pure reader

No database, no run directory, no knowledge of phases. One entry point:

```python
read(path: str | pathlib.Path) -> ElfFacts | None
```

It returns `None`, rather than raising, for anything that is not an ELF. The
tree walker calls it on every file in a carved rootfs, and a reader that raises
on the first truncated file aborts the walk.

`ElfFacts` is a frozen dataclass:

| Field | Source | Notes |
|---|---|---|
| `machine` | `e_machine` | mips, arm, aarch64, x86-64, i386, riscv, ppc, or the raw number |
| `bits` | `EI_CLASS` | 32 or 64 |
| `endian` | `EI_DATA` | little or big |
| `elf_type` | `e_type` | EXEC, DYN, REL, CORE |
| `interp` | `PT_INTERP` | the dynamic loader path; the libc flavour reads off it |
| `needed` | `DT_NEEDED` | the SBOM edges |
| `runpath` | `DT_RUNPATH` / `DT_RPATH` | |
| `nx` | `PT_GNU_STACK` flags | |
| `pie` | `e_type` + `PT_INTERP` | DYN with an interp is PIE; DYN without is a shared library |
| `relro` | `PT_GNU_RELRO` + `DT_BIND_NOW` | full, partial, none |
| `canary` | `__stack_chk_fail` in the symbol tables | |
| `stripped` | absence of `.symtab` | |
| `static` | no `PT_INTERP` and no `PT_DYNAMIC` | |

**Three states, not two.** `nx`, `pie`, `canary`, `stripped` and `static` each
report `yes`, `no` or `unknown`. A stripped static binary cannot honestly answer
"canary": the symbol that would prove it is gone, and its absence proves
nothing. `unknown` is the correct answer and the schema has room for it. This is
the same discipline `cba_coverage` applies to a gap — record the gap, do not let
it look accounted for.

**It must survive garbage.** A carved tree contains truncated files, files that
start with the right four magic bytes by accident, and headers whose offsets
point past the end of the file. Every one of those returns `None` or a partially
populated `ElfFacts` with `unknown` fields. None of them raises.

### 4.2 `audit_core/acquire.py` — provenance

```python
record(con, *, vendor, model, version, role, path, source, replace=False)
```

Streams the file through `hashlib.sha256` in bounded chunks, stats its size, and
writes one `cba_images` row. The primary key is `vendor|model|role`, so
recording a second `target` for the same SKU requires `--replace`, following the
`identify --replace` precedent and its documented limitation: on `--replace`,
`db.put` merges over the stored row, so an omitted optional field keeps its
stored value and cannot be cleared by omission.

It refuses a path that does not exist or cannot be read. There is no default
path: like `qualify --scores`, the material lives outside this repository and
guessing where is how a verb silently reads the wrong file.

### 4.3 `audit_core/triage.py` — the walk

```python
run(con, root, *, image_id=None, allow_no_elf=False) -> TriageSummary
```

Walks the carved root once. For each **regular file** it records a
`cba_inventory` row with its path relative to the root, its kind and its size.
For each ELF it also writes a `cba_binfacts` row.

Kind is decided by inspection, not by extension: `binary` via `elf.read`,
`script` via shebang, `config` for a non-ELF non-script file under `/etc`, and
`file` for everything else. `db.INVENTORY_KINDS` is currently
`("file", "function", "endpoint", "binary")`; this slice appends `"script"` and
`"config"` to it. That tuple is a validator list, not schema, so appending to it
needs no migration — but it is append-only for the same reason `MIGRATIONS` is:
removing a value silently invalidates rows already written.

**Directories and symlinks are not inventoried.** `cba_inventory` is the
coverage denominator, and a denominator should hold things that can be analysed.
A directory cannot be. Symlinks are the harder call: busybox applet links are
genuine signal about what a firmware's shell provides. They are left out anyway,
because counting several hundred applet links as unanalysed units would swamp
the denominator, and the signal is recovered properly by the agent identifying
busybox once as a component with its applet set as evidence.

Separately it scans `/etc/init.d/`, `/etc/inittab`, `/etc/rc.d/` and
`/etc/rc.local` for services started at boot, recording the service name, the
file that starts it, the executable path where it resolves, and **the matched
line as evidence**. A service row with no evidence line is not written.

It refuses, naming the cause, when `--root` is not a directory; when
`--image-id` names a row that is not in `cba_images`; and when the tree contains
zero ELF binaries unless `--allow-no-elf` is passed. See §8 for why that last
escape hatch exists rather than the refusal simply being softened.

The `--image-id` check matters because the whole value of `acquire` is that a
later reader can tell which build a row came from. An `image_id` that resolves
to nothing is a provenance claim with no provenance, and it fails silently in
exactly the place the slice exists to make checkable.

## 5. Data

Three new tables in `audit_core/schema.sql`, each registered in
`db.TABLE_SPECS`. `cba_inventory`, `cba_coverage` and `cba_components` are
reused unchanged — the payoff of keeping firmware on the shared prefix and the
shared `audit.py init`.

```sql
CREATE TABLE IF NOT EXISTS cba_images (
    id TEXT PRIMARY KEY,          -- vendor|model|role
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    version TEXT NOT NULL,
    role TEXT NOT NULL,           -- target | diff-reference
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER,
    source TEXT,
    acquired_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_binfacts (
    path TEXT PRIMARY KEY,        -- relative to the carved root
    image_id TEXT,
    machine TEXT NOT NULL,
    bits INTEGER NOT NULL,
    endian TEXT NOT NULL,
    elf_type TEXT NOT NULL,
    interp TEXT,
    needed TEXT,                  -- comma-joined DT_NEEDED
    runpath TEXT,
    nx TEXT, pie TEXT, relro TEXT, canary TEXT, stripped TEXT, static TEXT,
    sha256 TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_services (
    name TEXT PRIMARY KEY,
    image_id TEXT,
    start_source TEXT NOT NULL,   -- the init file that starts it
    exec_path TEXT,               -- the binary, where it resolves
    evidence TEXT NOT NULL,       -- the matched line
    ports TEXT,                   -- agent-asserted; the script leaves it blank
    ports_evidence TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));
```

**No `MIGRATIONS` entries are needed.** `db.MIGRATIONS` exists for columns added
to tables that already shipped, because SQLite has no
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` and `CREATE TABLE IF NOT EXISTS` is a
no-op against a table that is already there. A wholly new table has neither
problem: `workspace.apply_schema` executes the entire script, so
`audit.py init --timestamp <existing-ts>` adds all three to a run directory
created by an earlier stage. If a later slice adds a *column* to one of these
three, that column needs a `MIGRATIONS` entry.

**Contract changes in `db.py`.** Two new enums: `IMAGE_ROLES = ("target",
"diff-reference")` and the three-state `TRISTATE = ("yes", "no", "unknown")`
used by the five `cba_binfacts` mitigation columns. One append:
`INVENTORY_KINDS` gains `"script"` and `"config"`, per §4.3.

**One new validator.** `cba_services.ports` is the only column in these three
tables that the script never writes and the agent always does. A `ports` value
without a `ports_evidence` value is refused. This is the discipline
`_validate_verdict` applies to a refuting mechanism and `identity.check_evidence`
applies to a circular identification, at the one place in this slice where a
claim arrives from a model rather than from a file.

## 6. Interface

```
audit.py acquire --run DIR --vendor V --model M --version X
                 --role {target,diff-reference} --file PATH
                 --source TEXT [--replace] [--json]

audit.py triage  --run DIR --root CARVED_ROOTFS
                 [--image-id ID] [--allow-no-elf] [--json]
```

### Exit codes

Following `qualify`:

| Code | Meaning |
|---|---|
| 0 | recorded |
| 1 | refused — the message names the cause |
| 2 | usage error |

`triage` refusing an empty tree matters more than it looks. Writing an inventory
of nothing succeeds silently and poisons the coverage denominator of every phase
downstream: `coverage` would report full analysis of a zero-unit corpus, and
`indicators` would read it as a clean run. Fail closed.

## 7. What this slice deliberately does not do

| Not doing | Why | Where it goes |
|---|---|---|
| Carving | `audit_core` is stdlib-only and invokes no external tool; binwalk and unblob are neither stdlib nor present on every machine, and shelling out would make the phase's output machine-dependent and its tests unable to assert the real path | the orchestrator, instructed by the workflow |
| Deriving open ports | not honestly derivable from a static tree — boot-start is readable from init scripts, listening is not | the agent, asserted with `ports_evidence` |
| nvram defaults | file layouts are vendor-specific; a script that guesses them is wrong per vendor | the agent, recorded via `note` |
| Kernel and bootloader analysis | a different surface needing different tooling | a later slice |
| Patch-diff | needs two carved trees to exist first, which is what this slice provides | Stage 4c, `diff` |
| Dispatch and handler tables | that is `surface`; the boundary is that `triage` records *that* a service starts and from where, `surface` enumerates its handlers | Stage 4d, `surface` |
| A `firmware-audit` skill tree | that is spec §3.1, blocked on spec §10 being undecided | after §10 is settled |
| Writing a `qualify` verdict row | still no consumer; the debt 4a §6 recorded was the run directory, and this slice pays that part | the slice that first reads a verdict |
| Running any audit | `SESSION_HANDOFF.md` §3, the standing cost deferral | when the operator asks |

## 8. Risks

| Risk | Mitigation |
|---|---|
| The ELF reader is subtly wrong on an exotic target | Three-state reporting makes `unknown` available instead of a confident wrong answer; and the corpus self-consistency test (§9) is the only check that measures the reader against reality rather than against fixtures I wrote myself |
| The zero-ELF refusal fires on a legitimate tree | An RTOS/MCU image has no ELFs at all, and spec §8 names RTOS/MCU as one of the three golden targets, so this is real and not hypothetical. The refusal keeps its default and gains a documented `--allow-no-elf`: fail closed, with a way through that leaves a trace in the command line |
| Boot-start service extraction creeps into `surface` | The boundary is stated in §7 and the brief repeats it |
| `cba_binfacts.path` collides across two carved trees in one run | The key is the path relative to its root, so two images carved into one run would collide. This slice records `image_id` on the row; a later slice that genuinely triages two trees into one database must make the key composite, and that will need a migration |
| Prose regression in the new brief | Rule 6 — the derivation is written before the prose and reconciled against `git diff -U0` after. Rewriting shipped prose lost instructions five times out of five in Stage 1 |

## 9. Verification

All of it zero audit cost.

**`elf.py` against synthesized bytes.** No vendor binary enters the repository:
synthesized headers are license-clean, deterministic, small enough to read in
the test, and able to express combinations no binary on this machine has. A
fixture factory emits MIPS big- and little-endian, ARM, AArch64 and x86-64; EXEC
and DYN; with and without `PT_GNU_STACK`; full, partial and no RELRO; stripped
and unstripped. Alongside them, the garbage a carved tree actually contains:
zero-length, wrong magic, truncated at each structurally interesting offset,
`e_phoff` past EOF, and an absurd `e_phnum`.

**`acquire.py`** — hash against a known vector, missing-file refusal,
duplicate-role refusal, `--replace` behaviour, and the merge-on-replace
limitation asserted rather than assumed.

**`triage.py`** — a synthetic carved tree under `tmp_path` holding init scripts,
symlinks, a shebang script, several ELFs and junk; asserting inventory counts
and kinds, service extraction with evidence, and the zero-ELF refusal with and
without `--allow-no-elf`.

**One corpus test.** `triage` over `gl_inet/extracted/rootfs`, asserting
self-consistency: every `cba_binfacts` path present in `cba_inventory`, a
uniform architecture across the tree, and every resolvable service `exec_path`
pointing at a file that exists. It SKIPs when the corpus is absent, the shape
`bench` already uses, so it is green on any machine and meaningful on the
operator's.

**Gates.** `make all` stays green. `selftest` moves from 15 tables to 18 and
from 14 under contract to 17. `feature_lists.json` gains an entry per feature
with its `tests`, `modules` and `docs`, or `manifest` fails.

## 10. Decisions taken

1. **`audit_core` never carves** — chosen over shelling out to binwalk/unblob
   when present. Shelling out keeps the dependency list empty but makes the
   phase's output depend on what is installed, so the tests could only ever
   assert the fallback path and a missing tool would silently change what the
   phase produced.
2. **The firmware run reuses `audit.py init` and the `cba_` prefix** — chosen
   over an `fwa_` prefix and over a separate `init --kind firmware`. The shared
   spine is the parent spec's thesis; `coverage`, `status`, `bench` and
   `indicators` keep working with no edits. The accepted cost is that `cba_` now
   means "core" rather than "codebase-audit", a naming debt recorded here so it
   is not rediscovered as a surprise.
3. **Two verbs over three modules** — chosen over one verb doing both and over
   four small verbs. One verb cannot express recording a diff reference before
   it is carved, which is exactly what `diff` needs. Four verbs add to a CLI
   that already has 23 and make the orchestrator responsible for call order,
   which is what R5 and R6 exist to prevent.
4. **Both halves ship** — the script and `references/briefs/triage-brief.md`,
   for the reason in §3.
5. **Open ports are asserted, not derived** — a static tree does not contain the
   answer, and a verb that emits a confident wrong one is worse than a brief
   that asks for evidence.

## 11. Open questions

None blocking. Two noted for the slices that will meet them:

- Whether `cba_binfacts.path` becomes composite with `image_id` — forced the
  first time two carved trees share one run, which `diff` may or may not do
  depending on how it is designed.
- Whether `qualify`'s verdict gets written to `cba_images` or to a table of its
  own, once a phase exists that reads it.
