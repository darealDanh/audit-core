# Architecture

How this repository is put together, and why it is put together that way.
For *what has been built and what has not*, read [`progress.md`](progress.md).
For *how to pick the work back up*, read
[`SESSION_HANDOFF.md`](SESSION_HANDOFF.md).

---

## 1. The thing being built

This repository ships **one skill, made of two different kinds of material**:

| Material | What it is | Who executes it |
|---|---|---|
| **Prose** — `SKILL.md`, `workflows/`, `references/` | Instructions an LLM reads and follows | A model, at audit time |
| **Code** — `audit.py`, `audit_core/` | A stdlib-only Python CLI the prose calls | A shell, at audit time |

Everything hard about this project comes from that split. A bug in the code
fails loudly: a test goes red, a verb exits non-zero. A bug in the prose fails
*silently* — a model reads an instruction that is no longer there, does
something slightly worse, and the only evidence is a vulnerability nobody
found. The project's whole verification apparatus exists to make prose defects
as visible as code defects:

- `audit.py lint-skill` checks shipped prose against the economics contract.
- `tests/test_workflow_prose.py` and `tests/test_brief_templates.py` assert
  that specific instructions are present, by content, not by line number.
- **Anti-absence derivations** (`docs/superpowers/derivations/`) enumerate every
  intended prose change *before* it is made and reconcile against
  `git diff -U0` after. This exists because rewriting shipped prose lost
  instructions five times out of five in Stage 1.
- The **line-ending contract** (§7) keeps prose diffs small enough to read.

**Nothing in this repository is a web service, and nothing reaches the
network.** `audit_core` is stdlib-only by contract; `pyproject.toml` declares
`dependencies = []` and `requires-python = ">=3.10"`.

---

## 2. Repository layout

```
SKILL.md                  the skill's entry document (CRLF)
workflows/                one file per phase: recon, deploy, audit, fpcheck,
                          verify, report, source (+ an archived v1 pipeline)
references/               phase deep-dives, lessons learned, dispatch brief
                          templates under references/briefs/
claude/commands/          Claude Code launcher stubs

audit.py                  the CLI: 22 verbs, argparse, one cmd_* per verb
audit_core/               the logic the verbs are thin wrappers over
audit_core/schema.sql     the audit.db schema
audit_core/baseline-pre-stage3.sql
                          a frozen pre-Stage-3 database, used by selftest to
                          prove MIGRATIONS actually repairs an old run

install.sh / install.ps1  per-client installers
scripts/                  the verification harness (§8) - never installed
tests/                    pytest suite; tests/goldens/ holds adjudicated
                          reference finding sets
docs/superpowers/specs/   the design spec - the binding authority
docs/superpowers/plans/   one implementation plan per stage
docs/superpowers/derivations/
                          anti-absence derivations for prose edits
docs/baselines/           measurements and gate procedures, never edited in
                          place; a correction is a new dated file
.github/workflows/ci.yml  runs the same gates as `make check`
```

---

## 3. The phase pipeline

Seven phases, each a file in `workflows/`. The orchestrator runs them in order;
most transitions are user-gated.

```
recon ──> deploy ──> audit ──> fpcheck ──> (fork per finding) verify ──> report
  │                                                                        
  └── source: recon → audit → fpcheck → report, unattended, no live instance
```

- **recon** — detect the source, split it into feature groups, dispatch one
  mapping subagent per group, write a resume note.
- **deploy** — stand up a live instance. Skipped in source-only mode.
- **audit** — ingest prior CVEs to find patch-bypass surfaces, then one
  deep-audit subagent per group.
- **fpcheck** — static false-positive review. No live testing.
- **verify** — runs in a *forked* conversation, per finding, with a live PoC
  and an adversarial review. Refuses to run without explicit finding IDs.
- **report** — the lean maintainer format. Per-finding in the fork for live
  runs; one consolidated report for source-only runs.
- **source** — a composite that chains four phases unattended, auto-resolving
  every gate. Every finding it writes is `verified='source-only'`.

The orchestrator fans out to subagents in recon, audit and fpcheck. That
fan-out is where the money goes, and it is what the economics contract governs.

---

## 4. The economics contract (R1–R6)

The spec's §5 rules, enforced in `SKILL.md` and checked by `lint-skill`:

| Rule | What it requires | Where it lives |
|---|---|---|
| **R1** | The orchestrator never holds raw material — subagents read files, the orchestrator reads summaries | `audit_core/extract.py` |
| **R2** | Subagents return a fixed contract, not prose | `SKILL.md`, brief templates |
| **R3** | A context ceiling with checkpoint-restart, so a run survives its own length | `audit_core/ceiling.py` |
| **R4** | An MCP preflight that names only the servers a run needs | `audit_core/preflight.py` |
| **R5** | Reusable logic is an `audit.py` verb, never an inline heredoc | `audit.py` |
| **R6** | Dispatch briefs are files, not prose pasted into a prompt | `audit_core/briefs.py` |

R5's dependency is easy to miss and expensive to rediscover: `install.sh`
originally copied only the prose, so the moment a workflow invoked `audit.py`
every installed copy broke. The installer now copies `audit.py` and
`audit_core/` too, and substitutes `__SKILL_DIR__` so each client's copy calls
its own.

---

## 5. State model

One SQLite database per run, at `reports/audit-<timestamp>/audit.db`, created
by `audit.py init`.

**Fourteen tables under contract**, all prefixed `cba_`:

| Group | Tables |
|---|---|
| Recon | `cba_sources`, `cba_feature_groups`, `cba_attack_surface`, `cba_security_observations` |
| Audit | `cba_known_findings`, `cba_findings` |
| FP-check | `cba_fp_verdicts` |
| Coverage | `cba_inventory`, `cba_coverage` |
| Sweep | `cba_patterns`, `cba_pattern_hits` |
| Control | `cba_checkpoints` |
| Stage 3 | `cba_components`, `cba_chains` |

> `selftest` reports **15** tables in `schema.sql` against **14** under
> contract. The fifteenth is `sqlite_sequence`, which SQLite creates by itself
> for `AUTOINCREMENT`. Nothing is missing.

**Access is validated and bounded.** `audit_core/db.py` is the only writer.
It holds `TABLE_SPECS` (columns, required columns, validators) and refuses a
row that does not satisfy them — a verdict outside the enum, a component kind
that is not a kind, a chain that claims completeness it has not earned, an
identity with fewer than `MIN_EVIDENCE_CHARS` of evidence.

**Migrations are first-class.** SQLite has no `ALTER TABLE … ADD COLUMN IF NOT
EXISTS`, and `CREATE TABLE IF NOT EXISTS` is a no-op against a table that
already exists — so adding a column to `schema.sql` repairs *nothing* on a
database that exists already. `db.MIGRATIONS` carries the four column
additions, `migrate()` applies them, and `connect()` refuses a database that
has not been migrated. `selftest` proves the loop end to end by migrating the
frozen `baseline-pre-stage3.sql` and handing the result to `connect()`.

**`put(replace=True)` merges; it does not replace.** A bare
`INSERT OR REPLACE` drops every column the caller did not pass. That destroyed
`final_id`, `merged_into` and `final_severity` on a pivot — columns a
*different* workflow step writes. `db.put` now reads the stored row and merges.

---

## 6. `audit_core` module map

| Module | Lines | Responsibility |
|---|---|---|
| `db.py` | 579 | Validated, bounded access to a run's `audit.db`. Specs, validators, migrations, merge-on-replace. |
| `coverage.py` | 275 | Coverage accounting: the denominator, not a feeling. Inventory vs analyzed, a reason for every gap, and a gate. |
| `chains.py` | 237 | Propose cross-group finding pairs that compose into an exploit chain; record composed ones. |
| `extract.py` | 231 | Extract once, fan out without a cap (R1). |
| `transcript.py` | 231 | Parse a Claude Code JSONL session into typed records. |
| `budget.py` | 172 | Session economics: epochs, prefix, growth, attribution. |
| `bench.py` | 192 | Score a run against a golden set: recall, severity agreement, weighted recall, precision, coverage, cost per match. |
| `readings.py` | - | A measurement that can be a value, `absent` (no table) or `empty` (table, no rows) - never a silent `0`. |
| `indicators.py` | - | The four deterministic leading indicators and their dated snapshots. |
| `rerate.py` | - | Advisory report of findings whose severity disagrees with their own evidence. Stores nothing. |
| `sweep.py` | 184 | Sweep a confirmed bug pattern across the corpus. |
| `skill_lint.py` | 164 | The shipped skill against the economics contract. |
| `annotations.py` | 123 | An append-only journal: comprehension that survives a restart. |
| `ceiling.py` | 115 | The context ceiling and its checkpoint (R3). |
| `pivot.py` | 112 | Write a FALSE_POSITIVE verdict and the observation it pivots to, together. |
| `patterns.py` | 111 | Which registered bug patterns have been swept, and which have not. |
| `goldens.py` | 93 | Golden reference sets and adjudicated match records. |
| `workspace.py` | 81 | Create a run directory and apply its schema. |
| `briefs.py` | 75 | Render a subagent dispatch brief from a template (R6). |
| `preflight.py` | 69 | Write a project-scoped MCP config (R4). |
| `text.py` | 66 | Normalization shared by dedup, golden scoring and identity evidence. |
| `identity.py` | 45 | An asserted identity needs evidence that is not the component's own name. |

### The twenty-two verbs

```
init  selftest  preflight  brief  lint-skill            setup and self-check
put   rows      status     note   checkpoint            state
extract  coverage  sweep    patterns                    breadth
dedup    chain    pivot     identify                    quality
budget   bench    indicators  rerate                  measurement
```

### Stage 3's five quality mechanisms

Each answers a named cause of a missed CRITICAL in the tplink post-mortem,
where an audit found 9 of 19 known criticals:

1. **Pivot rule** (`pivot.py`) — a FALSE_POSITIVE must record what refuted it
   *and* what that refutation enables. A dismissal that leaves no trail loses
   the observation underneath it.
2. **Sweep-on-confirm** (`patterns.py`, `sweep.py`) — a confirmed bug becomes
   a registered pattern, and a registered pattern that was never swept is a
   reportable gap. One instance of a bug class is rarely the only one.
3. **Coverage denominator** (`coverage.py`) — analyzed over inventoried, with
   a reason for every gap, and a gate at phase exit. Coverage you cannot
   divide is a feeling.
4. **Identity discipline** (`identity.py`) — asserting what a component *is*
   requires evidence that is not its own filename. `km0_boot_0C000020.elf` is
   not evidence that the file is a boot image.
5. **Chain composition** (`chains.py`) — cross-group finding pairs are
   proposed as candidate chains, and findings never examined as enablers are
   reported as such. Two mediums in different groups can be one critical.

---

## 7. Two contracts that are easy to break by accident

### The line-ending contract

Six files ship with **CRLF**; everything else ships with **LF**.

```
SKILL.md
references/phase0-source-detection.md
references/phase2-feature-mapping.md
references/phase4-deep-audit.md
references/phase5-fp-check.md
workflows/_audit-pipeline-v1-archive.md
```

This is not legacy mess. `install.sh` substitutes `__SKILL_DIR__` line by line
with `sed`; normalising one of these files rewrites **every line of its diff**,
and a diff where every line changed is a diff in which an accidental deletion
is invisible. The authoritative list is
[`scripts/eol-manifest.txt`](scripts/eol-manifest.txt); the `eol` gate and
`tests/test_harness.py` both enforce it.

### `>` blockquotes in workflow files are presented, not executed

A command placed inside a `>` blockquote in a workflow file is shown to the
user rather than run. Stage 3 shipped its coverage gate into one and it never
executed in either mode. When adding a command to a workflow, check what block
it lands in.

---

## 8. The verification harness

`scripts/harness.py` owns every gate; `make` and CI are thin wrappers over it.
Adding a gate there makes it appear in `make list` and in CI with no further
edits.

| Gate | Default | What it proves |
|---|---|---|
| `tests` | yes | The pytest suite (569 tests). |
| `selftest` | yes | Verbs vs parser, `TABLE_SPECS` vs `schema.sql`, `MIGRATIONS` vs the frozen baseline — each comparing two structures built independently. |
| `lint` | yes | Shipped prose against the economics contract. |
| `eol` | yes | The CRLF/LF split above, across tracked *and* newly added files. |
| `manifest` | yes | `feature_lists.json` against the tree it describes: every path exists, every verb is dispatchable, every status is in the enum. |
| `install` | yes | A sandboxed `install.sh` run, no surviving `__SKILL_DIR__`, and the real install's mtime unmoved. |
| `bench` | opt-in | Recall, precision and cost against the tplink golden set. SKIPs when the corpus is absent. |

```bash
make check          # the six default gates
make all            # plus bench
make list           # every gate and what it checks
make json           # one JSON object, for CI and for agents
make eol            # any single gate
```

**The install gate is the reason the harness is Python and not a Makefile
recipe.** `install.sh` resolves its four destinations from `$HOME` and
`$CODEX_HOME` *at run time*, so an unguarded invocation overwrites the
operator's real working skill at `~/.claude/skills/codebase-audit/`. The gate
builds a throwaway `HOME`, **refuses to proceed if that HOME resolves to the
real one**, and asserts afterwards that all four real destinations' mtimes did
not move. A recipe that forgets one `env` assignment does the damage silently.

---

## 9. Measurement

Quality is measured, not asserted. `audit.py bench` scores a run's `audit.db`
against an adjudicated golden set in `tests/goldens/`:

- **Recall** — matched references over the reference count (currently 9/19).
- **Precision** — true positives over adjudicated findings (currently 39/40).
- **Cost per match** — the number that makes a cost win and a quality loss
  comparable (currently $73.15).

`tests/goldens/*/matches.json` and `rejections.json` are **human
adjudications**. They are never written by a tool and never regenerated.

`docs/baselines/` holds the measurements. A baseline is never edited in place:
a correction is a new dated file, so the correction stays visible in git
history. `2026-10-04-tplink-baseline.md` is superseded and labelled as such
rather than deleted.

---

## 10. Constraints that are not negotiable

1. **`audit_core` is stdlib-only** and reaches no network. `pyproject.toml`
   declares `dependencies = []`.
2. **Python 3.10 is the floor.** CI runs 3.10, 3.12 and 3.13.
3. **Never run `install.sh` or `install.ps1` without overriding `HOME`,
   `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** Use `make install-smoke`.
4. **Never write `tests/goldens/*/matches.json` or `rejections.json`.**
5. **Never edit a baseline in place.** Append, or write a new dated file.
6. **`~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` are
   read-only.** They hold real audit corpora and real session transcripts.
