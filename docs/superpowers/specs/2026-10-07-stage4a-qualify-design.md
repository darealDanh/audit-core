# Stage 4a — `qualify`, the hard GO/NO-GO gate

**Status:** design approved 2026-10-07, not yet planned.
**Derives from:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md)
§4 (the `firmware-audit` phase table) and §4.1 (`qualify` is a hard gate);
and `~/Documents/Offsec/Opswat/Devices/TARGET-HUNTING-PLAN.md` §0 (the three
filters), §1 (the slop measurement), §3 (target tiers) and §4 (payout paths).

The parent spec remains the binding authority. This document settles what §4.1
states in one sentence and does not specify.

---

## 1. Why this, and why only this

Spec §7's Stage 4 is the whole `firmware-audit` skill: **eleven phases**.
`codebase-audit` has seven and took Stages 0 through 3b to get right. Eleven
phases is not one implementation plan, and the writing-plans scope check says
so. Stage 4 is therefore being built as a series of vertical slices, and this
is the first.

`qualify` is the right first slice for three reasons.

**It is the only phase that pays for itself before the pipeline runs.** The
hunting plan's §0: *"An EOL device is unpayable: ZDI rejects it, vendor VDPs
reject it, and the vendor will not issue a fix or a CVE."* And §4: *"A week of
work on an EOS SKU pays zero."* Spec §4.1 puts it in token terms — *"An EOL SKU
pays zero and costs thousands of tokens."* A gate that refuses such a target is
a cost win under the operator's standing cost deferral, not scaffolding for a
later one.

**It is deterministic script work against data that already exists.**
`_intel/target-scores.csv` holds 1,716 scored models. No audit run, no model
dispatch, no benchmark. It can be verified for free, which matters while the
benchmark gates are deferred on cost.

**It teaches the shape of `firmware-audit` on one phase.** If the phase model,
the data contracts, or the evidence discipline are wrong, this is the cheapest
possible place to find out.

## 2. Goals and non-goals

### Goals

1. Decide GO or NO-GO for one `vendor|model` against the hunting plan's three
   filters, with a stated reason per filter.
2. Fail closed on every filter, including the one with no data behind it.
   *Correction, 2026-10-07 (whole-branch review):* "fail closed" holds for
   **absent** data - a missing row, a missing assertion, missing evidence. It
   does not hold for **asserted-false** data: an operator who states a false
   support claim with a concrete-looking string gets a GO (see §4.3, §7).
3. Make the GO decision auditable later: the evidence that justified it is in
   the output.

### Non-goals

- **No audit runs.** The gate reads a CSV and an operator assertion.
- **No new table, no migration, no row written anywhere.** See §6.
- **Not a target picker.** See §6.
- **No change to any existing verb or to what an audit records.**

### Constraints taken as given

- `audit_core` is stdlib-only, no network, Python ≥ 3.10.
- `~/Documents/Offsec/Opswat/Devices/` is **read-only**. `qualify` reads
  `_intel/target-scores.csv` and never writes to that tree.
- The benchmark gates remain deferred on cost; nothing here needs one.

## 3. The data, as it actually is

`_intel/target-scores.csv`, 1,716 rows:

```
vendor,model,rce_cves,slop_pct,max_cvss,first_pub,last_pub,top_source,top_ref_hosts,sample_cves
qnap,qts,43,0,10.0,2024-04-26,2026-06-10,security@qnapsecurity.com.tw,www.qnap.com,CVE-...
```

**There is no support-status column.** The hunting plan encodes support status
in prose tier tables, and the only structured source is `tenda_eol.json` plus
`tenda-support-status.csv` — one vendor out of 1,716 scored models. So the
filter the plan calls binding is the one with no data behind it. §4.3 is how
that is handled.

## 4. The three filters

### 4.1 F1 — proven-bad codebase

Hunting plan §0.1: *"a real RCE CVE in 2024–2025 (not 2026; pre-AI-slop
lineage)."*

**Rule:** the model has `rce_cves >= 1` **and** its CVE publication span
overlaps 2024-01-01 … 2025-12-31 — that is, `first_pub <= 2025-12-31` **and**
`last_pub >= 2024-01-01`.

An interval-overlap test, not "`first_pub` falls in 2024", because that is what
these two columns can honestly support. A model whose CVEs span 2023 → 2025 has
pre-slop lineage; a model whose CVEs are all 2026 does not. Claiming more
precision than `first_pub`/`last_pub` provide would be inventing a measurement.

### 4.2 F2 — low mining pressure

Hunting plan §2 Tier C: *"Anything with >20 CVEs and >50% VulDB."*

**Rule:** NO-GO when `rce_cves > 20` **and** `slop_pct > 50`. Both conditions,
as the plan states it — a high-CVE low-slop vendor (DrayTek: 87 CVEs, 2%) is a
Tier A target, and a low-CVE high-slop one is not strip-mined.

Thresholds are named constants (`MAX_CVES_WHEN_SLOPPY = 20`,
`MAX_SLOP_PCT = 50`), so changing the plan's judgement is a visible edit rather
than a number buried in an expression.

### 4.3 F3 — still supported, asserted with evidence

Hunting plan §0: *"Filter 3 is the binding constraint."*

There is no data, so the operator asserts it — and the assertion must carry
evidence that survives a check. The check has **two** parts, and the second
exists because the first is not sufficient.

**Part one — the existing floor.** `db.check_identity_evidence(path, evidence)`
is already in production behind `audit.py identify`: it enforces
`MIN_EVIDENCE_CHARS = 20` and requires tokens beyond those in the subject's own
name, filtered through `text.NOISE_WORDS`. `qualify` calls it with
`"<vendor>/<model>"` as the subject.

**Part two — a checkable reference.** Part one alone is NOT enough, and this was
verified empirically rather than assumed. Run against the existing check:

| Evidence | Existing check alone |
|---|---|
| `"Zyxel NWA50AX is supported"` | **accepted** |
| `"supported"` | rejected (too short) |

The first is circular — it restates the question and adds only the word
`supported`, which the novel-token test counts as new information. An evidence
rule that accepts a claim restating its own conclusion is the rule this project
already shipped once and had to fix (Stage 3, PF-6).

So evidence must ALSO contain at least one **checkable reference**: a four-digit
year, a dotted version, or a hostname. The principle is that a support claim is
evidence only when it points at something a reader can go and verify.

| Evidence | Verdict |
|---|---|
| `"Zyxel NWA50AX is supported"` | **rejected** — nothing to check |
| `"supported, still shipping firmware"` | **rejected** — nothing to check |
| `"the vendor says it is supported and current"` | **rejected** — nothing to check |
| `"advisory ZYXEL-SA-2026-02 issued 2026-02-14 for this SKU"` | accepted — `2026` |
| `"firmware 5.21 released 2026-03-02, …"` | accepted — `5.21` |
| `"EoS listing at zyxel.com shows no end-of-support date"` | accepted — `zyxel.com` |
| `"still in the Jun 2026 advisory per the NETGEAR security page"` | accepted — `2026` |

All seven rows were run against the candidate rule before this spec was
written; they are measurements, not illustrations.

*Correction, 2026-10-07 (whole-branch review):* the table can read as though
the rule discriminates **support** claims. It does not. It discriminates
**concrete strings from vague ones**: `"it is not supported anymore as of 2020"`
passes (it contains a year), and that is inherent to a floor that checks for a
verifiable handle rather than for truth, not a bug.

**Unknown is NO-GO, never a warning.** No assertion, or an assertion whose
evidence fails the check, fails the filter. This is the fail-closed direction on
the filter the plan calls binding, and the cost of being wrong is asymmetric: a
false NO-GO costs one re-run with better evidence, a false GO costs a week.

The evidence string travels into the output, so a later reader can audit why a
GO was issued rather than taking it on trust.

## 5. Interface

```
audit.py qualify --scores PATH --vendor V --model M \
                 --supported yes|no --support-evidence TEXT [--json]
```

- `--scores` is **required with no default.** The intel tree is read-only and
  outside the repository; tests use fixtures and a real run passes the path.
- A model absent from the scored set is **NO-GO**, with that as the reason —
  not an error, and not a pass by default.
- Output names each filter, its verdict, and its reason. `--json` emits the
  same as one object.

### Exit codes

`GO` → **0**. `NO-GO` → **1**. Error → **1**.

**This follows the existing convention rather than improving on it.** `audit.py`
uses only 0 and 1 today, and both existing gates — `coverage --gate` and
`patterns --gate` — return 1 on gate failure. A third code for this one verb
would give the suite three gates and two conventions.

The known cost, recorded rather than hidden: **a script cannot distinguish
NO-GO from an error by exit code alone.** That is already true of both existing
gates. `--json` carries the verdict explicitly and is the machine-readable path.
If this is ever worth fixing, it should be fixed across all three gates in one
change, not forked here.

## 6. What this slice deliberately does not do

| Not done | Why | Where it goes |
|---|---|---|
| Write a verdict row to any database | No firmware run directory exists yet; inventing a schema for a verdict with nowhere to live is speculation, and it would need a migration | The first slice that owns a firmware run |
| Rank a whole vendor's line | That is target *selection*; this is target *qualification*. Different question, and the plan's own workflow is per-target | A later slice, if an operator needs it |
| Read `tenda_eol.json` or `tenda-support-status.csv` | Structured EoS data for one vendor out of 1,716 models would make F3 look data-backed while remaining an assertion everywhere else | Revisit when EoS data covers enough SKUs to matter |
| The other ten `firmware-audit` phases | Eleven phases is not one plan | Later slices |
| The monorepo restructure (§3.1) | No second consumer of `audit_core` exists yet | When one does |
| Run any gate or audit | Operator decision of 2026-10-07, on cost | Operator's call |

## 7. Risks

| Risk | Mitigation |
|---|---|
| The evidence check is too lenient and rubber-stamps a support claim | The existing check alone WAS too lenient — verified, see §4.3 — which is why the checkable-reference requirement exists. *Correction, 2026-10-07:* testing both parts does not address the rule's ceiling. The rule blocks absent and vague claims and puts the assertion in the output, where a later reader can falsify it; it does not resist a motivated operator, and any 20+ character string with a year and one novel token passes (recorded as `qualify-f3-not-adversarial`) |
| The evidence check is too strict and blocks a legitimate GO | Fails in the cheap direction — one re-run with better evidence, against a week of wasted work |
| `target-scores.csv`'s schema changes and the loader breaks silently | The loader validates its header and refuses an unexpected one rather than reading columns positionally |
| A GO is issued and the target is EOL anyway | The evidence string is in the output; the decision is auditable after the fact |
| This slice ships and the remaining ten phases never follow | `qualify` has standalone value — it answers "is this worth a week?" with no other phase present |

## 8. Decisions taken

1. **Stage 4 is sliced; `qualify` is the first slice** — chosen over a monorepo
   restructure first (large, mechanical, no user-visible value, and the §10
   grey-audit question is unsettled) and over committing to all eleven phases
   in three sub-plans (long runway, and the gate cannot run under the cost
   deferral).
2. **F3 is asserted with evidence — the existing identity check PLUS a
   checkable reference — and fails closed** — chosen over an
   operator-maintained support file (1,716 models of curation nobody has
   started, going stale silently) and over scoring two filters and reporting
   support as unknown (makes the hard gate soft exactly where the plan says it
   is binding).
3. **NO-GO exits 1, matching the two existing gates** — chosen over a distinct
   exit 2, which would fork the convention for one verb.
4. **One SKU per invocation** — chosen over ranking a vendor line, which is a
   different question.

## 9. Open questions

None blocking. One to revisit once a firmware run directory exists: whether
`qualify`'s verdict should be recorded alongside the run it gates, and what
table would hold it.
