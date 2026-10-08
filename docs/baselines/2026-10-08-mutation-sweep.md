# Mutation sweep - audit_core, 2026-10-08

**Measured against:** branch `stage3c/core-hardening` at `a1c2990` (the commit
that made the gate fail on stale allowlist entries), after Stage 3c closed the
115 unexecuted statements (0 of 2392 now unexecuted). Working tree clean.
**Tests:** 779 collected and passing on the real tree. One of them,
`tests/test_harness.py::test_the_eol_manifest_matches_the_tree`, fails on the
unmutated *copy* the sweep builds and is therefore excluded from every mutant
run (the instrument reported this itself); see Caveats.
**Instrument:** `scripts/mutate.py`, `make mutate`, 8 workers, operators
`constant`, `compare`, `boolop`.
**Runtime:** 54m05s wall (3245.0s reported by the gate), 9410s user CPU.
The canary did not trip; the first-run state was empty, so this is a single
uninterrupted run.

## Result

| | count |
|---|---|
| mutants | 1068 |
| killed | 708 |
| survived | 360 |
| timeout | 0 |
| error (import) | 0 |

**Mutation score:** 708 / (708 + 360) = **66.3%** (survivor rate 33.7%).
The brief's ~42% survivor estimate was high; the real rate is a third.

Gate outcome: **FAIL**, as intended. 360 survivors, 9 allowlisted as
equivalent, **351 unexplained**, 0 stale allowlist entries.

## Where the tests are strong and weak

| Mutant kind | Killed / total | Kill rate |
|---|---|---|
| `not` removal | 89 / 89 | 100.0% |
| logic: compare + boolop | 225 / 258 | **87.2%** |
| all logic (compare + boolop + `not`) | 314 / 347 | 90.5% |
| constant: numeric and bool | 160 / 216 | 74.1% |
| constant: prose string (incl. 7 equivalent attribute docstrings) | 234 / 505 | **46.3%** |
| constant: prose string, excluding those 7 | 234 / 498 | 47.0% |
| **overall** | **708 / 1068** | **66.3%** |

**`audit_core`'s tests verify behaviour well and message text poorly.** Only 33
of the 360 survivors are logic; 271 are prose strings. Counts of survivors
alone mislead (strings are simply the most numerous constant), so rank work by
these rates, not by the survivor table below. Recomputed from the state file;
the coordinator's logic row (225/258) matches, and the table adds the 89 `not`
mutants, which that row omitted (258 + 216 + 505 = 979, not 1068).

## Real defects

**None found.** No sampled mutant was a case where the mutated behaviour was
correct and the original wrong. This is a statement about the 87 sampled
mutants only (see Sampling), not about the 360.

## Survivors by kind

| kind | survivors |
|---|---|
| constant: string fragment (messages, labels, separators) | 264 |
| constant: number (limits, defaults, precision) | 47 |
| constant: bool (`parents=True`, parameter defaults) | 9 |
| constant: attribute docstring (equivalent) | 7 |
| compare boundary/flip | 17 |
| boolop flip | 16 |
| **total** | 360 |

String fragments are 73% of survivors but also 47% of all mutants (505 of
1068), so the share says little; use the kill-rate table above for priority. The
expensive survivors are the 33 compare/boolop ones and the 56 numeric and bool
constants, which are boundaries, defaults and fallbacks.

## Survivors by (module, operator): 38 buckets

Sample (listed in full below) = the first, the median and the last survivor of the bucket by line
number (fewer when the bucket has fewer than three). Verdict rule applied to
each sampled mutant after reading its source line: a string fragment in output
the tests run -> weak test; a boundary, limit, default or boolean flag no test
distinguishes -> missing test; provably unobservable -> equivalent.

| module | operator | survivors | composition | sampled |
|---|---|---|---|---|
| `annotations.py` | compare | 1 | 1 compare | 1 |
| `annotations.py` | constant | 11 | 2 bool, 1 number, 8 string | 3 |
| `bench.py` | compare | 1 | 1 compare | 1 |
| `bench.py` | constant | 8 | 1 attr-docstring, 3 number, 4 string | 3 |
| `briefs.py` | constant | 10 | 2 bool, 1 number, 7 string | 3 |
| `budget.py` | constant | 47 | 6 number, 41 string | 3 |
| `ceiling.py` | compare | 2 | 2 compare | 2 |
| `ceiling.py` | constant | 27 | 5 number, 22 string | 3 |
| `chains.py` | boolop | 1 | 1 boolop | 1 |
| `chains.py` | constant | 18 | 1 bool, 2 number, 15 string | 3 |
| `coverage.py` | boolop | 1 | 1 boolop | 1 |
| `coverage.py` | constant | 15 | 1 number, 14 string | 3 |
| `db.py` | boolop | 1 | 1 boolop | 1 |
| `db.py` | compare | 2 | 2 compare | 2 |
| `db.py` | constant | 51 | 2 number, 49 string | 3 |
| `extract.py` | compare | 2 | 2 compare | 2 |
| `extract.py` | constant | 22 | 2 bool, 6 number, 14 string | 3 |
| `goldens.py` | constant | 3 | 3 string | 3 |
| `identity.py` | constant | 1 | 1 bool | 1 |
| `indicators.py` | boolop | 1 | 1 boolop | 1 |
| `indicators.py` | constant | 10 | 2 number, 8 string | 3 |
| `patterns.py` | boolop | 2 | 2 boolop | 2 |
| `patterns.py` | constant | 14 | 14 string | 3 |
| `pivot.py` | boolop | 3 | 3 boolop | 3 |
| `pivot.py` | constant | 6 | 6 string | 3 |
| `preflight.py` | constant | 7 | 1 number, 6 string | 3 |
| `qualify.py` | boolop | 4 | 4 boolop | 3 |
| `qualify.py` | compare | 7 | 7 compare | 3 |
| `qualify.py` | constant | 32 | 4 attr-docstring, 2 number, 26 string | 3 |
| `rerate.py` | compare | 1 | 1 compare | 1 |
| `rerate.py` | constant | 16 | 2 attr-docstring, 1 bool, 4 number, 9 string | 3 |
| `skill_lint.py` | constant | 9 | 9 string | 3 |
| `sweep.py` | boolop | 1 | 1 boolop | 1 |
| `sweep.py` | compare | 1 | 1 compare | 1 |
| `sweep.py` | constant | 12 | 4 number, 8 string | 3 |
| `text.py` | constant | 1 | 1 string | 1 |
| `transcript.py` | boolop | 2 | 2 boolop | 2 |
| `transcript.py` | constant | 7 | 7 number | 3 |

## Sampled mutants read

| mutant (full label; long ones truncated with `...`) | source line | verdict |
|---|---|---|
| `annotations.py:119:11 compare[0] Gt->GtE` | `if len(summary) > SUMMARY_CHARS:` | missing test |
| `annotations.py:22:16 constant[0] 120->121` | `SUMMARY_CHARS = 120` | missing test |
| `annotations.py:55:61 constant[0] ', '->''` | `raise AnnotationError(f"kind={kind!r} is not one of {', '.join(KINDS)}` | weak test |
| `annotations.py:118:52 constant[0] ' '->''` | `summary = latest.text.strip().replace("\n", " ")` | weak test |
| `bench.py:119:11 compare[0] Gt->GtE` | `if steps > 0:` | equivalent |
| `bench.py:37:0 constant[0] 'Credit lost per ladder step a match is u...` | `"""Credit lost per ladder step a match is under-rated.` | equivalent |
| `bench.py:233:43 constant[0] 0->1` | `duplicates=counts.get("DUPLICATE", 0),` | missing test |
| `bench.py:322:39 constant[0] ', '->''` | `"location overlap: " + ", ".join(sorted(shared))))` | weak test |
| `briefs.py:43:31 constant[0] 0->1` | `return match.group(0)` | equivalent |
| `briefs.py:62:25 constant[0] '; '->''` | `raise BriefError("; ".join(problems))` | weak test |
| `briefs.py:77:26 constant[0] True->False` | `out_dir.mkdir(parents=True, exist_ok=True)` | missing test |
| `budget.py:35:44 constant[0] 0->1` | `return [t for t in turns if t.context > 0]` | missing test |
| `budget.py:154:72 constant[0] '  vs  modelUsage '->''` | `out.append(f"  reconciliation   parsed sum_context {s.sum_context:,}  ` | weak test |
| `budget.py:171:33 constant[0] ' '->''` | `f"{e.mean:10,} {e.growth_per_turn:9,.0f}")` | weak test |
| `ceiling.py:92:11 compare[0] Lt->LtE` | `if e.turns < min_turns or e.mean <= 0:` | missing test |
| `ceiling.py:92:34 compare[0] LtE->Lt` | `if e.turns < min_turns or e.mean <= 0:` | missing test |
| `ceiling.py:48:30 constant[0] 0->1` | `if growth_per_turn <= 0:` | missing test |
| `ceiling.py:105:28 constant[0] ' '->''` | `out = [f"  {'epoch':>5s} {'turns':>6s} {'measured mean':>14s} "` | weak test |
| `ceiling.py:113:15 constant[0] '  figure above is unreliable for thi...` | `out.append("  figure above is unreliable for this session - report it ` | weak test |
| `chains.py:162:15 boolop[0] Or->And` | `if cid == eid or cgroup == egroup or not precondition:` | missing test |
| `chains.py:26:17 constant[0] 100->101` | `MAX_CANDIDATES = 100` | missing test |
| `chains.py:224:50 constant[0] ' across '->''` | `out = [f"chain candidates: {len(p.candidates)} across "` | weak test |
| `chains.py:239:40 constant[0] ' of '->''` | `f"  {p.without_precondition} of {p.findings_scanned} finding(s) "` | weak test |
| `coverage.py:258:15 boolop[0] Or->And` | `f"{r.phase or '<phase>'} --state analyzed --from-file <list>` "` | missing test |
| `coverage.py:21:21 constant[0] 5000->5001` | `MAX_UNITS_PER_CALL = 5000` | missing test |
| `coverage.py:193:21 constant[0] '    '->''` | `out.extend(f"    {reason:16s} {n}" for reason, n in r.by_reason)` | weak test |
| `coverage.py:261:15 constant[0] ', '->''` | `f"{', '.join(NOT_AUDITED_REASONS)}.")` | weak test |
| `db.py:419:15 boolop[0] And->Or` | `if c not in row and stored[c] is not None}` | missing test |
| `db.py:157:7 compare[0] Lt->LtE` | `if len(evidence) < MIN_EVIDENCE_CHARS:` | missing test |
| `db.py:570:32 compare[0] GtE->Gt` | `hi, lo = ((a, b) if _conf(a) >= _conf(b) else (b, a))` | missing test |
| `db.py:68:46 constant[0] ' is not one of '->''` | `raise DbError(f"{column}={value!r} is not one of {', '.join(allowed)}"` | weak test |
| `db.py:352:16 constant[0] ', '->''` | `names = ", ".join(missing_tables or missing_columns)` | weak test |
| `db.py:529:32 constant[0] ' '->''` | `out.extend(f"    {v:20s} {n}" for v, n in s.verdicts)` | weak test |
| `extract.py:141:20 compare[0] Gt->GtE` | `truncated = len(data) > MAX_UNIT_BYTES` | missing test |
| `extract.py:222:63 compare[0] Eq->NotEq` | `taken = {r.name: r.source for r in store.manifest() if r.unit == unit}` | missing test |
| `extract.py:25:13 constant[0] 25->26` | `BATCH_SIZE = 25` | missing test |
| `extract.py:134:32 constant[0] True->False` | `self.base.mkdir(parents=True, exist_ok=True)` | missing test |
| `extract.py:216:58 constant[0] '): '->''` | `f"(items {start}..{start + len(chunk) - 1}): {exc}") from exc` | weak test |
| `goldens.py:42:42 constant[0] "]: 'locations' must be non-empty"->''` | `raise GoldenError(f"{path}[{i}]: 'locations' must be non-empty")` | weak test |
| `goldens.py:44:38 constant[0] ': duplicate reference id '->''` | `raise GoldenError(f"{path}: duplicate reference id {item['id']}")` | weak test |
| `goldens.py:91:46 constant[0] "]: missing '"->''` | `raise GoldenError(f"{path}[{i}]: missing '{key}'")` | weak test |
| `identity.py:26:27 constant[0] False->True` | `replace: bool = False) -> None:` | missing test |
| `indicators.py:232:11 boolop[0] Or->And` | `if ea.get("state") == ABSENT or eb.get("state") == ABSENT:` | missing test |
| `indicators.py:55:46 constant[0] 1->2` | `return Reading.of(round(100 * r.fraction, 1),` | missing test |
| `indicators.py:126:21 constant[0] '  '->''` | `out.append(f"  {_LABELS[key]:<18} {r.render(_UNITS[key])}")` | weak test |
| `indicators.py:243:39 constant[0] 6->7` | `moved = f"{round(diff, 6):+}{unit}"` | missing test |
| `patterns.py:52:42 boolop[0] Or->And` | `return [PatternState(id=r["id"], name=r["name"] or "",` | missing test |
| `patterns.py:53:40 boolop[0] Or->And` | `origin_finding=r["origin_finding"] or "",` | missing test |
| `patterns.py:75:14 constant[0] 'no pattern '->''` | `f"no pattern {pattern_id!r} to mark swept; register one with "` | weak test |
| `patterns.py:102:32 constant[0] ' '->''` | `out.append(f"  {s.id:6s} {s.name:40.40s} {mark:11s} "` | weak test |
| `patterns.py:108:19 constant[0] '  A confirmed pattern that was neve...` | `out.append("  A confirmed pattern that was never swept is the tplink "` | weak test |
| `pivot.py:62:25 boolop[0] Or->And` | `"severity_hint": severity_hint or "",` | missing test |
| `pivot.py:63:20 boolop[0] Or->And` | `"location": location or ""})` | missing test |
| `pivot.py:77:8 boolop[0] Or->And` | `if (rule_applied or "").strip():` | missing test |
| `pivot.py:43:25 constant[0] 'a pivot needs --mechanism: what refuted...` | `raise db.DbError("a pivot needs --mechanism: what refuted the finding"` | weak test |
| `pivot.py:61:25 constant[0] 'Pivot from '->''` | `"observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",` | weak test |
| `pivot.py:61:61 constant[0] ' -- '->''` | `"observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",` | weak test |
| `preflight.py:32:31 constant[0] 'not found: '->''` | `raise PreflightError(f"not found: {config_path}")` | weak test |
| `preflight.py:48:19 constant[0] ', '->''` | `+ (", ".join(sorted(found)) or "(none)"))` | weak test |
| `preflight.py:65:63 constant[0] 2->3` | `path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")` | missing test |
| `qualify.py:90:38 boolop[0] Or->And` | `msg += f"  found:    {', '.join(actual) or '(no header)'}"` | missing test |
| `qualify.py:185:58 boolop[0] Or->And` | `f"CVE span {score.first_pub or '(missing)'}..{score.last_pub or '(miss` | missing test |
| `qualify.py:211:11 boolop[0] Or->And` | `f"{score.top_source or 'unknown'}")` | missing test |
| `qualify.py:116:60 compare[0] LtE->Lt` | `if not (math.isfinite(max_cvss) and 0 <= max_cvss <= 10):` | missing test |
| `qualify.py:187:15 compare[0] LtE->Lt` | `overlaps = score.first_pub <= WINDOW_END and score.last_pub >= WINDOW_` | missing test |
| `qualify.py:350:7 compare[0] In->NotIn` | `if "supported" in failed:` | missing test |
| `qualify.py:33:0 constant[0] 'The header of `_intel/target-scores.cs...` | `"""The header of `_intel/target-scores.csv` as of 2026-10-07.` | equivalent |
| `qualify.py:154:0 constant[0] 'Tier C, verbatim: "Anything with >20 ...` | `"""Tier C, verbatim: "Anything with >20 CVEs and >50% VulDB."` | equivalent |
| `qualify.py:355:11 constant[0] ' '->''` | `return " ".join(parts)` | weak test |
| `rerate.py:107:17 compare[0] Lt->LtE` | `"..." if end < len(text) else "")` | missing test |
| `rerate.py:51:9 constant[0] "the finding's own text says it is reach...` | `"the finding's own text says it is reachable without credentials"),` | weak test |
| `rerate.py:155:16 constant[0] 'member of a composed chain recorded a...` | `"member of a composed chain recorded as pre_auth",` | weak test |
| `rerate.py:178:61 constant[0] ', evidence implies at least '->''` | `out.append(f"  {f.finding_id}  filed {f.severity}, "` | weak test |
| `skill_lint.py:110:22 constant[0] 'prose names `audit.py '->''` | `f"prose names `audit.py {verb}`, which is not a real verb"))` | weak test |
| `skill_lint.py:131:18 constant[0] 'literal '->''` | `f"literal {SKILL_DIR_SENTINEL} survived install; "` | weak test |
| `skill_lint.py:162:20 constant[0] 'brief template does not state the...` | `"brief template does not state the R2 one-line return contract"))` | weak test |
| `sweep.py:171:20 boolop[0] Or->And` | `out = [f"sweep {result.pattern_id or '(unrecorded)'}: {len(result.hits` | missing test |
| `sweep.py:94:19 compare[0] Gt->GtE` | `if path.stat().st_size > MAX_FILE_BYTES:` | missing test |
| `sweep.py:26:11 constant[0] 500->501` | `MAX_HITS = 500` | missing test |
| `sweep.py:157:43 constant[0] ' hits and does not know what it did no...` | `f"stopped at {len(result.hits)} hits and does not know what it "` | weak test |
| `sweep.py:177:54 constant[0] ' hits - the pattern is too broad to tr...` | `out.append(f"  truncated at {len(result.hits)} hits - the pattern is "` | weak test |
| `text.py:54:35 constant[0] ' '->''` | `return _WS.sub(" ", _NOISE.sub(" ", (value or "").lower())).strip()` | weak test |
| `transcript.py:139:21 boolop[0] Or->And` | `session_id = session_id or rec.get("sessionId", "")` | missing test |
| `transcript.py:167:30 boolop[0] Or->And` | `thinking=(usage.get("output_tokens_details")` | missing test |
| `transcript.py:135:20 constant[0] 0->1` | `if tokens > 0:` | missing test |
| `transcript.py:161:55 constant[0] 0->1` | `+ usage.get("input_tokens", 0))` | missing test |
| `transcript.py:204:90 constant[0] 0->1` | `name, in_tokens = pending.pop(block.get("tool_use_id", ""), ("?", 0))` | missing test |

**Sample totals (87 mutants):** equivalent 5, weak test 38, missing test 44, real defect 0.
The verdict is assigned by kind (string fragment -> weak test; boundary, limit, default or flag -> missing test), so these totals restate the sample's composition more than they test it. The bucket verdict is mixed wherever a bucket holds both string and non-string constants; read the composition column before generalising.

## Allowlisted (9, equivalent only)

- 7 attribute docstrings (`bench.py:37`, `qualify.py:33/149/154/219`,
  `rerate.py:60/69`): bare string statements after an assignment; no runtime
  effect. mutate.py's docstring filter covers only module/class/function
  docstrings, so these slipped through as unkillable noise. Follow-up: teach
  `enumerate_mutations` to skip them, which would also retire the entries.
- `bench.py:119:11` `steps > 0` -> `>=`: `steps == 0` is handled by a
  `continue` two lines earlier.
- `briefs.py:43:31` `match.group(0)` -> `group(1)`: the value substituted for a
  missing placeholder is discarded, because a missing placeholder always
  raises `BriefError`.

Everything else is **left unallowlisted** and is the gap Task 15 closes. Two
candidates were read and *not* allowlisted for lack of proof: `ceiling.py:92`
`e.mean <= 0` (probably dead because `budget.py:35` drops zero-context turns,
not demonstrated) and `qualify.py` string fragments nobody asserts.

## Caveats on the instrument

- Three survivors show zero covering tests in the test map
  (`briefs.py:71`, `chains.py:185`, `identity.py:26`, all `False->True` on a
  parameter default in a multi-line `def`). The map is keyed by executable
  statement lines and these are continuation lines. The defaults are real
  untested behaviour (missing test), not unexecuted code.
- The excluded EOL-manifest test means mutants that only that test would
  catch are counted as survivors. None was identified in the sample.
- Verdicts are by kind plus reading the mutated line; I did not open the
  asserting test for each sampled mutant. 66 of 264 string survivors have a
  leading fragment that appears somewhere in `tests/`, so a minority of
  "weak" verdicts may be partly asserted by an adjacent piece.

## What this measurement is for

Line coverage finds the branch no test enters. This finds the branch a test
enters while asserting too little - the class this project recorded as "the
Task 2 test that substituted an easier input for the one its finding named."
audit_core is at 100% executed lines and a 66.3% mutation score: the 33.7%
difference is the measured gap between executing code and checking it.

A second sweep after any substantial change to `audit_core` compares against
this document: the score (66.3%), the survivor count (360, of which 351
unexplained) and the per-bucket table above. Any bucket whose count rises is a
regression in assertion strength. Per `SESSION_HANDOFF.md` rule 4 this file is
never edited in place; corrections or a re-measure go in a new dated file or an
appended dated note.
