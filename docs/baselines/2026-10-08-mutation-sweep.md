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

73% of survivors are string fragments: error and report text that tests
execute but whose wording nothing asserts. The expensive survivors are the 33
compare/boolop ones and the 47 numeric constants, which are boundaries and
fallbacks.

## Survivors by (module, operator): 38 buckets

Sample = the first, the median and the last survivor of the bucket by line
number (fewer when the bucket has fewer than three). Verdict rule applied to
each sampled mutant after reading its source line: a string fragment in output
the tests run -> weak test; a boundary, limit, default or boolean flag no test
distinguishes -> missing test; provably unobservable -> equivalent.

| module | operator | survivors | composition | sampled mutant -> verdict |
|---|---|---|---|---|
| `annotations.py` | compare | 1 | 1 compare | `annotations.py:119` compare -> missing test |
| `annotations.py` | constant | 11 | 2 bool, 1 number, 8 string | `annotations.py:22` number -> missing test; `annotations.py:55` string -> weak test; `annotations.py:118` string -> weak test |
| `bench.py` | compare | 1 | 1 compare | `bench.py:119` compare -> equivalent |
| `bench.py` | constant | 8 | 1 attr-docstring, 3 number, 4 string | `bench.py:37` attr-docstring -> equivalent; `bench.py:233` number -> missing test; `bench.py:322` string -> weak test |
| `briefs.py` | constant | 10 | 2 bool, 1 number, 7 string | `briefs.py:43` number -> equivalent; `briefs.py:62` string -> weak test; `briefs.py:77` bool -> missing test |
| `budget.py` | constant | 47 | 6 number, 41 string | `budget.py:35` number -> missing test; `budget.py:154` string -> weak test; `budget.py:171` string -> weak test |
| `ceiling.py` | compare | 2 | 2 compare | `ceiling.py:92` compare -> missing test; `ceiling.py:92` compare -> missing test |
| `ceiling.py` | constant | 27 | 5 number, 22 string | `ceiling.py:48` number -> missing test; `ceiling.py:105` string -> weak test; `ceiling.py:113` string -> weak test |
| `chains.py` | boolop | 1 | 1 boolop | `chains.py:162` boolop -> missing test |
| `chains.py` | constant | 18 | 1 bool, 2 number, 15 string | `chains.py:26` number -> missing test; `chains.py:224` string -> weak test; `chains.py:239` string -> weak test |
| `coverage.py` | boolop | 1 | 1 boolop | `coverage.py:258` boolop -> missing test |
| `coverage.py` | constant | 15 | 1 number, 14 string | `coverage.py:21` number -> missing test; `coverage.py:193` string -> weak test; `coverage.py:261` string -> weak test |
| `db.py` | boolop | 1 | 1 boolop | `db.py:419` boolop -> missing test |
| `db.py` | compare | 2 | 2 compare | `db.py:157` compare -> missing test; `db.py:570` compare -> missing test |
| `db.py` | constant | 51 | 2 number, 49 string | `db.py:68` string -> weak test; `db.py:352` string -> weak test; `db.py:529` string -> weak test |
| `extract.py` | compare | 2 | 2 compare | `extract.py:141` compare -> missing test; `extract.py:222` compare -> missing test |
| `extract.py` | constant | 22 | 2 bool, 6 number, 14 string | `extract.py:25` number -> missing test; `extract.py:134` bool -> missing test; `extract.py:216` string -> weak test |
| `goldens.py` | constant | 3 | 3 string | `goldens.py:42` string -> weak test; `goldens.py:44` string -> weak test; `goldens.py:91` string -> weak test |
| `identity.py` | constant | 1 | 1 bool | `identity.py:26` bool -> missing test |
| `indicators.py` | boolop | 1 | 1 boolop | `indicators.py:232` boolop -> missing test |
| `indicators.py` | constant | 10 | 2 number, 8 string | `indicators.py:55` number -> missing test; `indicators.py:126` string -> weak test; `indicators.py:243` number -> missing test |
| `patterns.py` | boolop | 2 | 2 boolop | `patterns.py:52` boolop -> missing test; `patterns.py:53` boolop -> missing test |
| `patterns.py` | constant | 14 | 14 string | `patterns.py:75` string -> weak test; `patterns.py:102` string -> weak test; `patterns.py:108` string -> weak test |
| `pivot.py` | boolop | 3 | 3 boolop | `pivot.py:62` boolop -> missing test; `pivot.py:63` boolop -> missing test; `pivot.py:77` boolop -> missing test |
| `pivot.py` | constant | 6 | 6 string | `pivot.py:43` string -> weak test; `pivot.py:61` string -> weak test; `pivot.py:61` string -> weak test |
| `preflight.py` | constant | 7 | 1 number, 6 string | `preflight.py:32` string -> weak test; `preflight.py:48` string -> weak test; `preflight.py:65` number -> missing test |
| `qualify.py` | boolop | 4 | 4 boolop | `qualify.py:90` boolop -> missing test; `qualify.py:185` boolop -> missing test; `qualify.py:211` boolop -> missing test |
| `qualify.py` | compare | 7 | 7 compare | `qualify.py:116` compare -> missing test; `qualify.py:187` compare -> missing test; `qualify.py:350` compare -> missing test |
| `qualify.py` | constant | 32 | 4 attr-docstring, 2 number, 26 string | `qualify.py:33` attr-docstring -> equivalent; `qualify.py:154` attr-docstring -> equivalent; `qualify.py:355` string -> weak test |
| `rerate.py` | compare | 1 | 1 compare | `rerate.py:107` compare -> missing test |
| `rerate.py` | constant | 16 | 2 attr-docstring, 1 bool, 4 number, 9 string | `rerate.py:51` string -> weak test; `rerate.py:155` string -> weak test; `rerate.py:178` string -> weak test |
| `skill_lint.py` | constant | 9 | 9 string | `skill_lint.py:110` string -> weak test; `skill_lint.py:131` string -> weak test; `skill_lint.py:162` string -> weak test |
| `sweep.py` | boolop | 1 | 1 boolop | `sweep.py:171` boolop -> missing test |
| `sweep.py` | compare | 1 | 1 compare | `sweep.py:94` compare -> missing test |
| `sweep.py` | constant | 12 | 4 number, 8 string | `sweep.py:26` number -> missing test; `sweep.py:157` string -> weak test; `sweep.py:177` string -> weak test |
| `text.py` | constant | 1 | 1 string | `text.py:54` string -> weak test |
| `transcript.py` | boolop | 2 | 2 boolop | `transcript.py:139` boolop -> missing test; `transcript.py:167` boolop -> missing test |
| `transcript.py` | constant | 7 | 7 number | `transcript.py:135` number -> missing test; `transcript.py:161` number -> missing test; `transcript.py:204` number -> missing test |

## Sampled mutants read

| mutant | operator | source line | verdict |
|---|---|---|---|
| `annotations.py:119` | compare | `if len(summary) > SUMMARY_CHARS:` | missing test |
| `annotations.py:22` | constant | `SUMMARY_CHARS = 120` | missing test |
| `annotations.py:55` | constant | `raise AnnotationError(f"kind={kind!r} is not one of {', '.join(KINDS)}` | weak test |
| `annotations.py:118` | constant | `summary = latest.text.strip().replace("\n", " ")` | weak test |
| `bench.py:119` | compare | `if steps > 0:` | equivalent |
| `bench.py:37` | constant | `"""Credit lost per ladder step a match is under-rated.` | equivalent |
| `bench.py:233` | constant | `duplicates=counts.get("DUPLICATE", 0),` | missing test |
| `bench.py:322` | constant | `"location overlap: " + ", ".join(sorted(shared))))` | weak test |
| `briefs.py:43` | constant | `return match.group(0)` | equivalent |
| `briefs.py:62` | constant | `raise BriefError("; ".join(problems))` | weak test |
| `briefs.py:77` | constant | `out_dir.mkdir(parents=True, exist_ok=True)` | missing test |
| `budget.py:35` | constant | `return [t for t in turns if t.context > 0]` | missing test |
| `budget.py:154` | constant | `out.append(f"  reconciliation   parsed sum_context {s.sum_context:,}  ` | weak test |
| `budget.py:171` | constant | `f"{e.mean:10,} {e.growth_per_turn:9,.0f}")` | weak test |
| `ceiling.py:92` | compare | `if e.turns < min_turns or e.mean <= 0:` | missing test |
| `ceiling.py:92` | compare | `if e.turns < min_turns or e.mean <= 0:` | missing test |
| `ceiling.py:48` | constant | `if growth_per_turn <= 0:` | missing test |
| `ceiling.py:105` | constant | `out = [f"  {'epoch':>5s} {'turns':>6s} {'measured mean':>14s} "` | weak test |
| `ceiling.py:113` | constant | `out.append("  figure above is unreliable for this session - report it ` | weak test |
| `chains.py:162` | boolop | `if cid == eid or cgroup == egroup or not precondition:` | missing test |
| `chains.py:26` | constant | `MAX_CANDIDATES = 100` | missing test |
| `chains.py:224` | constant | `out = [f"chain candidates: {len(p.candidates)} across "` | weak test |
| `chains.py:239` | constant | `f"  {p.without_precondition} of {p.findings_scanned} finding(s) "` | weak test |
| `coverage.py:258` | boolop | `f"{r.phase or '<phase>'} --state analyzed --from-file <list>` "` | missing test |
| `coverage.py:21` | constant | `MAX_UNITS_PER_CALL = 5000` | missing test |
| `coverage.py:193` | constant | `out.extend(f"    {reason:16s} {n}" for reason, n in r.by_reason)` | weak test |
| `coverage.py:261` | constant | `f"{', '.join(NOT_AUDITED_REASONS)}.")` | weak test |
| `db.py:419` | boolop | `if c not in row and stored[c] is not None}` | missing test |
| `db.py:157` | compare | `if len(evidence) < MIN_EVIDENCE_CHARS:` | missing test |
| `db.py:570` | compare | `hi, lo = ((a, b) if _conf(a) >= _conf(b) else (b, a))` | missing test |
| `db.py:68` | constant | `raise DbError(f"{column}={value!r} is not one of {', '.join(allowed)}"` | weak test |
| `db.py:352` | constant | `names = ", ".join(missing_tables or missing_columns)` | weak test |
| `db.py:529` | constant | `out.extend(f"    {v:20s} {n}" for v, n in s.verdicts)` | weak test |
| `extract.py:141` | compare | `truncated = len(data) > MAX_UNIT_BYTES` | missing test |
| `extract.py:222` | compare | `taken = {r.name: r.source for r in store.manifest() if r.unit == unit}` | missing test |
| `extract.py:25` | constant | `BATCH_SIZE = 25` | missing test |
| `extract.py:134` | constant | `self.base.mkdir(parents=True, exist_ok=True)` | missing test |
| `extract.py:216` | constant | `f"(items {start}..{start + len(chunk) - 1}): {exc}") from exc` | weak test |
| `goldens.py:42` | constant | `raise GoldenError(f"{path}[{i}]: 'locations' must be non-empty")` | weak test |
| `goldens.py:44` | constant | `raise GoldenError(f"{path}: duplicate reference id {item['id']}")` | weak test |
| `goldens.py:91` | constant | `raise GoldenError(f"{path}[{i}]: missing '{key}'")` | weak test |
| `identity.py:26` | constant | `replace: bool = False) -> None:` | missing test |
| `indicators.py:232` | boolop | `if ea.get("state") == ABSENT or eb.get("state") == ABSENT:` | missing test |
| `indicators.py:55` | constant | `return Reading.of(round(100 * r.fraction, 1),` | missing test |
| `indicators.py:126` | constant | `out.append(f"  {_LABELS[key]:<18} {r.render(_UNITS[key])}")` | weak test |
| `indicators.py:243` | constant | `moved = f"{round(diff, 6):+}{unit}"` | missing test |
| `patterns.py:52` | boolop | `return [PatternState(id=r["id"], name=r["name"] or "",` | missing test |
| `patterns.py:53` | boolop | `origin_finding=r["origin_finding"] or "",` | missing test |
| `patterns.py:75` | constant | `f"no pattern {pattern_id!r} to mark swept; register one with "` | weak test |
| `patterns.py:102` | constant | `out.append(f"  {s.id:6s} {s.name:40.40s} {mark:11s} "` | weak test |
| `patterns.py:108` | constant | `out.append("  A confirmed pattern that was never swept is the tplink "` | weak test |
| `pivot.py:62` | boolop | `"severity_hint": severity_hint or "",` | missing test |
| `pivot.py:63` | boolop | `"location": location or ""})` | missing test |
| `pivot.py:77` | boolop | `if (rule_applied or "").strip():` | missing test |
| `pivot.py:43` | constant | `raise db.DbError("a pivot needs --mechanism: what refuted the finding"` | weak test |
| `pivot.py:61` | constant | `"observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",` | weak test |
| `pivot.py:61` | constant | `"observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",` | weak test |
| `preflight.py:32` | constant | `raise PreflightError(f"not found: {config_path}")` | weak test |
| `preflight.py:48` | constant | `+ (", ".join(sorted(found)) or "(none)"))` | weak test |
| `preflight.py:65` | constant | `path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")` | missing test |
| `qualify.py:90` | boolop | `msg += f"  found:    {', '.join(actual) or '(no header)'}"` | missing test |
| `qualify.py:185` | boolop | `f"CVE span {score.first_pub or '(missing)'}..{score.last_pub or '(miss` | missing test |
| `qualify.py:211` | boolop | `f"{score.top_source or 'unknown'}")` | missing test |
| `qualify.py:116` | compare | `if not (math.isfinite(max_cvss) and 0 <= max_cvss <= 10):` | missing test |
| `qualify.py:187` | compare | `overlaps = score.first_pub <= WINDOW_END and score.last_pub >= WINDOW_` | missing test |
| `qualify.py:350` | compare | `if "supported" in failed:` | missing test |
| `qualify.py:33` | constant | `"""The header of `_intel/target-scores.csv` as of 2026-10-07.` | equivalent |
| `qualify.py:154` | constant | `"""Tier C, verbatim: "Anything with >20 CVEs and >50% VulDB."` | equivalent |
| `qualify.py:355` | constant | `return " ".join(parts)` | weak test |
| `rerate.py:107` | compare | `"..." if end < len(text) else "")` | missing test |
| `rerate.py:51` | constant | `"the finding's own text says it is reachable without credentials"),` | weak test |
| `rerate.py:155` | constant | `"member of a composed chain recorded as pre_auth",` | weak test |
| `rerate.py:178` | constant | `out.append(f"  {f.finding_id}  filed {f.severity}, "` | weak test |
| `skill_lint.py:110` | constant | `f"prose names `audit.py {verb}`, which is not a real verb"))` | weak test |
| `skill_lint.py:131` | constant | `f"literal {SKILL_DIR_SENTINEL} survived install; "` | weak test |
| `skill_lint.py:162` | constant | `"brief template does not state the R2 one-line return contract"))` | weak test |
| `sweep.py:171` | boolop | `out = [f"sweep {result.pattern_id or '(unrecorded)'}: {len(result.hits` | missing test |
| `sweep.py:94` | compare | `if path.stat().st_size > MAX_FILE_BYTES:` | missing test |
| `sweep.py:26` | constant | `MAX_HITS = 500` | missing test |
| `sweep.py:157` | constant | `f"stopped at {len(result.hits)} hits and does not know what it "` | weak test |
| `sweep.py:177` | constant | `out.append(f"  truncated at {len(result.hits)} hits - the pattern is "` | weak test |
| `text.py:54` | constant | `return _WS.sub(" ", _NOISE.sub(" ", (value or "").lower())).strip()` | weak test |
| `transcript.py:139` | boolop | `session_id = session_id or rec.get("sessionId", "")` | missing test |
| `transcript.py:167` | boolop | `thinking=(usage.get("output_tokens_details")` | missing test |
| `transcript.py:135` | constant | `if tokens > 0:` | missing test |
| `transcript.py:161` | constant | `+ usage.get("input_tokens", 0))` | missing test |
| `transcript.py:204` | constant | `name, in_tokens = pending.pop(block.get("tool_use_id", ""), ("?", 0))` | missing test |

Totals over the 87 sampled: see the verdict column. The bucket
verdict is mixed wherever a bucket contains both string and non-string
constants; read the composition column before generalising a bucket verdict.

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
