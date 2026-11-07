# Stage 4i review follow-ups: brief limits and lifecycle documentation

The Stage 4i fix-branch re-review found that the decide brief still omitted
parser rules a worker can violate (whitespace-only text, the 4096-byte caps on
required-state values and subject references, the 4096-item array and 256-step
caps, and the evidence-reference wire), and that SKILL.md and README.md did not
state every consequence of the new `superseded` status and latest-preparation
selection: a superseded generation cannot be re-prepared, and an upgraded run
ranks its existing decision rows so selection keeps its pre-upgrade choice.

Intended changes, written before editing:

`references/briefs/firmware-decide-brief.md`

1. In "Result artifact", define text as containing at least one
   non-whitespace character, so whitespace-only text is rejected.
2. In "Result artifact", state that every array holds at most 4096 items and
   every ordered step array (`setup_steps`, `action_steps`, `stop_conditions`)
   at most 256 steps.
3. In "Chain assessments", state the evidence-reference wire matched by
   `firmware_decide_results._REFERENCE`: a scheme of an ASCII letter followed by
   letters, digits or hyphens, `:`, 1-4096 characters without NUL, CR, LF or
   `#`, then `#` and a 1-128 character anchor of letters, digits, `.`, `_`, `:`
   or `-`.
4. In "Bench tests", state that each `required_state` value and each subject
   reference is at most 4096 UTF-8 bytes.

`SKILL.md` Stage 4i route

5. State that a superseded generation can never be prepared again; to retry
   the same input, change the policy bytes so a new generation is created.
6. State that upgrading an existing run ranks its stored decision rows so the
   row selected before the upgrade (the active row, else the latest completed)
   stays current.

`README.md` Stage 4i section

7. Describe the `superseded` status, latest-preparation selection without
   fallback, the superseded-generation re-prepare refusal (change policy
   bytes), and the upgrade ranking of existing rows.

Tests: `tests/test_firmware_decide_brief.py` pins clauses 1-4 against the parser
constants and pattern, and the SKILL.md route clauses 5-6.

## Reconciliation

Checked against `git diff -U0 SKILL.md README.md
references/briefs/firmware-decide-brief.md` after the edits. The brief hunks are
exactly items 1-4: the "Result artifact" text definition gains the
non-whitespace and whitespace-only rejection clause plus the 4096-item and
256-step caps (1, 2); the `evidence_refs` bullet gains the reference wire (3);
the `subject_refs` and `required_state` bullets gain the 4096-byte caps, with the
subject bullet only re-wrapped otherwise (4). The SKILL.md hunk is one appended
passage in the Stage 4i route closing paragraph covering items 5 and 6. The
README.md hunk is one new paragraph in the Stage 4i section covering item 7.
No other hunk exists in these files.
