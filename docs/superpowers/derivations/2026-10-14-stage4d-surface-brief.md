# Stage 4d surface brief derivation

## Sources

- [Stage 4d design](../specs/2026-10-14-stage4d-surface-design.md),
  §§3–9 and §11: complete denominator, state tuple, unknown lifecycle,
  evidence boundaries, importer ownership, and file-backed dispatch.
- [Stage 4d implementation plan](../plans/2026-10-14-stage4d-surface.md),
  Tasks 4–9: prepared batch provenance, strict result records, import/check
  separation, eight dispatch inputs, and the R2 return shape.
- `audit_core/surface.py`: canonical prepared index and batch construction.
- `audit_core/surface_results.py`: the actual `BatchResult`, `UnitDecision`,
  `SurfaceRecord`, and `UnknownRecord` shapes, strict parsing, provenance,
  assignment ownership, no-surface explanation, and cross-row validation.
- `audit_core/db.py`: coverage reasons and surface/unknown enum values.
- `audit_core/briefs.py`, the existing triage/diff briefs and derivations,
  and `audit_core/skill_lint.py`: real rendering, missing-input refusal,
  file-backed dispatch, and the bounded R2 return contract.

The implementation contracts are referenced by installed `audit_core/` paths
in the brief. The historical design and plan remain unchanged; their SQL
definitions are not a JSON result schema and are not copied into the brief.

## Choices and invariants

1. Declare exactly `run_dir`, `db_path`, `rootfs`, `image_id`,
   `manifest_sha256`, `worklist_index`, `batch_path`, and `result_path`.
   Database context is read only. Dispatch carries paths; index/batch contents
   and detailed reasoning stay on disk.
2. Require reading the installed result dataclasses, parser, semantics, and
   enums before writing output. Reference these schemas rather than embedding
   a second exhaustive JSON/SQL schema that can drift. Retain the operational
   details that are easy to confuse: version 1, index-byte SHA-256 as work-list
   identity, relative batch filename, verified descriptor digest, nulls,
   arrays, exact keys, UTF-8, and the 8 MiB result limit.
3. Keep every assigned manifest unit in scope, including configurations,
   wrappers, libraries, and units without service/ELF hints. Require exactly
   one decision per unit, no extra unit, and no silent omission. An analyzed
   no-surface decision needs an evidence-backed reason or explanatory unknown;
   no surface is not an unsupported assertion of no reachable attack path.
   A not-audited decision needs a valid reason and cannot publish surfaces.
   A budget skip cannot be disguised as completion.
4. Treat service, ELF, component, imports, strings, configuration, and caller
   information as leads. Absence of hints is never evidence of absence.
   Require the external entry point, dispatcher, concrete handler, and exact
   source/binary/configuration locations before drawing conclusions.
5. Require authentication/authorization ordering evidence relative to the
   handler. If ordering is unsettled, record unknown rather than inferring
   pre-auth from a missing string or a startup configuration.
6. Require lifecycle, posture, authentication requirement, reachability, and
   non-empty reach evidence on every surface. Evidence or refutation must cite
   a static path. Distinct entry points/protocols/state tuples receive distinct
   surfaces. Component ownership remains within the containing assigned unit.
7. Require explicit questions and exact settling observations for every
   unresolved field, including dispatch and handler. Unknown state values
   need matching open questions for the same surface and field. A null surface
   link is reserved for questions preventing identification of a surface.
   Open questions have null resolution/evidence; resolved questions require
   both. Unknown IDs are globally unique and surface IDs are image-scoped.
   `emulate`/`hardware` are deferred methods, not permission to execute them.
8. Require one strict JSON file only. The worker never writes SQL, records
   coverage, imports results, supplies importer-derived metadata, or certifies
   whole-run completion. The importer and explicit check own those operations.
9. Preserve the literal R2 line:
   `surface-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.
   Batch means `batch_id`; artifact means the supplied result file, not the
   canonical artifact installed later. Rows counts decisions written, including
   explicit not-audited decisions, not surfaces or nonexistent worker SQL writes.
   Honest open unknowns can accompany DONE; unfinished work requires PARTIAL,
   and inability to produce a valid bound result requires FAILED.

## Rejection boundaries and verification

Forbid vulnerability hunting, severity assignment, exploit/target execution,
emulation, inferred listeners, scope expansion, carved-root modification,
fetching/carving, and kernel/bootloader analysis. Do not convert a boot-start
line into runtime reachability, an open question into a refutation, or a
mapped handler into a vulnerability. Provenance disagreement requires failure,
not a repaired assignment or a different generation.

The Task 9 tests exercise the real CLI, `briefs.render`, and `write_brief`;
check all eight values and absence of leftover placeholders; reject every
missing input; ensure batch contents are never pasted into the rendered
artifact; pin the imperative contracts above; and run the rendered template
through the actual skill linter. The shared template inventory includes the
sixth brief. Compare each invariant against the rendered brief, not merely
the template's ability to substitute strings. Tests assert literal contract
requirements independently of implementation helpers.
