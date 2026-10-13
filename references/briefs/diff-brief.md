# Firmware semantic diff brief — {diff_id}

Audit run directory: {run_dir}
Diff ID: {diff_id}
Target carved root (patched/current build): {target_root}
Reference carved root (vulnerable build): {reference_root}
File-backed manifest: {manifest_path}
Detailed artifact: {artifact_path}
Known CVE/advisory supplied by the orchestrator: {known_advisory}
Known patched component supplied by the orchestrator: {patched_component}

## Assignment

Read the file-backed manifest at `{manifest_path}`. Keep raw diff contents out
of the dispatch and return; compare entries and inspect evidence on disk.
Start from the known patched component `{patched_component}`; file churn
elsewhere is not a vulnerability signal.

1. Establish the actual before/after mechanism with evidence from both builds.
   Cite exact locations (file, function, line or binary offset) separately in
   `{reference_root}` and `{target_root}`, trace the unsafe operation and the
   changed check or behavior, and explain how it addresses `{known_advisory}`.
2. Distinguish a security fix from compiler, packaging, timestamp, stripping,
   or configuration noise. Explain why the relevant change alters the unsafe
   mechanism. Record uncertainty and missing evidence instead of treating
   unexplained churn as a confirmed fix.
3. Record the fix idiom as an evidence-backed `cba_security_observations` row
   in `{run_dir}/audit.db` under the diff-specific `group_id` `diff-{diff_id}`.
   Use `audit.py put --db {run_dir}/audit.db --table cba_security_observations
   --set group_id=diff-{diff_id} --set observation=<bounded-mechanism-and-evidence>
   --set location=<exact-locations-in-both-builds>`. Keep evidence and an
   artifact reference in the observation text; do not invent a finding to
   record the known fix.
4. Search only the target `{target_root}` for sibling sites that still match
   the unsafe side of the idiom. Do not search the vulnerable reference for
   surviving siblings; it supplies the before evidence only. Record the
   searched locations, checked protections, and unresolved search limits.
5. Only when the idiom has an honest mechanical expression, register it with
   `audit.py put --db {run_dir}/audit.db --table cba_patterns --set id=<pattern-id>
   --set name=<idiom-name> --set regex=<honest-expression>
   --set notes=<diff-id-and-evidence-reference>`, then run
   `audit.py sweep --db {run_dir}/audit.db --pattern <pattern-id>
   --root {target_root} --record`. Do not force a semantic condition into a
   misleading regex. If the condition cannot be expressed mechanically, use
   direct semantic inspection and record why no pattern or sweep was used.
   Sweep hits are candidates to inspect, not confirmed findings; honor a
   truncated or failed sweep as an unresolved limitation.
6. Record non-mechanical sibling analysis and each surviving lead as bounded
   observations in `cba_security_observations` under `diff-{diff_id}`, with
   exact locations and evidence. Use the same `audit.py put` command and
   `group_id` as for the fix idiom. Explain how each lead still matches the
   unsafe mechanism and which protections you checked.

Do not turn every changed file or component into a finding. Do not begin broad
hunting, map handler tables, or emulate firmware. Do not modify either carved
tree.

## Detailed artifact and return

Write the detailed analysis to `{artifact_path}`. Keep it bounded to the
before/after mechanism, evidence from both builds, noise discrimination,
sibling search and its observations, any mechanical pattern/sweep results,
and unresolved limitations. Cite the manifest by path; do not dump its raw
contents or narrate every changed file. State explicitly when no surviving
sibling lead was established, and distinguish that result from an incomplete
search.

Return exactly one line, and nothing else:

    diff <DONE|PARTIAL|FAILED> rows=<n> artifact={artifact_path} [flags=<csv>]

Here rows counts the observations actually recorded for `diff-{diff_id}` in
this assignment. Choose PARTIAL or FAILED when evidence or search limitations
prevent completion and communicate those limitations in flags and the
artifact. Put detailed prose in the artifact, never in the return line.
