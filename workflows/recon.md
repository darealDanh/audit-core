# codebase-audit — recon: Source Detection + Reconnaissance + Feature Mapping

**Purpose**: Detect the audit target, identify feature groups, and produce a complete code-to-feature mapping via parallel subagents. End by writing the resume note.

**Entry**: User invokes the **recon** phase (see SKILL.md → *How phases are invoked per client*) or "audit this app" (full pipeline).
**Exit**: All feature groups mapped, resume note saved, user gate before deploy phase.

---

## Step 0 — MCP preflight

Unused MCP tool schemas are resident on every turn and are charged again in
accumulation. Before anything else, scope the run's MCP surface:

    python3 __SKILL_DIR__/audit.py preflight --server autorev=<autorev-command>

Then relaunch against it, as the command's own output states:

    claude --strict-mcp-config --mcp-config .audit-mcp.json

If the target needs no binary tooling, run `audit.py preflight` with no
`--server` at all. If `.audit-mcp.json` already exists, it is the user's —
read it, and pass `--force` only if they confirm.

## Step 1 — Create audit workspace

    AUDIT_DIR=$(python3 __SKILL_DIR__/audit.py init | tail -1)

`init` creates `files/`, `artifacts/`, `archived-poc/` and `briefs/`, and
applies the full schema to `audit.db`. It is idempotent: re-running a phase
never destroys rows an earlier phase recorded.

Record `AUDIT_DIR`. **Stay at the project root for the whole audit** —
reference `${AUDIT_DIR}` by path, never `cd` into it (SKILL.md Essential
Principle #10).

`archived-poc/` starts empty; verify forks may consult it for report-format examples, and the user archives each finalized report + its `poc/` into `archived-poc/<finding-id>/` after sending it to the maintainer.

## Step 2 — Phase 0 source detection

Follow [../references/phase0-source-detection.md](../references/phase0-source-detection.md) exactly:

1. Probe IDA Pro MCP (`mcp_ida-pro-mcp_list_instances`).
2. Scan workspace for source-code indicators (build files, common dirs).
3. Ask the user to choose the appropriate prompt variant (see SKILL.md → *Cross-client tool mapping*). *(Automated `source` mode: auto-select the **source** target without asking; abort if the target is binary/IDA-only — see [source.md](source.md).)*
4. Insert into `cba_sources`.

## Step 3 — Reconnaissance

Use your file-search tools — keyword/regex search, glob, and semantic/codebase search where your client provides it (see SKILL.md → *Cross-client tool mapping*) — and/or `mcp_ida-pro-mcp_survey_binary` (IDA) in parallel to gather:

- Language(s) and framework(s)
- Build/deploy system (Dockerfile, docker-compose, Makefile, install scripts)
- Top-level directory layout
- Entry points (HTTP routes, RPC handlers, CLI commands, scheduled tasks)
- Authentication/authorization patterns
- Configuration loading
- Existing test instances or compose files (helps deploy phase later)

## Step 4 — Define feature groups

Based on codebase size (see [../references/phase2-feature-mapping.md](../references/phase2-feature-mapping.md) Size Guidelines):

| Codebase size | Group count |
|---|---|
| Small (<50 files / <100 functions) | 3-5 |
| Medium | 5-8 |
| Large (>500 files / >1000 functions) | 8-12 |

Use the naming convention `G1…Gn` with stable IDs (so subagent outputs and SQL rows align).

Present the groups and ask the user to confirm (see SKILL.md → *Cross-client tool mapping*): "I've identified N feature groups. [list]. Should I proceed?" with options `["Looks good — proceed", "Let me adjust the groups"]`. *(Automated `source` mode: auto-accept the proposed groups without asking — see [source.md](source.md).)*

Insert approved groups into `cba_feature_groups` (status='pending').

## Step 5 — Parallel feature mapping subagents

**CRITICAL — use a writable subagent**: the mapping subagents must run with a **writable** agent (see SKILL.md → *Cross-client tool mapping*) so their SQL inserts and artifact files persist; a read-only agent (e.g. Claude/Copilot `Explore`) silently produces no SQL inserts or artifact files. (See [../references/lessons-learned.md](../references/lessons-learned.md) item #1.)

Spawn ONE subagent per feature group, ALL in parallel (one subagent-spawn call per group in the same response — see SKILL.md → *Cross-client tool mapping*).

For each group, render the brief and dispatch with its path:

    python3 __SKILL_DIR__/audit.py brief --phase recon --unit "$G" --run "$AUDIT_DIR" \
      --var group_id="$G" --var group_name="$NAME" \
      --var group_description="$DESC" --var key_directories="$DIRS" \
      --var run_dir="$AUDIT_DIR" --var source_access="$SRC" \
      --var known_findings="$KNOWN" \
      --var mapping_path="$AUDIT_DIR/files/$G-mapping.md"

The dispatch carries the brief path plus only what the brief cannot know.
Do not paste the brief's contents into the prompt, and never paste prior
phases' summaries (spec rule R6).

**Model:** mid tier, low effort — mapping is pattern work against clear
criteria. See SKILL.md → *Model and effort tiering*.

Each subagent returns one line. Read the results from SQL, not from the
return text.

After all subagents return:
- Verify each `files/G<n>-mapping.md` exists and is non-trivial.
- `UPDATE cba_feature_groups SET status='mapped' WHERE id=?` for each.
- Query SQL to confirm counts.

## Step 6 — Write the resume note

Use [../references/resume-note-template.md](../references/resume-note-template.md). Save to `/memories/session/<project>-audit-resume.md`. Include:

- Audit dir + DB path
- Pipeline status (recon DONE; deploy/audit/fpcheck/verify/report NOT STARTED)
- Feature group table (id, name, mapping file)
- Phase-2 observation counts (severity hint × group)
- Top "must-investigate" leads (12-20 items from observations) — these become the prioritization input for the audit phase
- Quirks / environment notes
- Resumption commands

## Step 7 — USER GATE

> _Automated `source` mode supersedes this gate — write the resume note and proceed to the audit phase without pausing (see [source.md](source.md))._

Present:

> Reconnaissance + feature mapping complete. N groups mapped with M total security observations. Resume note saved.
>
> Next: the **deploy** phase to bring up a live instance for later PoC verification, or the **audit** phase if you'll skip live testing (see SKILL.md for your client's exact phase syntax).
>
> Say **go deploy**, **go audit**, or **adjust** to revise mappings.
>
> **Before continuing, run a manual compact** (`/compact` in Claude Code or Codex CLI, Compact in Copilot Chat). The resume note + SQL state + per-group mapping artifacts are already on disk, so compacting now is lossless.

Do NOT auto-advance. *(Exception: automated `source` mode auto-advances through this gate — see [source.md](source.md).)*

## Quality Checks

- [ ] `cba_sources` has one confirmed row
- [ ] `cba_feature_groups` has all groups with status='mapped'
- [ ] Every group has a `files/G<n>-mapping.md` ≥ 50 lines
- [ ] Every group has ≥ 1 row in `cba_security_observations` (zero means mapping was too shallow → re-run that group's subagent)
- [ ] Resume note exists and includes the must-investigate leads list
