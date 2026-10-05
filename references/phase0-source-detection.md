# Phase 0: Source Detection

## Purpose

Automatically detect what code sources are available (source code, IDA Pro MCP binary analysis, or both) and confirm with the user before proceeding.

## Detection Logic

### 1. IDA Pro MCP Probe

```
Tool: ida-pro-mcp-list_instances (or ida-pro-mcp-server_health)
Success: Returns instance(s) with binary name, port, and reachability
Failure: Tool not available or returns empty/error — IDA Pro not connected
```

Record each available instance:
- Binary filename
- Port number
- Architecture (from survey_binary if available)

### 2. Source Code Detection

Scan current directory and immediate children for source code:

**Build files (highest confidence)**:
- `CMakeLists.txt`, `Makefile` → C/C++
- `package.json` → JavaScript/TypeScript
- `Cargo.toml` → Rust
- `go.mod` → Go
- `pom.xml`, `build.gradle` → Java
- `requirements.txt`, `setup.py`, `pyproject.toml` → Python
- `*.sln`, `*.csproj` → C#/.NET

**Source directories (medium confidence)**:
- `src/`, `lib/`, `app/`, `pkg/`
- Directories containing > 5 files with matching extensions

**Extension scan (lower confidence)**:
```
glob: **/*.cpp, **/*.c, **/*.h
glob: **/*.py
glob: **/*.js, **/*.ts
glob: **/*.java
glob: **/*.go
glob: **/*.rs
```

Count files per language. Report primary and secondary languages.

### 3. User Confirmation Prompts

Choose the appropriate prompt based on what was detected. Always ask the user to choose (see SKILL.md → *Cross-client tool mapping*) — never assume. *(Automated `source` mode: do **not** show these prompts — auto-select the **source** target, even when IDA is also detected, and abort only if there is no source at all; see [../workflows/source.md](../workflows/source.md).)*

**Both detected:**
> I found source code at `{path}` ({language}, {count} files) and IDA Pro MCP connected to `{binary}` on port {port}.
>
> Which should I use for the audit?

Choices: `["Both source code + IDA Pro (Recommended)", "Source code only", "IDA Pro binary analysis only"]`

**Only source detected:**
> I found source code at `{path}` ({language}, {count} files). Is this the audit target?

Choices: `["Yes, audit this source code", "I also have IDA Pro — let me connect it"]`

**Only IDA Pro detected:**
> IDA Pro MCP is connected to `{binary}`. Do you also have source code available?

Choices: `["IDA Pro only — proceed with binary analysis", "I have source code too — let me provide the path"]`

**Neither detected:**
> I couldn't find source code or an IDA Pro MCP connection. Please provide one or both:
> - Source code: Tell me the directory path
> - Binary: Load it in IDA Pro with the MCP plugin and tell me when ready

(Freeform input — no choices)

### 4. Dual-Source Strategy

When BOTH sources are available, use this division of labor:

| Task | Primary Source | Verification Source |
|------|---------------|-------------------|
| Feature mapping | Source code (richer context) | IDA (confirm compiled behavior) |
| Entry point discovery | Source code (route definitions) | IDA (export table, xrefs) |
| Data flow tracing | Source code (variable names, types) | IDA (actual register/memory flow) |
| String analysis | IDA (compiled strings, including generated) | Source (contextual meaning) |
| Authentication checks | Source code (policy logic) | IDA (bypass verification) |
| Crypto analysis | Source code (algorithm choice) | IDA (actual implementation, constants) |

## SQL Schema

The `cba_sources` table is created by `audit.py init` (recon Step 1). Insert the
confirmed source row into it; do not create the table.
