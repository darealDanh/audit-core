# Phase 2: Feature Mapping

## Purpose

Divide the application into logical feature groups, then map every feature to its implementing source code. This creates the structured attack surface inventory that Phase 4 auditors use.

## Feature Group Taxonomy

### Grouping Heuristics (in priority order)

1. **Authentication boundary**: Group auth-related code together (login, sessions, tokens, MFA, SSO, password reset)
2. **Core data processing**: The application's primary function — what it does to data (scan, transform, validate, render)
3. **File/data handling**: Upload, download, storage, archive, quarantine operations
4. **Configuration & admin**: Settings management, user management, role management
5. **Network/external**: Outbound connections, webhooks, integrations, federation
6. **Internal infrastructure**: IPC, messaging, database layer, caching
7. **External API surface**: Public endpoints, SDK/client-facing APIs
8. **Unauthenticated surface**: Anything accessible without credentials

### Naming Convention

| ID | Name Pattern | Examples |
|----|-------------|----------|
| G1 | Auth & Session | Login, MFA, token management |
| G2 | Core Processing | File scanning, data transformation |
| G3 | Config & Admin | Settings, user CRUD, policies |
| G4 | Storage & Data | Quarantine, archive, backup |
| G5 | Network & External | Webhooks, proxy, federation |
| G6 | Infrastructure | IPC, database, messaging |
| G7 | API Surface | REST endpoints, gRPC, GraphQL |
| G8 | Unauthenticated | Public pages, health checks, registration |

Adapt names to the target application. Not all groups will exist for every target.

### Size Guidelines

| Metric | Minimum | Ideal | Maximum |
|--------|---------|-------|---------|
| Groups | 3 | 6-8 | 12 |
| Files per group | 3 | 10-30 | 100 |
| Features per group | 2 | 5-15 | 30 |

If a group exceeds the maximum, split it. If below the minimum, merge with a related group.

## Subagent Brief

The dispatch brief is a template at `references/briefs/recon-brief.md`,
rendered per group by `audit.py brief`. Do not paste its contents into a
dispatch — render it and send the path (spec rule R6):

    python3 __SKILL_DIR__/audit.py brief --phase recon --unit G7 --run "$AUDIT_DIR" \
      --var group_id=G7 --var group_name='...' --var group_description='...' \
      --var key_directories='...' --var run_dir="$AUDIT_DIR" \
      --var mapping_path="$AUDIT_DIR/files/G7-mapping.md" \
      --var source_access='...' --var known_findings='...'

The *Mapping Output Storage* below remains the authority for what a mapping
row must contain.

### Source Access Instructions (fill into template)

**Source code only:**
```
Source code is at: {source_path}
Language: {language}
Use glob to find files, grep to search, and your file-read tool to read content.
```

**IDA Pro only:**
```
Binary analysis via IDA Pro MCP. The binary is {binary_name}.
- Use entity_query to find functions/strings/imports
- Use decompile to read function pseudocode
- Use analyze_function for compact analysis (callees, callers, strings)
- Use find_regex to search strings
- Use callgraph to trace call paths
- Use xrefs_to to find references to specific functions/data
```

**Both:**
```
You have TWO sources. Use source code as primary (better names, comments, types).
Use IDA Pro to verify compiled behavior when source is ambiguous.

Source code: {source_path} ({language})
IDA Pro: {binary_name} on port {port}

Prioritize source code for understanding logic. Use IDA for:
- Confirming compiled code matches source (no #ifdef differences)
- Finding strings or constants not obvious from source
- Tracing actual call paths (template instantiation, virtual dispatch)
```

## Mapping Output Storage

After all subagents return:

1. **Session files**: Save each group's full output to `files/{group_id}-mapping.md`
2. **SQL attack surface**:
   ```sql
   INSERT INTO cba_attack_surface (group_id, endpoint, method, auth_required, description)
   VALUES (?, ?, ?, ?, ?);
   ```
3. **SQL observations**:
   ```sql
   INSERT INTO cba_security_observations (group_id, observation, severity_hint, location)
   VALUES (?, ?, ?, ?);
   ```

## Quality Checks

Before presenting mappings to the user, verify:

- [ ] Every group has at least 2 features mapped
- [ ] Every mapped feature has at least one source file reference
- [ ] No source files are mapped to multiple groups (or if they are, it's intentional and documented)
- [ ] Authentication requirements are specified for every entry point
- [ ] At least 1 security observation exists per group (if zero, the mapping was too shallow)
