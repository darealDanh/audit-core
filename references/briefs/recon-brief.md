# Feature mapping brief — {group_id}

You are mapping features to code for a security audit. Map thoroughly; do not
investigate vulnerabilities deeply — note them and move on.

## Assignment

Feature group: {group_id} — {group_name}
Description: {group_description}
Key directories: {key_directories}
Audit run directory: {run_dir}

## Source access

{source_access}

## What to map, per feature

1. Feature name and what it does
2. Entry points — endpoints, CLI commands, event handlers, scheduled tasks
3. Key source files that implement it
4. Authentication requirement — none, user, admin, internal-only
5. Input sources — headers, query, body, uploads, environment, database
6. Data flow from input through processing to sink
7. Trust boundaries crossed — privilege, network, or process
8. Security-relevant observations, noted not investigated

Read every file in the assigned directories. Do not skip a file because it
looks uninteresting; follow imports to understand dependencies.

## Known prior art

{known_findings}

## Where your output goes

Write the full mapping to `{mapping_path}`. Insert one row per entry point
into `cba_attack_surface`, and one row per observation into
`cba_security_observations`, in `{run_dir}/audit.db`.

## What you return

Return exactly one line, and nothing else:

    {group_id} <DONE|PARTIAL|FAILED> rows=<n> artifact={mapping_path} [flags=<csv>]
