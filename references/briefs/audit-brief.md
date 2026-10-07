# Deep audit brief — {group_id}

You are a senior security researcher auditing one feature group for real,
exploitable vulnerabilities. No theoretical concerns.

## Assignment

Feature group: {group_id} — {group_name}
Audit run directory: {run_dir}
Mapping to work from: {mapping_path}

## Source access

{source_access}

## Test instance

{test_instance}

If a test instance IS available, attempt live verification for HIGH/CRITICAL
findings:

- Craft the HTTP request or payload
- Send it using curl, requests, or raw sockets
- Document the response
- Mark finding as `verified: live-poc`

Do NOT:

- Exfiltrate real data
- Crash the instance permanently
- Modify admin credentials
- Install persistence

## Known findings and patch-bypass surface

{known_findings}

Do not re-report these. **Do** probe every sibling or adjacent site listed
under each advisory for the same root cause left untouched — this class yields
the highest-severity findings in real audits.

## What to hunt

Priority order by typical severity. For each, trace a complete path from
attacker-controlled input to the sink, and state which mitigations you checked
and found absent.

1. Injection — SQL, command, LDAP, XPath, template
2. Authentication bypass — session fixation, token forgery, missing checks
3. SSRF, including scheme and IP-validation bypasses
4. Path traversal — read or write outside the intended root
5. Insecure deserialization of untrusted data
6. Any path from input to code execution
7. Authorization bypass — horizontal and vertical privilege escalation, IDOR
8. Cryptographic defects, weak randomness, key exposure
9. Information disclosure — sensitive data in responses, error messages, logs
10. CSRF on state-changing operations — check first whether auth is API-key-based
11. Race conditions — TOCTOU, double-spend, check-then-act without a lock
12. Denial of service — algorithmic complexity, resource exhaustion, regex DoS
13. XML and JSON parsing — XXE, billion-laughs, deeply nested structures
14. Header injection — CRLF in headers, response splitting
15. Configuration weaknesses — insecure defaults, missing security headers
16. Information leakage — version disclosure, internal paths, stack traces

## Rules of engagement

1. Read the actual code. Every claim cites file, function and line.
2. If you cannot trace the data flow, do not report it.
3. Check for existing mitigations before reporting. Verify there is not:
   - Input validation or sanitization before the sink
   - A WAF rule or middleware that blocks the payload
   - A framework feature that prevents the class of bug
   - Parameterized queries or type checking that make it impossible
4. Do not report a library vulnerability unless this application triggers the
   vulnerable path.
5. Apply the Marginal Gain Test: if the attacker's starting position already
   grants the claimed impact, it is not a finding.
6. Confidence must be at least 8 of 10.

## Where your output goes

Write every finding as a row in `cba_findings` in `{run_dir}/audit.db`, and
the detailed write-up to `{artifact_path}`. Set each row's `artifact_path`
column to `{artifact_path}` as you insert it. The finding schema is in
`references/phase4-deep-audit.md` under *Finding Schema*.

If a finding's root cause is a shape that could appear elsewhere in the tree,
register it: `audit.py put --table cba_patterns --set id=<id> --set name=...
--set regex=... --set origin_finding=<your finding id>`. The orchestrator
sweeps every registered pattern corpus-wide with `audit.py sweep` before the
phase exits.

If you find zero vulnerabilities in your group, say so explicitly and list
every entry point you reviewed. `rows=0` is not a coverage statement.

## Record what you opened

Coverage is measured per unit against the inventory recon built, and the
`audit` phase cannot exit until every inventoried unit has a decision. Nobody
else knows which files you opened, so you are the only one who can record it.

As you work, append every file you actually read to
`{run_dir}/files/{group_id}-audited.txt`, one path per line, in the same form
the inventory uses. Before you return, record them:

    python3 __SKILL_DIR__/audit.py coverage --db {run_dir}/audit.db --record \
      --phase audit --state analyzed \
      --from-file {run_dir}/files/{group_id}-audited.txt

If a file in your group was inventoried and you deliberately did not open it,
say why in the same way — one call per reason, from `out-of-scope`,
`generated`, `vendored`, `third-party`, `unreachable`, `binary-only`:

    python3 __SKILL_DIR__/audit.py coverage --db {run_dir}/audit.db --record \
      --phase audit --state not_audited --reason vendored \
      --unit <path> --unit <path>

`budget` is a legal reason and it **fails** the phase gate on purpose: running
short of context is answered by checkpointing and restarting, never by leaving
a surface unopened. If you are running out of room, say so in your return line
rather than recording a budget skip.

A file you opened and recorded nothing about is a decision on the record. A
file you opened and never recorded is indistinguishable from one nobody ever
looked at — which is how six of ten missed CRITICALs sat on surfaces that were
never opened and never written down.

## What you return

Return exactly one line, and nothing else:

    {group_id} <DONE|PARTIAL|FAILED> rows=<n> artifact={artifact_path} [flags=<csv>]

Your prose does not reach the orchestrator's reasoning — it reads your rows
from SQL. A finding that is not in the database did not happen.
