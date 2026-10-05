-- audit_core/schema.sql
-- Schema for a codebase-audit run. Applied by audit_core.workspace.apply_schema.
-- Every statement is IF NOT EXISTS: init is idempotent, and re-running a phase
-- must never destroy rows an earlier phase recorded.

CREATE TABLE IF NOT EXISTS cba_sources (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, source_path TEXT, source_language TEXT,
    source_file_count INTEGER, ida_binary TEXT, ida_port INTEGER, ida_arch TEXT,
    confirmed_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_feature_groups (
    id TEXT PRIMARY KEY, name TEXT, description TEXT, key_paths TEXT,
    status TEXT DEFAULT 'pending', created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_attack_surface (
    id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, endpoint TEXT, method TEXT,
    auth_required TEXT, description TEXT);

CREATE TABLE IF NOT EXISTS cba_security_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, observation TEXT,
    severity_hint TEXT, location TEXT);

CREATE TABLE IF NOT EXISTS cba_known_findings (
    id TEXT PRIMARY KEY, title TEXT, location TEXT, source TEXT,
    patched_in TEXT, severity TEXT, raw TEXT);

CREATE TABLE IF NOT EXISTS cba_findings (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    cwe TEXT,
    location TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    impact TEXT NOT NULL,
    attacker_position TEXT,
    boundary_crossed TEXT,
    data_flow TEXT,
    verified TEXT DEFAULT 'source-only',
    poc TEXT,
    remediation TEXT,
    artifact_path TEXT,
    created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_fp_verdicts (
    finding_id TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    reason TEXT,
    final_severity TEXT,
    final_id TEXT,
    merged_into TEXT,
    rule_applied TEXT,
    reviewed_at TEXT DEFAULT (datetime('now')));
