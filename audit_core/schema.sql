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
    refuting_mechanism TEXT,
    enabled_observation TEXT,
    reviewed_at TEXT DEFAULT (datetime('now')));

-- Stage 2 additions. Every statement below is IF NOT EXISTS for the same
-- reason the block above is: `audit.py init` runs again at the start of each
-- phase, and re-running a phase must never destroy a row an earlier phase
-- recorded.

CREATE TABLE IF NOT EXISTS cba_inventory (
    unit TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    group_id TEXT,
    size INTEGER,
    added_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_coverage (
    unit TEXT NOT NULL,
    phase TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (unit, phase));

CREATE TABLE IF NOT EXISTS cba_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    regex TEXT NOT NULL,
    origin_finding TEXT,
    language TEXT,
    notes TEXT,
    swept_at TEXT,
    hit_count INTEGER,
    created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_pattern_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    excerpt TEXT,
    triaged TEXT DEFAULT 'pending',
    swept_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase TEXT NOT NULL,
    reason TEXT NOT NULL,
    turns INTEGER,
    projected_context INTEGER,
    resume_note TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));

-- Stage 3 additions. IF NOT EXISTS for the same reason as every statement
-- above. New COLUMNS on the tables above cannot be declared this way --
-- SQLite has no ADD COLUMN IF NOT EXISTS, and CREATE TABLE IF NOT EXISTS is
-- a no-op against a table that already exists -- so those columns are
-- declared inline above for fresh databases and added to existing ones by
-- audit_core.db.migrate, which workspace.apply_schema runs after this file.

CREATE TABLE IF NOT EXISTS cba_components (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    asserted_identity TEXT NOT NULL,
    identity_evidence TEXT NOT NULL,
    confidence INTEGER,
    version TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_chains (
    id TEXT PRIMARY KEY,
    finding_ids TEXT NOT NULL,
    attacker_position TEXT NOT NULL,
    pre_auth TEXT,
    completeness TEXT NOT NULL,
    blocking_unknowns TEXT,
    created_at TEXT DEFAULT (datetime('now')));

-- Stage 4b additions. These are new tables, so the idempotent schema
-- application adds them to existing runs without a column migration.

CREATE TABLE IF NOT EXISTS cba_images (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    version TEXT NOT NULL,
    role TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER,
    source TEXT,
    acquired_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_binfacts (
    image_id TEXT NOT NULL,
    path TEXT NOT NULL,
    machine TEXT NOT NULL,
    bits INTEGER NOT NULL,
    endian TEXT NOT NULL,
    elf_type TEXT NOT NULL,
    interp TEXT,
    needed TEXT,
    runpath TEXT,
    nx TEXT,
    pie TEXT,
    relro TEXT,
    canary TEXT,
    stripped TEXT,
    static TEXT,
    sha256 TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, path));

CREATE TABLE IF NOT EXISTS cba_services (
    image_id TEXT NOT NULL,
    name TEXT NOT NULL,
    start_source TEXT NOT NULL,
    exec_path TEXT,
    evidence TEXT NOT NULL,
    ports TEXT,
    ports_evidence TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, name));

-- Stage 4c regular-file manifests are the image comparison source; generic
-- inventory remains the target coverage denominator.
CREATE TABLE IF NOT EXISTS cba_firmware_files (
    image_id TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, path));

-- Stage 4c comparisons retain summaries and only changed file entries.
CREATE TABLE IF NOT EXISTS cba_diffs (
    id TEXT PRIMARY KEY,
    reference_image_id TEXT NOT NULL,
    target_image_id TEXT NOT NULL,
    added_count INTEGER NOT NULL,
    removed_count INTEGER NOT NULL,
    modified_count INTEGER NOT NULL,
    unchanged_count INTEGER NOT NULL,
    manifest_path TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_diff_entries (
    diff_id TEXT NOT NULL,
    path TEXT NOT NULL,
    change TEXT NOT NULL,
    reference_kind TEXT,
    target_kind TEXT,
    reference_size INTEGER,
    target_size INTEGER,
    reference_sha256 TEXT,
    target_sha256 TEXT,
    PRIMARY KEY (diff_id, path));

-- Stage 4d surface phase provenance, handler maps, and settling questions.
CREATE TABLE IF NOT EXISTS cba_surface_runs (
    image_id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    unit_count INTEGER NOT NULL,
    batch_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT);

CREATE TABLE IF NOT EXISTS cba_firmware_surfaces (
    image_id TEXT NOT NULL,
    surface_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    entry_point TEXT NOT NULL,
    protocol TEXT NOT NULL,
    dispatch_path TEXT NOT NULL,
    handler TEXT NOT NULL,
    lifecycle_required TEXT NOT NULL,
    posture_required TEXT NOT NULL,
    auth_required TEXT NOT NULL,
    reachability TEXT NOT NULL,
    reach_evidence TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, surface_id));

CREATE TABLE IF NOT EXISTS cba_unknowns (
    id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    surface_id TEXT,
    field TEXT NOT NULL,
    question TEXT NOT NULL,
    settling_observation TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL,
    resolution TEXT,
    evidence TEXT,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')));
