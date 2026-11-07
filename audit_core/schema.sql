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

-- Stage 4e keeps independent lane generations and candidate-free receipts.
CREATE TABLE IF NOT EXISTS cba_hunt_runs (
    image_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    surface_snapshot_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    unit_count INTEGER NOT NULL,
    batch_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    PRIMARY KEY (image_id, lane));

CREATE TABLE IF NOT EXISTS cba_hunt_receipts (
    image_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    batch_path TEXT NOT NULL,
    batch_sha256 TEXT NOT NULL,
    result_path TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    unit_count INTEGER NOT NULL,
    candidate_count INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, lane, worklist_sha256, batch_path));

CREATE TABLE IF NOT EXISTS cba_hunt_candidates (
    image_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    title TEXT NOT NULL,
    bug_class TEXT NOT NULL,
    surface_ids TEXT NOT NULL,
    surface_context TEXT NOT NULL,
    attacker_position TEXT NOT NULL,
    input_evidence TEXT NOT NULL,
    data_flow TEXT NOT NULL,
    dangerous_operation TEXT NOT NULL,
    operation_evidence TEXT NOT NULL,
    mitigations_checked TEXT NOT NULL,
    lifecycle_required TEXT NOT NULL,
    posture_required TEXT NOT NULL,
    auth_required TEXT NOT NULL,
    reachability TEXT NOT NULL,
    state_evidence TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    impact_hypothesis TEXT NOT NULL,
    blockers TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, lane, candidate_id));

-- Stage 4f static review keeps firmware provenance separate from generic findings.
CREATE TABLE IF NOT EXISTS cba_firmware_fp_runs (
    image_id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL,
    surface_snapshot_sha256 TEXT NOT NULL,
    sink_worklist_sha256 TEXT NOT NULL,
    dark_worklist_sha256 TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    candidate_count INTEGER NOT NULL,
    batch_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT);

CREATE TABLE IF NOT EXISTS cba_firmware_fp_receipts (
    image_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    batch_path TEXT NOT NULL,
    batch_sha256 TEXT NOT NULL,
    result_path TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    assigned_count INTEGER NOT NULL,
    verdict_count INTEGER NOT NULL,
    true_positive_count INTEGER NOT NULL,
    false_positive_count INTEGER NOT NULL,
    duplicate_count INTEGER NOT NULL,
    pivot_count INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, candidate_snapshot_sha256, batch_path));

CREATE TABLE IF NOT EXISTS cba_firmware_fp_verdicts (
    image_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    batch_path TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    attacker_advantage TEXT NOT NULL,
    rules_applied TEXT NOT NULL,
    mitigation_analysis TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    root_cause_key TEXT,
    root_cause TEXT,
    dedup_evidence TEXT,
    duplicate_lane TEXT,
    duplicate_candidate_id TEXT,
    refuting_mechanism TEXT,
    pivot_id TEXT,
    reviewed_attacker_position TEXT,
    reviewed_data_flow TEXT,
    reviewed_impact_hypothesis TEXT,
    component_paths TEXT,
    surface_ids TEXT,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    reviewed_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, lane, candidate_id));

CREATE TABLE IF NOT EXISTS cba_firmware_pivots (
    image_id TEXT NOT NULL,
    pivot_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    source_lane TEXT NOT NULL,
    source_candidate_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    refuting_mechanism TEXT NOT NULL,
    enabled_observation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, pivot_id));

CREATE TABLE IF NOT EXISTS cba_firmware_findings (
    image_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    root_cause_key TEXT NOT NULL,
    canonical_lane TEXT NOT NULL,
    canonical_candidate_id TEXT NOT NULL,
    contributors TEXT NOT NULL,
    lanes TEXT NOT NULL,
    component_paths TEXT NOT NULL,
    surface_ids TEXT NOT NULL,
    title TEXT NOT NULL,
    bug_class TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    attacker_position TEXT NOT NULL,
    data_flow TEXT NOT NULL,
    impact_hypothesis TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    evidence_rung TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    derived_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, finding_id));

-- Stage 4g static chain evidence remains separate from generic source chains.
CREATE TABLE IF NOT EXISTS cba_firmware_chain_runs (
    image_id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL,
    surface_snapshot_sha256 TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    fpcheck_artifact_path TEXT NOT NULL,
    fpcheck_artifact_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    surface_count INTEGER NOT NULL,
    unknown_count INTEGER NOT NULL,
    pivot_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    graph_path TEXT,
    graph_sha256 TEXT,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT);

CREATE TABLE IF NOT EXISTS cba_firmware_chain_receipts (
    image_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    result_path TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    disposition_count INTEGER NOT NULL,
    blocker_count INTEGER NOT NULL,
    chain_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, candidate_snapshot_sha256));

CREATE TABLE IF NOT EXISTS cba_firmware_chain_dispositions (
    image_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    disposition TEXT NOT NULL,
    explanation TEXT NOT NULL,
    chain_ids TEXT NOT NULL,
    existing_unknown_ids TEXT NOT NULL,
    blocker_ids TEXT NOT NULL,
    pivot_followup_ids TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, finding_id));

CREATE TABLE IF NOT EXISTS cba_firmware_chain_unknowns (
    image_id TEXT NOT NULL,
    blocker_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    question TEXT NOT NULL,
    settling_observation TEXT NOT NULL,
    method TEXT NOT NULL,
    axes TEXT NOT NULL,
    affected_finding_ids TEXT NOT NULL,
    affected_edges TEXT NOT NULL,
    status TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, blocker_id));

CREATE TABLE IF NOT EXISTS cba_firmware_chains (
    image_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    member_ids TEXT NOT NULL,
    initial_attacker_position TEXT NOT NULL,
    initial_evidence_refs TEXT NOT NULL,
    initial_lifecycle TEXT NOT NULL,
    initial_posture TEXT NOT NULL,
    initial_authentication TEXT NOT NULL,
    pre_auth TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    completeness TEXT NOT NULL,
    existing_unknown_ids TEXT NOT NULL,
    blocker_ids TEXT NOT NULL,
    evidence_rung TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    derived_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, chain_id));

CREATE TABLE IF NOT EXISTS cba_firmware_chain_edges (
    image_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    producer_finding_id TEXT NOT NULL,
    consumer_finding_id TEXT NOT NULL,
    capability_kind TEXT NOT NULL,
    link_key TEXT NOT NULL,
    produced_capability TEXT NOT NULL,
    required_precondition TEXT NOT NULL,
    producer_evidence_refs TEXT NOT NULL,
    consumer_evidence_refs TEXT NOT NULL,
    supplemental_evidence_refs TEXT NOT NULL,
    required_state TEXT NOT NULL,
    result_state TEXT NOT NULL,
    transition_kind TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    existing_unknowns TEXT NOT NULL,
    blocker_ids TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    derived_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, chain_id, ordinal));

-- Stage 4h: immutable firmware dive generations and their local evidence rows.

CREATE TABLE IF NOT EXISTS cba_firmware_dive_runs (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    surface_snapshot_sha256 TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    chain_graph_path TEXT NOT NULL,
    chain_graph_sha256 TEXT NOT NULL,
    analyst_manifest_path TEXT NOT NULL,
    analyst_manifest_sha256 TEXT NOT NULL,
    journal_input_path TEXT NOT NULL,
    journal_input_sha256 TEXT NOT NULL,
    question_index_path TEXT NOT NULL,
    question_index_sha256 TEXT NOT NULL,
    question_count INTEGER NOT NULL,
    chain_blocker_count INTEGER NOT NULL,
    surface_unknown_count INTEGER NOT NULL,
    analyst_question_count INTEGER NOT NULL,
    retry_count INTEGER NOT NULL,
    conflict_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    journal_path TEXT,
    journal_sha256 TEXT,
    supported_count INTEGER NOT NULL,
    refuted_count INTEGER NOT NULL,
    inconclusive_count INTEGER NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    PRIMARY KEY (image_id, dive_generation));

CREATE TABLE IF NOT EXISTS cba_firmware_dive_questions (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    question_id TEXT NOT NULL,
    attempt_ordinal INTEGER NOT NULL,
    origin TEXT NOT NULL,
    method TEXT NOT NULL,
    question TEXT NOT NULL,
    settling_observation TEXT NOT NULL,
    subject_refs TEXT NOT NULL,
    resolution_contract TEXT NOT NULL,
    axes TEXT NOT NULL,
    prior_observation_id TEXT,
    supersedes_observation_ids TEXT NOT NULL,
    packet_path TEXT NOT NULL,
    packet_sha256 TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, dive_generation, question_id));

CREATE TABLE IF NOT EXISTS cba_firmware_dive_receipts (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    receipt_key TEXT NOT NULL,
    receipt_kind TEXT NOT NULL,
    question_id TEXT,
    attempt_ordinal INTEGER,
    packet_sha256 TEXT,
    result_path TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    outcome TEXT NOT NULL,
    dependency_count INTEGER NOT NULL,
    evidence_count INTEGER NOT NULL,
    successor_count INTEGER NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, dive_generation, receipt_key));

CREATE TABLE IF NOT EXISTS cba_firmware_dive_observations (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    question_id TEXT NOT NULL,
    attempt_ordinal INTEGER NOT NULL,
    observation_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    limitations TEXT NOT NULL,
    resolution_effect TEXT,
    evidence_rung TEXT,
    dependency_refs TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    successor_questions TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, dive_generation, question_id));

CREATE TABLE IF NOT EXISTS cba_firmware_dive_dependencies (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    question_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    observation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    logical_id TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    source_provenance TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, dive_generation, question_id, ordinal));

CREATE TABLE IF NOT EXISTS cba_firmware_dive_acquisitions (
    image_id TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    question_id TEXT NOT NULL,
    acquisition_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    contract_sha256 TEXT NOT NULL,
    spec_path TEXT NOT NULL,
    spec_sha256 TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    evidence_paths TEXT NOT NULL,
    details TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, dive_generation, question_id, acquisition_id));

-- Stage 4i: one immutable acquisition-decision lifecycle row per generation.
-- superseded_at and preparation_ordinal were appended after Stage 4i shipped;
-- db.MIGRATIONS adds them to existing databases in this same order.

CREATE TABLE IF NOT EXISTS cba_firmware_decide_runs (
    image_id TEXT NOT NULL,
    decision_generation TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    surface_snapshot_sha256 TEXT NOT NULL,
    candidate_snapshot_sha256 TEXT NOT NULL,
    chain_worklist_sha256 TEXT NOT NULL,
    graph_path TEXT NOT NULL,
    graph_sha256 TEXT NOT NULL,
    dive_generation TEXT NOT NULL,
    journal_path TEXT NOT NULL,
    journal_sha256 TEXT NOT NULL,
    overlay_sha256 TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_path TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    result_path TEXT,
    result_sha256 TEXT,
    package_path TEXT,
    package_sha256 TEXT,
    decision TEXT,
    primary_reason TEXT,
    reason_codes TEXT,
    chain_count INTEGER NOT NULL,
    bench_test_count INTEGER NOT NULL,
    script_count INTEGER NOT NULL,
    policy_match_count INTEGER NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    recorded_at TEXT,
    completed_at TEXT,
    superseded_at TEXT,
    preparation_ordinal INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (image_id, decision_generation));
