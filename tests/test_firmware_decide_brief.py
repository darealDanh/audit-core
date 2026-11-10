"""The firmware decision worker receives one bounded global assignment."""
import dataclasses
import hashlib
import json
import pathlib
import re

import pytest

from audit_core import briefs
from audit_core import firmware_decide_results as results


ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = briefs.template_path("firmware-decide")
VARIABLES = {"run_dir", "image_id", "decision_generation", "worklist_path", "result_path"}


def text():
    return TEMPLATE.read_text()


def test_decide_brief_has_exact_variables_and_return_contract(tmp_path):
    source = text()
    assert set(re.findall(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}", source)) == VARIABLES
    rendered = briefs.render(source.replace("__SKILL_DIR__", str(ROOT)),
                             {name: str(tmp_path / name) for name in VARIABLES})
    assert "firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]" in rendered


def test_decide_brief_pins_global_complete_chain_contract():
    source = text().lower()
    for required in ("one fresh strongest", "global", "every chain", "complete",
                     "strict json", "result-only", "duplicate keys", "extra keys",
                     "partial", "nonimportable", "same immutable"):
        assert required in source


def test_decide_brief_denies_authority_and_keeps_scripts_inert():
    source = text().lower()
    for required in ("do not write sql", "policy", "recommendation", "payout",
                     "canonical", "completion", "severity", "exploit", "report",
                     "do not execute", "proposed scripts"):
        assert required in source


def test_skill_routes_one_global_decision_worker():
    source = (ROOT / "firmware-audit" / "SKILL.md").read_text().lower()
    for required in ("stage 4i firmware decision", "firmware-decide-brief.md",
                     "audit.py decide --run", "--prepare", "--record", "--check",
                     "one fresh strongest", "partial", "proposed scripts"):
        assert required in source


def section(heading):
    source = text()
    start = source.index(f"\n## {heading}\n") + len(heading) + 5
    end = source.find("\n## ", start)
    return source[start:] if end == -1 else source[start:end]


def bullet_keys(heading):
    """Backticked names before each top-level bullet's first colon."""
    keys = set()
    for bullet in re.split(r"\n(?=- )", section(heading).replace("\n  ", " ")):
        match = re.match(r"- (.+?): ", bullet)
        if match:
            keys.update(re.findall(r"`([a-z0-9_]+)`", match.group(1)))
    return keys


def flat(heading):
    return " ".join(section(heading).split())


def fields(cls):
    return {item.name for item in dataclasses.fields(cls)}


def test_brief_schema_names_exactly_the_parser_fields():
    """Catches a brief schema that drifts from the parser dataclasses."""
    assert bullet_keys("Result artifact") == fields(results.DecisionResult)
    assert bullet_keys("Chain assessments") == fields(results.ChainAssessment)
    assert bullet_keys("Bench tests") == fields(results.BenchTest)
    required = flat("Bench tests").split("`required_state`: exactly ")[1]
    assert set(re.findall(r"`([a-z0-9_]+)`", required.split(".")[0])) == fields(
        results.RequiredState)
    assert set(re.findall(r"`([a-z0-9_]+)`", flat("Proposed scripts").split(". ")[1])) == fields(
        results.ProposedScript)
    assert '`{"kind": "empty"}`' in flat("Result artifact")
    assert "(`\"decision\"`), `chain_assessments`, `bench_tests`, and `proposed_scripts`" in flat(
        "Result artifact")


def test_brief_enumerations_and_limits_match_parser_constants():
    """Catches a stale disposition enum, script pattern, or size limit in the brief."""
    chains = flat("Chain assessments")
    assert "`, `".join(results._DISPOSITIONS) in chains.replace("`, or `", "`, `")
    scripts = flat("Proposed scripts")
    assert f"`{results._SCRIPT_NAME.pattern}`" in scripts
    assert f"at most {results.MAX_SCRIPTS} scripts" in scripts
    assert f"{results.MAX_SCRIPT_BYTES // 1024} KiB per script" in scripts
    assert f"{results.MAX_SCRIPT_TOTAL_BYTES // 1024} KiB in total" in scripts
    assert "unique after case folding" in scripts and "`Probe.sh` and `probe.sh`" in scripts
    assert f"{results.MAX_RESULT_BYTES // (1024 * 1024)} MiB" in flat("Result artifact")
    assert f"{results.MAX_TEXT_BYTES // 1024} KiB UTF-8" in flat("Result artifact")
    assert results.RESULT_SCHEMA_VERSION == 1 and "the integer `1`" in flat("Result artifact")


def test_brief_test_identity_recipe_reproduces_parser_identity():
    """Catches a documented test_id recipe that the parser would reject."""
    bench = flat("Bench tests")
    assert ("`firmware-decide-test-` followed by the lowercase SHA-256 of the test object "
            "without `test_id`, serialized as UTF-8 JSON with sorted keys, "
            "`(\",\", \":\")` separators, and non-ASCII characters left unescaped") in bench
    test = results.BenchTest(
        "", ("chain-a",), ("transition:chain-a:0",), "Titel ü", "purpose",
        results.RequiredState("image", "0" * 64, "factory", "default", "none"),
        ("setup",), ("action",), "signal", "control", ("stop",), (), None)
    body = results._bench_wire(test, include_id=False)
    documented = "firmware-decide-test-" + hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert documented == results._bench_identity(test)
    assert results._TEST_ID.fullmatch(documented)


def test_brief_pins_subject_state_and_shared_owner_rules():
    """Catches omitting the subject wires, frozen state binding, or subset-of-owners rule."""
    bench = flat("Bench tests")
    for required in (
            "`blocker:<source_id>` or `unknown:<source_id>`",
            "`transition:<chain_id>:<edge_ordinal>`",
            "`device` equals the image ID and `firmware` equals the graph's "
            "`candidate_snapshot_sha256`",
            "Every subject must be owned by at least one listed chain, and every listed "
            "chain must own at least one subject",
            "each list only a subset of its owner chains",
            "checked only against the listed chains",
            "the carried incoming state where the edge requires `any`",
            "uses the chain's initial state"):
        assert required in bench, required
    chains = flat("Chain assessments")
    for required in ("copied exactly from the frozen chain", "in graph order",
                     "exactly 1 through the chain count",
                     "copied whole (all keys and every location)",
                     "`dive:<observation_id>#conclusion` or `#evidence`"):
        assert required in chains, required


def test_brief_reads_worklist_incrementally_and_refuses_changed_generation():
    """Catches a brief that invites partitioned reading or generation switching."""
    assignment = flat("Assignment and authority")
    for required in ("Read the worklist incrementally from that exact path",
                     "never partition it by chain or component",
                     "never cap the chain or open precondition denominator",
                     "SHA-256 of the exact worklist bytes", "return FAILED",
                     "do not repair the worklist or switch to another generation"):
        assert required in assignment, required


def route():
    source = (ROOT / "firmware-audit" / "SKILL.md").read_text()
    start = source.index("### Stage 4i firmware decision")
    return source[start:source.index("\n### ", start + 1)]


def test_skill_route_orders_prepare_brief_record_check():
    """Catches a route that dispatches, records, or checks out of order."""
    body = route()
    steps = [
        "audit.py decide --run ${AUDIT_DIR} --root ${ROOTFS} \\\n      --policy ${DECISION_POLICY} --prepare --json",
        "firmware-decide-brief.md",
        "audit.py brief --phase firmware-decide",
        "audit.py decide --run ${AUDIT_DIR} --record ${RESULT_PATH}",
        "audit.py decide --run ${AUDIT_DIR} --root ${ROOTFS} --check",
    ]
    positions = [body.index(step) for step in steps]
    assert positions == sorted(positions)
    for step in steps[2:]:
        assert body.count(step) == 1, step


def test_skill_route_takes_paths_from_prepare_and_never_inlines():
    """Catches a route that guesses the worklist path or inlines the assignment."""
    body = " ".join(route().split())
    for required in (
            "Use the returned `image_id` and `decision_generation`",
            "set WORKLIST_PATH to `${AUDIT_DIR}/` plus the returned run-relative `worklist_path`",
            "Assign RESULT_PATH to the worker's writable result file",
            "--var worklist_path=${WORKLIST_PATH} --var result_path=${RESULT_PATH}",
            "Do not inline the worklist, policy, or evidence in the dispatch",
            "reads the worklist incrementally",
            "firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]",
            "The latest preparation is current", "`superseded`",
            "never fall back to an older completed generation"):
        assert required in body, required


def test_brief_states_parser_text_array_and_reference_bounds():
    """Catches a brief silent on whitespace-only text, byte/array caps, or the reference wire."""
    artifact = flat("Result artifact")
    for required in ("at least one non-whitespace character",
                     "whitespace-only text is rejected",
                     f"every array holds at most {results.MAX_ARRAY_ITEMS} items",
                     "each ordered step array holds at most 256 steps"):
        assert required in artifact, required
    with pytest.raises(results.FirmwareDecideResultError):
        results._text(" \n\t", "probe")
    with pytest.raises(results.FirmwareDecideResultError):
        results._ordered_text(["step"] * 257, "probe")
    assert results._ordered_text([f"step {n}" for n in range(256)], "probe")
    bench = flat("Bench tests")
    assert "nonempty sorted subjects, each at most 4096 UTF-8 bytes" in bench
    assert "`authentication`, each text of at most 4096 UTF-8 bytes" in bench
    chains = flat("Chain assessments")
    for required in ("`<scheme>:<locator>#<anchor>`",
                     "the scheme is an ASCII letter followed by ASCII letters, digits, or `-`",
                     "the locator is 1-4096 characters without NUL, CR, LF, or `#`",
                     "the anchor is 1-128 ASCII letters, digits, `.`, `_`, `:`, or `-`"):
        assert required in chains, required
    assert results._REFERENCE.pattern == (
        r"[A-Za-z][A-Za-z0-9-]*:[^\x00\r\n#]{1,4096}#[A-Za-z0-9._:-]{1,128}")


def test_skill_route_states_superseded_reprepare_and_upgrade_ranking():
    """Catches a route that implies a superseded generation can be revived or upgrades reorder."""
    body = " ".join(route().split())
    for required in ("A superseded generation can never be prepared again",
                     "change the policy bytes to create a new generation",
                     "Upgrading a run ranks its existing decision rows so the generation "
                     "selected before the upgrade stays current"):
        assert required in body, required
