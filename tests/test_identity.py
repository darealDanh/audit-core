import pytest

from audit_core import db, identity, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def test_evidence_that_only_repeats_the_filename_is_rejected():
    """The tplink miss, exactly: km0_boot_0C000020.elf was treated as a
    bootloader because it is called km0_boot. It holds the Realtek Wi-Fi
    driver and several CRITICALs."""
    with pytest.raises(db.DbError) as exc:
        identity.check_evidence("images/km0_boot_0C000020.elf",
                                "the file is named km0_boot_0C000020.elf")
    message = str(exc.value)
    assert "path" in message
    assert "km0_boot" in message


def test_evidence_naming_something_outside_the_path_is_accepted():
    identity.check_evidence(
        "images/km0_boot_0C000020.elf",
        "contains the string 'rtl8710 wlan firmware' at 0x0C00A120 and "
        "imports wifi_hal_init")


def test_evidence_too_short_to_be_evidence_is_rejected():
    with pytest.raises(db.DbError) as exc:
        identity.check_evidence("images/boot.elf", "ELF")
    assert str(identity.MIN_EVIDENCE_CHARS) in str(exc.value)


def test_the_check_ignores_case_and_path_separators():
    """`SRC/OSAL/Tss.c` and `src_osal_tss` tokenize the same way; evidence
    that restates the path in another casing or with another separator is
    the same circular claim."""
    with pytest.raises(db.DbError):
        identity.check_evidence("src/osal/Tss.c",
                                "found under SRC/OSAL as TSS dot C file")


def test_record_writes_a_component_row(con):
    identity.record(
        con, path="images/km0_boot_0C000020.elf", kind="binary",
        identity="Realtek RTL8710 Wi-Fi driver image",
        evidence="contains 'rtl8710 wlan firmware' at 0x0C00A120; imports "
                 "wifi_hal_init; no reset vector at offset 0",
        confidence="8", version="1.0.11")
    row = db.rows(con, "cba_components")[0]
    assert row["asserted_identity"].startswith("Realtek")
    assert row["confidence"] == 8


def test_put_rejects_a_circular_component_row_too(con):
    """The rule lives in the table contract, not only in the verb, so the
    generic `audit.py put --table cba_components` path cannot route around
    it."""
    with pytest.raises(db.DbError):
        db.put(con, "cba_components", {
            "path": "images/km0_boot.elf", "kind": "binary",
            "asserted_identity": "bootloader",
            "identity_evidence": "it is km0_boot.elf"})


def test_an_unknown_kind_is_rejected(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_components", {
            "path": "a.bin", "kind": "thingy",
            "asserted_identity": "x",
            "identity_evidence": "entropy 7.9 over the whole file, no ELF header"})
    assert "thingy" in str(exc.value)


def test_the_identity_rule_depends_on_these_noise_words():
    """IMPORTANT 6's other half. `text.NOISE_WORDS` is subtracted here to
    stop a circular claim slipping through dressed as a sentence, and
    subtracted by `chains._significant` to suppress generic joins -- two
    rules that want opposite changes out of one frozenset. The base
    docstring asked for "both callers' tests" and neither existed.

    This is this caller's. Each word below is one that
    test_the_check_ignores_case_and_path_separators and
    test_evidence_that_only_repeats_the_filename_is_rejected rely on: remove
    it and evidence that only restates its own path starts being accepted.
    """
    from audit_core import text
    for word in ("found", "under", "file", "named", "itself", "inside"):
        assert word in text.NOISE_WORDS, (
            f"{word!r} left text.NOISE_WORDS; evidence that only restates "
            f"its own path in a sentence is now accepted. Chain-proposal "
            f"noise belongs in chains.GENERIC_TOKENS, not here.")


def test_chain_proposal_noise_never_leaks_into_the_identity_rule():
    """The reason the two sets are separate: a word added for the chain
    proposer must not quietly make this rule reject more evidence."""
    from audit_core import chains
    identity.check_evidence(
        "images/boot.elf",
        "the memory layout places a persistent session credential table at "
        "offset 0x4000")
    assert "memory" in chains.GENERIC_TOKENS
    assert "memory" not in __import__(
        "audit_core.text", fromlist=["text"]).NOISE_WORDS


def test_record_replace_preserves_columns_the_caller_omitted(con):
    """record always put version and confidence in the row (as ""), so a
    --replace that did not mention them blanked what was stored."""
    identity.record(
        con, path="images/km0_boot_0C000020.elf", kind="binary",
        identity="Realtek RTL8710 Wi-Fi driver image",
        evidence="contains 'rtl8710 wlan firmware' at 0x0C00A120; imports "
                 "wifi_hal_init; no reset vector at offset 0",
        confidence="8", version="1.0.11")
    identity.record(
        con, path="images/km0_boot_0C000020.elf", kind="binary",
        identity="Realtek RTL8710 Wi-Fi driver image (revised)",
        evidence="contains 'rtl8710 wlan firmware' at 0x0C00A120; imports "
                 "wifi_hal_init; no reset vector at offset 0",
        replace=True)
    row = db.rows(con, "cba_components")[0]
    assert row["version"] == "1.0.11"
    assert row["confidence"] == 8
    assert row["asserted_identity"].endswith("(revised)")
