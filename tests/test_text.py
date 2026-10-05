from audit_core import text


def test_root_cause_key_normalizes_case_punctuation_and_whitespace():
    a = "Unbounded memcpy() into a fixed stack buffer."
    b = "unbounded   memcpy  into a fixed stack buffer"
    assert text.root_cause_key(a) == text.root_cause_key(b)
    assert text.root_cause_key(a) == "unbounded memcpy into a fixed stack buffer"


def test_root_cause_key_of_nothing_is_empty_not_an_error():
    assert text.root_cause_key(None) == ""
    assert text.root_cause_key("   ") == ""
    assert text.root_cause_key("!!!") == ""


def test_location_tokens_drops_tokens_shorter_than_the_minimum():
    """The tplink golden produced two false pairs from the bare token `tss`.

    REF-10 (a degenerate strncpy in update_bind_token) paired against
    G6-F3 (RSA key disclosure via ATTPGV) and G6-F4 (ATTPSK key-store
    overwrite) purely because `tss` is a substring of `TssRSASecretKey`
    and `osal_tss_init`. Four characters is the floor.
    """
    assert text.MIN_LOCATION_TOKEN == 4
    assert "tss" not in text.location_tokens("osal_tss_init tss")
    assert "osal_tss_init" in text.location_tokens("osal_tss_init tss")


def test_location_tokens_splits_on_path_and_address_punctuation():
    got = text.location_tokens("src/handlers/klap.c:120 klap_handshake1_handle@0x0E043264")
    assert "handlers" in got
    assert "klap_handshake1_handle" in got
    assert "0x0E043264".lower() in got
    assert "src" not in got        # three characters
    assert "120" not in got        # three characters


def test_location_tokens_is_case_insensitive():
    assert text.location_tokens("KlapHandshake") == text.location_tokens("klaphandshake")
