"""Permanent regression suite for SPIF-KEYSTORE-ID-TYPE-001.

Converted from the loop probe test_loop_keystore_id_type_probe.py
(cycle 2026-11-16-0822; preserved under the loop goal's
hidden_files/evidence/2026-11-16-0822/spif/). Probe legs are verbatim
after this docstring; the final parametrized leg was added at
conversion to cover the sibling entry points the same fix pass
validates (the probe exercised add_key / get_key / revoke /
authorize_role directly).

Invariant: a signature validates only under the key identity it
claims, and malformed inputs fail closed with a clean rejection
(ValueError / SPIFSignatureError) or a benign None/False lookup --
never a bare TypeError/AttributeError, and never silent aliasing of a
non-string id onto a different string identity.

Fix: one _require_str_id check applied at every keystore entry point
(add_key, add_hybrid_key, get_key, get_hybrid_key, remove_key,
revoke, unrevoke, is_revoked, authorize_role, deauthorize_role,
is_authorized_for_role, has_role_authorization_list, and the shared
_entry_path choke point) -- no silent coercion, no bare TypeError.
"""
import pytest

from spif.keystore import SPIFKeyStore
from spif.reader import SPIFSignatureError

CLEAN = (ValueError, SPIFSignatureError)
KEY = bytes(range(32))


@pytest.fixture()
def ks(tmp_path):
    return SPIFKeyStore(tmp_path / "ks")


# --- controls -------------------------------------------------------------
def test_control_add_get_roundtrip(ks):
    ks.add_key("alice", KEY)
    assert ks.get_key("alice") == KEY
    assert ks.has_key("alice")


def test_control_revoke_string(ks):
    ks.revoke("alice")
    assert ks.is_revoked("alice") is True
    assert ks.is_revoked("bob") is False


# --- hostile: add path ----------------------------------------------------
@pytest.mark.parametrize("bad", [123, None, ["alice"], {"a": 1}])
def test_add_key_nonstring_id_fails_clean(ks, bad):
    with pytest.raises(CLEAN):
        ks.add_key(bad, KEY)


def test_add_key_bytes_id_no_alias(ks):
    # bytes b'alice' must not silently register (or retrieve as) 'alice'
    try:
        ks.add_key(b"alice", KEY)
    except CLEAN:
        return
    except Exception:
        raise AssertionError("bare exception on bytes key_id")
    assert ks.get_key("alice") is None, "bytes id aliased onto string id 'alice'"


# --- hostile: lookup paths -------------------------------------------------
@pytest.mark.parametrize("bad", [123, None, ["alice"]])
def test_get_key_nonstring_lookup_clean(ks, bad):
    ks.add_key("alice", KEY)
    try:
        result = ks.get_key(bad)
    except CLEAN:
        return
    assert result is None, f"non-string lookup {bad!r} returned a key"


def test_get_key_bytes_lookup_no_alias(ks):
    ks.add_key("alice", KEY)
    try:
        result = ks.get_key(b"alice")
    except CLEAN:
        return
    assert result is None, "bytes lookup aliased onto string id 'alice'"


# --- hostile: revocation aliasing ------------------------------------------
def test_revoke_int_id_no_string_alias(ks):
    try:
        ks.revoke(123)
    except CLEAN:
        return
    except Exception:
        raise AssertionError("bare exception on int revoke")
    assert ks.is_revoked("123") is False, "revoke(123) silently revoked signer '123'"


def test_authorize_role_int_role_no_string_alias(ks):
    try:
        ks.authorize_role(123, "alice")
    except CLEAN:
        return
    except Exception:
        raise AssertionError("bare exception on int role")
    assert ks.has_role_authorization_list("123") is False, (
        "authorize_role(123, ...) silently created role '123'"
    )


# --- added at conversion: sibling entry points -------------------------
# The preserved probe exercises add_key / get_key / revoke /
# authorize_role. The fix is one keystore-wide pass, so the remaining
# entry points that take a key_id / role / signer_id are pinned here
# with the same clean-rejection expectation.

@pytest.mark.parametrize("bad", [123, None, b"alice", ["alice"]])
def test_sibling_entry_points_nonstring_id_fails_clean(ks, bad):
    from spif.pq_hybrid import ML_DSA_65_PUBLIC_KEY_LEN

    with pytest.raises(CLEAN):
        ks.add_hybrid_key(bad, KEY, b"M" * ML_DSA_65_PUBLIC_KEY_LEN)
    with pytest.raises(CLEAN):
        ks.get_hybrid_key(bad)
    with pytest.raises(CLEAN):
        ks.remove_key(bad)
    with pytest.raises(CLEAN):
        ks.unrevoke(bad)
    with pytest.raises(CLEAN):
        ks.is_revoked(bad)
    with pytest.raises(CLEAN):
        ks.deauthorize_role(bad, "alice")
    with pytest.raises(CLEAN):
        ks.deauthorize_role("role", bad)
    with pytest.raises(CLEAN):
        ks.is_authorized_for_role(bad, "alice")
    with pytest.raises(CLEAN):
        ks.is_authorized_for_role("role", bad)
    with pytest.raises(CLEAN):
        ks.has_role_authorization_list(bad)
