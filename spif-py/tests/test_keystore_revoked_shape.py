"""Permanent regression suite for SPIF-KEYSTORE-REVOKED-SHAPE-001.

Converted from the loop probe test_loop_keystore_revoked_probe.py
(cycle 2026-11-16-0222; preserved under the loop goal's
hidden_files/evidence/2026-11-16-0222/spif/). Probe legs are verbatim.

Invariant: a malformed revocation file must fail closed with a SPIF error
(SPIFSignatureError) on every read path -- never a bare TypeError/ValueError
a caller catching SPIFError would miss, and never a silent empty set that
treats a revoked signer as live (fail-open).

Fix: SPIFKeyStore._load_revoked shape-validates the parsed file
(the 'revoked' value must be an object mapping str -> int ms), in the
style of _load_roles, and raises SPIFSignatureError on any malformed
shape. A malformed file never reads as "no revocations".
"""
from __future__ import annotations
import json
import pytest
from spif.keystore import SPIFKeyStore
from spif.reader import SPIFSignatureError


def _ks(tmp_path, revoked_content):
    root = tmp_path / "k"
    ks = SPIFKeyStore(root)
    if revoked_content is not None:
        (root / "revoked.json").write_text(revoked_content)
    return ks


def test_control_missing_file_not_revoked(tmp_path):
    ks = _ks(tmp_path, None)
    assert ks.is_revoked("alice") is False
    assert ks.revoked_keys() == {}


def test_control_valid_file_revoked(tmp_path):
    ks = _ks(tmp_path, json.dumps({"revoked": {"alice": 1700000000000}}))
    assert ks.is_revoked("alice") is True
    assert ks.revoked_keys() == {"alice": 1700000000000}


def test_control_truncated_json_fails_closed_spif_error(tmp_path):
    ks = _ks(tmp_path, '{"revoked": {"alice": 17')
    with pytest.raises(SPIFSignatureError):
        ks.is_revoked("alice")


def test_revoked_as_string_fails_closed_spif_error(tmp_path):
    ks = _ks(tmp_path, json.dumps({"revoked": "alice"}))
    with pytest.raises(SPIFSignatureError):
        ks.is_revoked("alice")


def test_revoked_as_int_fails_closed_spif_error(tmp_path):
    ks = _ks(tmp_path, json.dumps({"revoked": 123}))
    with pytest.raises(SPIFSignatureError):
        ks.is_revoked("alice")


def test_revoked_as_list_of_names_fails_closed_spif_error(tmp_path):
    ks = _ks(tmp_path, json.dumps({"revoked": ["alice"]}))
    with pytest.raises(SPIFSignatureError):
        ks.is_revoked("alice")


def test_revoked_as_list_of_pairs_bad_element_fails_closed(tmp_path):
    ks = _ks(tmp_path, json.dumps({"revoked": [["alice", 1], ["bob"]]}))
    with pytest.raises(SPIFSignatureError):
        ks.revoked_keys()
