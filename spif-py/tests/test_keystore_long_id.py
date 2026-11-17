"""Permanent regression suite for SPIF-KEYSTORE-LONGID-001.

Converted from the loop probe test_loop_keystore_slug_probe.py
(cycle 2026-11-15-2322; preserved under the loop goal's
hidden_files/evidence/2026-11-15-2322/spif/). Probe legs are verbatim;
one leg (test_long_id_hybrid_fails_cleanly_not_oserror) was added at
conversion for the add_hybrid_key path the card also covers -- the
cycle's hybrid leg was an ad-hoc log, not a pytest leg.

Invariant: distinct key_ids must never resolve to the same stored key
(key identity attacks); a hostile/long key_id must fail closed with a
clean rejection, never a bare OSError and never a silent alias.

Fix: add_key/add_hybrid_key build their paths through the same
_entry_path length guard the lookups use, raising ValueError when the
slugged filename would exceed the limit.
"""
from __future__ import annotations
import pytest
from spif.keystore import SPIFKeyStore

ALICE = b"A" * 32
BOB = b"B" * 32

def test_control_exact_id_roundtrip(tmp_path):
    ks = SPIFKeyStore(tmp_path / "k")
    ks.add_key("alice", ALICE)
    assert ks.get_key("alice") == ALICE
    assert ks.get_key("bob") is None

def test_encoded_spelling_not_alias(tmp_path):
    ks = SPIFKeyStore(tmp_path / "k")
    ks.add_key("a/b", ALICE)
    # The literal percent-spelling is a DIFFERENT identity; it must not
    # retrieve a/b's key, and registering it must not overwrite a/b's.
    assert ks.get_key("a%2Fb") is None
    ks.add_key("a%2Fb", BOB)
    assert ks.get_key("a/b") == ALICE
    assert ks.get_key("a%2Fb") == BOB

def test_traversal_id_stays_inside_store(tmp_path):
    root = tmp_path / "k"
    ks = SPIFKeyStore(root)
    ks.add_key("../evil", ALICE)
    assert ks.get_key("../evil") == ALICE
    # No key file may appear outside the store root.
    assert not (tmp_path / "evil.pub").exists()
    assert not list(tmp_path.glob("*.pub"))

def test_case_spellings_distinct(tmp_path):
    ks = SPIFKeyStore(tmp_path / "k")
    ks.add_key("Alice", ALICE)
    assert ks.get_key("alice") is None
    ks.add_key("alice", BOB)
    assert ks.get_key("Alice") == ALICE
    assert ks.get_key("alice") == BOB

def test_long_id_fails_cleanly_not_oserror(tmp_path):
    ks = SPIFKeyStore(tmp_path / "k")
    long_id = "x" * 300
    with pytest.raises((ValueError, KeyError)):
        ks.add_key(long_id, ALICE)
    assert ks.get_key(long_id) is None

def test_unicode_spellings_distinct(tmp_path):
    ks = SPIFKeyStore(tmp_path / "k")
    ks.add_key("café", ALICE)
    assert ks.get_key("caf%C3%A9") is None
    assert ks.get_key("café") == ALICE

def test_long_id_hybrid_fails_cleanly_not_oserror(tmp_path):
    # Added at conversion (see module docstring): the card covers both
    # add paths; the preserved probe's pytest legs exercise add_key,
    # and the cycle's hybrid leg was an ad-hoc log showing the same
    # bare OSError from add_hybrid_key.
    from spif.pq_hybrid import ML_DSA_65_PUBLIC_KEY_LEN

    ks = SPIFKeyStore(tmp_path / "k")
    long_id = "x" * 300
    with pytest.raises((ValueError, KeyError)):
        ks.add_hybrid_key(long_id, ALICE, b"M" * ML_DSA_65_PUBLIC_KEY_LEN)
    assert ks.get_hybrid_key(long_id) is None
