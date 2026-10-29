"""Adversarial tests for the v1.3 trust layer (spif.trust).

Phase B: attack the revocation / timestamp / cross-document machinery with
replayed, duplicated, malformed, transplanted, poisoned, and oversized
inputs. The contract under attack:

- verify_artifact() NEVER raises on untrusted input — it returns a
  VerificationReport. The only statuses are VALID / REVOKED / INVALID /
  UNSIGNED / UNVERIFIABLE, and timestamps verified / unverified / absent.
- A mutation or forgery NEVER produces a false REVOKED or a false
  timestamp "verified".
- Resolution binds the exact referenced content_id, never "any artifact".

Helpers build artifacts the same way the v1.3 suites do, then hand-craft
chunk payloads with cbor2 and splice them in via trust.attach_chunk (which
repairs the checksum, so the document still parses and the trust layer —
not the checksum — is what is being tested).
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, Provenance, SPIFReader, SPIFFormatError
from spif.crypto import sign_document, generate_key
from spif.format import MAGIC, CHUNK_REVOCATION, CHUNK_TIMESTAMP, CHUNK_CHECKSUM
from spif.types import RevocationStatement
from spif.trust import (
    verify_artifact, create_revocation, attach_revocations, attach_timestamp,
    create_timestamp_anchor, attach_chunk, artifact_digest,
    extract_revocations, extract_timestamp,
    TRUST_VALID, TRUST_REVOKED, TRUST_INVALID, TRUST_UNSIGNED, TRUST_UNVERIFIABLE,
    TS_VERIFIED, TS_UNVERIFIED, TS_ABSENT,
)

ALL_TRUST = {TRUST_VALID, TRUST_REVOKED, TRUST_INVALID, TRUST_UNSIGNED, TRUST_UNVERIFIABLE}
ALL_TS = {TS_VERIFIED, TS_UNVERIFIED, TS_ABSENT}


def _b64(key) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _doc(text="hello world", ts=1_700_000_000_000):
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value=text)],
        provenance=Provenance(source_model="test-model", timestamp_ms=ts),
    )


def _signed(text="hello world", ts=1_700_000_000_000):
    key = generate_key()
    return key, sign_document(_doc(text, ts), key)


def _chunk_payload(data: bytes, want: int) -> bytes:
    """Raw payload bytes of the first chunk of type `want` in `data`."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == want:
            return data[offset + 5: offset + 5 + ln]
        offset += 5 + ln
    raise AssertionError(f"chunk 0x{want:02x} not found")


def _splice_chunk(data: bytes, chunk_type: int, payload: bytes) -> bytes:
    """Insert an EXTRA chunk of `chunk_type` before CHECKSUM and repair the
    checksum — builds artifacts with duplicate chunk types, which
    attach_chunk() refuses to produce."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == CHUNK_CHECKSUM:
            body = data[:offset] + struct.pack(">BI", chunk_type, len(payload)) + payload
            return body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()
        offset += 5 + ln
    raise AssertionError("no CHECKSUM chunk")


def _rev_entry(digest, signer, *, issued_ms=1_700_000_100_000, reason="retracted",
               signature=b"\x00" * 64):
    return {
        "artifact_digest": digest, "signer": signer, "issued_ms": issued_ms,
        "reason": reason, "signature": signature,
    }


# ---------------------------------------------------------------------------
# (c) Malformed chunk payloads: clean reports, never a crash, never
#     VALID-by-accident. Regression tests for the type-confusion crashes
#     where unhashable signer/authority values escaped verify_artifact()
#     as TypeError (fixed by type validation in types.from_cbor_dict).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_signer", [["evil"], {"a": 1}, 42, None])
def test_revocation_signer_wrong_type_is_clean_parse_error(bad_signer):
    _key, data = _signed()
    payload = cbor2.dumps(
        [_rev_entry(artifact_digest(data), bad_signer)], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert any("parse" in e for e in report.errors)
    assert report.revocations_applied == []


@pytest.mark.parametrize("bad_authority", [["tsa"], {"a": 1}, 42, None])
def test_timestamp_authority_wrong_type_is_clean_parse_error(bad_authority):
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": bad_authority, "time_ms": 1, "token": b"\x00" * 64},
        canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"someone": _b64(key)})
    assert report.trust_status == TRUST_INVALID
    assert any("parse" in e for e in report.errors)


def test_statement_object_with_unhashable_signer_is_forged_not_crash():
    _key, data = _signed()
    stmt = RevocationStatement(
        artifact_digest=artifact_digest(data), signer=["x"],  # type: ignore[arg-type]
        issued_ms=1, reason="retracted", signature=b"\x00" * 64)
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


@pytest.mark.parametrize("field,bad", [
    ("artifact_digest", 123), ("issued_ms", "soon"), ("issued_ms", {"x": 1}),
    ("reason", ["retracted"]), ("signature", "not-bytes"), ("signature", 7),
])
def test_revocation_entry_field_types_validated(field, bad):
    _key, data = _signed()
    entry = _rev_entry(artifact_digest(data), "whoever")
    entry[field] = bad
    payload = cbor2.dumps([entry], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status in ALL_TRUST
    assert report.trust_status != TRUST_REVOKED
    # Either the entry is rejected at parse (INVALID report) or it parses
    # and is classified forged (VALID artifact, forgery counted).
    assert report.trust_status == TRUST_INVALID or report.forged_revocations == 1


def test_timestamp_time_and_token_types_validated():
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": "tsa", "time_ms": "noon", "token": b"\x00" * 64},
        canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"tsa": _b64(key)})
    assert report.trust_status == TRUST_INVALID  # parse error, clean report
    assert report.timestamp_status == TS_ABSENT


# ---------------------------------------------------------------------------
# (c) Truncated / structurally malformed chunk payloads
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    b"",                                        # empty
    b"\x81",                                    # truncated CBOR array
    b"\x81\xa1\x61\x61",                        # truncated mid-entry
    cbor2.dumps({"not": "a list"}),             # wrong top-level type
    cbor2.dumps([1, 2, 3]),                     # entries not dicts
    cbor2.dumps([{"artifact_digest": "x"}]),    # entry missing fields
])
def test_malformed_revocation_payloads_clean_report(payload):
    _key, data = _signed()
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.revocations_applied == []


@pytest.mark.parametrize("payload", [
    b"",
    b"\xa1\x61\x61",                            # truncated CBOR map
    cbor2.dumps(["not", "a", "dict"]),          # wrong top-level type
    cbor2.dumps({"authority": "tsa"}),          # missing fields
])
def test_malformed_timestamp_payloads_clean_report(payload):
    _key, data = _signed()
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.timestamp_status == TS_ABSENT


def test_revocation_entry_missing_signature_counts_forged():
    key, data = _signed()
    entry = _rev_entry(artifact_digest(data), _b64(key))
    del entry["signature"]  # defaults to b"" -> cannot verify -> forged
    payload = cbor2.dumps([entry], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


def test_timestamp_entry_missing_token_is_unverified():
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": "tsa", "time_ms": 1_700_000_100_000}, canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"tsa": _b64(key)})
    assert report.trust_status == TRUST_VALID
    assert report.timestamp_status == TS_UNVERIFIED


@pytest.mark.parametrize("cut", [15, 30, 60])
def test_truncated_artifact_is_clean_report(cut):
    _key, data = _signed()
    stmt = create_revocation(data, _key)
    embedded = attach_revocations(data, [stmt])
    report = verify_artifact(embedded[:cut])  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.errors
