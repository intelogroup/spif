"""v1.3 revocation: signed statements, REVOKED trust status, forgery handling.

Covers SPEC §6.12 / §7.7. The trust layer (spif.trust) is what is under
test; plain §7.2 signature verification must be unaffected by the
post-signature REVOCATION chunk.
"""

import hashlib
import struct

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spif import (
    SPIFDocument, Node, Provenance, SPIFWriter, SPIFReader, Signature,
)
from spif.crypto import sign_document, generate_key
from spif.format import MAGIC, CHUNK_MULTISIG, CHUNK_CHECKSUM
from spif.trust import (
    verify_artifact, create_revocation, attach_revocations,
    extract_revocations, save_revocation_list, load_revocation_statements,
    artifact_digest, TRUST_VALID, TRUST_REVOKED, TRUST_INVALID, TRUST_UNSIGNED,
)


def _doc(text="hello world"):
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value=text)],
        provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
    )


def _signed(text="hello world"):
    key = generate_key()
    data = sign_document(_doc(text), key)
    return key, data


def _fix_checksum(data: bytes) -> bytes:
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == CHUNK_CHECKSUM:
            body = data[:offset]
            return body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()
        offset += 5 + ln
    raise AssertionError("no CHECKSUM chunk")


def _tampered(data: bytes) -> bytes:
    """Flip a payload byte, then repair the checksum so the document still
    parses — the signature (which the attacker cannot recompute) must fail."""
    b = bytearray(data)
    idx = data.find(b"hello world")
    assert idx > 0
    b[idx] = ord("H")
    return _fix_checksum(bytes(b))


# ---------------------------------------------------------------------------
# Control: no revocation
# ---------------------------------------------------------------------------

def test_signed_artifact_is_valid_without_revocation():
    _key, data = _signed()
    report = verify_artifact(data)
    assert report.trust_status == TRUST_VALID
    assert report.signature_status == "valid"
    assert report.revocations_applied == []
    assert report.forged_revocations == 0


def test_unsigned_artifact_is_unsigned():
    data = SPIFWriter().encode(_doc())
    report = verify_artifact(data)
    assert report.trust_status == TRUST_UNSIGNED
    assert report.signature_status == "unsigned"


# ---------------------------------------------------------------------------
# Valid revocations -> REVOKED
# ---------------------------------------------------------------------------

def test_revocation_supplied_as_list_marks_revoked():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    report = verify_artifact(data, revocations=[stmt])
    assert report.signature_status == "valid"          # cryptography is sound
    assert report.trust_status == TRUST_REVOKED        # but trust is retracted
    assert report.revocations_applied == [stmt]
    assert report.forged_revocations == 0


def test_revocation_embedded_in_chunk_marks_revoked():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="compromised")
    embedded = attach_revocations(data, [stmt])

    # The post-signature chunk must not disturb plain §7.2 verification.
    assert SPIFReader().verify_signature(embedded) is True
    # The reader exposes the embedded statements.
    doc = SPIFReader().decode(embedded)
    assert doc.revocations == [stmt]
    assert extract_revocations(embedded) == [stmt]

    report = verify_artifact(embedded)
    assert report.trust_status == TRUST_REVOKED
    assert report.revocations_applied == [stmt]


def test_revocation_via_list_file_marks_revoked(tmp_path):
    key, data = _signed()
    stmt = create_revocation(data, key, reason="superseded")
    path = tmp_path / "revocations.json"
    save_revocation_list([stmt], path)
    assert load_revocation_statements(path) == [stmt]

    report = verify_artifact(data, revocation_file=path)
    assert report.trust_status == TRUST_REVOKED


def test_writer_emitted_revocations_roundtrip():
    key = generate_key()
    doc = _doc()
    stmt = create_revocation(sign_document(doc, key), key, reason="retracted")
    doc.revocations = [stmt]
    data = sign_document(doc, key)
    assert artifact_digest(data) == stmt.artifact_digest
    report = verify_artifact(data)
    assert report.trust_status == TRUST_REVOKED


def test_cosigner_can_revoke_multisig():
    key_a, key_b = generate_key(), generate_key()
    import base64
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def _b64(k):
        return base64.b64encode(
            k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    doc = _doc()
    writer = SPIFWriter()
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(key_a), signature=b"\x00" * 64),
        Signature(algorithm="ed25519", signer=_b64(key_b), signature=b"\x00" * 64),
    ]
    dummy = writer.encode(doc)
    offset = len(MAGIC) + 2
    body = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_MULTISIG:
            body = dummy[:offset]
            break
        offset += 5 + ln
    assert body is not None
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(key_a), signature=key_a.sign(body)),
        Signature(algorithm="ed25519", signer=_b64(key_b), signature=key_b.sign(body)),
    ]
    data = writer.encode(doc)
    assert verify_artifact(data).trust_status == TRUST_VALID

    stmt = create_revocation(data, key_b, reason="compromised")
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_REVOKED


# ---------------------------------------------------------------------------
# Forged revocations -> ignored, flagged, artifact keeps its own status
# ---------------------------------------------------------------------------

def test_forged_revocation_by_non_signer_is_ignored_and_flagged():
    _key, data = _signed()
    attacker = generate_key()
    forged = create_revocation(data, attacker, reason="compromised")
    report = verify_artifact(data, revocations=[forged])
    assert report.trust_status == TRUST_VALID
    assert report.revocations_applied == []
    assert report.forged_revocations == 1


def test_forged_revocation_with_tampered_statement_is_flagged():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    stmt.issued_ms += 1  # mutate after signing -> statement signature breaks
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


def test_revocation_for_other_artifact_has_no_effect():
    key, data = _signed()
    _other_key, other = _signed("different content")
    stmt = create_revocation(other, key, reason="retracted")
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 0  # not about this artifact at all


def test_revocation_does_not_launder_bad_signature():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    report = verify_artifact(_tampered(data), revocations=[stmt])
    assert report.trust_status == TRUST_INVALID
    assert report.signature_status == "invalid"


def test_statement_against_unsigned_artifact_cannot_revoke():
    data = SPIFWriter().encode(_doc())
    attacker = generate_key()
    stmt = create_revocation(data, attacker, reason="retracted")
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_UNSIGNED
    assert report.forged_revocations == 1


# ---------------------------------------------------------------------------
# Statement hygiene
# ---------------------------------------------------------------------------

def test_bad_reason_code_rejected():
    key, data = _signed()
    with pytest.raises(ValueError):
        create_revocation(data, key, reason="oops")


def test_digest_stable_under_attachment():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    embedded = attach_revocations(data, [stmt])
    assert artifact_digest(embedded) == artifact_digest(data)
