"""One attestation per document (SPIF-CROSSAUTH-SIGNER-EXPANSION-001).

SIGNATURE and MULTISIG are two encodings of the same claim — the
signer set, which is part of a document's meaning (SPEC §7.2). The
reader previously verified every entry of *both* chunks against the
same public signing body and reported the union as the attested
signer set. Anyone holding a signed envelope could therefore append
the *other* auth chunk type carrying their own entry, signed with
their own key over that public body, recompute the CHECKSUM, and be
reported as an attested signer of a VALID document — and, because
signer-set membership confers revocation authority, revoke the
victim's document.

The rule now: a document carries exactly one attestation. decode()
rejects an envelope carrying both chunk types, just as it already
rejected a duplicate chunk of either type on its own — so a
decodable document holds at most one auth chunk in total, and the
reported signer set (and revocation authority) derives only from it.
Honest single-auth documents, and unsigned documents, are unaffected.
"""
import base64
import hashlib
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import Node, Provenance, SPIFDocument, SPIFWriter
from spif.crypto import generate_key, sign_document
from spif.format import CHUNK_CHECKSUM, CHUNK_MULTISIG, CHUNK_SIGNATURE, MAGIC
from spif.reader import SPIFFormatError, SPIFReader
from spif.types import Signature
from spif.trust import attach_revocations, create_revocation, verify_artifact

_CHUNK = struct.Struct(">BI")
TS = 1_700_000_000_000


def _b64(key):
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _chunks(data):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, off, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _insert_before_checksum(data, ctype, payload):
    parts = [data[:len(MAGIC) + 2]]
    for ct, off, p in _chunks(data):
        if ct == CHUNK_CHECKSUM:
            continue
        parts.append(_CHUNK.pack(ct, len(p)) + p)
    parts.append(_CHUNK.pack(ctype, len(payload)) + payload)
    body = b"".join(parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _body_of(data):
    for ct, off, _p in _chunks(data):
        if ct in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            return data[:off]
    raise AssertionError("no auth chunk")


def _entry(key, signer_id, body):
    return {"algorithm": "ed25519", "signer": signer_id,
            "signature": key.sign(body), "key_id": ""}


def _doc(value):
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=value)],
        provenance=Provenance(source_model="m", timestamp_ms=TS))


def _genuine_multisig(k1, k2):
    doc = _doc("multi")
    dummy = Signature(algorithm="ed25519", signer="x", signature=b"\x00" * 64)
    doc.signatures = [dummy, dummy]
    body = _body_of(SPIFWriter().encode(doc))
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(k1), signature=k1.sign(body)),
        Signature(algorithm="ed25519", signer=_b64(k2), signature=k2.sign(body)),
    ]
    return SPIFWriter().encode(doc)


VICTIM = generate_key()
SECOND = generate_key()
ATTACKER = generate_key()


def _forged_single_plus_multi():
    data = sign_document(_doc("victim"), VICTIM)
    body = _body_of(data)
    payload = cbor2.dumps([_entry(ATTACKER, _b64(ATTACKER), body)], canonical=True)
    return _insert_before_checksum(data, CHUNK_MULTISIG, payload)


def _forged_multi_plus_single():
    data = _genuine_multisig(VICTIM, SECOND)
    body = _body_of(data)
    payload = cbor2.dumps(_entry(ATTACKER, _b64(ATTACKER), body), canonical=True)
    return _insert_before_checksum(data, CHUNK_SIGNATURE, payload)


# --- Co-presence is rejected, both directions -----------------------------

def test_appended_multisig_to_single_signature_doc_rejected():
    forged = _forged_single_plus_multi()
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    rep = verify_artifact(forged)
    assert rep.trust_status == "INVALID"
    assert _b64(ATTACKER) not in rep.signers
    assert rep.signers == []


def test_appended_signature_to_multisig_doc_rejected():
    forged = _forged_multi_plus_single()
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    rep = verify_artifact(forged)
    assert rep.trust_status == "INVALID"
    assert _b64(ATTACKER) not in rep.signers
    assert rep.signers == []


def test_verify_signature_does_not_accept_copresent_auth():
    for forged in (_forged_single_plus_multi(), _forged_multi_plus_single()):
        with pytest.raises(SPIFFormatError):
            SPIFReader().verify_signature(forged)


# --- The escalation: an appended signer gains no revocation authority -----

def test_appended_signer_cannot_revoke_victims_document():
    forged = _forged_single_plus_multi()
    stmt = create_revocation(forged, ATTACKER)
    rep = verify_artifact(attach_revocations(forged, [stmt]))
    assert rep.trust_status != "REVOKED"
    assert rep.trust_status == "INVALID"
    assert len(rep.revocations_applied) == 0


# --- Cousins: duplicate auth chunks of a single type stay rejected ---------

def test_duplicate_signature_chunk_rejected():
    data = sign_document(_doc("victim"), VICTIM)
    body = _body_of(data)
    payload = cbor2.dumps(_entry(ATTACKER, _b64(ATTACKER), body), canonical=True)
    forged = _insert_before_checksum(data, CHUNK_SIGNATURE, payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    assert verify_artifact(forged).trust_status == "INVALID"


def test_duplicate_multisig_chunk_rejected():
    data = _genuine_multisig(VICTIM, SECOND)
    body = _body_of(data)
    payload = cbor2.dumps([_entry(ATTACKER, _b64(ATTACKER), body)], canonical=True)
    forged = _insert_before_checksum(data, CHUNK_MULTISIG, payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    assert verify_artifact(forged).trust_status == "INVALID"


# --- Honest documents are unaffected ---------------------------------------

def test_honest_single_signature_still_verifies():
    data = sign_document(_doc("victim"), VICTIM)
    rep = verify_artifact(data)
    assert rep.trust_status == "VALID"
    assert rep.signers == [_b64(VICTIM)]
    assert SPIFReader().verify_signature(data) is True


def test_honest_multisig_still_verifies():
    data = _genuine_multisig(VICTIM, SECOND)
    rep = verify_artifact(data)
    assert rep.trust_status == "VALID"
    assert rep.signers == [_b64(VICTIM), _b64(SECOND)]
    assert SPIFReader().verify_signature(data) is True


def test_genuine_signer_revocation_still_applies():
    # Revocation authority derives from the (single) accepted auth
    # chunk's signer set: the real signer can still revoke.
    data = sign_document(_doc("victim"), VICTIM)
    stmt = create_revocation(data, VICTIM)
    rep = verify_artifact(attach_revocations(data, [stmt]))
    assert rep.trust_status == "REVOKED"
    assert len(rep.revocations_applied) == 1


def test_unsigned_document_unaffected():
    data = SPIFWriter().encode(_doc("unsigned"))
    rep = verify_artifact(data)
    assert rep.trust_status == "UNSIGNED"
    assert rep.signers == []
