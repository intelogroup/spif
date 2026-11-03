"""Canonical-CBOR enforcement (SPIF-NONCANONICAL-ACCEPT-001).

The SIGNATURE chunk lies outside the signing body and the CHECKSUM is
recomputable, so anyone holding a valid envelope can re-encode that
chunk. The reader must fail closed on every non-canonical encoding —
duplicate map keys (either order), indefinite-length forms, non-minimal
length headers — and on bytes trailing the terminal CHECKSUM chunk,
instead of silently normalizing them into a VALID verdict whose meaning
depends on the decoder. Legitimate writer output must keep verifying.

Scope (SPEC §4.1 Option A): the full canonical gate applies to every
chunk of a document that carries a signature — §12.4's writer rule
("canonical CBOR for all chunks when a signature is present") made
reader-verifiable. Duplicate map keys are rejected in *every*
document, signed or unsigned: ambiguity is malformed, not variability.
Pure encoding variability (indefinite-length items, non-minimal forms,
key order) in an *unsigned* document is accepted per §4.1 / §12.1.
"""
import base64
import hashlib
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import Node, Provenance, SPIFDocument
from spif.crypto import generate_key, sign_document
from spif.format import CHUNK_PROVENANCE, CHUNK_SIGNATURE, CHUNK_CHECKSUM, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact

_CHUNK = struct.Struct(">BI")


def _doc():
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test",
                              timestamp_ms=1_700_000_000_000),
    )


def _chunks(data):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _with_chunk(data, chunk_type, payload_bytes):
    parts = [(ct, payload_bytes if ct == chunk_type else p)
             for ct, p in _chunks(data) if ct != CHUNK_CHECKSUM]
    body = data[: len(MAGIC) + 2] + b"".join(
        _CHUNK.pack(ct, len(p)) + p for ct, p in parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _sig_dict(data):
    payload = [p for ct, p in _chunks(data) if ct == CHUNK_SIGNATURE][0]
    return cbor2.loads(payload)


def _signed():
    key = generate_key()
    return key, sign_document(_doc(), key)


def _victim_id(key):
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _assert_rejected(evil):
    assert verify_artifact(evil).trust_status != "VALID"
    with pytest.raises(SPIFError):
        SPIFReader.strict().decode(evil)


def test_canonical_document_still_verifies():
    key, data = _signed()
    assert verify_artifact(data).trust_status == "VALID"
    assert SPIFReader.strict().verify_signature(data) is True


def test_duplicate_signer_key_victim_last_rejected():
    key, data = _signed()
    sd = _sig_dict(data)

    def kv(k, v):
        return cbor2.dumps(k) + cbor2.dumps(v)

    attacker_id = base64.b64encode(b"A" * 32).decode()
    body = (kv("algorithm", sd["algorithm"]) + kv("signer", attacker_id)
            + kv("signer", _victim_id(key)) + kv("signature", sd["signature"])
            + kv("key_id", sd.get("key_id", "")))
    evil = _with_chunk(data, CHUNK_SIGNATURE, b"\xa5" + body)
    _assert_rejected(evil)


def test_duplicate_signer_key_victim_first_rejected():
    key, data = _signed()
    sd = _sig_dict(data)

    def kv(k, v):
        return cbor2.dumps(k) + cbor2.dumps(v)

    attacker_id = base64.b64encode(b"B" * 32).decode()
    body = (kv("algorithm", sd["algorithm"]) + kv("signer", _victim_id(key))
            + kv("signer", attacker_id) + kv("signature", sd["signature"])
            + kv("key_id", sd.get("key_id", "")))
    evil = _with_chunk(data, CHUNK_SIGNATURE, b"\xa5" + body)
    _assert_rejected(evil)


def test_indefinite_length_signature_map_rejected():
    key, data = _signed()
    sd = _sig_dict(data)
    pairs = b"".join(cbor2.dumps(k) + cbor2.dumps(sd[k]) for k in sd)
    evil = _with_chunk(data, CHUNK_SIGNATURE, b"\xbf" + pairs + b"\xff")
    _assert_rejected(evil)


def test_longform_map_header_rejected():
    key, data = _signed()
    sd = _sig_dict(data)
    assert len(sd) < 24  # fits the short form; 0xB8 is the non-minimal form
    pairs = b"".join(cbor2.dumps(k) + cbor2.dumps(sd[k]) for k in sd)
    evil = _with_chunk(data, CHUNK_SIGNATURE, b"\xb8" + bytes([len(sd)]) + pairs)
    _assert_rejected(evil)


def test_duplicate_signature_key_garbage_first_rejected():
    key, data = _signed()
    sd = _sig_dict(data)
    body = b"".join(cbor2.dumps(k) + cbor2.dumps(sd[k])
                    for k in sd if k != "signature")
    body += cbor2.dumps("signature") + cbor2.dumps(b"\x00" * 64)
    body += cbor2.dumps("signature") + cbor2.dumps(sd["signature"])
    evil = _with_chunk(data, CHUNK_SIGNATURE,
                       bytes([0xA0 + len(sd) + 1]) + body)
    _assert_rejected(evil)


def test_duplicate_signature_key_real_first_rejected():
    key, data = _signed()
    sd = _sig_dict(data)
    body = b"".join(cbor2.dumps(k) + cbor2.dumps(sd[k])
                    for k in sd if k != "signature")
    body += cbor2.dumps("signature") + cbor2.dumps(sd["signature"])
    body += cbor2.dumps("signature") + cbor2.dumps(b"\x00" * 64)
    evil = _with_chunk(data, CHUNK_SIGNATURE,
                       bytes([0xA0 + len(sd) + 1]) + body)
    _assert_rejected(evil)


def test_duplicate_key_in_any_chunk_rejected():
    # The gate lives in the shared chunk loader, not the SIGNATURE path:
    # a duplicated key in the PROVENANCE chunk fails plain decode too.
    key, data = _signed()
    prov = [p for ct, p in _chunks(data) if ct == CHUNK_PROVENANCE][0]
    pd = cbor2.loads(prov)

    def kv(k, v):
        return cbor2.dumps(k) + cbor2.dumps(v)

    body = kv("source_model", "attacker") + b"".join(
        kv(k, pd[k]) for k in pd)
    evil = _with_chunk(data, CHUNK_PROVENANCE,
                       bytes([0xA0 + len(pd) + 1]) + body)
    with pytest.raises(SPIFError):
        SPIFReader().decode(evil)


def test_trailing_bytes_after_checksum_rejected():
    key, data = _signed()
    evil = data + b"\x04\x00\x00\x00\x02\x80\xffTRAILING-GARBAGE"
    _assert_rejected(evil)


# ---------------------------------------------------------------------------
# Option A boundary: signed => canonical everywhere; unsigned =>
# ambiguity rejected, variability accepted (SPEC §4.1 / §12.1 / §12.4)
# ---------------------------------------------------------------------------

from spif.writer import SPIFWriter  # noqa: E402


def _unsigned():
    return SPIFWriter().encode(_doc())


def _prov_dict(data):
    payload = [p for ct, p in _chunks(data) if ct == CHUNK_PROVENANCE][0]
    return cbor2.loads(payload)


def _indefinite_map_bytes(d, *, long_form_key=None):
    """Encode dict `d` as an indefinite-length CBOR map (0xBF ... 0xFF)
    with pairs in reverse (unsorted) order. If `long_form_key` names a
    key, that key's text header uses the non-minimal long form."""
    parts = [b"\xbf"]
    for k in reversed(list(d)):
        if k == long_form_key:
            kb = k.encode()
            parts.append(b"\x78" + bytes([len(kb)]) + kb)
        else:
            parts.append(cbor2.dumps(k))
        parts.append(cbor2.dumps(d[k]))
    parts.append(b"\xff")
    return b"".join(parts)


def test_unsigned_indefinite_map_and_unsorted_keys_read_fine():
    data = _unsigned()
    pd = _prov_dict(data)
    variant = _with_chunk(data, CHUNK_PROVENANCE,
                          _indefinite_map_bytes(pd, long_form_key="source_model"))
    doc = SPIFReader().decode(variant)
    assert doc.provenance.source_model == pd["source_model"]
    assert doc.payload[0].value == "canonical fact"
    assert verify_artifact(variant).trust_status == "UNSIGNED"


def test_unsigned_duplicate_key_rejected():
    # Ambiguity is not variability: a duplicated key in an unsigned
    # document is malformed even though §4.1 accepts its encoding forms.
    data = _unsigned()
    pd = _prov_dict(data)

    def kv(k, v):
        return cbor2.dumps(k) + cbor2.dumps(v)

    body = b"".join(kv(k, pd[k]) for k in pd)
    body += kv("source_model", "second-value-wins")
    evil = _with_chunk(data, CHUNK_PROVENANCE,
                       bytes([0xA0 + len(pd) + 1]) + body)
    with pytest.raises(SPIFError):
        SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status == "INVALID"


def _resign_with_chunk(data, key, chunk_type, payload_bytes):
    """Replace one pre-signature chunk's payload and re-sign the new
    signing body, so the resulting document's signature is genuinely
    valid and the chunk's encoding form is its only defect."""
    parts = [(ct, payload_bytes if ct == chunk_type else p)
             for ct, p in _chunks(data) if ct != CHUNK_CHECKSUM]
    prefix = data[: len(MAGIC) + 2]
    sig_index = next(i for i, (ct, _) in enumerate(parts)
                     if ct == CHUNK_SIGNATURE)
    body_to_sign = prefix + b"".join(
        _CHUNK.pack(ct, len(p)) + p for ct, p in parts[:sig_index])
    sd = _sig_dict(data)
    sd["signature"] = key.sign(body_to_sign)
    parts[sig_index] = (CHUNK_SIGNATURE, cbor2.dumps(sd, canonical=True))
    body = prefix + b"".join(
        _CHUNK.pack(ct, len(p)) + p for ct, p in parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def test_signed_indefinite_map_in_provenance_rejected():
    # The signed => canonical rule covers every chunk, not just the
    # auth chunks: a genuinely-signed document whose PROVENANCE chunk
    # uses an indefinite-length map fails the form gate at decode.
    key, data = _signed()
    pd = _prov_dict(data)
    evil = _resign_with_chunk(data, key, CHUNK_PROVENANCE,
                              _indefinite_map_bytes(pd))
    with pytest.raises(SPIFError):
        SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status == "INVALID"
