"""Canonical-CBOR enforcement (SPIF-NONCANONICAL-ACCEPT-001).

The SIGNATURE chunk lies outside the signing body and the CHECKSUM is
recomputable, so anyone holding a valid envelope can re-encode that
chunk. The reader must fail closed on every non-canonical encoding —
duplicate map keys (either order), indefinite-length forms, non-minimal
length headers — and on bytes trailing the terminal CHECKSUM chunk,
instead of silently normalizing them into a VALID verdict whose meaning
depends on the decoder. Legitimate writer output must keep verifying.
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
