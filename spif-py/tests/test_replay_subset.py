"""Permanent regression suite for SPIF-REPLAY-SUBSET-001.

Converted verbatim (assertions unchanged) from the loop probe
test_loop_subset_replay_probe.py (cycle 2026-11-14-2022).

Genuine 2-signer multisig envelope, provenance nonce N. Attacker strips
one signer entry (body_to_sign unchanged, remaining signature genuine,
checksum recomputed). Invariant: the stripped variant must not be
accepted as a FRESH document by the composed verify+ReplayGuard path --
signer k1's (signer, nonce) was already consumed by the full envelope.
ReplayGuard consumes the nonce per signer, so any signer-set
composition that re-presents a consumed (signer, nonce) pair is a
replay, in either presentation order.
"""
import base64, hashlib, struct
import cbor2, pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from spif import Node, Provenance, SPIFDocument, SPIFWriter
from spif.crypto import generate_key
from spif.format import CHUNK_CHECKSUM, CHUNK_MULTISIG, MAGIC
from spif.reader import SPIFReader
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature

_CHUNK = struct.Struct(">BI")
TS = 1_700_000_000_000
K1, K2 = generate_key(), generate_key()

def _b64(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

def _chunks(data):
    off = len(MAGIC) + 2; out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, off, data[off+5:off+5+ln])); off += 5 + ln
        if ct == CHUNK_CHECKSUM: break
    return out

def _body_of(data):
    for ct, off, _ in _chunks(data):
        if ct == CHUNK_MULTISIG: return data[:off]
    raise AssertionError("no multisig")

def _genuine():
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="multi")],
                       provenance=Provenance(source_model="m", timestamp_ms=TS, nonce="n-subset-1"))
    dummy = Signature(algorithm="ed25519", signer="x", signature=b"\x00"*64)
    doc.signatures = [dummy, dummy]
    body = _body_of(SPIFWriter().encode(doc))
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(K1), signature=K1.sign(body)),
        Signature(algorithm="ed25519", signer=_b64(K2), signature=K2.sign(body)),
    ]
    return SPIFWriter().encode(doc)

def _strip_to_first(data):
    parts = [data[:len(MAGIC)+2]]
    for ct, off, p in _chunks(data):
        if ct == CHUNK_CHECKSUM: continue
        if ct == CHUNK_MULTISIG:
            entries = cbor2.loads(p)
            p = cbor2.dumps(entries[:1], canonical=True)
        parts.append(_CHUNK.pack(ct, len(p)) + p)
    body = b"".join(parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()

def test_control_full_verifies_and_verbatim_replay_rejected():
    data = _genuine()
    assert SPIFReader().verify_signature(data) is True
    g = ReplayGuard(); doc = SPIFReader().decode(data)
    g.check(doc)
    with pytest.raises(SPIFReplayError):
        g.check(SPIFReader().decode(data))

def test_stripped_subset_verifies_cryptographically():
    stripped = _strip_to_first(_genuine())
    assert SPIFReader().verify_signature(stripped) is True
    assert len(SPIFReader().decode(stripped).signatures) == 1

def test_stripped_subset_is_replay_after_full_seen():
    data = _genuine(); stripped = _strip_to_first(data)
    g = ReplayGuard(); g.check(SPIFReader().decode(data))
    with pytest.raises(SPIFReplayError):
        g.check(SPIFReader().decode(stripped))

def test_full_is_replay_after_stripped_seen():
    data = _genuine(); stripped = _strip_to_first(data)
    g = ReplayGuard(); g.check(SPIFReader().decode(stripped))
    with pytest.raises(SPIFReplayError):
        g.check(SPIFReader().decode(data))
