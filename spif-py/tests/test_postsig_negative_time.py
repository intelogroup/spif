"""Permanent regression suite for SPIF-NEGATIVE-INT-001 (post-signature negative epoch extension).

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-19-2322: hostile negative epoch in post-signature chunks.
Invariant: SPEC 6.12 issued_ms is uint64, SPEC 6.13 time_ms is uint64.
Reader _require_int checks type only, no >=0 range (unlike Provenance
timestamp_ms which has a >=0 post_init guard). A negative epoch must fail
closed with SPIFError, never decode into the document.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_REVOCATION, CHUNK_TIMESTAMP, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _base():
    return SPIFWriter().encode(SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")]))
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with_extra(ct, obj):
    data=_base()
    parts=[(t,p) for t,p in _chunks(data) if t!=CHUNK_CHECKSUM]
    parts.append((ct, cbor2.dumps(obj)))
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(t,len(p))+p for t,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _rev(issued_ms):
    return [{"artifact_digest":"ab"*32, "signer":"alice", "issued_ms":issued_ms, "reason":"retracted", "signature":b"\x00"*64}]
def _ts(time_ms):
    return {"authority":"tsa1", "time_ms":time_ms, "token":b"\x00"*64}
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def test_control_revocation_positive_decodes():
    doc=SPIFReader().decode(_with_extra(CHUNK_REVOCATION,_rev(1700000000000))); assert doc.revocations[0].issued_ms==1700000000000
def test_control_revocation_zero_decodes():
    doc=SPIFReader().decode(_with_extra(CHUNK_REVOCATION,_rev(0))); assert doc.revocations[0].issued_ms==0
def test_control_timestamp_positive_decodes():
    doc=SPIFReader().decode(_with_extra(CHUNK_TIMESTAMP,_ts(1700000000000))); assert doc.timestamp_anchor.time_ms==1700000000000
def test_control_timestamp_zero_decodes():
    doc=SPIFReader().decode(_with_extra(CHUNK_TIMESTAMP,_ts(0))); assert doc.timestamp_anchor.time_ms==0
def test_revocation_negative_one_rejected(): _closed(_with_extra(CHUNK_REVOCATION,_rev(-1)))
def test_revocation_large_negative_rejected(): _closed(_with_extra(CHUNK_REVOCATION,_rev(-1700000000000)))
def test_timestamp_negative_one_rejected(): _closed(_with_extra(CHUNK_TIMESTAMP,_ts(-1)))
def test_timestamp_large_negative_rejected(): _closed(_with_extra(CHUNK_TIMESTAMP,_ts(-9999999999999)))


# --- Legs added at conversion: construction path ---

def test_revocation_negative_construction_rejected():
    from spif.types import RevocationStatement
    with pytest.raises((TypeError, ValueError)):
        RevocationStatement(artifact_digest="ab" * 32, signer="alice",
                            issued_ms=-1, reason="retracted",
                            signature=b"\x00" * 64)

def test_timestamp_negative_construction_rejected():
    from spif.types import TimestampAnchor
    with pytest.raises((TypeError, ValueError)):
        TimestampAnchor(authority="tsa1", time_ms=-1, token=b"\x00" * 64)
