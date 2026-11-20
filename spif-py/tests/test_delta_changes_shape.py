"""Permanent regression suite for SPIF-DELTA-CHANGES-SHAPE-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-19-1722: hostile DELTA changes element shape.
Invariant: SPEC 6.7 -- DELTA changes is [dict...]; Delta.changes is list[dict].
Reader checks only that changes is a list, never element types. A non-dict
change record must fail closed with SPIFError, never decode into the document.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_DELTA, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.types import Delta
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _doc():
    return SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        delta=Delta(base_hash="abc123", changes=[{"op": "replace", "path": "/n1", "value": "y"}]))
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with_delta(obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==CHUNK_DELTA else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _delta(changes):
    return {"base_hash": "abc123", "changes": changes}
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.delta.changes[0]["op"]=="replace"
def test_control_empty_changes_decodes():
    doc=SPIFReader().decode(_with_delta(_delta([]))); assert doc.delta.changes==[]
def test_control_missing_base_hash_rejected(): _closed(_with_delta({"changes": []}))
def test_change_int_rejected(): _closed(_with_delta(_delta([123])))
def test_change_string_rejected(): _closed(_with_delta(_delta(["replace"])))
def test_change_list_rejected(): _closed(_with_delta(_delta([["op","replace"]])))
def test_change_none_rejected(): _closed(_with_delta(_delta([None])))
def test_change_bool_rejected(): _closed(_with_delta(_delta([True])))
def test_change_mixed_valid_and_int_rejected(): _closed(_with_delta(_delta([{"op":"replace"}, 123])))


# --- Legs added at conversion: construction + writer paths ---

def test_delta_nondict_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        Delta(base_hash="abc123", changes=[123])

def test_writer_rejects_mutated_nondict_changes():
    doc = _doc()
    doc.delta.changes = ["replace"]
    with pytest.raises((TypeError, ValueError)):
        SPIFWriter().encode(doc)
