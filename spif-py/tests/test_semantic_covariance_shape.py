"""Permanent regression suite for SPIF-SEMANTIC-COVARIANCE-SHAPE-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-19-1122: hostile SEMANTIC covariance shape.
Invariant: SPEC 5.6 -- covariance is a dim x dim matrix, dim == len(embedding).
Reader checks only list-of-lists-of-numbers, never shape vs embedding dim;
SemanticLayer has no __post_init__. A non-square / ragged / wrong-size
covariance for the declared embedding must fail closed with SPIFError.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, Provenance, SemanticLayer, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_SEMANTIC, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _doc():
    return SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test", timestamp_ms=1700000000000, nonce="n1"),
        semantic=SemanticLayer(embedding=[0.1,0.2], embedding_model="test-model", covariance=[[1.0,0.0],[0.0,1.0]]))
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with_sem(obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==CHUNK_SEMANTIC else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _sem(**over):
    s={"embedding":[0.1,0.2],"embedding_model":"test-model","dim":2,"covariance":[[1.0,0.0],[0.0,1.0]]}
    s.update(over); return s
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.semantic.covariance==[[1.0,0.0],[0.0,1.0]]
def test_control_empty_covariance_decodes():
    doc=SPIFReader().decode(_with_sem(_sem(covariance=[]))); assert doc.semantic.covariance==[]
def test_control_square_1x1_for_dim1_decodes():
    doc=SPIFReader().decode(_with_sem(_sem(embedding=[0.5], dim=1, covariance=[[0.25]]))); assert doc.semantic.dim==1
def test_cov_1x1_for_dim2_rejected(): _closed(_with_sem(_sem(covariance=[[1.0]])))
def test_cov_3x3_for_dim2_rejected(): _closed(_with_sem(_sem(covariance=[[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]])))
def test_cov_ragged_rejected(): _closed(_with_sem(_sem(covariance=[[1.0,0.0],[0.0]])))
def test_cov_wide_rows_rejected(): _closed(_with_sem(_sem(covariance=[[1.0,0.0,0.0],[0.0,1.0,0.0]])))
def test_cov_single_row_rejected(): _closed(_with_sem(_sem(covariance=[[1.0,0.0]])))


# --- Legs added at conversion: construction + writer paths ---

def test_semantic_shape_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        SemanticLayer(embedding=[0.1, 0.2], embedding_model="m",
                      covariance=[[1.0]])

def test_writer_rejects_mutated_covariance_shape():
    doc = _doc()
    doc.semantic.covariance = [[1.0]]
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)
