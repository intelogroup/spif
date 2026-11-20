"""Permanent regression suite for SPIF-SEMANTIC-COVARIANCE-SHAPE-001 (dim-0 extension).

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-20-0522: SEMANTIC dim-0 embedding with non-empty covariance.
Invariant: SPEC 5.6 covariance is dim x dim where dim = len(embedding).
A SEMANTIC chunk whose embedding is empty/missing (dim 0) but whose
covariance is non-empty (1x1, 2x2, single row) is dimensionally
impossible and must fail closed with SPIFError, never decode.
Extension surface of SPIF-SEMANTIC-COVARIANCE-SHAPE-001 (dim-2 legs
already on that card); the dim-0 boundary was not covered.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_SEMANTIC, MAGIC
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
def _with_sem(obj):
    data=_base()
    parts=[(t,p) for t,p in _chunks(data) if t!=CHUNK_CHECKSUM]
    parts.append((CHUNK_SEMANTIC, cbor2.dumps(obj)))
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(t,len(p))+p for t,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _sem(emb_marker, cov):
    s={"embedding_model":"test-model","covariance":cov}
    if emb_marker is not None: s["embedding"]=emb_marker
    return s
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
# controls
def test_control_dim2_cov2x2_decodes():
    doc=SPIFReader().decode(_with_sem(_sem([0.1,0.2],[[1.0,0.0],[0.0,1.0]]))); assert doc.semantic.dim==2
def test_control_dim2_nocov_decodes():
    doc=SPIFReader().decode(_with_sem(_sem([0.1,0.2],[]))); assert doc.semantic.dim==2
def test_control_dim1_cov1x1_decodes():
    doc=SPIFReader().decode(_with_sem(_sem([0.5],[[1.0]]))); assert doc.semantic.dim==1
# hostile: dim 0 with non-empty covariance
def test_dim0_cov1x1_rejected(): _closed(_with_sem(_sem([ ],[[1.0]])))
def test_dim0_cov2x2_rejected(): _closed(_with_sem(_sem([ ],[[1.0,0.0],[0.0,1.0]])))
def test_dim0_cov_single_row_rejected(): _closed(_with_sem(_sem([ ],[[1.0,2.0]])))
def test_missing_embedding_cov1x1_rejected(): _closed(_with_sem(_sem(None,[[1.0]])))
