"""Permanent regression suite for SPIF-NONFINITE-NUMERIC-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-18-1122: hostile non-finite numeric fields (cousin of SPIF-ALTS-NONFINITE-WEIGHT-001).
Invariant: every numeric field in PAYLOAD confidence (Distribution mean/var/p5/p95),
SEMANTIC embedding/covariance, and PROVENANCE temperature/energy_wh must be finite;
a NaN or +/-Inf spelling fails closed with SPIFError -- never decoded, never VALID.
The ALTS fix proved the discipline intends finiteness; these surfaces only type-check numbers.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, Provenance, SemanticLayer, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_PAYLOAD, CHUNK_PROVENANCE, CHUNK_SEMANTIC, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
INF=float("inf"); NINF=float("-inf"); NAN=float("nan")
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
def _with(chunk_type, obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==chunk_type else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def _node(**conf_over):
    conf={"mean":0.9,"var":0.05,"shape":"gaussian","semantics":"epistemic"}
    conf.update(conf_over)
    return [{"id":"n1","type":"fact","value":"canonical fact","confidence":conf,"refs":[]}]
def _sem(**over):
    s={"embedding":[0.1,0.2],"embedding_model":"test-model","covariance":[[1.0,0.0],[0.0,1.0]]}
    s.update(over); return s
def _prov(**over):
    p={"source_model":"canonical-test","timestamp_ms":1700000000000,"nonce":"n1","temperature":0.5,"attempt":1,"energy_wh":1.0}
    p.update(over); return p
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.payload[0].value=="canonical fact"
# PAYLOAD confidence Distribution
def test_conf_mean_nan_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(mean=NAN)))
def test_conf_mean_inf_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(mean=INF)))
def test_conf_var_nan_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(var=NAN)))
def test_conf_var_inf_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(var=INF)))
def test_conf_var_neginf_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(var=NINF)))
def test_conf_p5_nan_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(p5=NAN)))
def test_conf_p95_inf_rejected(): _closed(_with(CHUNK_PAYLOAD,_node(p95=INF)))
# SEMANTIC
def test_embedding_inf_rejected(): _closed(_with(CHUNK_SEMANTIC,_sem(embedding=[0.1,INF])))
def test_embedding_neginf_rejected(): _closed(_with(CHUNK_SEMANTIC,_sem(embedding=[NINF,0.2])))
def test_embedding_nan_rejected(): _closed(_with(CHUNK_SEMANTIC,_sem(embedding=[0.1,NAN])))
def test_covariance_inf_rejected(): _closed(_with(CHUNK_SEMANTIC,_sem(covariance=[[INF]])))
def test_covariance_nan_rejected(): _closed(_with(CHUNK_SEMANTIC,_sem(covariance=[[NAN]])))
# PROVENANCE
def test_temperature_inf_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(temperature=INF)))
def test_temperature_neginf_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(temperature=NINF)))
def test_temperature_nan_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(temperature=NAN)))
def test_energy_inf_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(energy_wh=INF)))
def test_energy_nan_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(energy_wh=NAN)))


# --- Legs added at conversion: construction + writer paths ---

def test_provenance_nonfinite_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        Provenance(source_model="m", timestamp_ms=1, temperature=float("inf"))
    with pytest.raises((TypeError, ValueError)):
        Provenance(source_model="m", timestamp_ms=1, energy_wh=float("nan"))

def test_writer_rejects_mutated_nonfinite_provenance():
    doc = _doc()
    doc.provenance.temperature = float("inf")
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)

def test_writer_rejects_mutated_nonfinite_semantic():
    doc = _doc()
    doc.semantic.embedding = [0.1, float("nan")]
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)

def test_writer_rejects_mutated_nonfinite_confidence_var():
    doc = _doc()
    doc.payload[0].confidence.var = float("nan")
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)

def test_distribution_var_nonfinite_construction_rejected():
    from spif import Distribution
    with pytest.raises(ValueError):
        Distribution(mean=0.5, var=float("inf"))
    with pytest.raises(ValueError):
        Distribution(mean=0.5, var=float("nan"))
